package tbtc

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/internal/tecdsatest"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/tecdsa"
)

// multiOperatorTestChain gives each simulated node an independent operator
// identity while sharing the same in-memory chain state.
type multiOperatorTestChain struct {
	*localChain
	privateKey  *operator.PrivateKey
	operatorID  chain.OperatorID
	operatorIDs map[chain.Address]chain.OperatorID
}

func (c *multiOperatorTestChain) Signing() chain.Signing {
	return local_v1.NewSigner(c.privateKey)
}

func (c *multiOperatorTestChain) OperatorKeyPair() (
	*operator.PrivateKey,
	*operator.PublicKey,
	error,
) {
	return c.privateKey, &c.privateKey.PublicKey, nil
}

func (c *multiOperatorTestChain) GetOperatorID(
	address chain.Address,
) (chain.OperatorID, error) {
	id, ok := c.operatorIDs[address]
	if !ok {
		return 0, fmt.Errorf("unknown operator address [%s]", address)
	}
	return id, nil
}

// TestMultiOperatorSigningAndTerminatedWalletArchival models five independent
// nodes, each holding exactly one share of the same 4-of-5 tECDSA group. It
// first proves that the operators can jointly sign, then marks the wallet
// terminated and verifies that archival removes each share from the active
// wallet registry so the ordinary signing executor is no longer available.
func TestMultiOperatorSigningAndTerminatedWalletArchival(t *testing.T) {
	const groupSize = 5

	groupParameters := &GroupParameters{
		GroupSize:       groupSize,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	shareFixtures, err := tecdsatest.LoadPrivateKeyShareTestFixtures(groupSize)
	if err != nil {
		t.Fatalf("failed to load tECDSA share fixtures: [%v]", err)
	}

	operatorKeys := make([]*operator.PrivateKey, groupSize)
	operatorAddresses := make([]chain.Address, groupSize)
	operatorIDs := make(map[chain.Address]chain.OperatorID, groupSize)

	for i := 0; i < groupSize; i++ {
		privateKey, publicKey, err := operator.GenerateKeyPair(local_v1.DefaultCurve)
		if err != nil {
			t.Fatalf("failed to generate operator %d key: [%v]", i+1, err)
		}
		operatorKeys[i] = privateKey

		address, err := local_v1.NewSigner(privateKey).PublicKeyToAddress(publicKey)
		if err != nil {
			t.Fatalf("failed to derive operator %d address: [%v]", i+1, err)
		}
		operatorAddresses[i] = address
		operatorIDs[address] = chain.OperatorID(i + 1)
	}

	sharedChain := ConnectWithKey(operatorKeys[0])
	signers := make([]*signer, groupSize)
	for i := 0; i < groupSize; i++ {
		share := tecdsa.NewPrivateKeyShare(shareFixtures[i])
		signers[i] = &signer{
			wallet: wallet{
				publicKey:             share.PublicKey(),
				signingGroupOperators: operatorAddresses,
			},
			signingGroupMemberIndex: group.MemberIndex(i + 1),
			privateKeyShare:         share,
		}
	}

	walletPublicKey := signers[0].wallet.publicKey
	walletPublicKeyHash := bitcoin.PublicKeyHash(walletPublicKey)
	walletID, err := sharedChain.CalculateWalletID(walletPublicKey)
	if err != nil {
		t.Fatalf("failed to calculate wallet ID: [%v]", err)
	}

	sharedChain.setWallet(walletPublicKeyHash, &WalletChainData{
		EcdsaWalletID: walletID,
		State:         StateLive,
	})

	nodes := make([]*node, groupSize)
	executors := make([]*signingExecutor, groupSize)

	for i := 0; i < groupSize; i++ {
		nodeChain := &multiOperatorTestChain{
			localChain:  sharedChain,
			privateKey:  operatorKeys[i],
			operatorID:  chain.OperatorID(i + 1),
			operatorIDs: operatorIDs,
		}

		node, err := newNode(
			groupParameters,
			nodeChain,
			newLocalBitcoinChain(),
			local.ConnectWithKey(&operatorKeys[i].PublicKey),
			createMockKeyStorePersistence(t, signers[i]),
			&mockPersistenceHandle{},
			newTestScheduler(t),
			&mockCoordinationProposalGenerator{},
			Config{PreParamsPoolSize: 1, PreParamsGenerationTimeout: time.Hour},
		)
		if err != nil {
			t.Fatalf("failed to create operator node %d: [%v]", i+1, err)
		}

		executor, ok, err := node.getSigningExecutor(walletPublicKey)
		if err != nil {
			t.Fatalf("operator %d failed to create signing executor: [%v]", i+1, err)
		}
		if !ok {
			t.Fatalf("operator %d does not control its expected share", i+1)
		}
		if len(executor.signers) != 1 {
			t.Fatalf("operator %d controls %d shares; expected exactly one", i+1, len(executor.signers))
		}

		executor.signingAttemptsLimit *= 8
		nodes[i] = node
		executors[i] = executor
	}

	// All five independent operators participate in the same signing session.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	message := big.NewInt(20261128)
	var wait sync.WaitGroup
	errors := make(chan error, groupSize)
	for i := range executors {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			signature, _, _, err := executors[index].sign(ctx, message, 0)
			if err != nil {
				errors <- fmt.Errorf("operator %d signing failed: %w", index+1, err)
				return
			}
			if signature == nil || !ecdsa.Verify(
				walletPublicKey,
				message.Bytes(),
				signature.R,
				signature.S,
			) {
				errors <- fmt.Errorf("operator %d returned an invalid group signature", index+1)
			}
		}(i)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	// Termination removes the wallet from the active chain registry. Each
	// independent node then runs the same archival routine used at startup.
	sharedChain.setWallet(walletPublicKeyHash, &WalletChainData{
		EcdsaWalletID: walletID,
		State:         StateTerminated,
	})

	for i, node := range nodes {
		if err := node.archiveClosedWallets(); err != nil {
			t.Fatalf("operator %d failed to archive terminated wallet: [%v]", i+1, err)
		}

		if got := node.walletRegistry.getSigners(walletPublicKey); len(got) != 0 {
			t.Errorf("operator %d still has %d active signers after archival", i+1, len(got))
		}

	}
}
