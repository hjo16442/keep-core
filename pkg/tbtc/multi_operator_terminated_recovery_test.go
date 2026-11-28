package tbtc

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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

	"github.com/keep-network/keep-common/pkg/persistence"
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
// terminated and archives it. It verifies that archival removes shares from
// the active registry, while separately checking whether already-cached
// signing executors can still use their in-memory shares.
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

	// Archival removes signers from the registry, but getSigningExecutor is
	// cache-first. Verify whether executors created before termination can
	// still complete a threshold signature after the wallet is archived.
	postArchiveMessage := big.NewInt(20261129)
	postArchiveErrors := make(chan error, groupSize)
	for i := range executors {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			signature, _, _, err := executors[index].sign(ctx, postArchiveMessage, 0)
			if err != nil {
				postArchiveErrors <- fmt.Errorf("operator %d post-archive signing failed: %w", index+1, err)
				return
			}
			if signature == nil || !ecdsa.Verify(
				walletPublicKey,
				postArchiveMessage.Bytes(),
				signature.R,
				signature.S,
			) {
				postArchiveErrors <- fmt.Errorf("operator %d returned an invalid post-archive group signature", index+1)
			}
		}(i)
	}
	wait.Wait()
	close(postArchiveErrors)
	for err := range postArchiveErrors {
		t.Error(err)
	}
}

// TestWalletRegistry_ArchivedSignerNotLoadedAfterRestart uses the real disk
// persistence backend to model a process restart after wallet archival. The
// archived share remains on disk, but a fresh registry must not load it into
// the active signer cache.
func TestWalletRegistry_ArchivedSignerNotLoadedAfterRestart(t *testing.T) {
	storageDir := t.TempDir()
	persistenceHandle, err := persistence.NewProtectedDiskHandle(storageDir)
	if err != nil {
		t.Fatalf("failed to create disk persistence: [%v]", err)
	}

	chain := Connect()
	originalRegistry, err := newWalletRegistry(
		persistenceHandle,
		chain.CalculateWalletID,
	)
	if err != nil {
		t.Fatalf("failed to create original wallet registry: [%v]", err)
	}

	signer := createMockSigner(t)
	if err := originalRegistry.registerSigner(signer); err != nil {
		t.Fatalf("failed to persist wallet signer: [%v]", err)
	}

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	walletStorageKey := getWalletStorageKey(signer.wallet.publicKey)
	if err := originalRegistry.archiveWallet(walletPublicKeyHash); err != nil {
		t.Fatalf("failed to archive wallet: [%v]", err)
	}

	// The archive is retained on disk; archival is not secure deletion.
	archivedWalletPath := filepath.Join(storageDir, "archive", walletStorageKey)
	if _, err := os.Stat(archivedWalletPath); err != nil {
		t.Fatalf("expected archived wallet data to remain on disk: [%v]", err)
	}

	// A fresh registry models startup in a new process: it reads only the
	// persistence backend's non-archived ReadAll view.
	restartedRegistry, err := newWalletRegistry(
		persistenceHandle,
		chain.CalculateWalletID,
	)
	if err != nil {
		t.Fatalf("failed to recreate wallet registry: [%v]", err)
	}
	if got := restartedRegistry.getSigners(signer.wallet.publicKey); len(got) != 0 {
		t.Fatalf("expected no active signers after restart, got [%d]", len(got))
	}

	// There is no registry-level unarchive method, but an operator with
	// filesystem access can restore the retained directory to the current
	// storage area. Verify that a subsequent startup can then load the share.
	currentWalletPath := filepath.Join(storageDir, "current", walletStorageKey)
	if err := os.Rename(archivedWalletPath, currentWalletPath); err != nil {
		t.Fatalf("failed to restore archived wallet data for recovery check: [%v]", err)
	}
	recoveredRegistry, err := newWalletRegistry(
		persistenceHandle,
		chain.CalculateWalletID,
	)
	if err != nil {
		t.Fatalf("failed to create registry after manual restore: [%v]", err)
	}
	if got := recoveredRegistry.getSigners(signer.wallet.publicKey); len(got) != 1 {
		t.Fatalf("expected one signer after manual restore, got [%d]", len(got))
	}
}
