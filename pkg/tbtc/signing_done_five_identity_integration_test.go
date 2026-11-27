package tbtc

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/tecdsa"
	"github.com/keep-network/keep-core/pkg/tecdsa/signing"
)

// This regression test models five distinct network identities. Members 1, 2,
// and 3 are selected for the attempt, but member 4 (which is excluded) sends a
// signing-done message in place of member 3. The current implementation accepts
// that message because it validates only whole-group membership, not attempt
// membership. This test is intentionally scoped to message admission and barrier completion.
func TestSigningDoneCheck_ExcludedMemberSubstitutesForAttemptMember_FiveIdentities(t *testing.T) {
	const groupSize = 5
	const honestThreshold = 3

	privateKeys := make([]*operator.PrivateKey, groupSize)
	publicKeys := make([]*operator.PublicKey, groupSize)
	for i := 0; i < groupSize; i++ {
		privateKey, publicKey, err := operator.GenerateKeyPair(local_v1.DefaultCurve)
		if err != nil {
			t.Fatalf("failed to generate identity %d: %v", i+1, err)
		}
		privateKeys[i] = privateKey
		publicKeys[i] = publicKey
	}

	// Build the canonical group membership mapping from five distinct operator
	// addresses. The local chain signer can derive addresses for every public key.
	localChain := ConnectWithKey(groupSize, honestThreshold, privateKeys[0])
	operators := make([]chain.Address, groupSize)
	for i, publicKey := range publicKeys {
		address, err := localChain.Signing().PublicKeyToAddress(publicKey)
		if err != nil {
			t.Fatalf("failed to derive address for identity %d: %v", i+1, err)
		}
		operators[i] = address
	}

	membershipValidator := group.NewMembershipValidator(
		&testutils.MockLogger{},
		operators,
		localChain.Signing(),
	)

	// Each simulated operator has its own network key and broadcast channel.
	checks := make([]*signingDoneCheck, groupSize)
	channelName := fmt.Sprintf("signing-done-five-identities-%d", time.Now().UnixNano())
	for i, publicKey := range publicKeys {
		provider := local.ConnectWithKey(publicKey)
		broadcastChannel, err := provider.BroadcastChannelFor(channelName)
		if err != nil {
			t.Fatalf("failed to create broadcast channel for identity %d: %v", i+1, err)
		}
		broadcastChannel.SetUnmarshaler(func() net.TaggedUnmarshaler {
			return &signingDoneMessage{}
		})
		checks[i] = newSigningDoneCheck(groupSize, broadcastChannel, membershipValidator)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	message := big.NewInt(0x5151)
	attemptNumber := uint64(7)
	attemptTimeoutBlock := uint64(1000)
	attemptMembers := []group.MemberIndex{1, 2, 3}

	for _, check := range checks {
		check.listen(ctx, message, attemptNumber, attemptTimeoutBlock, attemptMembers)
	}

	// The signature is deliberately a fixture: this test isolates the Done
	// barrier and does not claim that the excluded member performed TSS signing.
	copiedTSSResult := &signing.Result{
		Signature: &tecdsa.Signature{
			R:          big.NewInt(200),
			S:          big.NewInt(300),
			RecoveryID: 2,
		},
	}

	// Members 1 and 2 are selected; member 4 is excluded but sends a Done
	// message carrying the same signature. Member 3, a selected member, is
	// silent. If the barrier completes, the excluded member substituted for 3.
	for _, sender := range []int{0, 1, 3} {
		err := checks[sender].signalDone(
			ctx,
			group.MemberIndex(sender+1),
			message,
			attemptNumber,
			copiedTSSResult,
			500+uint64(sender+1),
		)
		if err != nil {
			t.Fatalf("identity %d failed to broadcast Done: %v", sender+1, err)
		}
	}

	for i, check := range checks {
		result, _, err := check.waitUntilAllDone(ctx)
		if err != nil {
			t.Errorf("receiver identity %d did not complete the Done barrier: %v", i+1, err)
			continue
		}
		if result == nil || result.Signature == nil {
			t.Errorf("receiver identity %d returned an empty signature", i+1)
			continue
		}
		if !copiedTSSResult.Signature.Equals(result.Signature) {
			t.Errorf("receiver identity %d returned an unexpected signature", i+1)
		}
	}
}
