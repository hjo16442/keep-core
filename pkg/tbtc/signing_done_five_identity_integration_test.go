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

func setupFiveIdentityDoneChecks(t *testing.T) []*signingDoneCheck {
	t.Helper()

	const groupSize = 5
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

	localChain := ConnectWithKey(privateKeys[0])
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

	return checks
}

func startFiveIdentityDoneChecks(
	t *testing.T,
	checks []*signingDoneCheck,
	ctx context.Context,
) (*big.Int, uint64, []group.MemberIndex) {
	t.Helper()

	message := big.NewInt(0x5151)
	attemptNumber := uint64(7)
	attemptTimeoutBlock := uint64(1000)
	attemptMembers := []group.MemberIndex{1, 2, 3}
	for _, check := range checks {
		check.listen(ctx, message, attemptNumber, attemptTimeoutBlock, attemptMembers)
	}
	return message, attemptNumber, attemptMembers
}

func fixtureSigningResult(r int64) *signing.Result {
	return &signing.Result{
		Signature: &tecdsa.Signature{
			R:          big.NewInt(r),
			S:          big.NewInt(300),
			RecoveryID: 2,
		},
	}
}

// This test demonstrates that a whole-group member excluded from the current
// attempt can substitute for a selected member's Done confirmation. The
// signature is a fixture; this does not claim to execute the TSS protocol.
func TestSigningDoneCheck_ExcludedMemberSubstitutesForAttemptMember_FiveIdentities(t *testing.T) {
	checks := setupFiveIdentityDoneChecks(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	message, attemptNumber, _ := startFiveIdentityDoneChecks(t, checks, ctx)
	validTSSResult := fixtureSigningResult(200)

	// Members 1 and 2 are selected. Member 4 is excluded but sends a Done
	// message; selected member 3 remains silent.
	for _, sender := range []int{0, 1, 3} {
		if err := checks[sender].signalDone(
			ctx,
			group.MemberIndex(sender+1),
			message,
			attemptNumber,
			validTSSResult,
			500+uint64(sender+1),
		); err != nil {
			t.Fatalf("identity %d failed to broadcast Done: %v", sender+1, err)
		}
	}

	for i, check := range checks {
		result, _, err := check.waitUntilAllDone(ctx)
		if err != nil {
			t.Errorf("receiver identity %d did not complete the Done barrier: %v", i+1, err)
			continue
		}
		if result == nil || result.Signature == nil ||
			!validTSSResult.Signature.Equals(result.Signature) {
			t.Errorf("receiver identity %d returned an unexpected signature", i+1)
		}
	}
}

// This test demonstrates a bounded liveness attack: an excluded whole-group
// member can inject an additional Done message. The barrier requires exact
// equality with the selected-member count, so four accepted senders when three
// are expected makes completion impossible and forces the attempt to time out.
// All three selected members also send matching Done messages; no TSS bypass is
// claimed.
func TestSigningDoneCheck_ExcludedMemberCanBlockBarrier_FiveIdentities(t *testing.T) {
	checks := setupFiveIdentityDoneChecks(t)
	ctx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
	defer cancel()

	message, attemptNumber, _ := startFiveIdentityDoneChecks(t, checks, ctx)
	validTSSResult := fixtureSigningResult(200)

	// Member 4 is excluded, but all three selected members (1, 2, 3) also
	// broadcast matching Done messages. The extra accepted sender makes the
	// count 4 while expectedSignersCount remains 3.
	for _, sender := range []int{3, 0, 1, 2} {
		if err := checks[sender].signalDone(
			ctx,
			group.MemberIndex(sender+1),
			message,
			attemptNumber,
			validTSSResult,
			700,
		); err != nil {
			t.Fatalf("identity %d failed to broadcast Done: %v", sender+1, err)
		}
	}

	// Let every receiver process all four broadcasts before checking the
	// barrier's exact-count condition.
	time.Sleep(150 * time.Millisecond)

	for i, check := range checks {
		check.doneSignersMutex.Lock()
		acceptedCount := len(check.doneSigners)
		expectedCount := check.expectedSignersCount
		check.doneSignersMutex.Unlock()

		if acceptedCount != 4 || expectedCount != 3 {
			t.Errorf(
				"receiver identity %d expected 4 accepted senders against 3 expected, got accepted=%d expected=%d",
				i+1,
				acceptedCount,
				expectedCount,
			)
		}

		_, _, err := check.waitUntilAllDone(ctx)
		if err != errWaitDoneTimedOut {
			t.Errorf("receiver identity %d expected barrier timeout, got [%v]", i+1, err)
		}
	}
}
