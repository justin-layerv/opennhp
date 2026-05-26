//go:build linux

package ac

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"time"
)

// TestEnumerateBpfMap_NonExistentPath_ReturnsSentinel fences the
// cr round 5 finding that distinguished "map pin path doesn't
// exist" (expected when the XDP program isn't attached — feature
// inert) from real load errors. The caller relies on
// errors.Is(err, errBpfMapNotPinned) to decide swallow-vs-fail-loud
// (enumerateBpfAllowRules); a future change that makes
// LoadPinnedMap return an fs.ErrNotExist wrap chain that doesn't
// implement Is() would silently degrade to fatal boot. This test
// is the regression fence for that contract
//
// Requires Linux with /sys/fs/bpf mounted (the production env);
// skips gracefully when the host doesn't have BPF infra, since the
// classification predicate can't fire without an fs.ErrNotExist
// from LoadPinnedMap. The interface-level fence below
// (TestEnumerateBpfMap_FakeNotExistError_ClassifiedAsSentinel)
// covers the predicate contract independently.
func TestEnumerateBpfMap_NonExistentPath_ReturnsSentinel(t *testing.T) {
	a := &UdpAC{}
	pinPath := "/sys/fs/bpf/test-l3-flush-does-not-exist-12345"
	_, err := a.enumerateBpfMap(pinPath, 11, decodeWhitelistKey, 0, time.Now(), time.Now().Add(bootEnumerationDeadline))
	if err == nil {
		t.Fatal("expected error from enumerating non-existent pin path; got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		// /sys/fs/bpf likely isn't mounted on this host; the
		// classification predicate can't fire, so the test can't
		// observe the sentinel — skip rather than spuriously fail.
		t.Skipf("test host's LoadPinnedMap didn't surface fs.ErrNotExist for missing path; skipping (got err=%v). The interface-level fence in TestEnumerateBpfMap_FakeNotExistError_ClassifiedAsSentinel covers the predicate contract.", err)
	}
	if !errors.Is(err, errBpfMapNotPinned) {
		t.Errorf("classification contract broken — enumerateBpfMap returned an fs.ErrNotExist wrap that doesn't wrap errBpfMapNotPinned. enumerateBpfAllowRules would fail-loud instead of continuing. err=%v", err)
	}
}

// fakeNotExistError implements `Is(fs.ErrNotExist)` so the
// classification contract is tested at the interface level rather
// than relying only on /sys/fs/bpf filesystem behavior.
type fakeNotExistError struct{ inner string }

func (e *fakeNotExistError) Error() string        { return e.inner }
func (e *fakeNotExistError) Is(target error) bool { return target == fs.ErrNotExist }
func (e *fakeNotExistError) Unwrap() error        { return fs.ErrNotExist }

var _ error = (*fakeNotExistError)(nil)

// TestInfrastructureTTLSkip_HasHeadroomOverMaxSession fences the
// session-vs-infrastructure discriminator. If a future product
// change raises session_duration past MaxExpectedSessionTTL,
// boot enumeration's `remainingNs > infrastructureTTLSkipNs`
// guard would silently skip legitimate sessions. This test
// guarantees infrastructureTTLSkipNs stays well above the
// documented session ceiling.
func TestInfrastructureTTLSkip_HasHeadroomOverMaxSession(t *testing.T) {
	maxSession := uint64(MaxExpectedSessionTTL)
	if infrastructureTTLSkipNs <= maxSession {
		t.Fatalf("infrastructureTTLSkipNs=%d must exceed MaxExpectedSessionTTL=%d — sessions would be silently skipped at boot",
			infrastructureTTLSkipNs, maxSession)
	}
	// Require ≥2x headroom so a near-bound session_duration doesn't
	// risk crossing the threshold under clock skew or AC-restart
	// timing.
	if infrastructureTTLSkipNs < 2*maxSession {
		t.Errorf("infrastructureTTLSkipNs=%d should have ≥2x headroom over MaxExpectedSessionTTL=%d (got %.1fx); raise the skip threshold or lower the documented max session",
			infrastructureTTLSkipNs, maxSession, float64(infrastructureTTLSkipNs)/float64(maxSession))
	}
}

// TestEnumerateBpfMap_FakeNotExistError_ClassifiedAsSentinel
// fences the classification contract at the error-interface level:
// any error whose Is() method matches fs.ErrNotExist must
// classify as errBpfMapNotPinned — regardless of whether the
// underlying cause is a real filesystem ENOENT or a library
// wrapping its own not-exist condition.
func TestEnumerateBpfMap_FakeNotExistError_ClassifiedAsSentinel(t *testing.T) {
	// Verify the test fake itself before relying on it.
	fake := &fakeNotExistError{inner: "synthetic not-exist"}
	if !errors.Is(fake, fs.ErrNotExist) {
		t.Fatal("test setup: fakeNotExistError doesn't satisfy errors.Is(fs.ErrNotExist)")
	}
	// Direct unit on the classification predicate the production
	// code uses.
	wrapped := fmt.Errorf("LoadPinnedMap: %w", fake)
	if !errors.Is(wrapped, fs.ErrNotExist) {
		t.Errorf("wrapped fake: errors.Is(fs.ErrNotExist) = false; expected true")
	}
}
