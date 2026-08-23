package server

import (
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// Regression fences for #1507: the AC pubkey runtime-revocation
// gate. Every test in this file pins one invariant of the F5 pre-
// check at HandleACOnline call sites. Mirrors handle_ac_online_f3_test.go
// for the matching invariants of the F3 pre-check.

// newF5TestServer builds the standard F5 cloud-mode UdpServer
// fixture: empty peer/conn maps, a cloud-mode storageConfig, and
// the strict-mode revoke gate flag controlled by `strict`. Tests
// that need extra fields (licenseRateLimiter, acPubkeyCapVerifyRequire,
// pre-populated peer maps, alternate Storage backends) set them on
// the returned pointer. Reduces ~80 lines of duplicate &UdpServer{}
// literals while keeping each test's specific overrides explicit.
func newF5TestServer(t *testing.T, storage StorageBackend, strict bool) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:                     metrics.NewPublisherForTest(t),
		acPeerMap:                   map[string]*core.UdpPeer{},
		acConnectionMap:             map[string][]*ACConn{},
		acPubkeyRevokeVerifyRequire: strict,
		storage:                     storage,
		storageConfig:               &StorageConfig{Backend: StorageBackendDynamoDB},
	}
}

// TestHandleACOnline_F5StrictReject_RejectsRevokedPubkey is THE
// attack-break: a registration whose presented pubkey is on
// ACAssignment.RevokedPubKeys for the claimed acId must be rejected
// with ErrACPubkeyRevoked under strict mode, BEFORE bcrypt cost is
// paid (no GetLicense call). The test fixture only populates the
// revoked entry — no License — and the absence of a License-not-
// found error in the return path proves validateACLicense was not
// reached.
func TestHandleACOnline_F5StrictReject_RejectsRevokedPubkey(t *testing.T) {
	const acId = "ac-1507-revoked"
	revokedPubkey := testPubkey(0xAA)
	revokedPubkeyB64 := testPubkeyB64(0xAA)

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acId,
		CustomerID:     "cust-A",
		Version:        1,
		RevokedPubKeys: []string{revokedPubkeyB64},
	})

	s := newF5TestServer(t, mem, true)

	body, marshalErr := json.Marshal(readyACOnlineMsg(acId, "doesnt-matter-rejected-before-license-lookup"))
	if marshalErr != nil {
		t.Fatalf("marshal body: %v", marshalErr)
	}
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: revokedPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
		},
	}

	err := s.HandleACOnline(ppd)

	if !errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Fatalf("HandleACOnline returned err=%v, want ErrACPubkeyRevoked (52019)", err)
	}

	// Invariant: no peer leaked into acPeerMap. The pre-check runs
	// BEFORE the cloudMode AddACPeer block at msghandler.go, so a
	// strict reject must not create the peer.
	s.acPeerMapMutex.Lock()
	leakCount := len(s.acPeerMap)
	s.acPeerMapMutex.Unlock()
	if leakCount != 0 {
		t.Errorf("acPeerMap size after F5 strict reject = %d, want 0 (peer leaked)", leakCount)
	}

	// Invariants on metrics: revoked counter fires once,
	// registration-failure counter fires once, lookup-err counter
	// stays at zero (storage worked).
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevoked]; c != 1 {
		t.Errorf("MetricACPubkeyRevoked counter=%v, want 1", c)
	}
	if c := counters[MetricACRegistrationFailure]; c != 1 {
		t.Errorf("MetricACRegistrationFailure counter=%v, want 1", c)
	}
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 0 {
		t.Errorf("MetricACPubkeyRevokedLookupErr counter=%v, want 0 (storage worked, no lookup error)", c)
	}
}

// TestHandleACOnline_F5StrictReject_NoLicenseRateLimiter fences the
// no-rate-limiter deployment shape. The F5 hoist's
// `if s.licenseRateLimiter != nil` guard at msghandler.go must
// short-circuit cleanly when rate limiting isn't wired (etcd-only,
// single-tenant, or test fixtures), and the revoke reject must
// still take effect. Without this fence, a future "always require
// rate limiter" refactor that dropped the nil-guard would silently
// break those deployments.
func TestHandleACOnline_F5StrictReject_NoLicenseRateLimiter(t *testing.T) {
	const acId = "ac-1507-no-rl"
	revokedPubkey := testPubkey(0xBB)
	revokedPubkeyB64 := testPubkeyB64(0xBB)

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acId,
		Version:        1,
		RevokedPubKeys: []string{revokedPubkeyB64},
	})

	// licenseRateLimiter intentionally nil — the load-bearing
	// invariant is "F5 still rejects without a rate limiter."
	s := newF5TestServer(t, mem, true)

	body, _ := json.Marshal(readyACOnlineMsg(acId, ""))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: revokedPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 12345},
		},
	}

	err := s.HandleACOnline(ppd)

	if !errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Fatalf("HandleACOnline (no rate limiter) returned err=%v, want ErrACPubkeyRevoked", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevoked]; c != 1 {
		t.Errorf("MetricACPubkeyRevoked counter=%v, want 1", c)
	}
	if c := counters[MetricLicenseValidationRateLimited]; c != 0 {
		t.Errorf("MetricLicenseValidationRateLimited counter=%v, want 0 (no rate limiter, hoist skipped)", c)
	}
}

// TestHandleACOnline_F5_BypassedInNonCloudMode fences the
// `if cloudMode { ... }` guard around the F5 pre-check. Non-cloud
// (etcd / static) deployments don't use ACAssignment for identity,
// so the gate must be bypassed for them — running the lookup
// against a non-DDB backend would either fail or apply revocation
// data that doesn't belong to the deployment.
//
// Setup: storage non-nil but storageConfig.Backend != DynamoDB,
// so cloudMode evaluates false. The fixture also saturates
// acConnectionMap with distinct pubkeys + acPubkeyCapVerifyRequire
// so HandleACOnline exits via F3's in-lock cap reject (matching
// the pattern in TestHandleACOnline_F3StrictReject_InLockOnly_MetricFiresOnce);
// without that early reject the success path would call
// forwardToTransaction which the fixture doesn't wire.
//
// FIXTURE COUPLING: F3 in-lock saturation is the early-reject
// driver. If F3's in-lock check is moved or its strict-mode
// behavior changes, this test will fall through to a
// forwardToTransaction nil-deref instead of cleanly fencing the
// F5 bypass. Pair-debug with handle_ac_online_f3_test.go if this
// test ever fails with a panic instead of a verdict mismatch.
// The load-bearing assertion is `mem.GetCallCount("GetACAssignment") == 0` —
// that survives any F3-side change.
//
// (The rate-limiter would be a more F5-isolated early-exit
// mechanism, but it's itself inside the `if cloudMode { ... }`
// block — i.e. NOT mode-agnostic — so it can't drive the
// non-cloud-mode case we're fencing here.)
//
// THE INVARIANT: F5 metrics stay zero on the non-cloud path. A
// future refactor that flips the cloudMode predicate (or a typo'd
// constant) trips this fence instead of silently activating F5
// for non-cloud deployments. Storage GetACAssignment call count
// also asserts F5's lookup didn't run.
func TestHandleACOnline_F5_BypassedInNonCloudMode(t *testing.T) {
	const acId = "ac-1507-non-cloud"
	presentedPubkey := testPubkey(0xAA)
	presentedPubkeyB64 := testPubkeyB64(0xAA)

	mem := NewMemoryStorage()
	// Even with a revocation entry that would match the presented
	// pubkey on this acId, F5 must NOT run because the deployment
	// is not in cloud mode.
	mem.PutACAssignment(&ACAssignment{
		ACID:           acId,
		Version:        1,
		RevokedPubKeys: []string{presentedPubkeyB64},
	})

	// Saturate acConnectionMap with cap distinct OTHER pubkeys so
	// F3's in-lock check (unconditional, runs in every mode) trips
	// Exceeded for the presented pubkey and HandleACOnline returns
	// before forwardToTransaction.
	saturated := make([]*ACConn, MaxACConnsPerID)
	for i := 0; i < MaxACConnsPerID; i++ {
		saturated[i] = &ACConn{
			ACPeer: &core.UdpPeer{PubKeyBase64: testPubkeyB64(byte(i + 1))},
			ACId:   acId,
		}
	}

	s := &UdpServer{
		metrics:                     metrics.NewPublisherForTest(t),
		acPeerMap:                   map[string]*core.UdpPeer{},
		acConnectionMap:             map[string][]*ACConn{acId: saturated},
		acPubkeyCapVerifyRequire:    true, // F3 strict, drives the early reject.
		acPubkeyRevokeVerifyRequire: true, // F5 strict; if F5 ran, ErrACPubkeyRevoked would beat F3's reject.
		storage:                     mem,
		// storageConfig present but Backend != "dynamodb". cloudMode
		// = (storageConfig != nil && Backend == StorageBackendDynamoDB)
		// → false here, so F5 pre-check is skipped.
		storageConfig: &StorageConfig{Backend: StorageBackendEtcd},
	}

	body, _ := json.Marshal(readyACOnlineMsg(acId, ""))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: presentedPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
		},
	}

	err := s.HandleACOnline(ppd)

	// MUST be the F3 cap reject, NOT the F5 revoke reject. If F5
	// ran, it would have rejected first (since the F5 pre-check is
	// before the F3 in-lock check) and the error would be
	// ErrACPubkeyRevoked.
	if errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Fatal("non-cloud-mode deployment hit F5 reject; cloudMode predicate bypass regressed")
	}
	if !errors.Is(err, common.ErrACPubkeyCapExceeded) {
		t.Fatalf("expected F3 in-lock reject (ErrACPubkeyCapExceeded), got err=%v", err)
	}

	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevoked]; c != 0 {
		t.Errorf("MetricACPubkeyRevoked counter=%v, want 0 (F5 must not run in non-cloud mode)", c)
	}
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 0 {
		t.Errorf("MetricACPubkeyRevokedLookupErr counter=%v, want 0 (F5 lookup must not run)", c)
	}
	// F5's lookup of GetACAssignment must NOT have happened. If it
	// did, we'd see >= 1 here. (handleACServerAssignment is gated
	// on LicenseKey != "" and we set LicenseKey="", so it doesn't
	// call GetACAssignment either — making the count assertion
	// clean.)
	if got := mem.GetCallCount("GetACAssignment"); got != 0 {
		t.Errorf("GetACAssignment call count in non-cloud mode = %d, want 0 (F5 lookup ran despite cloudMode=false)", got)
	}
}

// TestHandleACOnline_F5StrictReject_RejectsRevokedPubkeyOnExistingPeer
// fences the most operationally important property of F5: a stolen
// pubkey that was previously trusted (already in acPeerMap from a
// prior successful registration) and is now revoked must be rejected
// at re-registration. Without this fence, a future refactor that
// moved F5 inside the `acPeer == nil` branch would silently regress
// the cold-registration-only behavior — fine for first-time-ever
// attackers, useless for the actual incident-response case
// (revoking a key after it has been trusted).
//
// The test pre-populates acPeerMap with the revoked pubkey to
// simulate a prior successful registration. F5 must still reject
// despite the AC being a "known" peer.
func TestHandleACOnline_F5StrictReject_RejectsRevokedPubkeyOnExistingPeer(t *testing.T) {
	const acId = "ac-1507-revoked-existing-peer"
	revokedPubkey := testPubkey(0xAA)
	revokedPubkeyB64 := testPubkeyB64(0xAA)

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acId,
		CustomerID:     "cust-A",
		Version:        1,
		RevokedPubKeys: []string{revokedPubkeyB64},
	})

	preexistingPeer := &core.UdpPeer{
		Hostname:     acId,
		Ip:           "203.0.113.1",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: revokedPubkeyB64,
		ExpireTime:   common.FarFutureExpiry,
		Type:         core.NHP_AC,
	}

	s := newF5TestServer(t, mem, true)
	// Pre-populate acPeerMap as if the AC successfully registered
	// before its pubkey was revoked. This is the realistic
	// incident-response case: the operator detected compromise
	// AFTER the AC was trusted.
	s.acPeerMap[revokedPubkeyB64] = preexistingPeer

	body, _ := json.Marshal(readyACOnlineMsg(acId, "doesnt-matter"))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: revokedPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
		},
	}

	err := s.HandleACOnline(ppd)

	if !errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Fatalf("HandleACOnline returned err=%v, want ErrACPubkeyRevoked (pre-existing peer was not re-checked against revocation list)", err)
	}

	// The pre-existing peer entry MUST be preserved. F5's reject
	// path doesn't go through the addedNewPeer cleanup branch (only
	// the F3 cap-reject TOCTOU path does), but pin this so a future
	// refactor that broadens the cleanup doesn't accidentally
	// evict a peer that F5 just rejected.
	s.acPeerMapMutex.Lock()
	got, present := s.acPeerMap[revokedPubkeyB64]
	s.acPeerMapMutex.Unlock()
	if !present {
		t.Error("pre-existing peer evicted from acPeerMap after F5 strict reject")
	}
	if got != preexistingPeer {
		t.Error("acPeerMap entry replaced (different pointer) after F5 reject; legitimate-peer-state corrupted")
	}

	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevoked]; c != 1 {
		t.Errorf("MetricACPubkeyRevoked counter=%v, want 1", c)
	}
	if c := counters[MetricACRegistrationFailure]; c != 1 {
		t.Errorf("MetricACRegistrationFailure counter=%v, want 1", c)
	}
}

// TestHandleACOnline_F5StrictReject_NonRevokedPubkeyOnSameACIDPasses
// fences the property the acceptance criterion in #1507 calls out
// explicitly: revoking a single pubkey for an acId must NOT lock out
// other (non-revoked) pubkeys registering for the same acId. Today's
// blue/green deployment shares one static pubkey across instances,
// but a future per-instance keypair model relies on this property.
//
// The non-revoked path passes the F5 pre-check and then hits
// validateACLicense with no License row in storage, so the
// registration still ultimately rejects — but with
// ErrServerACOpsFailed (license-not-found), NOT ErrACPubkeyRevoked.
// That distinction is the property: F5 didn't fire on a non-revoked
// pubkey.
func TestHandleACOnline_F5StrictReject_NonRevokedPubkeyOnSameACIDPasses(t *testing.T) {
	const acId = "ac-1507-mixed"
	revokedPubkeyB64 := testPubkeyB64(0xAA)
	legitimatePubkey := testPubkey(0xBB)

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acId,
		CustomerID:     "cust-A",
		Version:        1,
		RevokedPubKeys: []string{revokedPubkeyB64}, // 0xAA revoked, 0xBB legit
	})

	s := newF5TestServer(t, mem, true)

	body, _ := json.Marshal(readyACOnlineMsg(acId, "key-with-no-license-row"))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: legitimatePubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 12345},
		},
	}

	err := s.HandleACOnline(ppd)

	// Must NOT be the revoke error.
	if errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Fatal("non-revoked pubkey on same acId rejected as revoked; #1507 false-positive lockout")
	}
	// Must be the downstream license-validation reject (license row
	// not in storage). This proves F5 let the request through and
	// validateACLicense ran.
	if !errors.Is(err, common.ErrServerACOpsFailed) {
		t.Fatalf("HandleACOnline returned err=%v, want ErrServerACOpsFailed (license-validation reject after F5 passed)", err)
	}

	// F5 metric must NOT have fired on the legitimate pubkey.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevoked]; c != 0 {
		t.Errorf("MetricACPubkeyRevoked counter=%v, want 0 (non-revoked pubkey)", c)
	}
}

// TestHandleACOnline_F5PermitMode_AllowsRevokedPubkey fences the
// permit→strict rollout shape: in permit mode (default), a revoked
// pubkey logs+meters but does NOT reject. The downstream license
// validation still runs and rejects (no license row), so the test
// asserts on the absence of ErrACPubkeyRevoked rather than success
// — proving F5 emitted the metric without short-circuiting the
// pipeline.
func TestHandleACOnline_F5PermitMode_AllowsRevokedPubkey(t *testing.T) {
	const acId = "ac-1507-permit"
	revokedPubkey := testPubkey(0xAA)
	revokedPubkeyB64 := testPubkeyB64(0xAA)

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acId,
		CustomerID:     "cust-A",
		Version:        1,
		RevokedPubKeys: []string{revokedPubkeyB64},
	})

	// acPubkeyRevokeVerifyRequire intentionally false (permit mode).
	s := newF5TestServer(t, mem, false)

	body, _ := json.Marshal(readyACOnlineMsg(acId, "key-with-no-license-row"))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: revokedPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 12345},
		},
	}

	err := s.HandleACOnline(ppd)

	// Permit mode must NOT short-circuit on the revoke verdict.
	if errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Fatal("permit mode: revoked pubkey rejected; permit→strict rollout shape violated")
	}
	// The downstream license-not-found reject still fires —
	// that's the proof F5 didn't reject AND the request reached
	// validateACLicense.
	if !errors.Is(err, common.ErrServerACOpsFailed) {
		t.Fatalf("permit mode: err=%v, want ErrServerACOpsFailed (downstream reject)", err)
	}

	// The revoke metric still fires — permit-mode observability is
	// the whole point of the rollout window.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevoked]; c != 1 {
		t.Errorf("permit mode: MetricACPubkeyRevoked counter=%v, want 1 (must fire even when not rejecting)", c)
	}
}

// TestHandleACOnline_F5RateLimitHoist_SkipsLookupOnRateLimited fences
// the rate-limit-before-F5 hoist. Pre-hoist, an attacker spamming
// AOL packets with random unknown acIds got one DDB GetACAssignment
// per packet (CachedStorage doesn't cache NotFound), bypassing the
// validateACLicense rate limiter. Post-hoist, once the rate limiter
// trips, F5's DDB lookup is skipped and the request is rejected with
// a generic ErrServerACOpsFailed (matching validateACLicense's
// rate-limit reject shape — no info leak about whether F5 would
// have rejected).
//
// Test setup primes the rate limiter with a recorded failure for
// (addrStr, acId) so the next CheckRateLimit returns "throttled."
// We then assert that the F5 lookup-counter (call count on
// GetACAssignment) does NOT increment on the rate-limited packet —
// the only way to fence "F5 didn't run."
func TestHandleACOnline_F5RateLimitHoist_SkipsLookupOnRateLimited(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:            true,
		WindowSeconds:      60,
		MaxFailuresPerIP:   1,
		MaxFailuresPerACID: 1,
	})
	defer rl.Stop()

	const acId = "ac-1507-rl-hoist"
	const remoteAddr = "203.0.113.99:12345"

	mem := NewMemoryStorage()
	s := newF5TestServer(t, mem, true)
	s.licenseRateLimiter = rl

	// Prime the rate limiter so the next CheckRateLimit trips.
	rl.RecordFailure(remoteAddr, acId)
	if rlErr := rl.CheckRateLimit(remoteAddr, acId); rlErr == nil {
		t.Fatal("precondition: rate limiter not throttling after one failure")
	}

	// Sanity-check: GetACAssignment hasn't been called yet.
	if got := mem.GetCallCount("GetACAssignment"); got != 0 {
		t.Fatalf("precondition: GetACAssignment already called %d times", got)
	}

	pubkey := testPubkey(0xAA)
	// LicenseKey="" intentionally — the test fences F5's lookup,
	// not handleACServerAssignment's. handleACServerAssignment is
	// gated on `aolMsg.LicenseKey != ""` (see msghandler.go ~442);
	// leaving it empty skips that branch so the only path that
	// would touch GetACAssignment is the F5 pre-check we're
	// fencing. Empty LicenseKey would otherwise short-circuit
	// validateACLicense at its missing-key branch, but we expect
	// the rate-limit hoist to reject before that runs anyway.
	body, _ := json.Marshal(readyACOnlineMsg(acId, ""))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: pubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 12345},
		},
	}

	err := s.HandleACOnline(ppd)

	// Generic reject error — not ErrACPubkeyRevoked. Matches
	// validateACLicense's rate-limit reject shape so an attacker
	// can't distinguish "rate-limited" from "license invalid."
	if !errors.Is(err, common.ErrServerACOpsFailed) {
		t.Fatalf("rate-limited packet: err=%v, want ErrServerACOpsFailed", err)
	}
	if errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Error("rate-limited packet returned ErrACPubkeyRevoked; F5 ran despite hoist")
	}

	// THE INVARIANT: F5's GetACAssignment was NOT called on the
	// rate-limited packet. Pre-hoist this would have been 1; the
	// hoist short-circuits HandleACOnline before F5 runs. With
	// LicenseKey="" handleACServerAssignment is also skipped, so
	// the count is 0 cleanly.
	if got := mem.GetCallCount("GetACAssignment"); got != 0 {
		t.Errorf("GetACAssignment call count after rate-limited packet = %d, want 0 (rate-limit hoist must short-circuit BEFORE F5 lookup)", got)
	}

	// Rate-limited metric fires (both aggregate and preflight-split
	// for the hoist call site); F5 metrics stay at zero.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicenseValidationRateLimited]; c != 1 {
		t.Errorf("MetricLicenseValidationRateLimited counter=%v, want 1", c)
	}
	if c := counters[MetricLicenseValidationRateLimitedAtPreflight]; c != 1 {
		t.Errorf("MetricLicenseValidationRateLimitedAtPreflight counter=%v, want 1 (preflight-split must rise on the hoist site)", c)
	}
	if c := counters[MetricACPubkeyRevoked]; c != 0 {
		t.Errorf("MetricACPubkeyRevoked counter=%v, want 0 (F5 didn't run)", c)
	}
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 0 {
		t.Errorf("MetricACPubkeyRevokedLookupErr counter=%v, want 0", c)
	}
}

// TestHandleACOnline_F5StrictReject_FeedsLicenseRateLimiter fences
// the rate-limiter wiring on revoke-reject. Mirrors the F3 test of
// the same name: any registration-time reject class must feed the
// license rate limiter so an attacker burning a stolen+revoked
// pubkey is throttled by the same defense as other reject classes.
//
// Setup note: the test relies on handleACServerAssignment falling
// through gracefully because s.cloudMap is nil (autoAssignAC logs a
// warning and returns "accept directly"). If a future refactor turns
// that into a hard return, this test would silently fence the wrong
// path — handleACServerAssignment would short-circuit before F5
// runs. Verify the F5 reject is the cause when this test fails.
func TestHandleACOnline_F5StrictReject_FeedsLicenseRateLimiter(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:            true,
		WindowSeconds:      60,
		MaxFailuresPerIP:   1, // 1 failure = rate-limited
		MaxFailuresPerACID: 1,
	})
	defer rl.Stop()

	const acId = "ac-1507-ratelimit"
	const remoteAddr = "203.0.113.50:12345"
	revokedPubkey := testPubkey(0xAA)
	revokedPubkeyB64 := testPubkeyB64(0xAA)

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acId,
		CustomerID:     "cust-A",
		Version:        1,
		RevokedPubKeys: []string{revokedPubkeyB64},
	})

	s := newF5TestServer(t, mem, true)
	s.licenseRateLimiter = rl

	// Pre-condition: rate limiter has not seen this source yet.
	if rlErr := rl.CheckRateLimit(remoteAddr, acId); rlErr != nil {
		t.Fatalf("precondition: rate limiter already throttling: %v", rlErr)
	}
	// Pre-condition: s.cloudMap is nil. The test relies on
	// handleACServerAssignment's autoAssignAC fall-through (logs
	// a Warning and returns "accept directly" when cloudMap is nil)
	// so F5 runs as the actual reject point. If a future refactor
	// turns that into a hard return on nil cloudMap, this assertion
	// fails fast instead of letting the test silently fence the
	// wrong path.
	if s.cloudMap != nil {
		t.Fatalf("precondition: s.cloudMap = %v, want nil (F5 must be the reject point, not handleACServerAssignment)", s.cloudMap)
	}

	body, _ := json.Marshal(readyACOnlineMsg(acId, "doesnt-matter"))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: revokedPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.50"), Port: 12345},
		},
	}
	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Fatalf("HandleACOnline returned err=%v, want ErrACPubkeyRevoked", err)
	}

	// Post-condition: a subsequent CheckRateLimit call must report
	// throttled because the revoke-reject recorded a failure.
	if rlErr := rl.CheckRateLimit(remoteAddr, acId); rlErr == nil {
		t.Error("rate limiter NOT fed by F5 revoke-reject; attacker can burn revoked pubkey with no throttle")
	}
}

// TestHandleACOnline_F5PermitMode_StorageErrorEmitsLookupErr fences
// that permit and strict are behaviorally identical on a transient
// GetACAssignment error: both degrade to "skip the F5 check," both
// fire MetricACPubkeyRevokedLookupErr. Pairs with
// _StrictMode_AllowsRegistration below — together they pin the
// matrix so a future change like "escalate lookup-err to reject in
// permit mode for visibility" trips one of these tests instead of
// silently shipping a behavioral asymmetry.
func TestHandleACOnline_F5PermitMode_StorageErrorEmitsLookupErr(t *testing.T) {
	const acId = "ac-1507-permit-storage-err"
	pubkey := testPubkey(0xAA)

	mem := NewMemoryStorage()
	storage := &errStorageACAssignment{
		MemoryStorage: mem,
		err:           errors.New("ddb: ProvisionedThroughputExceededException"),
	}

	// acPubkeyRevokeVerifyRequire intentionally false (permit mode).
	s := newF5TestServer(t, storage, false)

	body, _ := json.Marshal(readyACOnlineMsg(acId, "key-with-no-license-row"))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: pubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 12345},
		},
	}

	err := s.HandleACOnline(ppd)

	// Permit mode + storage error must NOT short-circuit on revoke.
	if errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Fatal("permit mode + storage error: revoke reject fired; behavioral asymmetry vs strict mode")
	}
	if !errors.Is(err, common.ErrServerACOpsFailed) {
		t.Fatalf("permit mode + storage error: err=%v, want downstream ErrServerACOpsFailed", err)
	}

	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 1 {
		t.Errorf("MetricACPubkeyRevokedLookupErr counter=%v, want 1 (permit mode must still emit)", c)
	}
	if c := counters[MetricACPubkeyRevoked]; c != 0 {
		t.Errorf("MetricACPubkeyRevoked counter=%v, want 0 (storage error path)", c)
	}
}

// TestHandleACOnline_F5StorageError_AllowsRegistration fences the
// availability fallback: if GetACAssignment errors transiently, the
// gate degrades to "skip the F5 check" and the lookup-err counter
// fires. Strict-mode does NOT escalate the lookup error to a reject
// — that would weaponize a storage flap into a fleet-wide outage.
//
// The test injects a transient error on the F5 pre-check's
// GetACAssignment call. The downstream license validation still
// rejects (no license row), so the test asserts on absence of
// ErrACPubkeyRevoked + presence of the lookup-err counter.
func TestHandleACOnline_F5StorageError_AllowsRegistration(t *testing.T) {
	const acId = "ac-1507-storage-err"
	revokedPubkey := testPubkey(0xAA)

	mem := NewMemoryStorage()
	storage := &errStorageACAssignment{
		MemoryStorage: mem,
		err:           errors.New("ddb: ProvisionedThroughputExceededException"),
	}

	s := newF5TestServer(t, storage, true) // strict mode

	body, _ := json.Marshal(readyACOnlineMsg(acId, "key-with-no-license-row"))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: revokedPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.4"), Port: 12345},
		},
	}

	err := s.HandleACOnline(ppd)

	// Must NOT escalate storage error to a revoke reject.
	if errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Fatal("strict mode: storage error escalated to revoke reject; availability contract violated")
	}
	// The downstream license-not-found reject fires — proof F5
	// degraded gracefully.
	if !errors.Is(err, common.ErrServerACOpsFailed) {
		t.Fatalf("strict mode + storage error: err=%v, want downstream ErrServerACOpsFailed", err)
	}

	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 1 {
		t.Errorf("MetricACPubkeyRevokedLookupErr counter=%v, want 1", c)
	}
	if c := counters[MetricACPubkeyRevoked]; c != 0 {
		t.Errorf("MetricACPubkeyRevoked counter=%v, want 0 (storage error path)", c)
	}
}
