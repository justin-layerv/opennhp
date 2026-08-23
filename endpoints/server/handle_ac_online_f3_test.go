package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// Regression fence for #1157 F3: an attacker presenting a NEW pubkey
// under an acId that has already saturated MaxACConnsPerID distinct
// pubkeys must be rejected in strict mode WITHOUT leaking the rejected
// pubkey into acPeerMap. The pre-fix trace (now blocked) was:
//
//  1. acPeer == nil && cloudMode -> validateACLicense + AddACPeer
//  2. acquire acConnectionMapMutex.Lock
//  3. F3 verdict = Exceeded -> return reject
//  4. peer remains in acPeerMap forever (no removal path on reject)
//
// That left an unbounded growth surface: an attacker spamming N
// distinct pubkeys against one acId would grow acPeerMap by N
// entries that never decrement — the F3 attack surface re-emerging
// as memory pressure (and as a CPU-DoS via N bcrypt rounds).
//
// Post-fix invariant: F3 pre-check runs BEFORE validateACLicense and
// AddACPeer in cloud mode, so a strict reject never reaches the
// peer-creation block. acPeerMap stays empty AND acConnectionMap is
// unchanged.
func TestHandleACOnline_F3StrictReject_NoPeerLeak(t *testing.T) {
	s := &UdpServer{
		metrics:                  metrics.NewPublisherForTest(t),
		acPeerMap:                map[string]*core.UdpPeer{},
		acConnectionMap:          map[string][]*ACConn{},
		acPubkeyCapVerifyRequire: true,
		storageConfig:            &StorageConfig{Backend: StorageBackendDynamoDB},
	}

	const acId = "ac-1157-f3-fence"

	// Saturate this acId with MaxACConnsPerID distinct legitimate
	// pubkeys, each on its own ACConn. The 11th registration with
	// a new attacker pubkey must reject.
	saturated := make([]*ACConn, MaxACConnsPerID)
	for i := 0; i < MaxACConnsPerID; i++ {
		saturated[i] = &ACConn{
			ACPeer: &core.UdpPeer{PubKeyBase64: testPubkeyB64(byte(i + 1))},
			ACId:   acId,
		}
	}
	s.acConnectionMap[acId] = saturated

	// Attacker pubkey: distinct from every saturated entry.
	attackerPubkey := make([]byte, 32)
	for i := range attackerPubkey {
		attackerPubkey[i] = 0xFE
	}
	attackerPubkeyB64 := base64.StdEncoding.EncodeToString(attackerPubkey)

	body, err := json.Marshal(readyACOnlineMsg(acId, ""))
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: attackerPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
		},
	}

	err = s.HandleACOnline(ppd)

	// errors.Is over != because HandleACOnline returns the `error`
	// interface (errorlint). The underlying value is the package
	// sentinel pointer, so default-equality matches even without
	// Error.Is.
	if !errors.Is(err, common.ErrACPubkeyCapExceeded) {
		t.Fatalf("HandleACOnline returned err=%v, want ErrACPubkeyCapExceeded (52015)", err)
	}

	// Invariant 1: acPeerMap must NOT contain the attacker's pubkey.
	// This is the leak fence — pre-fix this would have been 1.
	s.acPeerMapMutex.Lock()
	leakCount := len(s.acPeerMap)
	_, attackerPresent := s.acPeerMap[attackerPubkeyB64]
	s.acPeerMapMutex.Unlock()
	if leakCount != 0 {
		t.Errorf("acPeerMap size after F3 strict reject = %d, want 0 (#1157 F3 memory leak regression)", leakCount)
	}
	if attackerPresent {
		t.Error("attacker pubkey present in acPeerMap after F3 strict reject; #1157 F3 leak regression")
	}

	// Invariant 2: acConnectionMap[acId] is unchanged.
	s.acConnectionMapMutex.RLock()
	after := s.acConnectionMap[acId]
	s.acConnectionMapMutex.RUnlock()
	if len(after) != MaxACConnsPerID {
		t.Errorf("acConnectionMap[%q] size after reject = %d, want %d (legitimate ACs displaced)", acId, len(after), MaxACConnsPerID)
	}

	// Invariant 3: exactly one cap-exceeded metric AND one
	// registration-failure metric per reject. Pre-fix dropped the
	// in-lock check would have been the only one to fire; post-fix
	// the pre-check fires it once and the in-lock check never runs.
	// Either way the counter must be 1 — never 0 (silent reject) or
	// 2 (double-emission).
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyCapExceeded]; c != 1 {
		t.Errorf("MetricACPubkeyCapExceeded counter=%v, want 1", c)
	}
	if c := counters[MetricACRegistrationFailure]; c != 1 {
		t.Errorf("MetricACRegistrationFailure counter=%v, want 1", c)
	}
}

// TestHandleACOnline_F3StrictReject_DoesNotEvictPreexistingPeer fences a
// related invariant: when an AC reconnects in cloud mode and finds its
// previously-registered acPeerMap entry still present (its ACConn was
// removed earlier via removeACConnectionRecord on disconnect, but the
// peer record persisted), an F3 strict reject must NOT delete that
// pre-existing entry. Pre-fix, the cleanup branch was gated on
// `cloudMode && acPeer != nil` — true regardless of whether the peer
// was added in *this* call or a prior one — so a TOCTOU-induced reject
// would wrongly evict the legitimate peer. Post-fix the cleanup is
// gated on `addedNewPeer`, set true only inside the AddACPeer branch.
//
// Test scenario: acPeerMap has the AC's pre-existing entry; the AC's
// pubkey is absent from a saturated acConnectionMap[acId]; the
// pre-check fires the strict reject. We assert that the pre-existing
// peer is still in acPeerMap after the reject. (The pre-check path
// short-circuits before the in-lock cleanup branch, but the same
// addedNewPeer invariant holds for the in-lock path that this test
// can't deterministically race against.)
func TestHandleACOnline_F3StrictReject_DoesNotEvictPreexistingPeer(t *testing.T) {
	s := &UdpServer{
		metrics:                  metrics.NewPublisherForTest(t),
		acPeerMap:                map[string]*core.UdpPeer{},
		acConnectionMap:          map[string][]*ACConn{},
		acPubkeyCapVerifyRequire: true,
		storageConfig:            &StorageConfig{Backend: StorageBackendDynamoDB},
	}

	const acId = "ac-1157-f3-preexisting"

	// Pre-existing peer in acPeerMap (AddACPeer-was-called-in-a-prior-
	// invocation simulation). We don't initialize device because the
	// test only asserts on acPeerMap; the in-lock cleanup branch is
	// the path that touches device, and we don't reach it here.
	preexistingPubkey := make([]byte, 32)
	for i := range preexistingPubkey {
		preexistingPubkey[i] = 0xCC
	}
	preexistingPubkeyB64 := base64.StdEncoding.EncodeToString(preexistingPubkey)
	preexistingPeer := &core.UdpPeer{
		Hostname:     "ac-cleanup-test",
		Ip:           "10.0.0.50",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: preexistingPubkeyB64,
		ExpireTime:   common.FarFutureExpiry,
		Type:         core.NHP_AC,
	}
	s.acPeerMap[preexistingPubkeyB64] = preexistingPeer

	// Saturate acConnectionMap[acId] with cap distinct OTHER pubkeys —
	// pre-existing pubkey absent so the AC's reconnect tries to add a
	// new slot (which the cap rejects).
	saturated := make([]*ACConn, MaxACConnsPerID)
	for i := 0; i < MaxACConnsPerID; i++ {
		saturated[i] = &ACConn{
			ACPeer: &core.UdpPeer{PubKeyBase64: testPubkeyB64(byte(i + 1))},
			ACId:   acId,
		}
	}
	s.acConnectionMap[acId] = saturated

	body, err := json.Marshal(readyACOnlineMsg(acId, ""))
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: preexistingPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 12345},
		},
	}

	err = s.HandleACOnline(ppd)
	if !errors.Is(err, common.ErrACPubkeyCapExceeded) {
		t.Fatalf("HandleACOnline returned err=%v, want ErrACPubkeyCapExceeded", err)
	}

	// THE INVARIANT: pre-existing peer is preserved.
	s.acPeerMapMutex.Lock()
	got, present := s.acPeerMap[preexistingPubkeyB64]
	size := len(s.acPeerMap)
	s.acPeerMapMutex.Unlock()
	if !present {
		t.Error("pre-existing peer evicted from acPeerMap after F3 strict reject; addedNewPeer gate regression")
	}
	if got != preexistingPeer {
		t.Error("acPeerMap entry replaced (different pointer) after F3 reject; legitimate peer corrupted")
	}
	if size != 1 {
		t.Errorf("acPeerMap size after reject = %d, want 1 (only the pre-existing entry)", size)
	}
}

// TestHandleACOnline_F3StrictReject_FeedsLicenseRateLimiter fences
// the rate-limiter wiring on cap-reject. An attacker burning N
// distinct pubkeys to FIFO-evict the legitimate AC is the same
// population the license rate limiter exists to throttle —
// validateACLicense rejects already feed it via recordLicenseFailure,
// so cap rejects must too. Pre-fix the cap-reject path silently
// bypassed the limiter, letting an attacker burn pubkeys without
// accumulating rate-limit pressure.
func TestHandleACOnline_F3StrictReject_FeedsLicenseRateLimiter(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:            true,
		WindowSeconds:      60,
		MaxFailuresPerIP:   1, // 1 failure = rate-limited; tight so test deterministic
		MaxFailuresPerACID: 1,
	})
	defer rl.Stop()

	s := &UdpServer{
		metrics:                  metrics.NewPublisherForTest(t),
		acPeerMap:                map[string]*core.UdpPeer{},
		acConnectionMap:          map[string][]*ACConn{},
		acPubkeyCapVerifyRequire: true,
		storageConfig:            &StorageConfig{Backend: StorageBackendDynamoDB},
		licenseRateLimiter:       rl,
	}

	const acId = "ac-1157-f3-ratelimit"
	const remoteAddr = "203.0.113.50:12345"

	saturated := make([]*ACConn, MaxACConnsPerID)
	for i := 0; i < MaxACConnsPerID; i++ {
		saturated[i] = &ACConn{
			ACPeer: &core.UdpPeer{PubKeyBase64: testPubkeyB64(byte(i + 1))},
			ACId:   acId,
		}
	}
	s.acConnectionMap[acId] = saturated

	// Pre-condition: rate limiter has not seen this source yet.
	if rlErr := rl.CheckRateLimit(remoteAddr, acId); rlErr != nil {
		t.Fatalf("precondition: rate limiter already throttling: %v", rlErr)
	}

	attackerPubkey := make([]byte, 32)
	for i := range attackerPubkey {
		attackerPubkey[i] = 0xAA
	}
	body, _ := json.Marshal(readyACOnlineMsg(acId, ""))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: attackerPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.50"), Port: 12345},
		},
	}
	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrACPubkeyCapExceeded) {
		t.Fatalf("HandleACOnline returned err=%v, want ErrACPubkeyCapExceeded", err)
	}

	// Post-condition: a subsequent CheckRateLimit call must report
	// throttled because the cap-reject recorded a failure.
	if rlErr := rl.CheckRateLimit(remoteAddr, acId); rlErr == nil {
		t.Error("rate limiter NOT fed by F3 cap-reject; attacker can burn pubkeys with no throttle")
	}
}

// TestHandleACOnline_F3StrictReject_InLockOnly_MetricFiresOnce fences
// the metric-fires-exactly-once invariant on the in-lock TOCTOU
// reject path. The pre-check and the in-lock check both call
// applyACPubkeyCapVerdict and each is structurally able to fire
// MetricACPubkeyCapExceeded — the flow ensures only one fires per
// packet (pre-check returns early; in-lock only runs if pre-check
// let through), but no test pins the in-lock-only case directly.
//
// Setup: cloudMode=false (so the cloudMode-gated pre-check at line
// ~485 is skipped) with strict-mode F3 still enabled. The unconditional
// in-lock check at line ~575 is the only path that observes the
// saturated map. A future refactor that moved the metric increment
// from applyACPubkeyCapVerdict into both call sites would silently
// double-fire the metric in production but stay invisible without
// this fence.
func TestHandleACOnline_F3StrictReject_InLockOnly_MetricFiresOnce(t *testing.T) {
	pubkeyBytes := make([]byte, 32)
	for i := range pubkeyBytes {
		pubkeyBytes[i] = 0xBB
	}
	pubkeyB64 := base64.StdEncoding.EncodeToString(pubkeyBytes)

	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		acPeerMap: map[string]*core.UdpPeer{
			// Pre-existing peer so the cloudMode AddACPeer path is moot
			// (we set cloudMode=false anyway, but this keeps the path
			// equivalent to a non-cloud production deployment).
			pubkeyB64: {
				Hostname:     "ac-inlock-test",
				Ip:           "10.0.0.99",
				Port:         common.DefaultNHPPort,
				PubKeyBase64: pubkeyB64,
				ExpireTime:   common.FarFutureExpiry,
				Type:         core.NHP_AC,
			},
		},
		acConnectionMap:          map[string][]*ACConn{},
		acPubkeyCapVerifyRequire: true,
		// storageConfig is intentionally nil. HandleACOnline derives
		// cloudMode = (storageConfig != nil && Backend == DynamoDB);
		// nil storageConfig → cloudMode=false → the cloudMode-gated
		// pre-check at msghandler.go ~485 is skipped. The in-lock
		// check at ~575 runs unconditionally and is the only path
		// that fires MetricACPubkeyCapExceeded in this fixture, which
		// is what lets the test assert metric==1 without contention
		// from the pre-check.
	}

	const acId = "ac-1157-f3-inlock"

	// Saturate with cap distinct OTHER pubkeys so the in-lock check
	// sees verdict=Exceeded for the presented (different) pubkey.
	saturated := make([]*ACConn, MaxACConnsPerID)
	for i := 0; i < MaxACConnsPerID; i++ {
		saturated[i] = &ACConn{
			ACPeer: &core.UdpPeer{PubKeyBase64: testPubkeyB64(byte(i + 1))},
			ACId:   acId,
		}
	}
	s.acConnectionMap[acId] = saturated

	body, _ := json.Marshal(readyACOnlineMsg(acId, ""))
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: pubkeyBytes,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.99"), Port: 12345},
		},
	}

	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrACPubkeyCapExceeded) {
		t.Fatalf("HandleACOnline returned err=%v, want ErrACPubkeyCapExceeded (in-lock reject path)", err)
	}

	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyCapExceeded]; c != 1 {
		t.Errorf("MetricACPubkeyCapExceeded counter=%v, want 1 (in-lock check must fire exactly once; double-fire would indicate the metric leaked into a per-call-site emission)", c)
	}
	if c := counters[MetricACRegistrationFailure]; c != 1 {
		t.Errorf("MetricACRegistrationFailure counter=%v, want 1", c)
	}
}

// TestRemoveACPeer pins the symmetric undo of AddACPeer: it must
// remove from BOTH core.Device's peer table and acPeerMap, matching
// AddACPeer's two writes. Today's only caller is HandleACOnline's
// in-lock TOCTOU cleanup branch (#1157 F3); a future write target
// added to AddACPeer must be widened here in the same PR or the
// TOCTOU race re-introduces the F3 leak.
func TestRemoveACPeer(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()

	s := &UdpServer{
		device:    device,
		acPeerMap: map[string]*core.UdpPeer{},
	}

	pkB64 := testPubkeyB64(0xAB)
	peer := &core.UdpPeer{
		Hostname:     "ac-cleanup-test",
		Ip:           "10.0.0.1",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: pkB64,
		ExpireTime:   common.FarFutureExpiry,
		Type:         core.NHP_AC,
	}
	s.AddACPeer(peer)
	if _, ok := s.acPeerMap[pkB64]; !ok {
		t.Fatal("precondition: peer not added to acPeerMap")
	}

	s.removeACPeer(pkB64)

	if _, ok := s.acPeerMap[pkB64]; ok {
		t.Error("acPeerMap still contains pubkey after removeACPeer")
	}
	if len(s.acPeerMap) != 0 {
		t.Errorf("acPeerMap size after cleanup = %d, want 0", len(s.acPeerMap))
	}
}
