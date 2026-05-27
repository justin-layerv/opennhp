package ac

import (
	"bytes"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestHandleUdpACOperations_DedupeRunsBeforeUnmarshal pins the
// ordering invariant from issue #1123: the AOP replay-dedupe gate
// runs ahead of json.Unmarshal and HandleAccessControl, so a
// future refactor that moves the dedupe call below either of them
// fails this test even though every aopReplayCache unit test still
// passes. We verify ordering by handing the function a
// deliberately-malformed BodyMessage: if dedupe runs first, we get
// ErrACDuplicateTransaction; if it runs after Unmarshal, we get a
// parse error first.
//
// The pre-mark and the ppd construction MUST share the same
// sendTime; the cache key is (pubkey, txid, sendTime), so a
// mismatch silently turns this into a first-seen and the
// ordering-invariant assertion would pass for the wrong reason.
func TestHandleUdpACOperations_DedupeRunsBeforeUnmarshal(t *testing.T) {
	a := &UdpAC{
		config:    &Config{ACId: "test-ac"},
		aopReplay: newAOPReplayCache(),
	}

	const txid uint64 = 100
	pub := pubkeyN('A')

	// Pre-mark the (pubkey, txid, sendTime) triple so the call we
	// measure sees it as a duplicate.
	if !a.aopReplay.MarkSeen(pub, txid, testSendTime) {
		t.Fatal("first MarkSeen must succeed")
	}

	ppd := &core.PacketParserData{
		SenderTrxId:    txid,
		RemotePubKey:   pub,
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
		// BodyMessage left nil — json.Unmarshal would error on it.
	}

	err := a.HandleUdpACOperations(ppd)

	if !errors.Is(err, common.ErrACDuplicateTransaction) {
		t.Fatalf("got err=%v, want ErrACDuplicateTransaction (dedupe must run before json.Unmarshal)", err)
	}
}

// TestHandleUdpACOperations_EmptyPubkeyDistinct asserts the
// fail-closed pubkey check returns ErrACMissingPeerPubkey, NOT
// ErrACDuplicateTransaction. Distinguishing these matters for
// oncall: a duplicate-spike alert should not be triggered by an
// upstream invariant violation (validatePeer didn't populate
// RemotePubKey).
func TestHandleUdpACOperations_EmptyPubkeyDistinct(t *testing.T) {
	a := &UdpAC{
		config:    &Config{ACId: "test-ac"},
		aopReplay: newAOPReplayCache(),
	}

	ppd := &core.PacketParserData{
		SenderTrxId:    300,
		RemotePubKey:   nil,
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
	}

	err := a.HandleUdpACOperations(ppd)

	if !errors.Is(err, common.ErrACMissingPeerPubkey) {
		t.Fatalf("got err=%v, want ErrACMissingPeerPubkey (empty pubkey must not masquerade as duplicate)", err)
	}
	if errors.Is(err, common.ErrACDuplicateTransaction) {
		t.Fatal("empty pubkey must not surface as a duplicate transaction")
	}
}

// TestHandleUdpACOperations_WrongLengthPubkeyDistinct fences the
// round-8 cr bug: a hypothetical 31- or 64-byte RemotePubKey
// (future cipher scheme regression, parser bug, fuzz harness) used
// to fall through the handler's zero-length-only check, then get
// rejected at MarkSeen's `len != PublicKeySize` guard, and surface
// as ErrACDuplicateTransaction — exactly the masquerade that
// adding ErrACMissingPeerPubkey was supposed to prevent. The
// handler check now matches the cache's invariant, so wrong-length
// pubkeys take the same Critical-log + ErrACMissingPeerPubkey path
// as zero-length.
func TestHandleUdpACOperations_WrongLengthPubkeyDistinct(t *testing.T) {
	a := &UdpAC{
		config:    &Config{ACId: "test-ac"},
		aopReplay: newAOPReplayCache(),
	}

	for _, n := range []int{1, 16, core.PublicKeySize - 1, core.PublicKeySize + 1, 64} {
		t.Run("len="+strconv.Itoa(n), func(t *testing.T) {
			ppd := &core.PacketParserData{
				SenderTrxId:    400,
				RemotePubKey:   bytes.Repeat([]byte{'X'}, n),
				RemoteSendTime: testSendTime,
				HeaderType:     core.NHP_AOP,
			}
			err := a.HandleUdpACOperations(ppd)

			if !errors.Is(err, common.ErrACMissingPeerPubkey) {
				t.Fatalf("got err=%v, want ErrACMissingPeerPubkey (wrong-length pubkey must not masquerade as duplicate)", err)
			}
			if errors.Is(err, common.ErrACDuplicateTransaction) {
				t.Fatal("wrong-length pubkey must not surface as a duplicate transaction")
			}
		})
	}
}

// TestHandleUdpACOperations_FirstSeenProceedsToUnmarshal is the
// counterpart fence: a fresh (pubkey, txid, sendTime) triple must
// NOT short-circuit at the dedupe gate. With a parseable but empty
// BodyMessage, json.Unmarshal succeeds, HandleAccessControl logs
// ErrACEmptyPassAddress (no src/dst addrs) but the function
// continues and ART-forwarding fails on an empty
// RemoteTransactionMap with ErrTransactionIdNotFound. The test
// asserts the error is the downstream class, NOT
// ErrACDuplicateTransaction — i.e., dedupe let the call through
// and a downstream gate fired.
//
// Hardening over a previous nil-body shape: an explicit
// downstream-error assertion + minimal ConnData fixture means a
// future refactor that reorders device-touching code above
// json.Unmarshal still surfaces loudly (wrong error class) instead
// of relying on parse failure to short-circuit before any
// device-touching call. The fixture deliberately stops at
// ConnData{} (zero-value) — RemoteTransactionMap is nil and a nil
// map read in FindRemoteTransaction returns nil cleanly under the
// mutex.
func TestHandleUdpACOperations_FirstSeenProceedsToUnmarshal(t *testing.T) {
	a := &UdpAC{
		config:     &Config{ACId: "test-ac"},
		aopReplay:  newAOPReplayCache(),
		tokenStore: common.NewTokenStore[*AccessEntry](),
	}

	ppd := &core.PacketParserData{
		SenderTrxId:    200,
		RemotePubKey:   pubkeyN('B'),
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
		BodyMessage:    []byte("{}"),
		ConnData:       &core.ConnectionData{},
	}

	err := a.HandleUdpACOperations(ppd)

	if err == nil {
		t.Fatal("first-seen triple with empty body must surface a downstream error, not nil")
	}
	if errors.Is(err, common.ErrACDuplicateTransaction) {
		t.Fatal("first-seen triple must not be reported as duplicate (dedupe short-circuited incorrectly)")
	}
	if !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("got err=%v, want ErrTransactionIdNotFound (empty body reaches HandleAccessControl + ART forwarding; absence of a remote transaction is the deterministic downstream failure)", err)
	}
}

// TestApplyDefaultIpSubstitution fences the load-bearing IP-substitution
// invariant on the AC ipset-write path. Two production callers depend
// on this behavior:
//   - QURL resources where the destination is the AC itself (Traefik
//     proxy) — sentinel `0.0.0.0` means "local to this AC."
//   - FRPS-behind-AC overlay (nhp #1977 / SLACK_QURL_ROLLOUT.md §6,
//     2026-05-18) — the resource.toml overlay renders `Addr.Ip = ""`
//     so the ipset entry keys on (agent_ip, port, ac_local_ip), the
//     triple a real customer SYN actually has at the AC kernel. If
//     this substitution stops working, the FRPS-specific knock
//     produces an inert ipset entry no packet ever matches.
//
// The previous form of these tests duplicated the substitution loop
// inline (a tautology — both production and test computed the same
// pattern). Now they call `applyDefaultIpSubstitution` directly so a
// regression in the production helper actually trips this test.
func TestApplyDefaultIpSubstitution(t *testing.T) {
	tests := []struct {
		name        string
		defaultIp   string
		dstIp       string
		expectedIp  string
		description string
	}{
		{
			name:        "sentinel_0.0.0.0_replaced",
			defaultIp:   "10.0.1.50",
			dstIp:       SentinelLocalIP,
			expectedIp:  "10.0.1.50",
			description: "SentinelLocalIP should be replaced with DefaultIp",
		},
		{
			name:        "empty_ip_replaced_frps_behind_ac",
			defaultIp:   "10.0.1.50",
			dstIp:       "",
			expectedIp:  "10.0.1.50",
			description: "empty IP should be replaced with DefaultIp (FRPS-behind-AC overlay path)",
		},
		{
			name:        "real_ip_preserved",
			defaultIp:   "10.0.1.50",
			dstIp:       "192.168.1.100",
			expectedIp:  "192.168.1.100",
			description: "real IP should be preserved",
		},
		{
			name:        "no_default_ip_sentinel_unchanged",
			defaultIp:   "",
			dstIp:       SentinelLocalIP,
			expectedIp:  SentinelLocalIP,
			description: "sentinel unchanged when DefaultIp not configured (AC hasn't booted yet)",
		},
		{
			name:        "no_default_ip_empty_unchanged",
			defaultIp:   "",
			dstIp:       "",
			expectedIp:  "",
			description: "empty IP unchanged when DefaultIp not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dstAddrs := []*common.NetAddress{
				{Ip: tt.dstIp, Port: 443},
			}

			applyDefaultIpSubstitution(tt.defaultIp, dstAddrs)

			if dstAddrs[0].Ip != tt.expectedIp {
				t.Errorf("%s: got IP %q, want %q", tt.description, dstAddrs[0].Ip, tt.expectedIp)
			}
		})
	}
}

// TestApplyDefaultIpSubstitution_MultipleAddresses fences the
// per-address branch decision: real IPs preserved, empty + sentinel
// both substituted, mixed correctly across a single slice.
func TestApplyDefaultIpSubstitution_MultipleAddresses(t *testing.T) {
	dstAddrs := []*common.NetAddress{
		{Ip: SentinelLocalIP, Port: 443}, // sentinel - should be replaced
		{Ip: "192.168.1.100", Port: 22},  // real IP - should be preserved
		{Ip: "", Port: 8080},             // empty - should be replaced (FRPS overlay)
	}

	applyDefaultIpSubstitution("10.0.1.50", dstAddrs)

	expected := []string{"10.0.1.50", "192.168.1.100", "10.0.1.50"}
	for i, addr := range dstAddrs {
		if addr.Ip != expected[i] {
			t.Errorf("address[%d]: got IP %q, want %q", i, addr.Ip, expected[i])
		}
	}
}

// TestApplyDefaultIpSubstitution_NilEntries fences the defensive
// nil-skip in the helper. Production callers never pass nil entries,
// but a future refactor that builds dstAddrs from sparse inputs would
// otherwise nil-deref. Asserts both halves of the contract: nil
// entries stay nil (no in-place compaction), and non-nil entries
// receive the substitution.
func TestApplyDefaultIpSubstitution_NilEntries(t *testing.T) {
	dstAddrs := []*common.NetAddress{
		nil,
		{Ip: "", Port: 8080},
		nil,
	}

	applyDefaultIpSubstitution("10.0.1.50", dstAddrs)

	if dstAddrs[0] != nil {
		t.Errorf("dstAddrs[0]: nil entry became %+v — slice must not be compacted in place", dstAddrs[0])
	}
	if dstAddrs[1].Ip != "10.0.1.50" {
		t.Errorf("dstAddrs[1]: non-nil entry not substituted: got %q want %q", dstAddrs[1].Ip, "10.0.1.50")
	}
	if dstAddrs[2] != nil {
		t.Errorf("dstAddrs[2]: nil entry became %+v — slice must not be compacted in place", dstAddrs[2])
	}
	if len(dstAddrs) != 3 {
		t.Errorf("slice length changed: got %d want 3 — slice must not be resized", len(dstAddrs))
	}
}

// TestHandleAccessControl_RejectsNonPositiveOpenTime is the defense-in-depth
// fence for the #1946 cap. ipset.Add (utils/iptables.go) passes the
// timeout verbatim into `ipset add ... timeout N`, and the kernel
// treats `timeout 0` as PERMANENT. The /refresh handler's
// remainingSec<=0 short-circuit (httpac.go) is the primary fence; this
// gate is the secondary fence — a regression that drops the short-
// circuit must still hit this and fail-closed rather than punching a
// permanent firewall hole.
//
// Constructs only the artMsg path (no UdpAC fields touched) because
// the guard fires at the top of HandleAccessControl before any
// ipset/iptables call. A future refactor that moves the guard below
// the first ipset call would still pass this test BUT would also pass
// the live ipset call (which would create the permanent entry) —
// guard placement is documented and not test-fenced. The unit test
// covers the contract; live ipset is in #1950 (Tier 1 smoke).
func TestHandleAccessControl_RejectsNonPositiveOpenTime(t *testing.T) {
	a := &UdpAC{}
	for _, openTimeSec := range []int{0, -1, -1000} {
		artMsg, err := a.HandleAccessControl(&AccessEntry{}, openTimeSec, nil)
		if err == nil {
			t.Errorf("openTimeSec=%d: expected error, got nil", openTimeSec)
			continue
		}
		if !errors.Is(err, common.ErrACInvalidOpenTime) {
			t.Errorf("openTimeSec=%d: error = %v, want ErrACInvalidOpenTime", openTimeSec, err)
		}
		if artMsg == nil {
			t.Errorf("openTimeSec=%d: artMsg must be allocated even on rejection", openTimeSec)
			continue
		}
		if artMsg.ErrCode != common.ErrACInvalidOpenTime.ErrorCode() {
			t.Errorf("openTimeSec=%d: artMsg.ErrCode = %q, want %q", openTimeSec, artMsg.ErrCode, common.ErrACInvalidOpenTime.ErrorCode())
		}
	}
}

// TestHandleAccessControl_AdmissionGate_BreakerOpen fences the L3-only
// security contract: when the flush scheduler's circuit breaker is
// open, HandleAccessControl MUST refuse the NHP-AOP with
// ErrACSchedulerBreakerOpen (53010), not with the previous
// misleading ErrACInvalidOpenTime (53009)
//
// The fail-closed admission is what keeps the post-L7-removal
// boundary intact: a stuck flusher must not admit new sessions
// whose kernel state we cannot later guarantee to tear down.
func TestHandleAccessControl_AdmissionGate_BreakerOpen(t *testing.T) {
	// Construct a real scheduler so IsBreakerOpen is wired correctly.
	// A NoOpFlusher keeps Flush calls from doing anything; we trip
	// the breaker manually via repeated recordBreakerErr.
	sched := NewScheduler(&NoOpFlusher{},
		WithBreakerThreshold(2),
		WithBreakerWindow(60*time.Second),
	)
	sched.Start()
	defer shutdownOrFail(t, sched)
	// Force the breaker open.
	sched.recordBreakerErr()
	sched.recordBreakerErr()
	if !sched.IsBreakerOpen() {
		t.Fatalf("setup: breaker did not open after 2 errors with threshold=2")
	}

	a := &UdpAC{expirySched: sched}
	artMsg, err := a.HandleAccessControl(&AccessEntry{}, 60 /* valid */, nil)
	if !errors.Is(err, common.ErrACSchedulerBreakerOpen) {
		t.Fatalf("got err=%v, want ErrACSchedulerBreakerOpen (admission must refuse when breaker open)", err)
	}
	if artMsg == nil {
		t.Fatal("artMsg must be allocated even on rejection")
	}
	if artMsg.ErrCode != common.ErrACSchedulerBreakerOpen.ErrorCode() {
		t.Errorf("artMsg.ErrCode = %q, want %q", artMsg.ErrCode, common.ErrACSchedulerBreakerOpen.ErrorCode())
	}
	if artMsg.ErrCode == common.ErrACInvalidOpenTime.ErrorCode() {
		t.Error("admission denial must NOT surface as ErrACInvalidOpenTime — that misleads on-call")
	}

	// Second AOP while breaker is still open must ALSO be refused
	//
	artMsg2, err2 := a.HandleAccessControl(&AccessEntry{}, 60, nil)
	if !errors.Is(err2, common.ErrACSchedulerBreakerOpen) {
		t.Errorf("2nd AOP while breaker still open: got err=%v, want ErrACSchedulerBreakerOpen", err2)
	}
	if artMsg2 == nil || artMsg2.ErrCode != common.ErrACSchedulerBreakerOpen.ErrorCode() {
		t.Errorf("2nd AOP artMsg.ErrCode mismatch: %+v", artMsg2)
	}
}

// TestHandleAccessControl_AdmissionGate_FeatureOff_NoBreakerCheck
// fences the no-op-when-disabled contract: with the scheduler nil
// (feature disabled), the admission gate must NOT short-circuit and
// must NOT panic on the nil expirySched read.
func TestHandleAccessControl_AdmissionGate_FeatureOff_NoBreakerCheck(t *testing.T) {
	a := &UdpAC{expirySched: nil}
	// openTimeSec=-1 to short-circuit before any kernel writes — we
	// only want to verify the admission gate doesn't panic on nil and
	// reaches the second (openTimeSec) gate.
	_, err := a.HandleAccessControl(&AccessEntry{}, -1, nil)
	if !errors.Is(err, common.ErrACInvalidOpenTime) {
		t.Errorf("with scheduler nil and openTimeSec=-1, expected ErrACInvalidOpenTime (passes admission gate, fails openTime gate); got %v", err)
	}
}

// TestScheduleFlushIfEnabled_NoOp_WhenNil fences the
// scheduleFlushIfEnabled wrapper's nil-safety: call sites in
// HandleAccessControl sprinkle calls without per-site nil-checks,
// so the wrapper must silently no-op when the feature is off.
func TestScheduleFlushIfEnabled_NoOp_WhenNil(t *testing.T) {
	a := &UdpAC{expirySched: nil}
	// Just verifying no panic.
	a.scheduleFlushIfEnabled(&AccessEntry{}, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP, time.Now().Add(60*time.Second))
}

// TestScheduleFlushIfEnabled_NilEntry_DropsAndDoesNotPanic fences the
// nil-entry guard added in cr round 2: a nil entry would create a
// phantom scheduler entry (Scheduled but not tracked), so the function
// drops the schedule and increments MetricL3FlushScheduleNilEntry
// rather than panicking. Production should never hit this path; the
// metric is the observability signal that a future caller regressed.
func TestScheduleFlushIfEnabled_NilEntry_DropsAndDoesNotPanic(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer shutdownOrFail(t, sched)

	a := &UdpAC{expirySched: sched}
	a.scheduleFlushIfEnabled(nil, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP, time.Now().Add(60*time.Second))

	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after nil-entry schedule attempt = %d, want 0 — nil-entry guard let a phantom scheduler entry through", got)
	}
}

// TestScheduleFlushIfEnabled_BuildsCorrectFlowKey fences the
// FlowKey construction path for each protocol the dispatch table
// in msghandler.go hits (TCP, UDP, ICMP, Any) by routing each call
// through a recording flusher and inspecting the scheduled keys.
func TestScheduleFlushIfEnabled_BuildsCorrectFlowKey(t *testing.T) {
	cases := []struct {
		name      string
		srcIP     string
		dstIP     string
		dstPort   int
		proto     FlowProto
		wantPort  uint16
		wantProto FlowProto
	}{
		{name: "tcp-443", srcIP: "192.0.2.10", dstIP: "192.0.2.20", dstPort: 443, proto: FlowProtoTCP, wantPort: 443, wantProto: FlowProtoTCP},
		{name: "udp-53", srcIP: "10.0.0.5", dstIP: "10.0.0.6", dstPort: 53, proto: FlowProtoUDP, wantPort: 53, wantProto: FlowProtoUDP},
		{name: "icmp-noport", srcIP: "192.0.2.1", dstIP: "192.0.2.2", dstPort: 0, proto: FlowProtoICMP, wantPort: 0, wantProto: FlowProtoICMP},
		{name: "any-noport", srcIP: "203.0.113.5", dstIP: "203.0.113.6", dstPort: 0, proto: FlowProtoAny, wantPort: 0, wantProto: FlowProtoAny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := newRecordingFlusher()
			// Far-future deadline so the entry stays in the index for
			// inspection (doesn't fire during the test).
			sched := NewScheduler(rec, WithTickInterval(5*time.Millisecond), WithWheelSize(1000))
			sched.Start()
			defer shutdownOrFail(t, sched)

			a := &UdpAC{expirySched: sched}
			a.scheduleFlushIfEnabled(&AccessEntry{}, c.srcIP, c.dstIP, c.dstPort, c.proto, time.Now().Add(60*time.Second))

			expected, err := MakeFlowKey(c.srcIP, c.dstIP, c.dstPort, c.proto)
			if err != nil {
				t.Fatalf("MakeFlowKey: %v", err)
			}
			shard := sched.shards[expected.shard()]
			shard.mu.Lock()
			entry, ok := shard.entries[expected]
			shard.mu.Unlock()
			if !ok {
				t.Fatalf("expected entry for FlowKey %+v not found in shard index", expected)
			}
			if entry.FlowKey.DstPort != c.wantPort {
				t.Errorf("DstPort: got %d want %d", entry.FlowKey.DstPort, c.wantPort)
			}
			if entry.FlowKey.Protocol != c.wantProto {
				t.Errorf("Protocol: got %s want %s", entry.FlowKey.Protocol, c.wantProto)
			}
		})
	}
}

// TestScheduleFlushIfEnabled_RejectsMalformedFlowKey fences the
// graceful-skip path: a bogus IP (or 0.0.0.0 wildcard) must not
// trip the scheduler — kernel state was already written by the
// caller; this is best-effort defense-in-depth.
func TestScheduleFlushIfEnabled_RejectsMalformedFlowKey(t *testing.T) {
	rec := newRecordingFlusher()
	sched := NewScheduler(rec, WithTickInterval(5*time.Millisecond), WithWheelSize(1000))
	sched.Start()
	defer shutdownOrFail(t, sched)

	a := &UdpAC{expirySched: sched}
	// Malformed source IP — MakeFlowKey rejects.
	a.scheduleFlushIfEnabled(&AccessEntry{}, "not-an-ip", "192.0.2.2", 443, FlowProtoTCP, time.Now().Add(60*time.Second))
	// Unspecified IP — MakeFlowKey rejects (wildcard fence).
	a.scheduleFlushIfEnabled(&AccessEntry{}, "0.0.0.0", "192.0.2.2", 443, FlowProtoTCP, time.Now().Add(60*time.Second))

	if got := sched.EntryCount(); got != 0 {
		t.Errorf("expected zero entries (malformed inputs rejected at FlowKey boundary); got %d", got)
	}
}

// TestNewFlusherForFilterMode_UnsupportedMode fences the
// fail-loud behavior on an unrecognized FilterMode value. A future
// enum addition (FilterMode=2) that forgets to wire a flusher must
// not silently fall through to a nil flusher; the AC's Start() must
// fail loud at boot rather than schedule no-op flushes forever
func TestNewFlusherForFilterMode_UnsupportedMode(t *testing.T) {
	for _, mode := range []int{2, 3, 99, -1} {
		t.Run(strconv.Itoa(mode), func(t *testing.T) {
			f, err := newFlusherForFilterMode(mode)
			if err == nil {
				t.Errorf("FilterMode=%d: expected error, got nil (flusher=%T)", mode, f)
			}
			if f != nil {
				t.Errorf("FilterMode=%d: expected nil flusher, got %T", mode, f)
			}
		})
	}
}
