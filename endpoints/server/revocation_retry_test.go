package server

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// P4e Slice 3 (#2793): tests for the server NHP_REV retry-until-ack-or-age-out
// engine. The pure tracker (track / supersede / clearAck / collectDue) is tested
// with an injected clock so age-out and due-for-retry are deterministic without
// sleeping. The engine integration (runRevocationRetryTick / redelivery / ack
// clear / disconnect-keeps-pending) is tested against a real UdpServer with a
// buffered sendMsgCh the test drains.

const (
	testRetryInterval = 5 * time.Second
	testRetryAgeOut   = 60 * time.Second
	testSlotPubkeyA   = "test-slot-pubkey-a"
	testSlotPubkeyB   = "test-slot-pubkey-b"
)

// fakeClock is a manually-advanced time source for deterministic tracker tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestTracker(clk *fakeClock) *revocationRetryTracker {
	rt := newRevocationRetryTracker(testRetryInterval, testRetryAgeOut)
	rt.now = clk.now
	return rt
}

// ── Pure tracker tests ──────────────────────────────────────────────────────

// TestRetryTracker_TrackThenAckClears: a tracked revoke is cleared by an ack at
// the same epoch, and the matching is exact on (acId, acPubkey, scope, scopeKey).
func TestRetryTracker_TrackThenAckClears(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rt := newTestTracker(clk)

	rt.track("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 5, "evt-1")
	if n := rt.pendingCount(); n != 1 {
		t.Fatalf("pendingCount after track = %d, want 1", n)
	}
	// An ack for a DIFFERENT AC must not clear it.
	if _, cleared := rt.clearAck("ac-2", testSlotPubkeyA, "qurl", "qurl:qX", 5); cleared {
		t.Fatal("ack for a different acId wrongly cleared the entry")
	}
	// An ack for a DIFFERENT blue/green slot under the same AC ID must not clear it.
	if _, cleared := rt.clearAck("ac-1", testSlotPubkeyB, "qurl", "qurl:qX", 5); cleared {
		t.Fatal("ack for a sibling acPubkey wrongly cleared the entry")
	}
	// An ack with a mismatched scope_key must not clear it.
	if _, cleared := rt.clearAck("ac-1", testSlotPubkeyA, "qurl", "qurl:qOTHER", 5); cleared {
		t.Fatal("ack with mismatched scope_key wrongly cleared the entry")
	}
	// The matching ack clears it.
	if _, cleared := rt.clearAck("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 5); !cleared {
		t.Fatal("matching ack did not clear the entry")
	}
	if n := rt.pendingCount(); n != 0 {
		t.Fatalf("pendingCount after ack = %d, want 0", n)
	}
}

// TestRetryTracker_AckHigherEpochClears / lower epoch does not: a convergence ack
// at >= the tracked epoch clears; an ack for an older epoch than what is pending
// leaves the newer revoke outstanding.
func TestRetryTracker_AckEpochBoundary(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rt := newTestTracker(clk)

	rt.track("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 5, "evt-5")
	// Ack for an older epoch (4) must NOT clear the pending epoch-5 revoke.
	if _, cleared := rt.clearAck("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 4); cleared {
		t.Fatal("stale ack (epoch 4 < pending 5) wrongly cleared the entry")
	}
	if n := rt.pendingCount(); n != 1 {
		t.Fatalf("pendingCount = %d, want 1 after stale ack", n)
	}
	// Ack at a higher epoch (6) DOES clear (convergence at/above).
	if _, cleared := rt.clearAck("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 6); !cleared {
		t.Fatal("ack at higher epoch did not clear")
	}
}

// TestRetryTracker_HigherEpochSupersedes: a strictly-greater epoch for the same
// key replaces the entry in place (resets the age-out clock + attempts); a lower
// epoch is ignored; bound stays one entry per (AC, key).
func TestRetryTracker_HigherEpochSupersedes(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rt := newTestTracker(clk)

	rt.track("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 5, "evt-5")
	clk.advance(10 * time.Second)
	rt.track("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 7, "evt-7") // supersede
	if n := rt.pendingCount(); n != 1 {
		t.Fatalf("pendingCount = %d, want 1 (supersede replaces in place)", n)
	}
	// A lower epoch (6) is ignored — the pending epoch-7 still stands.
	rt.track("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 6, "evt-6")
	// An ack at epoch 7 clears; an ack at epoch 6 would not (it's below the
	// superseding epoch 7), proving the superseding epoch took.
	if _, cleared := rt.clearAck("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 6); cleared {
		t.Fatal("ack at epoch 6 cleared, but pending should be the superseding epoch 7")
	}
	if _, cleared := rt.clearAck("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 7); !cleared {
		t.Fatal("ack at the superseding epoch 7 did not clear")
	}
}

// TestRetryTracker_CollectDue_RetryThenAgeOut walks the clock: nothing due before
// the interval; due-for-retry after the interval; aged-out (and removed) after
// the deadline, with the aged-out item reported so the caller can tick degraded.
func TestRetryTracker_CollectDue_RetryThenAgeOut(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rt := newTestTracker(clk)
	rt.track("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 1, "evt-1")

	// Before the interval: nothing due.
	clk.advance(testRetryInterval - time.Second)
	if due := rt.collectDue(); len(due) != 0 {
		t.Fatalf("collectDue before interval = %d items, want 0", len(due))
	}

	// After the interval (still before age-out): due for retry, NOT aged out.
	clk.advance(2 * time.Second) // now interval+1s elapsed
	due := rt.collectDue()
	if len(due) != 1 || due[0].agedOut {
		t.Fatalf("collectDue after interval = %+v, want 1 retry item (not aged out)", due)
	}
	// collectDue does not remove a retry item.
	if n := rt.pendingCount(); n != 1 {
		t.Fatalf("pendingCount after retry-due = %d, want 1", n)
	}

	// After the age-out deadline: aged-out item reported AND removed.
	clk.advance(testRetryAgeOut) // well past firstSentAt+ageOut
	due = rt.collectDue()
	if len(due) != 1 || !due[0].agedOut {
		t.Fatalf("collectDue after age-out = %+v, want 1 aged-out item", due)
	}
	if n := rt.pendingCount(); n != 0 {
		t.Fatalf("pendingCount after age-out = %d, want 0 (entry dropped)", n)
	}
}

// TestRetryTracker_ReTrackPreservesFirstSent: a redelivery (re-track at the same
// epoch) advances the retry clock but keeps the age-out clock anchored at the
// original send, so repeated retries cannot postpone age-out forever.
func TestRetryTracker_ReTrackPreservesFirstSent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rt := newTestTracker(clk)
	rt.track("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 1, "evt-1")

	// Drive several redeliveries, each after one interval.
	for i := 0; i < 5; i++ {
		clk.advance(testRetryInterval + time.Second)
		due := rt.collectDue()
		if len(due) == 1 && due[0].agedOut {
			// Once we cross firstSentAt+ageOut, it ages out regardless of retracks.
			return
		}
		rt.track("ac-1", testSlotPubkeyA, "qurl", "qurl:qX", 1, "evt-1") // redelivery re-track
	}
	// By now > ageOut has elapsed since firstSentAt; the next collect must age out.
	clk.advance(testRetryAgeOut)
	due := rt.collectDue()
	if len(due) != 1 || !due[0].agedOut {
		t.Fatalf("re-tracks postponed age-out: collectDue = %+v, want aged-out", due)
	}
}

// ── Config parse tests ──────────────────────────────────────────────────────

func TestParseRevocationRetryConfig_Defaults(t *testing.T) {
	t.Setenv(RevocationRetryEnabledEnvVar, "")
	t.Setenv(RevocationRetryIntervalEnvVar, "")
	t.Setenv(RevocationRetryAgeOutEnvVar, "")
	enabled, interval, ageOut, err := parseRevocationRetryConfig()
	if err != nil {
		t.Fatalf("defaults err=%v", err)
	}
	if enabled {
		t.Fatal("engine must default OFF")
	}
	if interval != defaultRevocationRetryInterval || ageOut != defaultRevocationRetryAgeOut {
		t.Fatalf("defaults = (%s,%s), want (%s,%s)", interval, ageOut, defaultRevocationRetryInterval, defaultRevocationRetryAgeOut)
	}
}

func TestParseRevocationRetryConfig_EnabledWithOverrides(t *testing.T) {
	t.Setenv(RevocationRetryEnabledEnvVar, "true")
	t.Setenv(RevocationRetryIntervalEnvVar, "10")
	t.Setenv(RevocationRetryAgeOutEnvVar, "120")
	enabled, interval, ageOut, err := parseRevocationRetryConfig()
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !enabled || interval != 10*time.Second || ageOut != 120*time.Second {
		t.Fatalf("got (%v,%s,%s), want (true,10s,120s)", enabled, interval, ageOut)
	}
}

func TestParseRevocationRetryConfig_Rejects(t *testing.T) {
	for _, tc := range []struct {
		name             string
		enabled, iv, age string
	}{
		{"bad_enabled", "maybe", "", ""},
		{"bad_interval", "true", "notanint", ""},
		{"sub_floor_interval", "true", "0", ""},
		{"ageout_not_greater_than_interval", "true", "10", "10"},
		{"ageout_below_interval", "true", "30", "20"},
		// Passes the interval check (8 > 5) but the age-out (8s) is below the 15s
		// SLO — must be rejected by the censoring-invariant guard (#2792).
		{"ageout_below_slo", "true", "5", "8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(RevocationRetryEnabledEnvVar, tc.enabled)
			t.Setenv(RevocationRetryIntervalEnvVar, tc.iv)
			t.Setenv(RevocationRetryAgeOutEnvVar, tc.age)
			if _, _, _, err := parseRevocationRetryConfig(); err == nil {
				t.Fatalf("%s: expected an error, got nil", tc.name)
			}
		})
	}
}

// TestParseRevocationRetryConfig_RejectsAgeOutBelowSLO is the non-vacuous guard
// for the censoring invariant (#2792): an age-out override that is above the
// retry interval (so it clears the interval check) but at/below the SLO must be
// rejected at Start — otherwise every genuine p99 breach would be silently
// censored into RevocationAgedOut and the latency alarm would go inert. Asserts
// the error specifically names the SLO so a regression that lets the interval
// check shadow this one (or removes it) is caught, not just "some error fired".
func TestParseRevocationRetryConfig_RejectsAgeOutBelowSLO(t *testing.T) {
	// interval below the SLO so the interval check passes; age-out between the
	// interval and the SLO so ONLY the SLO guard can reject it.
	intervalSec := 5
	ageOutSec := int(RevocationDeliveryLatencyP99SLO.Seconds()) - 1 // 14s: > interval, < SLO
	if time.Duration(intervalSec)*time.Second >= RevocationDeliveryLatencyP99SLO {
		t.Fatalf("test setup invalid: interval %ds must be below the SLO %s", intervalSec, RevocationDeliveryLatencyP99SLO)
	}
	t.Setenv(RevocationRetryEnabledEnvVar, "true")
	t.Setenv(RevocationRetryIntervalEnvVar, strconv.Itoa(intervalSec))
	t.Setenv(RevocationRetryAgeOutEnvVar, strconv.Itoa(ageOutSec))

	_, _, _, err := parseRevocationRetryConfig()
	if err == nil {
		t.Fatal("expected an error for age-out below the SLO, got nil")
	}
	// The error must be the SLO guard, not the interval check shadowing it.
	if !strings.Contains(err.Error(), "SLO") {
		t.Fatalf("error %q does not mention the SLO — the censoring-invariant guard is not the one that fired", err.Error())
	}

	// Boundary: age-out exactly AT the SLO is also degenerate and must be rejected
	// (strictly-greater requirement).
	t.Setenv(RevocationRetryAgeOutEnvVar, strconv.Itoa(int(RevocationDeliveryLatencyP99SLO.Seconds())))
	if _, _, _, err := parseRevocationRetryConfig(); err == nil {
		t.Fatal("expected an error for age-out exactly at the SLO, got nil")
	}

	// And just ABOVE the SLO with a valid interval passes (proves the guard is a
	// boundary, not a blanket reject).
	t.Setenv(RevocationRetryAgeOutEnvVar, strconv.Itoa(int(RevocationDeliveryLatencyP99SLO.Seconds())+1))
	if _, _, _, err := parseRevocationRetryConfig(); err != nil {
		t.Fatalf("age-out just above the SLO should pass, got err=%v", err)
	}
}

// ── Engine integration tests ────────────────────────────────────────────────

// newRetryEngineServer builds a UdpServer armed with the retry engine, a real
// device, a buffered sendMsgCh, metrics, and an acConnectionMap, using an
// injected clock so the test drives age-out/retry deterministically.
func newRetryEngineServer(t *testing.T, clk *fakeClock) (*UdpServer, chan *core.MsgData) {
	t.Helper()
	sendCh := make(chan *core.MsgData, 16)
	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		device:          core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		acConnectionMap: map[string][]*ACConn{},
		sendMsgCh:       sendCh,
		revocationRetry: newTestTracker(clk),
	}
	return s, sendCh
}

func putRetryConn(s *UdpServer, acID string, seed byte) {
	s.acConnectionMap[acID] = append(s.acConnectionMap[acID], &ACConn{
		ConnData: &core.ConnectionData{},
		ACPeer:   &core.UdpPeer{PubKeyBase64: testPubkeyB64(seed), Type: core.NHP_AC},
		ACId:     acID,
	})
}

func drainAllSends(sendCh chan *core.MsgData) []*core.MsgData {
	var out []*core.MsgData
	for {
		select {
		case md := <-sendCh:
			out = append(out, md)
		default:
			return out
		}
	}
}

// TestRetryEngine_RedeliversUnackedRevoke: a tracked revoke whose retry interval
// has elapsed is retransmitted as an NHP_REV to the AC's live connection, with
// the correct (verbatim) scope_key + epoch.
func TestRetryEngine_RedeliversUnackedRevoke(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, sendCh := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)

	// Simulate the fanout having tracked this revoke.
	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")

	// Advance past the retry interval and run a tick.
	clk.advance(testRetryInterval + time.Second)
	s.runRevocationRetryTick()

	sends := drainAllSends(sendCh)
	if len(sends) != 1 {
		t.Fatalf("redelivery enqueued %d NHP_REV, want 1", len(sends))
	}
	if sends[0].HeaderType != core.NHP_REV {
		t.Fatalf("redelivery header type=%d, want NHP_REV", sends[0].HeaderType)
	}
	var revMsg common.ACRevocationMsg
	if err := json.Unmarshal(sends[0].Message, &revMsg); err != nil {
		t.Fatalf("redelivery body not ACRevocationMsg: %v", err)
	}
	if revMsg.ScopeKey != "qurl:qX" || revMsg.RevocationEpoch != 3 {
		t.Fatalf("redelivery body = %+v, want scope_key=qurl:qX epoch=3", revMsg)
	}
	// Still pending (un-acked), age-out clock unchanged.
	if n := s.revocationRetry.pendingCount(); n != 1 {
		t.Fatalf("pendingCount after redelivery = %d, want 1", n)
	}
}

// TestRetryEngine_AckStopsRetry: once the AC acks, the tracker is cleared and a
// subsequent tick does NOT redeliver. Proves the ack path actually stops the loop.
func TestRetryEngine_AckStopsRetry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, sendCh := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)
	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")

	// The AC's NHP_RVA arrives and is attributed + cleared.
	ppd := ackPPD(t, common.ACRevocationAckMsg{
		Scope: "qurl", ScopeKey: "qurl:qX", RevocationEpoch: 3, EventId: "evt-3",
	}, testPubkey(7))
	if err := s.HandleRevocationAck(ppd); err != nil {
		t.Fatalf("HandleRevocationAck err=%v", err)
	}
	if n := s.revocationRetry.pendingCount(); n != 0 {
		t.Fatalf("pendingCount after ack = %d, want 0", n)
	}

	// A later tick must not redeliver anything.
	clk.advance(testRetryInterval + time.Second)
	s.runRevocationRetryTick()
	if sends := drainAllSends(sendCh); len(sends) != 0 {
		t.Fatalf("redelivered %d NHP_REV after ack, want 0", len(sends))
	}
}

// TestRetryEngine_SameACIDBlueGreenAckClearsOnlyAckingSlot is the regression
// for #2793's proof gap: acConnectionMap can hold multiple live blue/green slots
// under one acId. A NHP_RVA from one authenticated pubkey must clear only that
// slot's pending entry; the sibling slot must stay pending and be redelivered to
// its exact pubkey.
func TestRetryEngine_SameACIDBlueGreenAckClearsOnlyAckingSlot(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, sendCh := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)
	putRetryConn(s, "ac-1", 8)

	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")
	if n := s.revocationRetry.pendingCount(); n != 2 {
		t.Fatalf("pendingCount after two-slot fanout = %d, want 2", n)
	}

	ppd := ackPPD(t, common.ACRevocationAckMsg{
		Scope: "qurl", ScopeKey: "qurl:qX", RevocationEpoch: 3, EventId: "evt-3",
	}, testPubkey(7))
	if err := s.HandleRevocationAck(ppd); err != nil {
		t.Fatalf("HandleRevocationAck err=%v", err)
	}
	if n := s.revocationRetry.pendingCount(); n != 1 {
		t.Fatalf("pendingCount after first slot ack = %d, want 1 (sibling must remain pending)", n)
	}

	clk.advance(testRetryInterval + time.Second)
	s.runRevocationRetryTick()

	sends := drainAllSends(sendCh)
	if len(sends) != 1 {
		t.Fatalf("redelivery enqueued %d NHP_REV, want 1 for the unacked sibling", len(sends))
	}
	if !bytes.Equal(sends[0].PeerPk, testPubkey(8)) {
		t.Fatalf("redelivery PeerPk = %x, want unacked sibling pubkey %x", sends[0].PeerPk, testPubkey(8))
	}
	var revMsg common.ACRevocationMsg
	if err := json.Unmarshal(sends[0].Message, &revMsg); err != nil {
		t.Fatalf("redelivery body not ACRevocationMsg: %v", err)
	}
	if revMsg.ScopeKey != "qurl:qX" || revMsg.RevocationEpoch != 3 || revMsg.EventId != "evt-3" {
		t.Fatalf("redelivery body = %+v, want original revoke for unacked sibling", revMsg)
	}
}

// TestRetryEngine_AgeOutEmitsDegradedNotSilentDrop: an un-acked revoke past the
// age-out deadline ticks MetricRevocationAgedOut (the DE-Risk #5 degraded signal)
// and is dropped — NOT silently and NOT redelivered. This is the core
// proof-of-delivery guarantee.
func TestRetryEngine_AgeOutEmitsDegradedNotSilentDrop(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, sendCh := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)
	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")

	// Advance past the age-out deadline and tick.
	clk.advance(testRetryAgeOut + time.Second)
	s.runRevocationRetryTick()

	// Degraded metric fired exactly once.
	counters := serverCounters(t, s)
	if c := counters[MetricRevocationAgedOut]; c != 1 {
		t.Fatalf("%s = %v, want 1 (age-out must emit the degraded signal)", MetricRevocationAgedOut, c)
	}
	// NOT redelivered (aged out, not retried).
	if sends := drainAllSends(sendCh); len(sends) != 0 {
		t.Fatalf("aged-out revoke was redelivered (%d sends), want 0", len(sends))
	}
	// Dropped from the tracker (not a silent leak that retries forever).
	if n := s.revocationRetry.pendingCount(); n != 0 {
		t.Fatalf("pendingCount after age-out = %d, want 0", n)
	}
}

// TestRetryEngine_TrackFanoutMissingPubkeyEmitsUntrackable covers the impossible
// but security-relevant invariant break where an NHP_REV was already enqueued
// to a connection that cannot be keyed to an authenticated AC pubkey. There is
// no per-slot identity to track or ack against, so the proof gap must tick the
// untrackable counter immediately rather than polluting retry age-out.
func TestRetryEngine_TrackFanoutMissingPubkeyEmitsUntrackable(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, _ := newRetryEngineServer(t, clk)

	s.trackFanout([]*ACConn{{ACId: "ac-1"}}, "qurl", "qurl:qX", 3, "evt-3")

	if n := s.revocationRetry.pendingCount(); n != 0 {
		t.Fatalf("pendingCount after untrackable fanout = %d, want 0", n)
	}
	counters := serverCounters(t, s)
	if c := counters[MetricRevocationUntrackable]; c != 1 {
		t.Fatalf("%s = %v, want 1 for untrackable fanout", MetricRevocationUntrackable, c)
	}
	if c := counters[MetricRevocationAgedOut]; c != 0 {
		t.Fatalf("%s = %v, want 0 (untrackable must not pollute retry age-out)", MetricRevocationAgedOut, c)
	}
}

// TestRetryEngine_TrackFanoutMissingACIDEmitsUntrackable covers the matching
// untrackable-after-enqueue case for a non-nil ACConn that has an authenticated
// pubkey but no usable ACId. Whitespace-only ACId is intentionally included here
// to keep trackFanout aligned with HandleACOnline and resolveACIdentityFromPubkey.
// Without a real ACId, the retry engine cannot target future redelivery or
// attribute the ack key, so it must emit the same degraded proof signal instead
// of silently skipping the connection.
func TestRetryEngine_TrackFanoutMissingACIDEmitsUntrackable(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, _ := newRetryEngineServer(t, clk)

	s.trackFanout([]*ACConn{
		nil, // nil is a defensive no-op; it was not a valid enqueue target.
		{ACId: "   ", ACPeer: &core.UdpPeer{PubKeyBase64: testSlotPubkeyA}},
	}, "qurl", "qurl:qX", 3, "evt-3")

	if n := s.revocationRetry.pendingCount(); n != 0 {
		t.Fatalf("pendingCount after missing-acId fanout = %d, want 0", n)
	}
	counters := serverCounters(t, s)
	if c := counters[MetricRevocationUntrackable]; c != 1 {
		t.Fatalf("%s = %v, want 1 for missing-acId fanout", MetricRevocationUntrackable, c)
	}
	if c := counters[MetricRevocationAgedOut]; c != 0 {
		t.Fatalf("%s = %v, want 0 (untrackable must not pollute retry age-out)", MetricRevocationAgedOut, c)
	}
}

// TestRetryEngine_TrackFanoutUnackableScopeNotTracked is the #2793 false-age-out
// guard for the "cell" scope. The server ACCEPTS and fans out "cell" (it is in
// revocationWireScopes), but the AC DROPS it without acking (wireRevocationScope
// applies only qurl/resource/session). So the retry engine must NOT record a
// pending proof entry for a cell-scoped fanout — otherwise the never-arriving ack
// would age out to a FALSE RevocationAgedOut on every targeted AC once the engine
// is armed. The skip is clean: not an untrackable invariant break, not an age-out.
// Proven non-vacuously: the SAME well-formed conn IS tracked for an ackable scope.
func TestRetryEngine_TrackFanoutUnackableScopeNotTracked(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, _ := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)
	conns := s.acConnectionMap["ac-1"]

	// "cell" is accepted+fanned-out but unackable: it must not be tracked.
	s.trackFanout(conns, "cell", "cell:cX", 3, "evt-cell")
	if n := s.revocationRetry.pendingCount(); n != 0 {
		t.Fatalf("pendingCount after cell-scoped fanout = %d, want 0 (cell is unackable, must not be tracked)", n)
	}
	counters := serverCounters(t, s)
	if c := counters[MetricRevocationUntrackable]; c != 0 {
		t.Fatalf("%s = %v, want 0 (an unackable scope is a clean skip, not an invariant break)", MetricRevocationUntrackable, c)
	}
	if c := counters[MetricRevocationAgedOut]; c != 0 {
		t.Fatalf("%s = %v, want 0 (an unackable scope must never age out)", MetricRevocationAgedOut, c)
	}

	// Non-vacuous: the SAME well-formed conn IS tracked for an ackable scope, so
	// the zero above is the scope gate, not a broken conn.
	s.trackFanout(conns, "qurl", "qurl:qX", 3, "evt-qurl")
	if n := s.revocationRetry.pendingCount(); n != 1 {
		t.Fatalf("pendingCount after qurl-scoped fanout = %d, want 1 (an ackable scope must be tracked)", n)
	}
}

// TestFanoutRevocation_SkipsNilAndNilPeerButSendsKeylessPeer fences the
// fanoutRevocation defensive guard: a nil conn, or a conn with a nil ACPeer,
// must be skipped without panicking on conn.ACPeer.PublicKey(), while a keyless
// but non-nil ACPeer is still sent. This pins the documented send/track
// asymmetry for malformed-registry entries — unreachable under current
// invariants, so it has no production caller and is fenced here directly.
func TestFanoutRevocation_SkipsNilAndNilPeerButSendsKeylessPeer(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, sendCh := newRetryEngineServer(t, clk)

	conns := []*ACConn{
		nil, // nil conn: skipped, no panic
		{ConnData: &core.ConnectionData{}, ACId: "ac-nilpeer"}, // nil ACPeer: skipped, no panic
		{
			ConnData: &core.ConnectionData{},
			ACPeer:   &core.UdpPeer{PubKeyBase64: "", Type: core.NHP_AC},
			ACId:     "ac-keyless",
		},
		{
			ConnData: &core.ConnectionData{},
			ACPeer:   &core.UdpPeer{PubKeyBase64: testPubkeyB64(9), Type: core.NHP_AC},
			ACId:     "ac-valid",
		},
	}

	sent, ok := s.fanoutRevocation(conns, []byte(`{"scope":"qurl"}`))
	if !ok {
		t.Fatal("fanoutRevocation ok=false, want true (no backpressure)")
	}
	if sent != 2 {
		t.Fatalf("fanoutRevocation sent=%d, want 2 (keyless and well-formed conns)", sent)
	}
	msgs := drainAllSends(sendCh)
	if len(msgs) != 2 {
		t.Fatalf("enqueued %d messages, want exactly 2 NHP_REV", len(msgs))
	}
	for i, msg := range msgs {
		if msg.HeaderType != core.NHP_REV {
			t.Fatalf("message %d header type=%d, want NHP_REV", i, msg.HeaderType)
		}
	}
	if len(msgs[0].PeerPk) != 0 {
		t.Fatalf("keyless peer PeerPk len=%d, want 0", len(msgs[0].PeerPk))
	}
	if len(msgs[1].PeerPk) == 0 {
		t.Fatal("well-formed peer PeerPk len=0, want non-empty")
	}
}

// TestRetryEngine_DisconnectKeepsPendingThenRedeliversOnReconnect is the
// decision-#3 guard: a control-connection blip (AC has no live conn) does NOT
// clear the pending revoke (clearing would leave the AC's persisted flow
// un-revoked — the exact #2793 gap). The entry is KEPT and redelivered once the
// AC reconnects.
func TestRetryEngine_DisconnectKeepsPendingThenRedeliversOnReconnect(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, sendCh := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)
	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")

	// AC disconnects: remove its live connection but DO NOT touch the tracker.
	delete(s.acConnectionMap, "ac-1")

	// A retry tick fires while the AC is gone: no send, but the pending entry is KEPT.
	clk.advance(testRetryInterval + time.Second)
	s.runRevocationRetryTick()
	if sends := drainAllSends(sendCh); len(sends) != 0 {
		t.Fatalf("redelivered to a disconnected AC (%d sends), want 0", len(sends))
	}
	if n := s.revocationRetry.pendingCount(); n != 1 {
		t.Fatalf("pendingCount while disconnected = %d, want 1 (must NOT clear on disconnect)", n)
	}

	// AC reconnects (same acId). The next retry tick redelivers.
	putRetryConn(s, "ac-1", 7)
	clk.advance(testRetryInterval + time.Second)
	s.runRevocationRetryTick()
	sends := drainAllSends(sendCh)
	if len(sends) != 1 || sends[0].HeaderType != core.NHP_REV {
		t.Fatalf("post-reconnect redelivery = %d sends, want 1 NHP_REV", len(sends))
	}
}

// TestRetryEngine_DisconnectedSlotDoesNotRedeliverToSameACIDSibling proves
// redelivery does not broaden from the originally-targeted AC slot to a sibling
// pubkey that happens to share the same acId. That sibling may never have hosted
// the revoked flow, and sending to it cannot prove delivery to the disconnected
// slot that did.
func TestRetryEngine_DisconnectedSlotDoesNotRedeliverToSameACIDSibling(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, sendCh := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)
	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")

	// Original slot disappears; a different blue/green sibling under the same
	// acId is live. This must NOT be treated as a valid redelivery target.
	s.acConnectionMap["ac-1"] = nil
	putRetryConn(s, "ac-1", 8)

	clk.advance(testRetryInterval + time.Second)
	s.runRevocationRetryTick()
	if sends := drainAllSends(sendCh); len(sends) != 0 {
		t.Fatalf("redelivered to same-acId sibling (%d sends), want 0", len(sends))
	}
	if n := s.revocationRetry.pendingCount(); n != 1 {
		t.Fatalf("pendingCount with only sibling live = %d, want 1", n)
	}

	// When the original pubkey reconnects, redelivery resumes to that exact slot.
	putRetryConn(s, "ac-1", 7)
	clk.advance(testRetryInterval + time.Second)
	s.runRevocationRetryTick()
	sends := drainAllSends(sendCh)
	if len(sends) != 1 {
		t.Fatalf("post-original-reconnect redelivery = %d sends, want 1", len(sends))
	}
	if !bytes.Equal(sends[0].PeerPk, testPubkey(7)) {
		t.Fatalf("redelivery PeerPk = %x, want original slot pubkey %x", sends[0].PeerPk, testPubkey(7))
	}
}

// TestRetryEngine_AckMidTickDoesNotResurrect is the deterministic guard for the
// resurrect-acked-revoke hole: if the AC's ack clears the pending entry AFTER the
// retry tick snapshotted it (collectDue) but BEFORE the redelivery re-records the
// send, the redelivery must NOT recreate the entry. Were it recreated (with a
// fresh age-out clock), a cleanly-acked + delivered revoke could later age out to
// a FALSE RevocationAgedOut — the one outcome a proof-of-delivery signal cannot
// tolerate. Reproduced single-threaded by interleaving the steps by hand.
func TestRetryEngine_AckMidTickDoesNotResurrect(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, sendCh := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)
	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")

	// Make the entry due for retry, then grab the snapshot the tick would act on.
	clk.advance(testRetryInterval + time.Second)
	due := s.revocationRetry.collectDue()
	if len(due) != 1 || due[0].agedOut {
		t.Fatalf("precondition: collectDue = %+v, want 1 retry item", due)
	}

	// The AC's ack lands NOW (mid-tick, after the snapshot, before redelivery).
	if _, cleared := s.revocationRetry.clearAck("ac-1", testPubkeyB64(7), "qurl", "qurl:qX", 3); !cleared {
		t.Fatal("precondition: ack did not clear the pending entry")
	}
	if n := s.revocationRetry.pendingCount(); n != 0 {
		t.Fatalf("precondition: pendingCount after ack = %d, want 0", n)
	}

	// Now the tick proceeds to redeliver the stale snapshot item. The redundant
	// NHP_REV may go out (harmless — convergence-ack), but the entry must NOT be
	// resurrected.
	s.redeliverPendingRevocation(due[0])
	if n := s.revocationRetry.pendingCount(); n != 0 {
		t.Fatalf("redelivery RESURRECTED an acked revoke: pendingCount = %d, want 0", n)
	}
	_ = drainAllSends(sendCh) // redundant resend is acceptable; we only assert no resurrection

	// And a subsequent age-out window must NOT produce a false degraded tick,
	// since nothing is pending.
	clk.advance(testRetryAgeOut + time.Second)
	s.runRevocationRetryTick()
	if c := serverCounters(t, s)[MetricRevocationAgedOut]; c != 0 {
		t.Fatalf("%s = %v, want 0 (a resurrected-then-aged-out acked revoke is a false degraded signal)", MetricRevocationAgedOut, c)
	}
}

// TestRetryEngine_DisabledIsInert: with the engine disabled (tracker nil),
// trackFanout / clearPendingRevocationAck are no-ops and no routine runs — the
// Unit-1 ack-send/receive stay inert, preserving the default fire-and-forget
// behavior for a pre-ack fleet.
func TestRetryEngine_DisabledIsInert(t *testing.T) {
	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		acConnectionMap: map[string][]*ACConn{},
		// revocationRetry intentionally nil (disabled)
	}
	putRetryConn(s, "ac-1", 7)
	// These must not panic and must do nothing.
	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")
	s.clearPendingRevocationAck("ac-1", testPubkeyB64(7), "qurl", "qurl:qX", 3)
	// No tracker, nothing to assert beyond not panicking; HandleRevocationAck
	// still records the proof metric without a tracker.
	ppd := ackPPD(t, common.ACRevocationAckMsg{Scope: "qurl", ScopeKey: "qurl:qX", RevocationEpoch: 3}, testPubkey(7))
	if err := s.HandleRevocationAck(ppd); err != nil {
		t.Fatalf("HandleRevocationAck (engine off) err=%v", err)
	}
	if c := serverCounters(t, s)[MetricRevocationAckReceived]; c != 1 {
		t.Fatalf("%s = %v, want 1 even with engine off", MetricRevocationAckReceived, c)
	}
	// Engine off: NO latency sample is recorded (no firstSentAt to measure).
	if got := serverLatencies(t, s)[MetricRevocationDeliveryLatency]; len(got) != 0 {
		t.Fatalf("%s recorded %d samples with engine off, want 0", MetricRevocationDeliveryLatency, len(got))
	}
}

// serverLatencies snapshots the server metrics publisher's recorded latency
// samples (metric name → ms observations) for assertion.
func serverLatencies(t *testing.T, s *UdpServer) map[string][]float64 {
	t.Helper()
	return s.metrics.LatenciesForTest(t)
}

// ── Revocation-delivery-latency SLO (#2792) ──────────────────────────────────

// TestRevocationDeliveryLatency_MeasuresEmitToAckSpan is the non-vacuous proof
// that the SLO histogram measures the REAL emit→ack span, not a ~0ms self-fulfilling
// gap. It drives the injectable clock: track at T0, advance by a KNOWN 7s, then
// run the production ack path (clearPendingRevocationAck). It asserts the single
// recorded sample EQUALS 7000ms (the injected gap, computed from firstSentAt) and
// landed under MetricRevocationDeliveryLatency — proving both the span endpoints
// and the millisecond computation. A test that acked at T0 and only asserted
// "< SLO" on a ~0ms gap is exactly the vacuous trap the gospel's "measured AND
// tested" guards against; this advances the clock so the measurement is load-bearing.
func TestRevocationDeliveryLatency_MeasuresEmitToAckSpan(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, _ := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)

	// Emit (T0): record firstSentAt at the current fake-clock instant.
	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")

	// A KNOWN gap elapses before the AC's ack lands.
	const gap = 7 * time.Second
	clk.advance(gap)

	// Ack (T1): the production wiring path measures now-firstSentAt and records it.
	s.clearPendingRevocationAck("ac-1", testPubkeyB64(7), "qurl", "qurl:qX", 3)

	samples := serverLatencies(t, s)[MetricRevocationDeliveryLatency]
	if len(samples) != 1 {
		t.Fatalf("%s recorded %d samples, want exactly 1", MetricRevocationDeliveryLatency, len(samples))
	}
	if got, want := samples[0], float64(gap.Milliseconds()); got != want {
		t.Fatalf("recorded latency = %v ms, want %v ms (the injected emit→ack gap) — the histogram is not measuring firstSentAt→ack", got, want)
	}
	// The 7s sample is within the SLO bound (the gospel's "tested" assertion).
	if samples[0] >= float64(RevocationDeliveryLatencyP99SLO.Milliseconds()) {
		t.Fatalf("recorded latency %v ms is not below the SLO bound %v ms", samples[0], RevocationDeliveryLatencyP99SLO.Milliseconds())
	}
}

// TestRevocationDeliveryLatency_BoundIsNonVacuous proves the SLO check can FAIL:
// a delivery slower than RevocationDeliveryLatencyP99SLO (but still under the
// age-out, so it is acked rather than censored) records a value that EXCEEDS the
// bound. Without this, an "always < SLO" assertion could pass on a broken
// measurement that records 0; here we show the bound actually discriminates.
func TestRevocationDeliveryLatency_BoundIsNonVacuous(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, _ := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)

	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 3, "evt-3")

	// A slow-but-delivered revoke: past the SLO, still inside the age-out window
	// (so it is acked, not aged out — only acked revokes enter the histogram).
	overSLO := RevocationDeliveryLatencyP99SLO + 5*time.Second
	if overSLO >= testRetryAgeOut {
		t.Fatalf("test setup invalid: over-SLO gap %s must stay below age-out %s", overSLO, testRetryAgeOut)
	}
	clk.advance(overSLO)
	s.clearPendingRevocationAck("ac-1", testPubkeyB64(7), "qurl", "qurl:qX", 3)

	samples := serverLatencies(t, s)[MetricRevocationDeliveryLatency]
	if len(samples) != 1 {
		t.Fatalf("%s recorded %d samples, want exactly 1", MetricRevocationDeliveryLatency, len(samples))
	}
	if samples[0] < float64(RevocationDeliveryLatencyP99SLO.Milliseconds()) {
		t.Fatalf("recorded latency %v ms did NOT exceed the SLO bound %v ms — the bound would never catch a real breach", samples[0], RevocationDeliveryLatencyP99SLO.Milliseconds())
	}
}

// TestRevocationDeliveryLatency_SLOBelowAgeOut pins the load-bearing invariant
// that makes the histogram observable: the SLO bound MUST be strictly below the
// age-out deadline. A revoke un-acked past the age-out is dropped WITHOUT a
// latency sample (RevocationAgedOut instead), so if the SLO were >= the age-out
// the histogram could never contain a value that breaches it — the alarm would
// be structurally silent. Asserting the relationship in code keeps a future
// cadence/age-out retune from silently censoring the SLO signal.
func TestRevocationDeliveryLatency_SLOBelowAgeOut(t *testing.T) {
	if RevocationDeliveryLatencyP99SLO >= defaultRevocationRetryAgeOut {
		t.Fatalf("SLO %s must be strictly below the age-out %s, else a breaching latency is censored into RevocationAgedOut and never enters the histogram",
			RevocationDeliveryLatencyP99SLO, defaultRevocationRetryAgeOut)
	}
}

// TestRevocationDeliveryLatency_StaleAckRecordsNoSample: an ack that does NOT
// clear an entry (wrong epoch / wrong AC) records no latency sample — the
// histogram counts proven deliveries only, never a no-op ack.
func TestRevocationDeliveryLatency_StaleAckRecordsNoSample(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, _ := newRetryEngineServer(t, clk)
	putRetryConn(s, "ac-1", 7)
	s.trackFanout(s.acConnectionMap["ac-1"], "qurl", "qurl:qX", 5, "evt-5")

	clk.advance(3 * time.Second)
	// Stale ack (epoch 4 < pending 5): does not clear, must not record.
	s.clearPendingRevocationAck("ac-1", testPubkeyB64(7), "qurl", "qurl:qX", 4)
	if got := serverLatencies(t, s)[MetricRevocationDeliveryLatency]; len(got) != 0 {
		t.Fatalf("stale ack recorded %d latency samples, want 0", len(got))
	}
	// pending entry survives the stale ack.
	if n := s.revocationRetry.pendingCount(); n != 1 {
		t.Fatalf("pendingCount after stale ack = %d, want 1", n)
	}
}
