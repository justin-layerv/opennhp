package server

import (
	"encoding/json"
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
// the same epoch, and the matching is exact on (acId, scope, scopeKey).
func TestRetryTracker_TrackThenAckClears(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rt := newTestTracker(clk)

	rt.track("ac-1", "qurl", "qurl:qX", 5, "evt-1")
	if n := rt.pendingCount(); n != 1 {
		t.Fatalf("pendingCount after track = %d, want 1", n)
	}
	// An ack for a DIFFERENT AC must not clear it.
	if rt.clearAck("ac-2", "qurl", "qurl:qX", 5) {
		t.Fatal("ack for a different acId wrongly cleared the entry")
	}
	// An ack with a mismatched scope_key must not clear it.
	if rt.clearAck("ac-1", "qurl", "qurl:qOTHER", 5) {
		t.Fatal("ack with mismatched scope_key wrongly cleared the entry")
	}
	// The matching ack clears it.
	if !rt.clearAck("ac-1", "qurl", "qurl:qX", 5) {
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

	rt.track("ac-1", "qurl", "qurl:qX", 5, "evt-5")
	// Ack for an older epoch (4) must NOT clear the pending epoch-5 revoke.
	if rt.clearAck("ac-1", "qurl", "qurl:qX", 4) {
		t.Fatal("stale ack (epoch 4 < pending 5) wrongly cleared the entry")
	}
	if n := rt.pendingCount(); n != 1 {
		t.Fatalf("pendingCount = %d, want 1 after stale ack", n)
	}
	// Ack at a higher epoch (6) DOES clear (convergence at/above).
	if !rt.clearAck("ac-1", "qurl", "qurl:qX", 6) {
		t.Fatal("ack at higher epoch did not clear")
	}
}

// TestRetryTracker_HigherEpochSupersedes: a strictly-greater epoch for the same
// key replaces the entry in place (resets the age-out clock + attempts); a lower
// epoch is ignored; bound stays one entry per (AC, key).
func TestRetryTracker_HigherEpochSupersedes(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rt := newTestTracker(clk)

	rt.track("ac-1", "qurl", "qurl:qX", 5, "evt-5")
	clk.advance(10 * time.Second)
	rt.track("ac-1", "qurl", "qurl:qX", 7, "evt-7") // supersede
	if n := rt.pendingCount(); n != 1 {
		t.Fatalf("pendingCount = %d, want 1 (supersede replaces in place)", n)
	}
	// A lower epoch (6) is ignored — the pending epoch-7 still stands.
	rt.track("ac-1", "qurl", "qurl:qX", 6, "evt-6")
	// An ack at epoch 7 clears; an ack at epoch 6 would not (it's below the
	// superseding epoch 7), proving the superseding epoch took.
	if rt.clearAck("ac-1", "qurl", "qurl:qX", 6) {
		t.Fatal("ack at epoch 6 cleared, but pending should be the superseding epoch 7")
	}
	if !rt.clearAck("ac-1", "qurl", "qurl:qX", 7) {
		t.Fatal("ack at the superseding epoch 7 did not clear")
	}
}

// TestRetryTracker_CollectDue_RetryThenAgeOut walks the clock: nothing due before
// the interval; due-for-retry after the interval; aged-out (and removed) after
// the deadline, with the aged-out item reported so the caller can tick degraded.
func TestRetryTracker_CollectDue_RetryThenAgeOut(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rt := newTestTracker(clk)
	rt.track("ac-1", "qurl", "qurl:qX", 1, "evt-1")

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
	rt.track("ac-1", "qurl", "qurl:qX", 1, "evt-1")

	// Drive several redeliveries, each after one interval.
	for i := 0; i < 5; i++ {
		clk.advance(testRetryInterval + time.Second)
		due := rt.collectDue()
		if len(due) == 1 && due[0].agedOut {
			// Once we cross firstSentAt+ageOut, it ages out regardless of retracks.
			return
		}
		rt.track("ac-1", "qurl", "qurl:qX", 1, "evt-1") // redelivery re-track
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

	// The AC's NHP_RACK arrives and is attributed + cleared.
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
	if !s.revocationRetry.clearAck("ac-1", "qurl", "qurl:qX", 3) {
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
	s.clearPendingRevocationAck("ac-1", "qurl", "qurl:qX", 3)
	// No tracker, nothing to assert beyond not panicking; HandleRevocationAck
	// still records the proof metric without a tracker.
	ppd := ackPPD(t, common.ACRevocationAckMsg{Scope: "qurl", ScopeKey: "qurl:qX", RevocationEpoch: 3}, testPubkey(7))
	if err := s.HandleRevocationAck(ppd); err != nil {
		t.Fatalf("HandleRevocationAck (engine off) err=%v", err)
	}
	if c := serverCounters(t, s)[MetricRevocationAckReceived]; c != 1 {
		t.Fatalf("%s = %v, want 1 even with engine off", MetricRevocationAckReceived, c)
	}
}
