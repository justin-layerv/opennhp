package server

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// qURL v2 revocation retry-until-ack-or-age-out engine (P4e Slice 3, #2793).
//
// Closes the DE-Risk #5 proof-of-delivery gap: the server→AC NHP_REV fanout is
// fire-and-forget UDP, so a lost NHP_REV leaves the AC's flow alive to natural
// expiry. This engine records a pending entry per targeted AC at fanout time,
// retransmits the NHP_REV on a fixed cadence until the AC acks (NHP_RACK clears
// the pending entry) or an age-out deadline elapses, at which point it ticks the
// RevocationAgedOut degraded metric (NEVER a silent drop) and drops the entry.
//
// Convergence-ack semantics make redelivery safe (see common.ACRevocationAckMsg
// + the AC's HandleUdpACRevocation): the AC validates and acks EVERY redelivered
// NHP_REV regardless of how many flows it flushes, and its admitEpoch watermark
// makes a re-applied event idempotent. So a retransmit to an AC that already
// applied (or that restarted and has nothing to flush) is harmless, and a
// retransmit to an AC whose flow persisted across a control-connection blip is
// exactly what is required.
//
// ── Rollout gating (default OFF) ────────────────────────────────────────────
// A fleet of pre-ack ACs never sends NHP_RACK, so with the engine ON every
// revoke would retry to age-out and storm RevocationAgedOut + retransmit load.
// The engine therefore arms only when NHP_REVOCATION_RETRY_ENABLED=true. Until
// then, fanout still records nothing and the AC ack-send / server ack-receive
// (shipped inert in the prior unit) are no-ops. Flip to true only once the
// fleet ships ack support.
//
// ── Lock discipline (see endpoints/server/CLAUDE.md) ────────────────────────
// revocationRetryTracker.mu is LEAF-MOST: it is never held while acquiring
// acConnectionMapMutex or while sending on sendMsgCh. The retry routine
// snapshots due entries under mu (and releases it), then resolves the live
// ACConn (under acConnectionMapMutex, released) and sends lock-free — so the
// engine introduces no new lock-order edge.

const (
	// RevocationRetryEnabledEnvVar arms the retry/age-out engine. Default OFF
	// (see rollout note above). Accepts the same truthy/falsey tokens as the
	// other server gates via parseRevocationRetryEnabled.
	RevocationRetryEnabledEnvVar = "NHP_REVOCATION_RETRY_ENABLED"
	// RevocationRetryIntervalEnvVar overrides the retransmit cadence (whole
	// seconds). The engine re-sends an un-acked NHP_REV no more often than this.
	RevocationRetryIntervalEnvVar = "NHP_REVOCATION_RETRY_INTERVAL_SECONDS"
	// RevocationRetryAgeOutEnvVar overrides the age-out deadline (whole
	// seconds): a pending revoke un-acked this long after it was first sent is
	// declared degraded (RevocationAgedOut) and dropped.
	RevocationRetryAgeOutEnvVar = "NHP_REVOCATION_RETRY_AGE_OUT_SECONDS"

	// defaultRevocationRetryInterval is the retransmit cadence default. ~5s
	// balances delivery latency against retransmit load; tune via env for the
	// revocation-latency SLO (#2792).
	defaultRevocationRetryInterval = 5 * time.Second
	// defaultRevocationRetryAgeOut is the age-out default. ~60s bounds how long
	// the engine keeps proving delivery before declaring the revoke degraded.
	defaultRevocationRetryAgeOut = 60 * time.Second
	// minRevocationRetryInterval floors the cadence so a typo cannot turn the
	// retry routine into a busy-loop on sendMsgCh.
	minRevocationRetryInterval = 1 * time.Second

	// RevocationDeliveryLatencyP99SLO is the qURL v2 revocation-latency SLO
	// (#2792): the p99 wall-clock time from the server enqueuing an NHP_REV for
	// an AC (firstSentAt, recorded in track at fanout time) to that AC's
	// proof-of-delivery ack (NHP_RACK) landing and being attributed (clearAck).
	// This is the measurable emit→ack span; the full revoke-API→AC-flush span is
	// NOT observable server-side (qurl-service is the upstream API and the AC
	// flush/apply path is gated off — see #2792), so emit→ack is the proxy the
	// gospel's "'immediate' must be a number" requirement is measured against
	// (docs/design/QURL_V2_KEYED_IDENTITY.md, the revocation-latency SLO bullet).
	//
	// Why 15s, tied to the retry cadence and age-out:
	//   - A delivered-on-first-try ack lands in ~1 control-plane RTT (sub-second).
	//   - Each lost NHP_REV adds one retransmit interval (defaultRevocationRetryInterval,
	//     ~5s) before the next attempt can be acked.
	//   - 15s ≈ tolerate up to ~2 lost NHP_REVs (0 retransmits ≈ RTT; 1 ≈ 5s;
	//     2 ≈ 10s, plus RTT slack) before the p99 is considered breached.
	//
	// Load-bearing invariant — this SLO MUST stay strictly below the age-out
	// (defaultRevocationRetryAgeOut, ~60s): a revoke un-acked past the age-out
	// becomes RevocationAgedOut and is dropped WITHOUT recording a latency sample,
	// so the recorded MetricRevocationDeliveryLatency distribution is bounded
	// [~0, ageOut) by construction. With 15s < 60s a genuine p99 breach is
	// observable in the histogram (rather than silently censored into the
	// age-out counter). The two signals are complementary: this SLO alarms on
	// SLOW-but-delivered revokes; MetricRevocationAgedOut alarms on
	// NEVER-delivered ones. Neither alone proves delivery — see the alarm wiring
	// in terraform/modules/monitoring/main.tf, kept in lockstep with this value.
	//
	// p99 viability rests on the EMF emission, not the CloudWatch statistic set:
	// RecordLatency dual-emits an EMF event per observation (see
	// endpoints/metrics/publisher.go::emitEMF), and only the EMF stream supports
	// the extended_statistic="p99" the alarm uses (a min/max/sum/count statistic
	// set cannot compute percentiles — the #871 convention). Do NOT remove the
	// EMF latency path without re-homing this alarm.
	//
	// Keep this in lockstep with the Terraform alarm threshold
	// (terraform/modules/monitoring/main.tf, revocation_delivery_latency_high):
	// the alarm threshold is expressed in MILLISECONDS (15000) because
	// RecordLatency records milliseconds.
	RevocationDeliveryLatencyP99SLO = 15 * time.Second
)

// parseRevocationRetryEnabled parses NHP_REVOCATION_RETRY_ENABLED. Empty/unset
// is false (default OFF). Mirrors the other server boolean-gate parsers: an
// unrecognized token is an error so an operator typo fails Start rather than
// silently leaving the engine off.
func parseRevocationRetryEnabled(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "false", "0", "no", "off":
		return false, nil
	case "true", "1", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("must be true or false")
	}
}

// parseRevocationRetryDuration parses a whole-seconds env override, returning
// def when unset/empty. A non-integer, negative, or (for the interval) sub-floor
// value is an error so a typo fails Start. floor is the minimum allowed positive
// value (0 disables the floor check, used for the age-out which is validated
// against the interval by the caller).
func parseRevocationRetryDuration(raw string, def, floor time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("must be an integer number of seconds")
	}
	if seconds <= 0 {
		return 0, fmt.Errorf("must be a positive number of seconds")
	}
	d := time.Duration(seconds) * time.Second
	if floor > 0 && d < floor {
		return 0, fmt.Errorf("must be at least %s", floor)
	}
	return d, nil
}

// pendingRevocationKey identifies one un-acked revoke targeted at one AC. Keyed
// by (acId, scope, scopeKey) so a higher epoch for the same identity supersedes
// the lower in place (one pending entry per AC per identity, bounding the map).
// scopeKey here is the WIRE form (scope-prefixed) the server sent into the
// NHP_REV and the AC echoes verbatim in its ack — matched by string equality.
type pendingRevocationKey struct {
	acId     string
	scope    string
	scopeKey string // wire (scope-prefixed) form
}

// pendingRevocation is the tracked state for one un-acked revoke.
type pendingRevocation struct {
	epoch       int64
	eventId     string
	firstSentAt time.Time
	lastSentAt  time.Time
	attempts    int
}

// revocationRetryTracker holds the per-AC un-acked revokes and drives the
// retry/age-out decisions. All methods are safe for concurrent use; mu is
// leaf-most (never held across a conn-map lock or a sendMsgCh send).
//
// now is injectable so the age-out / due-for-retry logic is unit-testable
// without sleeping; production uses time.Now.
type revocationRetryTracker struct {
	mu       sync.Mutex
	pending  map[pendingRevocationKey]*pendingRevocation
	interval time.Duration
	ageOut   time.Duration
	now      func() time.Time
}

func newRevocationRetryTracker(interval, ageOut time.Duration) *revocationRetryTracker {
	return &revocationRetryTracker{
		pending:  make(map[pendingRevocationKey]*pendingRevocation),
		interval: interval,
		ageOut:   ageOut,
		now:      time.Now,
	}
}

// track records (or supersedes) a pending revoke for acId at fanout/redelivery
// time. A strictly-greater epoch for the same (acId, scope, scopeKey) resets the
// entry (new first-sent clock, attempts) — the older revoke is obsolete. A
// re-track at the same epoch (a redelivery this engine itself drove) updates
// lastSentAt/attempts but preserves firstSentAt so the age-out clock keeps
// running from the original send. An equal-or-lower epoch than an existing entry
// at a HIGHER epoch is ignored (the higher-epoch revoke already supersedes it).
func (rt *revocationRetryTracker) track(acId, scope, scopeKey string, epoch int64, eventId string) {
	k := pendingRevocationKey{acId: acId, scope: scope, scopeKey: scopeKey}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := rt.now()
	if cur, ok := rt.pending[k]; ok {
		if epoch < cur.epoch {
			// A lower epoch than what is already pending: the pending (higher)
			// revoke already covers this identity. Ignore.
			return
		}
		if epoch == cur.epoch {
			// Same revoke, re-sent: advance the attempt clock, keep firstSentAt.
			cur.lastSentAt = now
			cur.attempts++
			cur.eventId = eventId
			return
		}
		// Strictly greater epoch supersedes: reset the entry in place.
	}
	rt.pending[k] = &pendingRevocation{
		epoch:       epoch,
		eventId:     eventId,
		firstSentAt: now,
		lastSentAt:  now,
		attempts:    1,
	}
}

// markResent records a redelivery of an ALREADY-tracked pending entry: it
// advances lastSentAt/attempts but PRESERVES firstSentAt (the age-out clock
// keeps running from the original send). Unlike track, it is update-if-present:
// it does NOT create an entry.
//
// This distinction is load-bearing for the proof-of-delivery signal. The retry
// routine snapshots due items under mu (collectDue), releases mu, then resolves
// the live conn and re-records the send. Between the snapshot and this call, a
// concurrent clearAck (the AC's ack landed mid-tick) may have deleted the entry,
// or a higher-epoch track may have superseded it. If redelivery used track
// (add-or-supersede), it would RESURRECT a cleanly-acked revoke with a reset
// age-out clock — which could later age out to a FALSE RevocationAgedOut, the
// one outcome a delivery-proof feature cannot tolerate. The presence + exact-
// epoch guard here no-ops both the acked-mid-tick (absent) and superseded-mid-
// tick (epoch differs) cases, so a redelivery never recreates state.
func (rt *revocationRetryTracker) markResent(acId, scope, scopeKey string, epoch int64) {
	k := pendingRevocationKey{acId: acId, scope: scope, scopeKey: scopeKey}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	cur, ok := rt.pending[k]
	if !ok || cur.epoch != epoch {
		// Acked (absent) or superseded (different epoch) mid-tick — do not
		// resurrect or touch the newer entry.
		return
	}
	cur.lastSentAt = rt.now()
	cur.attempts++
}

// clearAck removes the pending entry for (acId, scope, scopeKey) when the acked
// epoch is at least the tracked epoch (a convergence ack proves the AC reached
// the post-revocation state at/above that epoch). An ack for a lower epoch than
// what is pending does NOT clear it — a newer revoke is outstanding and must
// still be proven delivered.
//
// Returns (elapsed, cleared): cleared is true iff an entry was removed, and on a
// clear elapsed is the revocation-delivery latency for the SLO histogram (#2792)
// — the wall-clock from the entry's firstSentAt (the original NHP_REV enqueue,
// preserved verbatim across redeliveries by markResent) to now. Measured under
// the same lock that reads firstSentAt and against the tracker's injectable
// clock, so a test can drive a known gap deterministically. elapsed is the
// zero Duration when nothing was cleared (caller must gate the recording on
// cleared, not on elapsed != 0 — a same-instant ack legitimately yields 0).
func (rt *revocationRetryTracker) clearAck(acId, scope, scopeKey string, ackEpoch int64) (elapsed time.Duration, cleared bool) {
	k := pendingRevocationKey{acId: acId, scope: scope, scopeKey: scopeKey}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	cur, ok := rt.pending[k]
	if !ok {
		return 0, false
	}
	if ackEpoch < cur.epoch {
		return 0, false
	}
	// Latency from the original send (firstSentAt, preserved across retries by
	// markResent), so it spans every lost-NHP_REV retransmit. Clamp negative
	// (only reachable if the injected clock runs backwards) to 0.
	elapsed = rt.now().Sub(cur.firstSentAt)
	if elapsed < 0 {
		elapsed = 0
	}
	delete(rt.pending, k)
	return elapsed, true
}

// dueItem is a snapshot of a pending entry the retry routine should act on this
// tick — either redeliver (agedOut=false) or declare degraded (agedOut=true).
type dueItem struct {
	key     pendingRevocationKey
	epoch   int64
	eventId string
	agedOut bool
}

// collectDue returns the pending entries that need action this tick and, for the
// aged-out ones, removes them from the map under the same lock (so a slow
// redelivery loop cannot double-count an age-out). An entry ages out when
// now-firstSentAt >= ageOut; otherwise it is due for redelivery when
// now-lastSentAt >= interval. Entries that are neither (recently sent, not yet
// aged out) are skipped this tick.
//
// Age-out is checked BEFORE the retry-interval so an entry that crossed the
// deadline is declared degraded rather than retransmitted one last time.
func (rt *revocationRetryTracker) collectDue() []dueItem {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := rt.now()
	var due []dueItem
	for k, p := range rt.pending {
		if now.Sub(p.firstSentAt) >= rt.ageOut {
			due = append(due, dueItem{key: k, epoch: p.epoch, eventId: p.eventId, agedOut: true})
			delete(rt.pending, k)
			continue
		}
		if now.Sub(p.lastSentAt) >= rt.interval {
			due = append(due, dueItem{key: k, epoch: p.epoch, eventId: p.eventId, agedOut: false})
		}
	}
	return due
}

// pendingCount reports the number of tracked un-acked revokes (test/observability).
func (rt *revocationRetryTracker) pendingCount() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.pending)
}

// trackFanout records the just-sent NHP_REV for each AC it was enqueued to, so
// the retry engine can prove delivery. Called by the fanout handler AFTER a
// successful enqueue. No-op when the engine is disabled (tracker nil). scopeKey
// is the WIRE (scope-prefixed) form — the same bytes the AC echoes in its ack.
func (s *UdpServer) trackFanout(conns []*ACConn, scope, scopeKey string, epoch int64, eventId string) {
	if s.revocationRetry == nil {
		return
	}
	for _, conn := range conns {
		if conn == nil || conn.ACId == "" {
			continue
		}
		s.revocationRetry.track(conn.ACId, scope, scopeKey, epoch, eventId)
	}
}

// clearPendingRevocationAck clears the pending entry an AC's NHP_RACK
// acknowledges and, on a clear, records the emit→ack revocation-delivery latency
// into the SLO histogram (MetricRevocationDeliveryLatency, #2792). Called by
// HandleRevocationAck after it has attributed the ack to acId via the
// authenticated pubkey. No-op when the engine is disabled (tracker nil — the
// default; no firstSentAt exists to measure against). scope / scopeKey are the
// verbatim (scope-prefixed) values the AC echoed.
func (s *UdpServer) clearPendingRevocationAck(acId, scope, scopeKey string, ackEpoch int64) {
	if s.revocationRetry == nil {
		return
	}
	elapsed, cleared := s.revocationRetry.clearAck(acId, scope, scopeKey, ackEpoch)
	if !cleared {
		return
	}
	// Record the delivery latency (ms) for this acked revoke. RecordLatency is
	// nil-safe and dual-emits a statistic set + an EMF event; the EMF stream is
	// what backs the p99 alarm. Gated on cleared (not elapsed): a same-instant
	// ack is a legitimate ~0ms sample, not a missing one.
	s.metrics.RecordLatency(MetricRevocationDeliveryLatency, float64(elapsed.Milliseconds()))
	log.Debug("server-ac(%s)[RevocationRetry] cleared pending revoke on ack (scope=%q key=%q epoch=%d latency=%s)",
		acId, scope, scopeKey, ackEpoch, elapsed)
}

// revocationRetryRoutine is the background retry/age-out loop. Modeled on
// acPubkeyRevokeSweepRoutine: joins s.wg, exits on s.signals.stop, and stops
// sending before Stop() closes s.sendMsgCh (Stop calls wg.Wait() before
// close(sendMsgCh), so a returned routine has already ceased sending). Started
// only when the engine is armed.
func (s *UdpServer) revocationRetryRoutine() {
	defer s.wg.Done()
	defer log.Info("revocationRetryRoutine stopped")
	log.Info("revocationRetryRoutine started (interval=%s ageOut=%s)",
		s.revocationRetry.interval, s.revocationRetry.ageOut)

	ticker := time.NewTicker(s.revocationRetry.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.signals.stop:
			return
		case <-ticker.C:
			s.runRevocationRetryTick()
		}
	}
}

// runRevocationRetryTick processes one retry cadence: redeliver every due
// un-acked revoke and declare every aged-out one degraded. Extracted from the
// routine so it is directly testable without the ticker/stop ceremony.
func (s *UdpServer) runRevocationRetryTick() {
	for _, item := range s.revocationRetry.collectDue() {
		if item.agedOut {
			// DE-Risk #5 degraded signal: a revoke we could not prove delivered.
			// Emitted, never silently dropped, so it can be alarmed.
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricRevocationAgedOut)
			}
			log.Warning("server-ac(%s)[RevocationRetry] revoke AGED OUT un-acked (scope=%q key=%q epoch=%d eventId=%q); fired %s — a revocation could not be proven delivered",
				item.key.acId, item.key.scope, item.key.scopeKey, item.epoch, item.eventId, MetricRevocationAgedOut)
			continue
		}
		s.redeliverPendingRevocation(item)
	}
}

// redeliverPendingRevocation resends the NHP_REV for one due pending entry to
// its AC's currently-live connection(s), then re-tracks the send (advancing the
// attempt clock without resetting the age-out clock). If the AC has no live
// connection right now (a control-connection blip / reconnect in progress) the
// resend is skipped this tick — the pending entry is KEPT (decision #3: do NOT
// clear on disconnect, or the flow survives un-revoked) and redelivered on a
// later tick once the AC reconnects, or aged out to degraded if it never does.
//
// Lock discipline: resolves the live conn under acConnectionMapMutex (released)
// then sends lock-free on sendMsgCh; the tracker mu is taken only inside
// re-track. No nesting.
func (s *UdpServer) redeliverPendingRevocation(item dueItem) {
	conns := s.liveACConnsForId(item.key.acId)
	if len(conns) == 0 {
		// AC not currently connected. Keep the pending entry (it will age out to
		// degraded if the AC never returns) and try again next tick.
		log.Debug("server-ac(%s)[RevocationRetry] no live connection for redelivery; keeping pending (scope=%q key=%q epoch=%d)",
			item.key.acId, item.key.scope, item.key.scopeKey, item.epoch)
		return
	}

	revMsg := &common.ACRevocationMsg{
		Scope:           item.key.scope,
		ScopeKey:        item.key.scopeKey, // wire (scope-prefixed) form, as originally sent
		RevocationEpoch: item.epoch,
		EventId:         item.eventId,
	}
	revBytes, err := json.Marshal(revMsg)
	if err != nil {
		// A fixed-shape struct cannot realistically fail to marshal; if it did,
		// re-sending identical (still-unmarshalable) bytes would not help, so log
		// and leave the entry to age out rather than spin.
		log.Error("server-ac(%s)[RevocationRetry] failed to marshal redelivery NHP_REV (eventId=%q): %v",
			item.key.acId, item.eventId, err)
		return
	}

	// Reuse the fanout send primitive (non-blocking enqueue, fail-closed on a
	// full queue). A backpressure skip this tick simply retries next tick.
	sent, _ := s.fanoutRevocation(conns, revBytes)
	if sent == 0 {
		return
	}
	// Record the redelivery with update-if-present semantics: advances
	// lastSentAt/attempts and preserves firstSentAt (age-out clock unchanged),
	// but does NOT recreate the entry if a concurrent ack cleared it (or a higher
	// epoch superseded it) between collectDue's snapshot and now — preventing a
	// resurrected-acked-revoke false age-out. See markResent.
	s.revocationRetry.markResent(item.key.acId, item.key.scope, item.key.scopeKey, item.epoch)
	log.Debug("server-ac(%s)[RevocationRetry] redelivered NHP_REV (scope=%q key=%q epoch=%d)",
		item.key.acId, item.key.scope, item.key.scopeKey, item.epoch)
}

// liveACConnsForId snapshots the live AC connections for acId under
// acConnectionMapMutex.RLock and returns a fresh slice the caller reads
// lock-free. Mirrors findACConnectionsForRevocation's targeted branch for a
// single id.
func (s *UdpServer) liveACConnsForId(acId string) []*ACConn {
	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	conns := s.acConnectionMap[acId]
	if len(conns) == 0 {
		return nil
	}
	out := make([]*ACConn, len(conns))
	copy(out, conns)
	return out
}

// parseRevocationRetryConfig reads + validates the three engine env vars and
// returns (enabled, interval, ageOut). It enforces, in order:
//   - interval >= floor (a sub-floor cadence risks a busy-loop on sendMsgCh);
//   - ageOut > interval (an age-out at or below one retry interval would declare
//     a revoke degraded before its first retransmit could be acked);
//   - ageOut > RevocationDeliveryLatencyP99SLO (the censoring invariant): a
//     revoke acked after the age-out is dropped as RevocationAgedOut WITHOUT a
//     latency sample, so an age-out at/below the SLO would silently censor every
//     genuine p99 breach into the aged-out counter and leave the latency alarm
//     structurally inert. The compile-time default (60s > 15s) satisfies this,
//     but an operator override (NHP_REVOCATION_RETRY_AGE_OUT_SECONDS) could not —
//     so it is enforced here at Start, not only by the default-pinning unit test.
//
// Returns an error so an operator typo / misconfig fails Start rather than
// silently mis-arming the engine or blinding the SLO alarm.
func parseRevocationRetryConfig() (enabled bool, interval, ageOut time.Duration, err error) {
	enabled, err = parseRevocationRetryEnabled(os.Getenv(RevocationRetryEnabledEnvVar))
	if err != nil {
		return false, 0, 0, fmt.Errorf("%s: %w", RevocationRetryEnabledEnvVar, err)
	}
	interval, err = parseRevocationRetryDuration(os.Getenv(RevocationRetryIntervalEnvVar), defaultRevocationRetryInterval, minRevocationRetryInterval)
	if err != nil {
		return false, 0, 0, fmt.Errorf("%s: %w", RevocationRetryIntervalEnvVar, err)
	}
	ageOut, err = parseRevocationRetryDuration(os.Getenv(RevocationRetryAgeOutEnvVar), defaultRevocationRetryAgeOut, 0)
	if err != nil {
		return false, 0, 0, fmt.Errorf("%s: %w", RevocationRetryAgeOutEnvVar, err)
	}
	if ageOut <= interval {
		return false, 0, 0, fmt.Errorf("%s (%s) must be greater than %s (%s)",
			RevocationRetryAgeOutEnvVar, ageOut, RevocationRetryIntervalEnvVar, interval)
	}
	// Censoring-invariant guard (#2792): the age-out must strictly exceed the
	// revocation-delivery SLO, else a p99 breach is censored into
	// RevocationAgedOut and the latency alarm goes silent. See the doc above.
	if ageOut <= RevocationDeliveryLatencyP99SLO {
		return false, 0, 0, fmt.Errorf("%s (%s) must exceed the revocation-delivery SLO (%s), else a p99 breach is censored into %s and the latency alarm goes silent",
			RevocationRetryAgeOutEnvVar, ageOut, RevocationDeliveryLatencyP99SLO, MetricRevocationAgedOut)
	}
	return enabled, interval, ageOut, nil
}
