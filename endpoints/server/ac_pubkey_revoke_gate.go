package server

import (
	"context"
	"strings"
	"sync"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// AC pubkey runtime-revocation gate (#1507, follow-up from #1157 F5).
//
// Pre-#1507 there was no way to revoke a previously-trusted AC
// pubkey at runtime. Once an AC's pubkey was observed in a
// successful HandleACOnline it was re-accepted on every subsequent
// registration regardless of operational status. The closest
// safeguards — License.Active=false and License.ExpiresAt — are
// per-license, kick legitimate ACs that share the license, and
// only take effect at the next re-registration without an
// operator-visible audit trail of WHICH pubkey was rejected.
//
// Fix: a per-acId denylist (ACAssignment.RevokedPubKeys, see
// storage.go) consulted on every registration. CachedStorage's
// adaptive TTL is the propagation window — 60s normally, 5s
// during reassignment.
//
// Rollout: permit→strict via NHP_AC_PUBKEY_REVOKE_VERIFY (same
// pattern as F3/F4). Permit logs+metric and accepts; strict
// rejects with ErrACPubkeyRevoked.
//
// Storage-error policy: a non-NotFound transient lookup error
// degrades to "skip the gate" + MetricACPubkeyRevokedLookupErr —
// matches autoAssignAC's fallthrough and F4's lookup-err policy.
// Strict mode does NOT escalate; otherwise a storage flap becomes
// a fleet-wide outage. Operators alarm on the metric.
//
// Scope: registration-time admission only. Mid-session connection
// drop on revocation (parent #1157 F5 second half) is tracked as
// a separate follow-up.
//
// Audit log: every Revoked verdict emits a Warning line tagged
// [ACPubkeyRevoked]. Strict-mode rejects log unconditionally;
// permit-mode logs sample at 1/permitModeLogSampleMod with a
// sync.Once first-anchor.
//
// Information-disclosure trade-off: a strict-mode reject returns
// ErrACPubkeyRevoked (52019), distinct from rate-limit /
// license-validation rejects (ErrServerACOpsFailed). An attacker
// presenting a revoked pubkey from a not-yet-throttled source
// learns "this specific pubkey is revoked." The leak IS the
// audit primitive — incident-response wants the AC's logs to
// carry the revocation reason so the operator can confirm the
// yank took effect. Do NOT genericize this to ErrServerACOpsFailed
// to "close the info leak"; the rate-limiter bounds the probe rate
// and the on-call runbook framing classifies a 52019 spike as
// "attacker is testing your acId list," not "attacker has the
// stolen key in flight." See PR #1538 for the operator-side
// runbook.
//
// Metrics (also see per-const docs below):
//   - MetricACPubkeyRevoked            — revoked-pubkey hit
//   - MetricACPubkeyRevokedLookupErr   — F5 lookup storage error
//   - MetricACPubkeyRevokeListOversize — runaway list length sentinel
//   - MetricACPubkeyRevokeGateBug      — fail-closed dispatch-bug fence

// ACPubkeyRevokeVerifyEnvVar gates the strict-mode reject. Accepts
// the same truthy/falsy tokens as the other server gates.
const ACPubkeyRevokeVerifyEnvVar = "NHP_AC_PUBKEY_REVOKE_VERIFY"

// MetricACPubkeyRevoked fires once per AC registration where the
// presented pubkey appears in ACAssignment.RevokedPubKeys for the
// claimed acId. Page-worthy in strict mode (operator-confirmed
// kill of a specific AC instance is being attempted; if the metric
// is non-zero AND the operator did not just revoke, that's the
// "revoked pubkey is still being presented" forensic signal).
//
// MetricACPubkeyRevokedLookupErr fires when the ACAssignment
// lookup for the F5 pre-check itself errors (storage transient).
// Strict-mode behavior is "skip the gate, accept the registration"
// — the metric is the only signal. A sustained non-zero rate
// means storage is flaky AND the gate is silently degraded; should
// be paged on independently of the revocation counter.
//
// MetricACPubkeyRevokeListOversize fires once per AOL whose
// ACAssignment has a RevokedPubKeys list at or past
// acPubkeyRevokeListLengthWarn. Unlike the once-per-process
// firstLongRevokeListLog (forensic anchor), this counter aggregates
// across acIds — operators see a non-zero rate for ANY long-list
// observation regardless of which acId, so a runaway-append on
// acId-Y still surfaces even after acId-X consumed the log anchor.
// Drives the standing dashboard signal; #1547 tracks adding a
// hard upper bound.
//
// MetricACPubkeyRevokeGateBug fires when applyACPubkeyRevokeVerdict
// hits its fail-closed default branch — reachable only when a future
// PR adds a verdict constant without registering it in the switch.
// Page-worthy: a non-zero rate here means a server-side dispatch-
// table bug is rejecting registrations as ErrACPubkeyRevokedInternal
// (52020), which is observationally indistinguishable from a real
// revoked-pubkey reject if you only watch ACPubkeyRevoked. Alarming
// on metrics not log strings is the right operator path.
const (
	MetricACPubkeyRevoked            = "ACPubkeyRevoked"
	MetricACPubkeyRevokedLookupErr   = "ACPubkeyRevokedLookupErr"
	MetricACPubkeyRevokeListOversize = "ACPubkeyRevokeListOversize"
	MetricACPubkeyRevokeGateBug      = "ACPubkeyRevokeGateBug"
)

// acPubkeyRevokeListLengthWarn is the size at which evaluate logs a
// rate-limited Warning that an ACAssignment.RevokedPubKeys list has
// grown past operationally-realistic bounds. The kernel's linear
// scan stays cheap well past this threshold; the warning is an
// admin-tool sanity check, not a performance gate. Operator
// workflow is "revoke one pubkey at a time during incident
// response," so a list this large signals either (a) a runaway
// admin tool that's appending without dedupe, or (b) an attempt to
// use F5 as a license-wide kill switch (where License.Active=false
// is the right primitive). Either way the operator should see it.
const acPubkeyRevokeListLengthWarn = 50

// acPubkeyRevokeVerdict captures what verifyACPubkeyRevoked
// recommends.
type acPubkeyRevokeVerdict int

const (
	// Leave iota=0 unnamed on purpose — same structural fail-closed
	// pattern as the other gates. An uninitialized verdict falls
	// through to applyACPubkeyRevokeVerdict's switch default and
	// rejects with ErrACPubkeyRevokedInternal. Without this shift,
	// verdictACPubkeyRevokeOK would be the zero value and a future
	// caller that forgot to set the verdict would silently accept.
	_ acPubkeyRevokeVerdict = iota
	// verdictACPubkeyRevokeOK: presented pubkey is NOT in the
	// revocation list (or the list is empty / the assignment has no
	// RevokedPubKeys field). Accept unconditionally.
	verdictACPubkeyRevokeOK
	// verdictACPubkeyRevokeRevoked: presented pubkey appears in
	// ACAssignment.RevokedPubKeys. Permit logs+metric and accepts
	// (pre-fix behavior); strict rejects.
	verdictACPubkeyRevokeRevoked
)

// Per-process forensic anchors. Each guarantees at least one log
// line for its event class, so a shared-NAT-noise burst can't drown
// the audit stream entirely. All three are package-level sync.Once
// — that's the same pattern as F3/F4 today and means tests sharing
// a binary can consume the anchor in test order.
//
// TODO: as more F5 tests land, move these to fields on UdpServer
// (or a small struct constructed per test) so test-ordering
// coupling on the global anchor stops mattering. Today the metric
// is the load-bearing assertion in every test that touches these,
// so the coupling is acknowledged but not blocking.
var (
	// firstPermitACPubkeyRevokeLog: permit-mode revoke-permit anchor.
	firstPermitACPubkeyRevokeLog sync.Once
	// firstLongRevokeListLog: runaway-admin-tool sanity Warning.
	// Once-per-process keeps log volume bounded; the metric
	// (MetricACPubkeyRevokeListOversize) is the standing signal.
	firstLongRevokeListLog sync.Once
	// firstLookupErrLog: storage-error anchor. Pre-#1507-r14 the log
	// was unsampled and would emit per AOL during a DDB flap.
	// Non-anchor occurrences now sample at 1/permitModeLogSampleMod.
	firstLookupErrLog sync.Once
)

// parseACPubkeyRevokeVerify decodes NHP_AC_PUBKEY_REVOKE_VERIFY.
// Thin wrapper around parsePermitStrictEnv so every gate uses one
// token grammar.
func parseACPubkeyRevokeVerify(raw string) (bool, error) {
	return parsePermitStrictEnv(raw)
}

// verifyACPubkeyRevoked is the pure policy kernel. Given the
// presented base64 pubkey and the revocation list, returns the
// verdict.
//
// Separating kernel from side-effect wrapper makes the policy
// table unit-testable without a UdpServer — mirrors
// verifyACPubkeyCap in ac_pubkey_cap_gate.go.
//
// An empty / nil revoked slice short-circuits to OK without
// allocating. Per-call allocation matters: this kernel runs on
// every NHP_AOL in cloud mode and the common case in steady-state
// is "no revocations for this acId." A linear scan is preferred
// over a map for typical small list sizes (operator revokes one
// pubkey at a time during incident response; lists in the dozens
// are operationally unrealistic — a license-wide compromise calls
// for License.Active=false, not 100 RevokedPubKeys entries).
func verifyACPubkeyRevoked(presentedPubkey string, revokedPubkeys []string) acPubkeyRevokeVerdict {
	// Empty-list short-circuit FIRST so the dominant "no revocations
	// for this acId" steady-state path returns without doing any
	// work — matches the kernel-doc claim above.
	if len(revokedPubkeys) == 0 {
		return verdictACPubkeyRevokeOK
	}
	// TrimSpace on both sides: operators pasting a pubkey from a
	// terminal or Slack can pick up trailing \n / leading space.
	// Symmetric trim keeps the kernel contract explicit — whitespace
	// does not participate in identity comparison. Mirrors
	// verifyLicensePubkey. URL-safe vs std base64 and padded vs
	// unpadded are deliberately NOT normalized: those are real
	// format divergences admin tooling must catch (#1536's CLI),
	// not whitespace typos.
	presentedTrim := strings.TrimSpace(presentedPubkey)
	// Empty presented pubkey can never legitimately match. The
	// upstream codec (core.PacketParserData.RemotePubKey) and
	// validateACLicense both reject zero-length pubkeys before this
	// kernel runs, but if a future refactor lets a zero-byte through
	// AND a future write path emits "" in revokedPubkeys, the empty-
	// match would blackhole legitimate ACs. Short-circuit makes that
	// combination inert at the kernel level.
	if presentedTrim == "" {
		return verdictACPubkeyRevokeOK
	}
	for _, rk := range revokedPubkeys {
		if strings.TrimSpace(rk) == presentedTrim {
			return verdictACPubkeyRevokeRevoked
		}
	}
	return verdictACPubkeyRevokeOK
}

// applyACPubkeyRevokeVerdict centralizes metric + log emission AND
// reject-error selection — single source of truth for both
// "proceed?" and "which error?". Mirrors applyACPubkeyCapVerdict.
//
// Returns (proceed, rejectErr):
//   - (true, nil) — caller proceeds, gate accepted the registration
//   - (false, rejectErr) — caller aborts with rejectErr as the
//     AAK ErrCode/ErrMsg
//
// Strict-mode rejects log unconditionally (the audit primitive).
// Permit-mode logs sample at 1/permitModeLogSampleMod with a
// sync.Once first-anchor.
func (s *UdpServer) applyACPubkeyRevokeVerdict(
	verdict acPubkeyRevokeVerdict,
	acId string,
	presentedPubkey string,
	transactionId uint64,
	addrStr string,
) (bool, *common.Error) {
	switch verdict {
	case verdictACPubkeyRevokeOK:
		return true, nil
	case verdictACPubkeyRevokeRevoked:
		s.metrics.IncrCounter(MetricACPubkeyRevoked)
		if s.acPubkeyRevokeVerifyRequire {
			log.Warning("server-ac(%s#%d@%s)[ACPubkeyRevoked] revoked pubkey rejected under strict mode; pubkey=%s... (see #1507)",
				acId, transactionId, addrStr, pubkeyLogPrefix(presentedPubkey))
			return false, common.ErrACPubkeyRevoked
		}
		if shouldSamplePermitLog(transactionId) {
			log.Warning("server-ac(%s#%d@%s)[ACPubkeyRevoked] revoked pubkey permitted (sample 1/%d); pubkey=%s... (page-worthy in strict — see #1507)",
				acId, transactionId, addrStr, permitModeLogSampleMod, pubkeyLogPrefix(presentedPubkey))
		} else {
			firstPermitACPubkeyRevokeLog.Do(func() {
				log.Warning("server-ac(%s#%d@%s)[ACPubkeyRevoked] revoked pubkey permitted (per-process forensic anchor; non-anchor occurrences sampled at 1/permitModeLogSampleMod); pubkey=%s... (see #1507)",
					acId, transactionId, addrStr, pubkeyLogPrefix(presentedPubkey))
			})
		}
		return true, nil
	}
	// Fail-closed default. Same pattern as the other gates: a future
	// PR that adds a new verdict constant and forgets to register
	// it here rejects with ErrACPubkeyRevokedInternal so the agent
	// log doesn't blame revocation for what is actually a server-
	// side dispatch-table bug. The metric is the paging primitive —
	// a non-zero rate is the dispatch-bug signal independent of
	// log scraping.
	//
	// Permit-mode asymmetry by design: this branch rejects fail-
	// closed even when acPubkeyRevokeVerifyRequire == false. Permit
	// mode is "don't reject on a *known* verdict that says the
	// pubkey is revoked"; an unknown verdict is a server bug, not a
	// policy decision, and rejecting it surfaces the bug rather
	// than silently accepting the registration with the wrong code
	// path having run.
	s.metrics.IncrCounter(MetricACPubkeyRevokeGateBug)
	log.Error("server-ac(%s#%d@%s)[ACPubkeyRevoked] [GATE_UNKNOWN_VERDICT] verdict=%d rejecting fail-closed (fired %s)",
		acId, transactionId, addrStr, verdict, MetricACPubkeyRevokeGateBug)
	return false, common.ErrACPubkeyRevokedInternal
}

// evaluateACPubkeyRevokeVerdict performs the storage lookup half of
// the F5 gate. Mirrors evaluateACIDCustomerVerdict's shape for F4.
// NotFound is treated as OK (no assignment → no revocations); a
// transient error fires MetricACPubkeyRevokedLookupErr + returns OK
// (skip the gate) — see package doc for the storage-error policy.
//
// Cache-warming side effect: F5 runs before F4
// (evaluateACIDCustomerVerdict inside validateACLicense), warming
// the CachedStorage entry F4 then reads. Do NOT consolidate the
// two lookups into a shared-result pattern — that would couple
// the gates' control flow and make individual deletion harder.
func (s *UdpServer) evaluateACPubkeyRevokeVerdict(
	ctx context.Context,
	acId string,
	presentedPubkey string,
	transactionId uint64,
	addrStr string,
) acPubkeyRevokeVerdict {
	if s.storage == nil {
		return verdictACPubkeyRevokeOK
	}
	assignment, err := s.storage.GetACAssignment(ctx, acId)
	if err != nil {
		if IsNotFoundError(err) {
			return verdictACPubkeyRevokeOK
		}
		// Transient error: degrade to skip-the-gate + lookup-err
		// counter. Strict mode does NOT escalate — see package doc.
		s.metrics.IncrCounter(MetricACPubkeyRevokedLookupErr)
		// Log sampling: an unsampled Warning per AOL would flood the
		// log stream during a DDB throughput-exceeded flap on a
		// high-rate fleet. Mirrors permit-mode pattern: sync.Once
		// first-anchor + 1/permitModeLogSampleMod sampling. Operators
		// alarm on the metric; the log is the forensic supplement.
		if shouldSamplePermitLog(transactionId) {
			log.Warning("server-ac(%s#%d@%s)[ACPubkeyRevoked] ACAssignment lookup failed: %v (skipping gate, sample 1/%d, fired %s)",
				acId, transactionId, addrStr, err, permitModeLogSampleMod, MetricACPubkeyRevokedLookupErr)
		} else {
			firstLookupErrLog.Do(func() {
				log.Warning("server-ac(%s#%d@%s)[ACPubkeyRevoked] ACAssignment lookup failed: %v (skipping gate, per-process forensic anchor; non-anchor sampled at 1/%d; fired %s)",
					acId, transactionId, addrStr, err, permitModeLogSampleMod, MetricACPubkeyRevokedLookupErr)
			})
		}
		return verdictACPubkeyRevokeOK
	}
	// Defense against backend (nil, nil) contract violations — skip
	// rather than nil-deref.
	if assignment == nil {
		return verdictACPubkeyRevokeOK
	}
	if len(assignment.RevokedPubKeys) >= acPubkeyRevokeListLengthWarn {
		// Counter fires every observation across all acIds (standing
		// dashboard signal — survives an early-process anchor consumed
		// by a different acId).
		s.metrics.IncrCounter(MetricACPubkeyRevokeListOversize)
		// Log fires once per process as a forensic anchor; operators
		// alarm on the metric, not the log.
		firstLongRevokeListLog.Do(func() {
			log.Warning("server-ac(%s#%d@%s)[ACPubkeyRevoked] revoked-pubkey list length %d — operator workflow is one-pubkey-at-a-time, license-wide kills should use License.Active=false (per-process forensic anchor; alarm on %s; see #1507, #1547)",
				acId, transactionId, addrStr, len(assignment.RevokedPubKeys), MetricACPubkeyRevokeListOversize)
		})
	}
	return verifyACPubkeyRevoked(presentedPubkey, assignment.RevokedPubKeys)
}
