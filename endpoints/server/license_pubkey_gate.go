package server

import (
	"strings"
	"sync"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// License pubkey binding gate (#1155).
//
// Pre-#1155 the License record was a bearer token: an AC that
// presented a valid license key was accepted under any claimed acId
// with an attacker-chosen keypair, landed in acConnectionMap[acId],
// and received every subsequent NHP_AOP (plaintext access graph) for
// that acId. A leaked or stolen license key therefore acted as full
// access — any holder could impersonate any customer's AC. Full
// attack walkthrough in https://github.com/layervai/nhp/issues/1155.
//
// The fix bolts identity onto the license: License.BoundPubKeys
// carries an allowlist of base64-encoded AC static pubkeys permitted
// to register under that license. The gate below runs AFTER
// validateACLicense has confirmed the license key + bcrypt + active
// + expiry; it then compares the AEAD-authenticated peer pubkey
// (ppd.RemotePubKey, extracted by the noise handshake in
// responder.go) against the allowlist.
//
// Rollout is the permit→strict pattern we use across security gates
// (#1122 HMAC, #1154 HeaderType, #1156 ARD allowlist).
// NHP_LICENSE_PUBKEY_VERIFY defaults to false (permit). Permit mode
// logs and counts unbound and mismatch verdicts but accepts the
// registration so existing unprovisioned licenses keep working;
// operators watch the rollout counter drain before flipping strict.
// Strict mode rejects the registration.
//
// Scope: the gate covers only the UDP NHP_AOL handler
// (HandleACOnline → validateACLicense). It does NOT cover the
// HTTP /plugins path — HTTP endpoints terminate TLS + authenticate
// via JWT/Auth0, which is an independent identity binding. If the
// HTTP path ever grows a code route that provisions AC connections
// from an NHP license, the gate needs to be plugged into that path
// too.
//
// Provisioning expectation: BoundPubKeys is expected to be populated
// at license-issuance time by the console / admin tooling (separate
// workstream). For existing licenses, an operator will need to run a
// one-shot migration before flipping strict — the permit-mode
// MetricLicensePubkeyUnbound counter is the "how many licenses still
// need provisioning" gauge.
//
// Alarm-semantics caveat (mirrors #1154): when BoundPubKeys is empty
// for a given license, an attacker presenting a stolen license key
// with any pubkey lands in verdictUnbound, NOT verdictMismatch. The
// mismatch counter stays at zero under active attack as long as the
// victim's license hasn't been provisioned. Strict mode eliminates
// the ambiguity by rejecting unbound licenses outright. The
// MetricLicensePubkeyUnbound counter must drain to zero BEFORE
// flipping strict — both to avoid locking out legitimate unprovisioned
// licenses and to make MetricLicensePubkeyMismatch trustworthy as a
// per-attack signal.
//
// Permit-mode rate-limiting posture: the existing
// s.recordLicenseFailure rate limiter only fires on strict-mode
// rejects (proceed=false). In permit mode a single attacker with a
// valid license key + N attacker pubkeys can increment
// MetricLicensePubkeyMismatch without tripping the per-IP / per-AC
// failure cap. This is intentional — rate-limiting a permit-mode
// reject-that-still-accepts would change the observable behavior
// and break the "permit preserves pre-fix behavior" contract. When
// setting up alarms on MetricLicensePubkeyMismatch during burn-in,
// configure them on the ratio (mismatch / total registrations),
// not on the raw counter rate, so a probing attacker can't trigger
// false alarms that noise out the real signal. After flipping
// strict, the rate limiter re-engages because rejects become
// proceed=false.
//
// Attacker-controlled trxId vs sampling: the permit-mode
// Warning/Info sampling uses trxId % N, but trxId is attacker-
// chosen (the agent's NextCounterIndex increments locally per
// session, and a MitM/forged agent can pick any value). An
// adversary pacing flips against the modulus can keep the Warning
// stream dry. This does NOT defeat detection — metrics fire
// unconditionally on every verdict and ARE the trusted alarm
// surface. The sync.Once first-per-process anchor gives one
// forensic Warning per verdict regardless of sampling. Treat logs
// as secondary forensic anchors in permit mode; the metric is
// load-bearing.
//
// Key-rotation ops trap (post-strict-flip): when rotating an AC's
// static keypair, update License.BoundPubKeys to include the new
// pubkey BEFORE flipping the AC to use it — not after. Reversing
// the order means the AC registers under the new pubkey, misses
// the allowlist, and lands in verdictLicenseMismatch → every
// legitimate retry increments recordLicenseFailure and eventually
// the AC rate-limits itself out until the limiter window clears.
// Operators reading the strict-mode mismatch counter would see
// exactly the same signal as an actual attack. Correct rotation
// order MUST be codified in the rollout runbook alongside the
// unbound-counter-drains-before-flipping-strict precondition. Both
// are now documented (#1262):
// docs/runbooks/license-pubkey-strict-flip.md. Provisioning is done
// with the nhp-license-admin CLI (endpoints/licenseadmin/main), which
// enforces the canonical-encoding contract at write time.
//
// Metric mode-semantics (runbook concern):
// MetricLicensePubkeyUnbound means different things in each mode —
// during permit it's "licenses still missing BoundPubKeys
// (rollout incomplete)"; after flipping strict it's "rejected
// registrations (every AC with an unprovisioned license gets
// locked out until admin provisions it)". Alerting rules that
// were valid pre-flip need to be re-anchored post-flip: the
// threshold that meant "still migrating" during permit means
// "legitimate ACs being rejected" during strict. Same counter,
// opposite actionability.
//
// Strict-mode log-flood risk (premature flip):
// verdictLicenseUnbound and verdictLicenseMismatch both emit an
// unsampled log.Warning per-reject in strict mode — deliberate
// because per-reject visibility is what operators want once
// strict is in force. But if strict is flipped before
// MetricLicensePubkeyUnbound drains to zero, every legitimate
// unprovisioned AC retry will write a full Warning line, and the
// log stream can flood within minutes. The pre-flip drain-to-zero
// check is the primary defense; a secondary one would be per-AC
// log dedupe, which is deferred — see the rollout runbook
// precondition check instead of papering over the symptom in the
// gate itself.

// LicensePubkeyVerifyEnvVar gates the strict-mode reject. Accepts
// the same truthy/falsy tokens as NHP_KNOCK_HEADERTYPE_VERIFY so the
// operator mental model stays uniform across gates.
const LicensePubkeyVerifyEnvVar = "NHP_LICENSE_PUBKEY_VERIFY"

// Metric constants. MetricLicensePubkeyMismatch fires once per
// AC registration where the presented pubkey is absent from a
// non-empty BoundPubKeys allowlist — that's the #1155 attack
// signature (stolen license + attacker keypair). Page-worthy in
// strict mode; worth watching in permit mode.
//
// MetricLicensePubkeyUnbound fires when BoundPubKeys is empty,
// which is the zero-value signal that the license record was never
// provisioned with an expected pubkey. A non-zero rate in permit
// mode is the rollout signal; it must drop to zero before flipping
// strict or legitimate unprovisioned licenses will be locked out.
const (
	MetricLicensePubkeyMismatch = "LicensePubkeyMismatch"
	MetricLicensePubkeyUnbound  = "LicensePubkeyUnbound"
)

// licensePubkeyVerdict captures what verifyLicensePubkey recommends
// the caller do with an incoming AC registration.
type licensePubkeyVerdict int

const (
	// Leave iota=0 unnamed on purpose so the Go zero-value of
	// licensePubkeyVerdict does NOT map to any named constant.
	// An uninitialized verdict falls through to the switch
	// default in applyLicensePubkeyVerdict, which rejects
	// fail-closed with ErrLicensePubkeyInternal. Without this
	// shift, verdictLicenseOK would be the zero value and an
	// uninitialized verdict would silently accept. Mirrors the
	// #1154 gate's structural fail-closed pattern.
	_ licensePubkeyVerdict = iota
	// verdictLicenseOK: presented pubkey is in the (non-empty)
	// allowlist. Accept unconditionally.
	verdictLicenseOK
	// verdictLicenseUnbound: BoundPubKeys is empty (unprovisioned).
	// Permit mode accepts with legacy warning; strict rejects.
	verdictLicenseUnbound
	// verdictLicenseMismatch: BoundPubKeys is non-empty and does
	// NOT contain the presented pubkey (the #1155 attack signature).
	// Permit mode logs + metric and accepts (pre-fix behavior so
	// rollout is non-breaking); strict mode rejects.
	verdictLicenseMismatch
)

// firstPermitLicenseUnboundLog and firstPermitLicenseMismatchLog
// guarantee at least one forensic anchor per process for each
// verdict, independent of the trxId-modulus sampling — same
// rationale as knock_headertype_gate.go. Fresh deploys with
// trxIds 1..99 would otherwise produce zero log lines for the
// first legitimate unbound license or the first attack; the
// metric still fires, but operators want log text to correlate.
//
// Shared testability hazard with the #1154 pair: these are
// package-level sync.Once so whichever test runs first consumes
// the guard. No test today inspects the anchor emissions, so it's
// not a live problem; if a future test asserts "first emit fires,"
// move these onto UdpServer.
var (
	firstPermitLicenseUnboundLog  sync.Once
	firstPermitLicenseMismatchLog sync.Once
)

// parseLicensePubkeyVerify decodes NHP_LICENSE_PUBKEY_VERIFY.
// Thin wrapper around parsePermitStrictEnv so every gate across
// the server uses one token grammar — see parsePermitStrictEnv's
// docstring for the accepted set and the fail-closed-on-typo
// rationale.
func parseLicensePubkeyVerify(raw string) (bool, error) {
	return parsePermitStrictEnv(raw)
}

// verifyLicensePubkey is the pure policy kernel. Given the peer's
// presented pubkey and the License.BoundPubKeys allowlist, it
// returns the verdict.
//
// Separating kernel from side-effect wrapper (applyLicensePubkey-
// Verdict) makes the policy table unit-testable without a UdpServer
// — mirrors verifyKnockHeaderType in knock_headertype_gate.go.
//
// The kernel does NOT consult the strict flag. Strict-vs-permit
// decides only WHAT to DO with a given verdict (reject vs log);
// the verdict itself is purely "what does the data say?" This
// separation means a future refactor that adds reporting /
// shadow-mode / audit-only wouldn't need to change the kernel.
//
// A caller that constructs this function with empty presented
// pubkey would get verdictLicenseMismatch (or Unbound if the
// allowlist is also empty). validateACLicense never actually
// invokes it with an empty pubkey today because ppd.RemotePubKey
// is set by the noise handshake before the handler runs, but the
// kernel stays defensive: empty-vs-empty should NEVER match as OK.
func verifyLicensePubkey(presented string, allow []string) licensePubkeyVerdict {
	if len(allow) == 0 {
		return verdictLicenseUnbound
	}
	// TrimSpace on BOTH sides is defense-in-depth against the
	// canonical-encoding contract documented on License.BoundPubKeys.
	// Admin tooling is expected to enforce "no leading/trailing
	// whitespace" at write-time (#1262), but an operator pasting a
	// pubkey from a terminal / CI logs / Slack can easily end up with
	// a trailing \n that would silently convert a legitimate AC into
	// a verdictLicenseMismatch (indistinguishable from attack). The
	// presented value comes from base64.StdEncoding.EncodeToString
	// which doesn't produce whitespace, but symmetric trim keeps the
	// kernel contract explicit: whitespace doesn't participate in
	// identity comparison.
	//
	// NOT normalized: URL-safe vs std base64, padded vs unpadded —
	// those are genuine format divergences that admin tooling must
	// catch. Fixing them at kernel-read time would hide a bug in the
	// provisioning path, not a typo in the data.
	presentedTrim := strings.TrimSpace(presented)
	// presented="" with a non-empty allow list is a mismatch: a
	// zero pubkey cannot appear in a legitimate allowlist (ECDH
	// keys are 32 non-zero bytes, base64-encoded). Defense in
	// depth against a future caller that forgets to populate
	// presented.
	if presentedTrim == "" {
		return verdictLicenseMismatch
	}
	for _, entry := range allow {
		if strings.TrimSpace(entry) == presentedTrim {
			return verdictLicenseOK
		}
	}
	return verdictLicenseMismatch
}

// applyLicensePubkeyVerdict is the side-effect side of the policy
// — centralizes metric + log emission AND the reject-error
// selection so the switch statement is the single source of truth
// for both "proceed?" and "which error?" Mirrors
// applyKnockHeaderTypeVerdict in knock_headertype_gate.go.
//
// Returns (proceed, rejectErr):
//   - (true, nil) — caller proceeds, gate accepted the registration
//   - (false, rejectErr) — caller aborts with rejectErr as the
//     AAK ErrCode/ErrMsg
//
// Permit-mode logs are sampled at 1/permitModeLogSampleMod (shared
// constant with the #1154 gate) to survive an attack flood without
// drowning the log stream; metrics fire unconditionally.
func (s *UdpServer) applyLicensePubkeyVerdict(
	verdict licensePubkeyVerdict,
	acId string,
	presentedBase64 string,
	transactionId uint64,
	addrStr string,
	keyPrefix string,
) (bool, *common.Error) {
	switch verdict {
	case verdictLicenseOK:
		return true, nil
	case verdictLicenseUnbound:
		// No nil-guard on s.metrics: UdpServer.metrics is initialized
		// by NewUdpServer at startup and applyKnockHeaderTypeVerdict
		// already assumes the invariant. Test helpers mirror the
		// production invariant — see testServer /
		// testServerWithRateLimiter wiring metrics via
		// metrics.NewPublisherForTest. Same at verdictLicenseMismatch.
		s.metrics.IncrCounter(MetricLicensePubkeyUnbound)
		if s.licensePubkeyVerifyRequire {
			log.Warning("server-ac(%s#%d@%s)[LicensePubkey] unbound license rejected under strict mode; key=%s...; pubkey=%s... (provision BoundPubKeys)",
				acId, transactionId, addrStr, keyPrefix, pubkeyLogPrefix(presentedBase64))
			return false, common.ErrLicensePubkeyUnbound
		}
		// Info (not Warning) in permit mode: unbound licenses are
		// the expected rollout signal, not an attack indicator.
		// Permit+mismatch stays at Warning because that IS an
		// attack signature.
		//
		// Include the presented pubkey even on the permit-mode /
		// unbound / Info path: the documented alarm-semantics
		// caveat is that an attacker presenting a stolen license
		// with any pubkey lands HERE (verdictUnbound), not in
		// verdictMismatch, as long as BoundPubKeys is empty.
		// Post-incident forensics need the attacker pubkey captured
		// in at least sampled/anchor log lines so retrospective
		// correlation is possible during the permit-mode burn-in.
		if shouldSamplePermitLog(transactionId) {
			log.Info("server-ac(%s#%d@%s)[LicensePubkey] unbound license permitted; key=%s...; pubkey=%s... (sample 1/%d; flip strict when unbound=0)",
				acId, transactionId, addrStr, keyPrefix, pubkeyLogPrefix(presentedBase64), permitModeLogSampleMod)
		} else {
			firstPermitLicenseUnboundLog.Do(func() {
				log.Info("server-ac(%s#%d@%s)[LicensePubkey] unbound license permitted; key=%s...; pubkey=%s... (first-per-process anchor; sampled thereafter)",
					acId, transactionId, addrStr, keyPrefix, pubkeyLogPrefix(presentedBase64))
			})
		}
		return true, nil
	case verdictLicenseMismatch:
		s.metrics.IncrCounter(MetricLicensePubkeyMismatch)
		if s.licensePubkeyVerifyRequire {
			// Log format mirrors knock_headertype_gate.go: semicolon-
			// separates descriptor clauses so operators grepping
			// [LicensePubkey] alongside [HeaderType] see consistent
			// parsing.
			log.Warning("server-ac(%s#%d@%s)[LicensePubkey] pubkey mismatch rejected under strict mode; key=%s...; pubkey=%s... (see #1155)",
				acId, transactionId, addrStr, keyPrefix, pubkeyLogPrefix(presentedBase64))
			return false, common.ErrLicensePubkeyMismatch
		}
		if shouldSamplePermitLog(transactionId) {
			log.Warning("server-ac(%s#%d@%s)[LicensePubkey] pubkey mismatch permitted; key=%s...; pubkey=%s... (sample 1/%d; page-worthy in strict — see #1155)",
				acId, transactionId, addrStr, keyPrefix, pubkeyLogPrefix(presentedBase64), permitModeLogSampleMod)
		} else {
			firstPermitLicenseMismatchLog.Do(func() {
				log.Warning("server-ac(%s#%d@%s)[LicensePubkey] pubkey mismatch permitted; key=%s...; pubkey=%s... (first-per-process anchor; sampled thereafter — see #1155)",
					acId, transactionId, addrStr, keyPrefix, pubkeyLogPrefix(presentedBase64))
			})
		}
		return true, nil
	}
	// Fail-closed default. Same pattern as
	// applyKnockHeaderTypeVerdict: a future PR that adds a new
	// verdict constant and forgets to register it here will reject
	// with ErrLicensePubkeyInternal (52014) — distinct from the
	// mismatch (52012) and unbound (52013) codes so the agent log
	// doesn't blame the license for what is actually a server-side
	// dispatch-table bug.
	log.Error("server-ac(%s#%d@%s)[LicensePubkey] [GATE_UNKNOWN_VERDICT] verdict=%d rejecting fail-closed",
		acId, transactionId, addrStr, verdict)
	return false, common.ErrLicensePubkeyInternal
}

// pubkeyLogPrefix returns a short, safe-to-log form of a base64
// pubkey for correlation. Full pubkeys are public (they ride on
// the wire), so truncation is an ops-UX nicety rather than a
// confidentiality boundary — 12 chars is enough to disambiguate in
// practice while keeping log lines readable. Returns "<empty>"
// instead of an empty string so grep-friendly log scans don't
// silently match non-log lines.
func pubkeyLogPrefix(pk string) string {
	if pk == "" {
		return "<empty>"
	}
	if len(pk) > 12 {
		return pk[:12]
	}
	return pk
}
