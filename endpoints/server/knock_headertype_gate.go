package server

import (
	"sync"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// firstPermitLegacyLog and firstPermitMismatchLog guarantee at
// least one forensic anchor Warning/Info line per process for
// each verdict, independent of the trxId-modulus sampling. Fresh
// deploys with trxIds 1..99 would otherwise produce zero log
// lines for the first legitimate legacy agent or the first
// attack — the metric still fires, but an operator staring at
// dashboards has no log text to correlate. These fire exactly
// once per process (reset on restart).
//
// Testability hazard: these are package-level sync.Once so
// whichever test runs first consumes the guard. No test today
// inspects log output so this isn't a live problem, but if a
// future test asserts "first emit fires," either (a) move these
// onto UdpServer so each test gets its own, or (b) add a
// test-only reset hook under a build tag.
var (
	firstPermitLegacyLog   sync.Once
	firstPermitMismatchLog sync.Once
)

// Knock HeaderType verify gate (#1154).
//
// Pre-#1154 the server trusted the unauthenticated wire HeaderType
// byte to decide whether an incoming knock was an open
// (NHP_KNK / NHP_RKN) or a close (NHP_EXT). Because the wire
// HeaderType is not mixed into the noise chain-hash and the trailing
// "HMAC" slot is an unkeyed BLAKE2s salted with
// initialHashBytes || rs_pub (both public), a MitM could flip
// NHP_KNK → NHP_EXT on the wire, recompute the unkeyed hash, and
// cause the server to emit NHP_AOP with openTime=1 — revoking the
// victim's access without any crypto break. Full attack walkthrough
// in https://github.com/layervai/nhp/issues/1154.
//
// The fix does NOT change the wire format or the noise crypto. The
// agent now mirrors the wire HeaderType inside the AEAD-encrypted
// body (AgentKnockMsg.HeaderType). The server compares body and
// wire and rejects mismatches. The body sits inside the
// chain-hash-authenticated AEAD payload, so an attacker cannot
// flip it without the initiator's static private key.
//
// Rollout is the same permit→strict pattern as the #1122 HMAC gate
// and the #1156 ARD allowlist. NHP_KNOCK_HEADERTYPE_VERIFY defaults
// to false (permit). Permit mode logs mismatches at Warning and
// emits the mismatch counter but still processes the knock using
// the wire header — operators verify the permit-metric stays at
// zero across a deploy cycle before flipping strict. Strict mode
// rejects the knock and emits the strict-reject counter. Legacy
// agents that predate the body-HeaderType populate zero; the
// legacy counter tracks their rollout.
//
// Scope: the gate covers only the UDP wire path via
// HandleKnockRequest. The HTTP path at handleHttpOpenResource
// synthesizes knkMsg.HeaderType = NHP_EXT from an already-
// authenticated JWT request (req.Command == "exit"), so there's
// no wire-header vs body-header comparison to make. The #1154
// threat model is UDP-only — don't extend the gate to HTTP without
// also changing the shape of what it verifies.
//
// DHP knocks (DHP_KNK wire type) don't populate AgentKnockMsg
// because they carry DHPKnockMsg, which doesn't have a HeaderType
// field. A MitM flipping wire DHP_KNK → NHP_EXT would land in the
// non-DHP parse branch, decode the DHPKnockMsg bytes as
// AgentKnockMsg (producing body.HeaderType=0 and body.AuthServiceId=""),
// and hit the gate as verdictLegacy. In permit mode the gate
// proceeds with wireType=NHP_EXT, but FindAuthSvcProvider("")
// rejects the knock before any NHP_AOP broadcast — the DHP→NHP
// flip is self-limiting at the ASP lookup, not at this gate.
// If DHPKnockMsg ever grows an overlapping JSON field that would
// let the flipped packet survive the ASP lookup, revisit this
// scope note.
//
// Server-to-server forwarding (NHP_FWD receiver in forward.go)
// parses an AgentKnockMsg from the re-decrypted inner packet but
// does NOT re-apply this gate. The invariant that keeps this safe
// is STRONGER than "ignore the wire side": the forward receiver
// consults NEITHER knkMsg.HeaderType NOR knockPpd.HeaderType for
// the openTime decision (see forward.go — openTime is sourced from
// resData.OpenTime). Any future refactor that ADDS consumption of
// either header (e.g., porting the NHP_EXT → openTime=1 short-
// circuit from the local path to the forward path) must re-apply
// this gate against the inner knockPpd.HeaderType + knkMsg.HeaderType
// pair. See follow-up #1250 for the defense-in-depth addition.
//
// Consequence for permit-mode rollout: an attacker-flipped knock
// in permit mode behaves ASYMMETRICALLY between local and
// forwarded AC paths —
//
//   - local AC:      openTime=1 may fire (attacker-flipped wire
//                    value is consulted in udpserver.go).
//   - forwarded AC:  openTime = resData.OpenTime; the attacker
//                    flip is ignored entirely because the forward
//                    path doesn't consult HeaderType.
//
// This asymmetry is not a security bug (both paths fix at strict),
// but it's the kind of thing an operator reading dashboards should
// know about. Strict mode eliminates it by rejecting mismatches at
// the ingress server before they can diverge.
//
// Additional alarm-semantics caveat: when body.HeaderType is zero
// (legacy agent), a MitM flipping wire NHP_KNK → NHP_EXT is
// indistinguishable from a legitimate NHP_EXT. The gate classifies
// both as verdictLegacy, and MetricKnockHeaderTypeMismatch stays
// at zero. During a burn-in where the fleet is still majority-
// legacy, an operator watching only the mismatch counter would
// see zero under active attack. This is why
// MetricKnockHeaderTypeLegacy must drain to zero BEFORE flipping
// strict — not just for operator UX, but to make the mismatch
// counter trustworthy as a per-attack signal. The #1257 flip
// tracker spells this out in the burn-in checklist.

// KnockHeaderTypeVerifyEnvVar gates the strict-mode reject. Accepts
// the same truthy/falsy tokens as NHP_INTERNAL_AUTH_REQUIRE so the
// operator mental model stays uniform across gates.
const KnockHeaderTypeVerifyEnvVar = "NHP_KNOCK_HEADERTYPE_VERIFY"

// Metric constants. MetricKnockHeaderTypeMismatch fires once per
// incoming knock where the AEAD-authenticated body.HeaderType
// differs from the wire HeaderType — that's the #1154 attack
// signature (or, much less likely, a client bug). Page-worthy in
// strict mode; worth watching in permit mode.
//
// MetricKnockHeaderTypeLegacy fires when body.HeaderType is zero
// (NHP_KPL), which is the zero-value signal that the client predates
// this fix. A non-zero rate in permit mode is the rollout signal;
// it must drop to zero before flipping strict or legitimate legacy
// agents will be locked out.
const (
	MetricKnockHeaderTypeMismatch = "KnockHeaderTypeMismatch"
	MetricKnockHeaderTypeLegacy   = "KnockHeaderTypeLegacy"
)

// knockHeaderTypeVerdict captures what verifyKnockHeaderType
// recommends the caller do with an incoming knock.
type knockHeaderTypeVerdict int

const (
	// Leave iota=0 unnamed on purpose so the Go zero-value of
	// `knockHeaderTypeVerdict` does NOT map to any named
	// constant. An uninitialized verdict (e.g. struct field or
	// channel default) falls through to the switch default in
	// applyKnockHeaderTypeVerdict, which rejects fail-closed
	// with ErrKnockHeaderTypeInternal. Without this shift,
	// verdictOK would be the zero value and an uninitialized
	// verdict would silently accept.
	_ knockHeaderTypeVerdict = iota
	// verdictOK: body and wire agree; use the body value (authenticated).
	verdictOK
	// verdictLegacy: body HeaderType is zero (legacy agent). Permit
	// mode falls back to the wire value; strict mode rejects.
	verdictLegacy
	// verdictMismatch: body and wire disagree (the #1154 attack
	// signature). Permit mode logs + metric and still uses the wire
	// value (pre-fix behavior so rollout is non-breaking); strict
	// mode rejects.
	verdictMismatch
)

// parseKnockHeaderTypeVerify decodes NHP_KNOCK_HEADERTYPE_VERIFY.
// Thin wrapper around parsePermitStrictEnv so this gate and
// NHP_INTERNAL_AUTH_REQUIRE share one token grammar — see
// parsePermitStrictEnv's docstring for the accepted set and the
// fail-closed-on-typo rationale.
func parseKnockHeaderTypeVerify(raw string) (bool, error) {
	return parsePermitStrictEnv(raw)
}

// verifyKnockHeaderType is the pure policy kernel. Given the body
// and wire HeaderType values plus the strict flag, it returns the
// verdict and the HeaderType the caller should use going forward.
//
// The returned `use` value matters only when the caller proceeds
// (i.e., applyKnockHeaderTypeVerdict returns proceed=true). On
// reject paths the returned value is whatever the kernel happened
// to have available — callers MUST NOT consume `use` after an
// observed rejection. Today nhpauth.go writes
// `knkMsg.HeaderType = useType` only after the `if !proceed`
// guard, so the ordering is safe; a refactor that moves the
// assignment above the guard would zero or otherwise corrupt
// the caller's state.
//
// The per-verdict table below enumerates which combinations
// reject and which continue. The consistent rule across the
// proceed paths: strict trusts the authenticated body value,
// permit preserves the pre-fix wire behavior. Reject paths
// return whatever was convenient; callers honor the "don't
// consume on reject" contract above.
//   - verdictOK → use body value (equal to wire, so either is fine)
//   - verdictLegacy + permit → use wire value (pre-fix behavior)
//   - verdictLegacy + strict → caller rejects; returned value unused
//   - verdictMismatch + permit → use wire value (pre-fix behavior,
//     preserves rollout compat)
//   - verdictMismatch + strict → caller rejects; returned value unused
//
// The body-zero check fires BEFORE the body==wire equality check,
// so `bodyType==KPL && wireType==KPL` falls into verdictLegacy (not
// verdictOK) regardless of whether the upstream dispatcher rejects
// raw NHP_KPL packets. That ordering keeps the policy uniform even
// if a future refactor loosens the upstream gate — the zero-value
// body is ALWAYS interpreted as "legacy agent," never as a real
// headerType.
func verifyKnockHeaderType(bodyType, wireType int, strict bool) (use int, verdict knockHeaderTypeVerdict) {
	// NHP_KPL is the first iota value (= 0), which is also the Go
	// zero-value a legacy agent emits because it doesn't populate
	// the field. The wire-level dispatcher rejects raw NHP_KPL
	// packets, so this can only mean "legacy agent."
	if bodyType == core.NHP_KPL {
		if strict {
			return bodyType, verdictLegacy
		}
		return wireType, verdictLegacy
	}
	if bodyType == wireType {
		return bodyType, verdictOK
	}
	if strict {
		return bodyType, verdictMismatch
	}
	return wireType, verdictMismatch
}

// permitModeLogSampleMod is the sampling modulus for per-target
// Warning logs in permit mode. Under a sustained attack flood
// (MitM flipping every knock), a 1-to-1 log-per-knock rate would
// flood the Warning stream without adding information — the metric
// counter is the actual attack signal. One Warning per N knocks
// preserves enough anchor lines for forensics while capping the
// log volume. Strict mode logs every reject (the whole point).
//
// Sampling is deterministic: NHP agents allocate TrxIds from an
// atomic counter per device session (see Device.NextCounterIndex
// in nhp/core/device.go — returns AFTER atomic increment, so the
// first allocation is 1, never 0). `trxId % N == 0` therefore
// yields exactly 1/N of an agent session's knocks sampled,
// starting at trxId=N (not trxId=0). For a flood of 100k knocks
// from one agent the modulus emits 1000 sampled lines — enough
// for forensics, small enough not to dominate the log stream.
//
// Two consequences a future reader should know about:
//
//   - An attacker pacing flips against the counter (suppressing
//     flips on sampled indices) can keep the Warning stream dry.
//     This does NOT defeat detection: the metric counter
//     increments unconditionally on every mismatch and IS the
//     trusted alarm surface. Log lines are forensic anchors only.
//
//   - A very brief attack (fewer than permitModeLogSampleMod
//     knocks from a fresh session) may produce zero log lines
//     while the metric still fires. Same posture as above — the
//     metric is the signal, the log is auxiliary.
const permitModeLogSampleMod = 100

// shouldSamplePermitLog reports whether a given transaction ID
// should land in the sampled Warning/Info stream. Extracted into
// its own function so the modulus arithmetic is unit-testable
// without capturing log output. A trxId==0 input is unreachable
// in practice (NextCounterIndex starts at 1) but the function
// still handles it correctly: 0 % N == 0 means "log the first
// attempt" — a benign overstate if ever reached.
//
// Distribution note: transaction IDs come from a monotonic
// counter (NextCounterIndex / atomic.AddUint64), so the
// trxId-mod-N sampling slot is uniform under any monotonically-
// increasing source — every Nth transaction across the whole
// process samples regardless of which AC, which gate, or which
// header type produced it. A pathological case where one AC's
// trxIDs always landed on non-sample slots would require that
// AC's trxIDs to be aligned to N's complement (N=100, txIDs
// always ≡ {1..99}), which can't happen with a global monotonic
// counter. The per-process sync.Once anchors (firstPermitAC*,
// firstLookupErrLog) bound the worst case at "at least one entry
// per process per gate." If permitModeLogSampleMod ever moves
// off a global counter to a per-AC source, revisit.
//
// The previous revision of this function had an explicit guard
// against permitModeLogSampleMod==0 (divide-by-zero). A reviewer
// correctly noted that with a compile-time constant the guard is
// dead code by construction; removed in favor of trusting the
// const. If the modulus ever needs to be runtime-tunable, reintroduce
// the guard along with the tuning plumbing.
func shouldSamplePermitLog(transactionId uint64) bool {
	return transactionId%permitModeLogSampleMod == 0
}

// applyKnockHeaderTypeVerdict is the side-effect side of the
// policy — it centralizes the metric + log emission AND the
// reject-error selection so the switch statement is the single
// source of truth for both "proceed?" and "which error?"
//
// Returns (proceed, rejectErr):
//   - (true, nil) — caller proceeds, gate accepted the knock
//   - (false, rejectErr) — caller aborts with rejectErr as the
//     ack ErrCode/ErrMsg
//
// The log lines include the transaction ID + peer address so an
// operator correlating a page-worthy counter can find the packet in
// the wire log. HeaderType values are formatted via
// core.HeaderTypeToString for readability (NHP-KNK vs raw integer).
// Permit-mode logs are sampled at 1/permitModeLogSampleMod to
// survive an attack flood without drowning the log stream; metrics
// fire unconditionally so the signal is intact.
func (s *UdpServer) applyKnockHeaderTypeVerdict(verdict knockHeaderTypeVerdict, bodyType, wireType int, transactionId uint64, addrStr string) (bool, *common.Error) {
	switch verdict {
	case verdictOK:
		return true, nil
	case verdictLegacy:
		s.metrics.IncrCounter(MetricKnockHeaderTypeLegacy)
		if s.knockHeaderTypeVerifyRequire {
			log.Warning("server-agent(#%d@%s)[HeaderType] legacy body (zero) rejected under strict mode; wire=%s",
				transactionId, addrStr, core.HeaderTypeToString(wireType))
			return false, common.ErrKnockHeaderTypeLegacy
		}
		// Info (not Warning) in permit mode: legacy knocks are the
		// expected signal during rollout, not an attack indicator.
		// The metric is the signal; the log line just gives an
		// operator a transaction ID to chase when investigating a
		// specific agent. Permit+mismatch stays at Warning because
		// that IS an attack signature.
		if shouldSamplePermitLog(transactionId) {
			log.Info("server-agent(#%d@%s)[HeaderType] legacy body (zero) permitted; wire=%s (sample 1/%d; flip strict when legacy=0)",
				transactionId, addrStr, core.HeaderTypeToString(wireType), permitModeLogSampleMod)
		} else {
			// Fresh-deploy anchor: make sure at least one Info
			// line exists per process for legacy knocks even
			// if trxIds 1..N-1 never hit the sample boundary.
			firstPermitLegacyLog.Do(func() {
				log.Info("server-agent(#%d@%s)[HeaderType] legacy body (zero) permitted; wire=%s (first-per-process anchor; sampled thereafter)",
					transactionId, addrStr, core.HeaderTypeToString(wireType))
			})
		}
		return true, nil
	case verdictMismatch:
		s.metrics.IncrCounter(MetricKnockHeaderTypeMismatch)
		if s.knockHeaderTypeVerifyRequire {
			// Issue-number references live in SERVER logs (grepped
			// by operators during incident response) but NOT in
			// user-visible error strings (ErrKnockHeaderType* in
			// nhp/common/errors.go) — different surfaces, different
			// audiences. Server-side ops want a click-through from
			// log → GitHub issue; agent logs stay grep-friendly.
			log.Warning("server-agent(#%d@%s)[HeaderType] mismatch rejected under strict mode; body=%s wire=%s (see #1154)",
				transactionId, addrStr, core.HeaderTypeToString(bodyType), core.HeaderTypeToString(wireType))
			return false, common.ErrKnockHeaderTypeMismatch
		}
		if shouldSamplePermitLog(transactionId) {
			log.Warning("server-agent(#%d@%s)[HeaderType] mismatch permitted; body=%s wire=%s (sample 1/%d; page-worthy in strict — see #1154)",
				transactionId, addrStr, core.HeaderTypeToString(bodyType), core.HeaderTypeToString(wireType), permitModeLogSampleMod)
		} else {
			// Fresh-deploy anchor: the first attack per process
			// emits a Warning even if sampling would otherwise
			// skip it. Operators need at least one log line for
			// forensics on the earliest incident; subsequent
			// flips rely on the sample path.
			firstPermitMismatchLog.Do(func() {
				log.Warning("server-agent(#%d@%s)[HeaderType] mismatch permitted; body=%s wire=%s (first-per-process anchor; sampled thereafter — see #1154)",
					transactionId, addrStr, core.HeaderTypeToString(bodyType), core.HeaderTypeToString(wireType))
			})
		}
		return true, nil
	}
	// Fail-closed default. A future PR that adds a new verdict
	// constant and forgets to register it here will reject with
	// ErrKnockHeaderTypeInternal (52011) — distinct from the
	// mismatch (52009) and legacy (52010) codes so the agent
	// log doesn't blame tampering for what is actually a server-
	// side dispatch-table bug. Logged at Error with a stable
	// grep-friendly marker so an ops team can alarm on "new
	// verdict added, dispatch table missed" with a single
	// substring instead of parsing the free-text message.
	log.Error("server-agent(#%d@%s)[HeaderType] [GATE_UNKNOWN_VERDICT] verdict=%d rejecting fail-closed", transactionId, addrStr, verdict)
	return false, common.ErrKnockHeaderTypeInternal
}
