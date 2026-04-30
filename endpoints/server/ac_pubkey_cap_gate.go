package server

import (
	"sync"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// AC pubkey-cap gate (#1157 F3).
//
// Pre-#1157 the per-acId connection cap (MaxACConnsPerID) counted
// total live connections, regardless of pubkey. An attacker holding
// a valid license key (e.g., via #1155's pre-fix bearer-token gap or
// any future license-leak path) could present MaxACConnsPerID
// distinct attacker pubkeys under one acId — each from a different
// source IP — and FIFO-evict the legitimate AC's connection out of
// acConnectionMap[acId]. With the legitimate AC evicted, the
// attacker's connections become the sole receivers of plaintext
// NHP_AOP for that acId. Authenticated DoS that converges on
// full impersonation when paired with #1155 in permit mode.
//
// Fix: count DISTINCT pubkeys per acId, not total connections.
// A given AC's static pubkey can appear in multiple ACConn entries
// (blue/green from different IPs is legitimate), but a single
// attacker keypair only ever consumes ONE slot. Reaching the cap
// under attack now requires N attacker pubkeys, which:
//   - costs more (each pubkey is one keygen + provisioning step),
//   - reveals N distinct attacker identities in the logs (each
//     pubkey is an evidentiary fingerprint), and
//   - dovetails with #1155's BoundPubKeys allowlist: a strict-mode
//     allowlist with K entries caps the attack at min(K, MaxACs)
//     impersonator slots regardless of how many pubkeys the
//     attacker burns.
//
// Rollout: permit→strict via NHP_AC_PUBKEY_CAP_VERIFY, mirroring
// #1155 and #1156. Permit mode logs+metrics but accepts (preserves
// pre-fix behavior so deploy doesn't break ACs that legitimately
// consume more distinct pubkeys than expected during a key-rotation
// window). Strict mode rejects with ErrACPubkeyCapExceeded.
//
// Interaction with #1155: when License.BoundPubKeys is provisioned
// AND the license-pubkey gate is in strict mode, F3 is largely
// moot — the attacker's keypair is rejected at validateACLicense
// before HandleACOnline ever reaches this gate. F3 protects the
// permit-mode rollout window of #1155 AND the unbound-license case
// (legacy / unprovisioned). The gate stays load-bearing forever for
// configurations where BoundPubKeys is intentionally permissive
// (e.g., shared-pool licenses).
//
// Scope: registration path only (HandleACOnline).
// acConnectionMap[acId] is otherwise read freely; once a connection
// is in the map, this gate doesn't re-evaluate. That's intentional —
// re-evaluation would create a windowed-DoS where a transient cap
// overage drops a legitimate connection that has been live for
// hours. The cap is a registration-time admission control, not a
// runtime invariant.

// ACPubkeyCapVerifyEnvVar gates the strict-mode reject. Accepts the
// same truthy/falsy tokens as the other server gates.
const ACPubkeyCapVerifyEnvVar = "NHP_AC_PUBKEY_CAP_VERIFY"

// MetricACPubkeyCapExceeded fires once per AC registration where
// adding the presented pubkey would push distinct-pubkey count
// above MaxACConnsPerID. Page-worthy in strict mode (active
// eviction attack); worth watching in permit mode as the rollout
// signal that legitimate clients are bumping the cap.
const MetricACPubkeyCapExceeded = "ACPubkeyCapExceeded"

// acPubkeyCapVerdict captures what verifyACPubkeyCap recommends.
type acPubkeyCapVerdict int

const (
	// Leave iota=0 unnamed on purpose so the Go zero-value of
	// acPubkeyCapVerdict does NOT map to any named constant.
	// Mirrors the structural fail-closed pattern in
	// license_pubkey_gate.go: an uninitialized verdict falls
	// through to applyACPubkeyCapVerdict's switch default and
	// rejects with ErrACPubkeyCapInternal. Without this shift,
	// verdictACPubkeyCapOK would be the zero value and a future
	// caller that forgot to set the verdict would silently accept.
	_ acPubkeyCapVerdict = iota
	// verdictACPubkeyCapOK: presented pubkey is already known
	// (in-place re-registration) OR distinct count is below the
	// cap. Accept unconditionally.
	verdictACPubkeyCapOK
	// verdictACPubkeyCapExceeded: presented pubkey is new AND
	// adding it would push distinct count above MaxACConnsPerID.
	// Permit accepts with metric+log; strict rejects.
	verdictACPubkeyCapExceeded
)

// firstPermitACPubkeyCapLog guarantees at least one forensic
// anchor per process, mirroring the sync.Once pattern in
// license_pubkey_gate.go. Same shared-testability hazard: package-
// level so whichever test runs first consumes the guard. No test
// today inspects the anchor.
var firstPermitACPubkeyCapLog sync.Once

// parseACPubkeyCapVerify decodes NHP_AC_PUBKEY_CAP_VERIFY. Thin
// wrapper around parsePermitStrictEnv so every gate uses one token
// grammar.
func parseACPubkeyCapVerify(raw string) (bool, error) {
	return parsePermitStrictEnv(raw)
}

// extractPubkeysFromConns walks an ACConn slice and returns the
// PubKeyBase64 of every conn whose ACPeer is non-nil. Centralizes
// the snapshot loop used by HandleACOnline's F3 pre-check (under
// RLock) and the F3 in-lock authoritative check (under Lock); the
// kernel below dedupes, so duplicates from blue/green re-registration
// don't perturb the verdict.
//
// Cross-test dependency: TestHandleACOnline_F5_BypassedInNonCloudMode
// (handle_ac_online_f5_test.go) relies on the in-lock F3 cap reject
// as the early-exit driver for the non-cloud case. If a future
// refactor hoists the in-lock check out of cloudMode, changes the
// strict-mode default, or otherwise alters the cap-reject behavior,
// pair-debug that test — its load-bearing assertion
// (mem.GetCallCount("GetACAssignment") == 0) survives, but the
// errors.Is(err, ErrACPubkeyCapExceeded) assertion would mis-fire.
func extractPubkeysFromConns(conns []*ACConn) []string {
	out := make([]string, 0, len(conns))
	for _, c := range conns {
		if c != nil && c.ACPeer != nil {
			out = append(out, c.ACPeer.PubKeyBase64)
		}
	}
	return out
}

// verifyACPubkeyCap is the pure policy kernel. Given the presented
// pubkey, the existing connections for the acId, and the cap, it
// returns the verdict.
//
// Separating kernel from side-effect wrapper makes the policy
// table unit-testable without a UdpServer — mirrors
// verifyLicensePubkey in license_pubkey_gate.go.
//
// Accepts existingPubkeys as a slice of base64 strings (extracted
// by the caller from acConnectionMap[acId] under the existing
// mutex). Caller-extracted slice keeps the kernel lock-free and
// avoids leaking the lock contract into kernel tests.
//
// The kernel handles the in-place re-registration case: if
// presentedPubkey is already in existingPubkeys, the registration
// does NOT consume a new slot regardless of cap state. This
// preserves the legitimate "same AC, new IP from a socket
// recreation or NLB-vs-direct flip" path.
//
// Known constraint — same-IP key rotation under saturation:
// If acConnectionMap[acId] is at MaxACConnsPerID with all DISTINCT
// pubkeys (the saturated-distinct shape this gate fences) AND a
// legitimate AC at IP_X rotates its static pubkey from pkA → pkA_new,
// the kernel sees presented=pkA_new, existing=[pkA, ..., pkJ] with
// distinct=cap and verdicts Exceeded — even though the msghandler's
// same-IP replacement loop would have replaced IP_X's slot rather
// than appended. This is a false-positive reject only in strict
// mode AND only when the saturated-distinct shape has been reached.
// Operationally rare (today's blue/green deploy shares one static
// pubkey, so distinct count is typically 1-2, not 10), but a
// rotation that hadn't fully retired old keys could trip this.
// Workaround: drain old pubkeys before rotating into a saturated
// state. Pinned by TestVerifyACPubkeyCap_SameIPKeyRotation_UnderSaturation_Exceeded
// so a future PR that "fixes" this false-positive surfaces the
// trade-off discussion at PR time.
//
// Returns (verdict, distinctCount) so applyACPubkeyCapVerdict can log
// the observed count without re-walking the slice. A single pass
// builds the distinct set, then membership and cap checks read it.
func verifyACPubkeyCap(presentedPubkey string, existingPubkeys []string, capLimit int) (acPubkeyCapVerdict, int) {
	// existingPubkeys may contain duplicates (multiple ACConns for
	// blue/green can share a pubkey), so dedupe in one pass.
	distinct := make(map[string]struct{}, len(existingPubkeys))
	for _, pk := range existingPubkeys {
		distinct[pk] = struct{}{}
	}
	distinctCount := len(distinct)
	// Same-pubkey re-registration: never consumes a slot, regardless
	// of how close the cap is.
	if _, present := distinct[presentedPubkey]; present {
		return verdictACPubkeyCapOK, distinctCount
	}
	if distinctCount >= capLimit {
		return verdictACPubkeyCapExceeded, distinctCount
	}
	return verdictACPubkeyCapOK, distinctCount
}

// applyACPubkeyCapVerdict is the side-effect side of the policy
// — centralizes metric + log emission AND the reject-error
// selection so the switch is the single source of truth for both
// "proceed?" and "which error?". Mirrors
// applyLicensePubkeyVerdict.
//
// Returns (proceed, rejectErr):
//   - (true, nil) — caller proceeds, gate accepted the registration
//   - (false, rejectErr) — caller aborts with rejectErr as the
//     AAK ErrCode/ErrMsg
//
// Permit-mode logs are sampled at 1/permitModeLogSampleMod (shared
// constant with the other gates) to survive an attack flood
// without drowning the log stream; metrics fire unconditionally.
func (s *UdpServer) applyACPubkeyCapVerdict(
	verdict acPubkeyCapVerdict,
	acId string,
	presentedBase64 string,
	distinctCount int,
	transactionId uint64,
	addrStr string,
) (bool, *common.Error) {
	switch verdict {
	case verdictACPubkeyCapOK:
		return true, nil
	case verdictACPubkeyCapExceeded:
		// No nil-guard on s.metrics: UdpServer.metrics is initialized
		// by NewUdpServer at startup. Test helpers wire metrics via
		// metrics.NewPublisherForTest. Same invariant as the other
		// server gates.
		s.metrics.IncrCounter(MetricACPubkeyCapExceeded)
		if s.acPubkeyCapVerifyRequire {
			log.Warning("server-ac(%s#%d@%s)[ACPubkeyCap] distinct-pubkey cap exceeded; rejecting under strict mode; pubkey=%s...; distinct=%d/%d (see #1157 F3)",
				acId, transactionId, addrStr, pubkeyLogPrefix(presentedBase64), distinctCount, MaxACConnsPerID)
			return false, common.ErrACPubkeyCapExceeded
		}
		if shouldSamplePermitLog(transactionId) {
			log.Warning("server-ac(%s#%d@%s)[ACPubkeyCap] distinct-pubkey cap exceeded; permitted (sample 1/%d); pubkey=%s...; distinct=%d/%d (page-worthy in strict — see #1157 F3)",
				acId, transactionId, addrStr, permitModeLogSampleMod, pubkeyLogPrefix(presentedBase64), distinctCount, MaxACConnsPerID)
		} else {
			firstPermitACPubkeyCapLog.Do(func() {
				log.Warning("server-ac(%s#%d@%s)[ACPubkeyCap] distinct-pubkey cap exceeded; permitted (per-process forensic anchor; non-anchor occurrences sampled at 1/permitModeLogSampleMod); pubkey=%s...; distinct=%d/%d (see #1157 F3)",
					acId, transactionId, addrStr, pubkeyLogPrefix(presentedBase64), distinctCount, MaxACConnsPerID)
			})
		}
		return true, nil
	}
	// Fail-closed default. Same pattern as the other gates: a future
	// PR that adds a new verdict constant and forgets to register
	// it here rejects with ErrACPubkeyCapInternal so the agent log
	// doesn't blame eviction for what is actually a server-side
	// dispatch-table bug.
	log.Error("server-ac(%s#%d@%s)[ACPubkeyCap] [GATE_UNKNOWN_VERDICT] verdict=%d rejecting fail-closed",
		acId, transactionId, addrStr, verdict)
	return false, common.ErrACPubkeyCapInternal
}
