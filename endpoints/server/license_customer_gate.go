package server

import (
	"sync"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// License-customer cross-check gate (#1157 F4).
//
// Pre-#1157 the AC-online registration accepted a license from any
// CustomerID under any acId. A license issued to customer A could
// be presented with an acId that belongs to customer B and the
// server would happily register the AC under B's identity.
// Combined with #1155-pre-fix bearer-token semantics or any
// license-leak path, this becomes cross-customer impersonation:
// customer A's license (or a leaked copy) lets the holder pose as
// customer B's AC and receive plaintext NHP_AOP for B's resources.
//
// Source-of-truth question. The only field that records which
// customer "owns" an acId is ACAssignment.CustomerID. That field
// is populated by two paths:
//   1. ADMIN: the console's NHP-provisioning workflow writes
//      ACAssignment with the customer's ULID at AC-issuance time.
//      This value is non-circular — it predates any registration.
//   2. AUTO-ASSIGN: msghandler.go autoAssignAC populates CustomerID
//      from the registering license at first-time auto-assignment
//      (msghandler.go ~810). This value IS derived from the same
//      license we're trying to validate, so it carries no
//      independent identity signal — it just records "the first
//      license that registered this acId."
//
// Gate behavior. We treat ACAssignment.CustomerID as TOFU
// (trust-on-first-use):
//   - If GetACAssignment returns ErrNotFound or CustomerID is
//     empty, this is the first registration for the acId. The
//     license claim is accepted; autoAssignAC will write the
//     mapping. Verdict: verdictACIDCustomerUnbound.
//   - If a populated CustomerID exists and license.CustomerID
//     matches, accept. Verdict: verdictACIDCustomerOK.
//   - If a populated CustomerID exists and license.CustomerID
//     disagrees, reject in strict mode. Verdict:
//     verdictACIDCustomerMismatch.
//
// TOFU race caveat. An attacker who registers an acId BEFORE the
// legitimate customer can pin the wrong customer mapping and
// thereby lock the legitimate customer out (verdictMismatch on
// every legitimate retry). Mitigations:
//   - Admin-provisioned ACAssignment.CustomerID (path 1 above)
//     pre-empts the race entirely. The console workstream's AC
//     provisioning UI is expected to populate this field at
//     issuance time (tracked in #1262).
//   - The #1155 BoundPubKeys gate, when in strict mode, blocks
//     attacker pubkeys before they can win the race — F4 is the
//     defense-in-depth layer for the period when #1155 is in
//     permit mode or BoundPubKeys is unprovisioned.
//   - Operators paging on MetricLicenseCustomerMismatch in strict
//     mode can detect a TOFU-race incident and reset the
//     ACAssignment manually. Runbook tracked in the same #1262
//     provisioning workstream.
//
// Rollout: permit→strict via NHP_LICENSE_ACID_CUSTOMER_VERIFY,
// matching #1155 / #1156 / #1157-F3. Permit logs+metrics but
// accepts (preserves pre-fix behavior so existing deployments
// where ACAssignment.CustomerID was never populated by the admin
// path don't break the moment this PR rolls out). Strict rejects.
//
// Storage-error policy. The gate's lookup of ACAssignment is on
// the registration hot path. A transient storage outage MUST NOT
// reject legitimate registrations — the same availability
// contract as autoAssignAC's "fall through to accept directly"
// branch. The gate calls verifyACIDCustomer with
// (existingCustomerID, licenseCustomerID); the caller in
// validateACLicense converts a storage error to verdictUnbound
// (skip-the-cross-check) AND fires MetricLicenseCustomerLookupErr
// for observability. Strict mode does NOT escalate lookup errors
// to rejects — that would weaponize a storage glitch into an
// outage. The metric stays observable so a sustained lookup-err
// rate is paged before it can mask a real attack.
//
// Scope. This gate runs only in cloud mode (storage backend is
// configured AND license validation ran). Non-cloud (etcd / static)
// deployments don't use ACAssignment for customer identity, so
// the gate is bypassed for them. Same scope as #1155.

// LicenseACIDCustomerVerifyEnvVar gates the strict-mode reject.
// Accepts the same truthy/falsy tokens as the other server gates.
const LicenseACIDCustomerVerifyEnvVar = "NHP_LICENSE_ACID_CUSTOMER_VERIFY"

// MetricLicenseCustomerMismatch fires once per AC registration
// where license.CustomerID disagrees with ACAssignment.CustomerID
// for the claimed acId. Page-worthy in strict mode (active
// cross-customer impersonation attempt OR an admin tooling bug
// that mis-mapped the assignment).
//
// MetricLicenseCustomerLookupErr fires when the ACAssignment
// lookup itself errors (storage transient). Strict-mode behavior
// is "skip the cross-check, accept the registration" — the metric
// is the only signal. A sustained non-zero rate means storage is
// flaky AND the gate is silently degraded; should be paged on
// independently of the mismatch counter.
const (
	MetricLicenseCustomerMismatch  = "LicenseCustomerMismatch"
	MetricLicenseCustomerLookupErr = "LicenseCustomerLookupErr"
)

// licenseACIDCustomerVerdict captures what verifyACIDCustomer
// recommends.
type licenseACIDCustomerVerdict int

const (
	// Leave iota=0 unnamed on purpose — same structural fail-closed
	// pattern as the other gates. Uninitialized verdict falls
	// through to applyACIDCustomerVerdict's switch default and
	// rejects with ErrLicenseCustomerInternal.
	_ licenseACIDCustomerVerdict = iota
	// verdictACIDCustomerOK: ACAssignment.CustomerID matches
	// license.CustomerID. Accept unconditionally.
	verdictACIDCustomerOK
	// verdictACIDCustomerUnbound: ACAssignment doesn't exist OR has
	// an empty CustomerID. First registration (TOFU) — accept.
	// Operators watching the rollout can flip strict only after
	// admin tooling has populated the mapping for all live ACs;
	// strict mode treats Unbound as accept (same as OK) because
	// rejecting would hard-block first-registration of every new
	// AC, which is by design a non-attack flow. Mismatch is the
	// strict-mode reject signal.
	verdictACIDCustomerUnbound
	// verdictACIDCustomerMismatch: ACAssignment.CustomerID is
	// non-empty AND disagrees with license.CustomerID. The #1157
	// F4 attack signature. Permit logs+metric and accepts (pre-fix
	// behavior); strict rejects.
	verdictACIDCustomerMismatch
)

// firstPermitACIDCustomerMismatchLog guarantees at least one
// forensic anchor per process. Mirrors the other gates' sync.Once
// pattern.
var firstPermitACIDCustomerMismatchLog sync.Once

// parseLicenseACIDCustomerVerify decodes
// NHP_LICENSE_ACID_CUSTOMER_VERIFY. Thin wrapper around
// parsePermitStrictEnv so every gate uses one token grammar.
func parseLicenseACIDCustomerVerify(raw string) (bool, error) {
	return parsePermitStrictEnv(raw)
}

// verifyACIDCustomer is the pure policy kernel. Given the
// ACAssignment-recorded customer (existingCustomerID — empty
// means "no assignment or assignment with empty CustomerID")
// and the license's claimed customer, returns the verdict.
//
// Empty license customer is treated as Mismatch when an existing
// assignment is bound to a non-empty customer: a license with no
// CustomerID is misconfigured, and silently accepting it under a
// bound assignment would permit cross-customer impersonation by a
// blank-customer license. The console's License.Validate already
// rejects empty CustomerID at write-time, so this kernel only
// catches the defense-in-depth case where a future caller forgets
// to set the field.
func verifyACIDCustomer(existingCustomerID, licenseCustomerID string) licenseACIDCustomerVerdict {
	if existingCustomerID == "" {
		return verdictACIDCustomerUnbound
	}
	if licenseCustomerID == "" || licenseCustomerID != existingCustomerID {
		return verdictACIDCustomerMismatch
	}
	return verdictACIDCustomerOK
}

// applyACIDCustomerVerdict is the side-effect side of the policy.
// Centralizes metric + log emission AND the reject-error
// selection so the switch is the single source of truth for both
// "proceed?" and "which error?". Mirrors
// applyLicensePubkeyVerdict.
//
// Returns (proceed, rejectErr):
//   - (true, nil) — caller proceeds, gate accepted
//   - (false, rejectErr) — caller aborts with rejectErr as the
//     AAK ErrCode/ErrMsg
func (s *UdpServer) applyACIDCustomerVerdict(
	verdict licenseACIDCustomerVerdict,
	acId string,
	licenseCustomerID string,
	existingCustomerID string,
	transactionId uint64,
	addrStr string,
	keyPrefix string,
) (bool, *common.Error) {
	switch verdict {
	case verdictACIDCustomerOK, verdictACIDCustomerUnbound:
		// Both verdicts proceed silently. Unbound is the expected
		// first-registration / pre-rollout path; emitting a Warning
		// per-Unbound would flood logs during the rollout window.
		// The MetricLicenseCustomerLookupErr counter (fired by the
		// caller on storage error) is the operator's burn-in
		// signal, not an Unbound counter — Unbound is structurally
		// indistinguishable from "first-time AC registration" and
		// is not by itself a rollout-incomplete indicator.
		return true, nil
	case verdictACIDCustomerMismatch:
		s.metrics.IncrCounter(MetricLicenseCustomerMismatch)
		if s.licenseACIDCustomerVerifyRequire {
			log.Warning("server-ac(%s#%d@%s)[LicenseCustomer] customer mismatch rejected under strict mode; key=%s...; license_customer=%s; bound_customer=%s (see #1157 F4)",
				acId, transactionId, addrStr, keyPrefix, licenseCustomerID, existingCustomerID)
			return false, common.ErrLicenseCustomerMismatch
		}
		if shouldSamplePermitLog(transactionId) {
			log.Warning("server-ac(%s#%d@%s)[LicenseCustomer] customer mismatch permitted; key=%s...; license_customer=%s; bound_customer=%s (sample 1/%d; page-worthy in strict — see #1157 F4)",
				acId, transactionId, addrStr, keyPrefix, licenseCustomerID, existingCustomerID, permitModeLogSampleMod)
		} else {
			firstPermitACIDCustomerMismatchLog.Do(func() {
				log.Warning("server-ac(%s#%d@%s)[LicenseCustomer] customer mismatch permitted; key=%s...; license_customer=%s; bound_customer=%s (per-process forensic anchor; non-anchor occurrences sampled at 1/permitModeLogSampleMod — see #1157 F4)",
					acId, transactionId, addrStr, keyPrefix, licenseCustomerID, existingCustomerID)
			})
		}
		return true, nil
	}
	// Fail-closed default. Same pattern as the other gates.
	log.Error("server-ac(%s#%d@%s)[LicenseCustomer] [GATE_UNKNOWN_VERDICT] verdict=%d rejecting fail-closed",
		acId, transactionId, addrStr, verdict)
	return false, common.ErrLicenseCustomerInternal
}
