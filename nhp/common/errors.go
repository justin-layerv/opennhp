package common

import (
	"strconv"
)

var errorMap map[string]*Error = make(map[string]*Error)

type Error struct {
	code string
	msg  string
}

// implement NhpError interface
func (e *Error) Error() string {
	return e.msg
}

func (e *Error) ErrorCode() string {
	return e.code
}

func (e *Error) ErrorNumber() int {
	n, _ := strconv.Atoi(e.code)
	return n
}

func newError(code string, msg string) *Error {
	if dup, exists := errorMap[code]; exists {
		// Package-init fail-fast: a duplicated code would otherwise silently
		// clobber the earlier entry in errorMap and misreport every
		// ErrorCodeToError lookup for it. Any test run (or process start)
		// trips this immediately, so collisions cannot ship.
		panic("nhp/common: duplicate error code " + code + " (already used by " + dup.msg + ")")
	}
	e := &Error{
		code: code,
		msg:  msg,
	}
	errorMap[code] = e
	return e
}

func ErrorCodeToError(code string) *Error {
	e, found := errorMap[code]
	if found {
		return e
	}
	return nil // should not happen
}

// IsSuccessErrCode returns true if the error code represents success.
// Per NHP protocol, success is indicated by:
//   - empty string (implicit success, no error)
//   - ErrSuccess.ErrorCode() i.e. "0" (explicit success)
func IsSuccessErrCode(errCode string) bool {
	return errCode == "" || errCode == ErrSuccess.ErrorCode()
}

// ErrorFromResponse maps a protocol response's code to a concrete error. Known
// NHP codes retain their canonical, localized error. Extension codes emitted by
// an auth service or AC retain the authenticated response message instead of
// becoming a nil *Error inside a non-nil error interface.
//
// Two deliberate properties, despite what the name might suggest:
//
//   - For a KNOWN code the wire message is DISCARDED, not preserved. The
//     canonical string is the trusted one; there is no reason to surface remote
//     text when we already have our own. The wire message is not lost to
//     operators — every call site logs `ackMsg.ErrMsg` immediately before
//     calling this.
//
//     The known-code return is the shared package-level sentinel itself (a
//     pointer identity that TestErrorFromResponseKnownCodeUsesCanonicalError
//     asserts), NOT a copy. Callers must treat it as read-only: mutating the
//     returned *Error to attach a per-request message would corrupt that
//     sentinel process-wide for every future caller. Use WithExtra, which
//     returns a new Error, if you need to attach context.
//
//   - For an unknown code the returned message IS remote-controlled. Treat it
//     as untrusted display text: log it, surface it, but never parse it or
//     branch on it. Only the code is a contract.
//
// It never returns nil. That is load-bearing, not incidental: the replaced
// `ErrorCodeToError` returns a nil *Error for unregistered codes, and assigning
// a nil *Error to an `error` variable yields a non-nil interface wrapping a nil
// pointer — `err != nil` is true and `err.Error()` then dereferences a nil
// receiver and panics. Callers assign the result straight into an `error`, so
// returning nil here would reopen that trap.
func ErrorFromResponse(code, message string) *Error {
	if e := ErrorCodeToError(code); e != nil {
		return e
	}
	if message == "" {
		message = "unknown NHP error code " + code
	}
	return &Error{code: code, msg: message}
}

// application errors
var (
	// generic
	ErrSuccess                             = newError("0", "")
	ErrExit                                = newError("1", "must exit")
	ErrJsonParseFailed                     = newError("50001", "json parse failed")
	ErrTransactionIdNotFound               = newError("50002", "transaction id not found")
	ErrTransactionFailedByTimeout          = newError("50003", "transaction failed due to time out")
	ErrTransactionFailedByClosedConnection = newError("50004", "transaction failed by closed connection")
	ErrTransactionFailedByClosedDevice     = newError("50005", "transaction failed by closed device")
	ErrTransactionRepliedWithWrongType     = newError("50006", "transaction replied wrong type")
	ErrPacketToMessageRoutineStopped       = newError("50007", "packet to message routine stopped")
	ErrInvalidIpAddress                    = newError("50008", "invalid ip address")
	ErrPacketEncryptionFailed              = newError("50009", "packet encryption failed")
	ErrTransactionClosed                   = newError("50010", "transaction closed before message could be forwarded")

	// agent
	ErrKnockUserNotSpecified   = newError("51001", "knock user not specified")
	ErrKnockServerNotFound     = newError("51002", "failed to find knock server")
	ErrKnockTerminatedByCookie = newError("51003", "knock terminated by cookie")

	// agentsdk
	ErrNoAgentInstance = newError("51100", "agent instance does not exist")
	ErrInvalidInput    = newError("51101", "invalid input parameter")

	// server
	ErrKnockApiRequestFailed       = newError("52001", "knock api request failed")
	ErrAuthServiceProviderNotFound = newError("52002", "failed to find auth service provider")
	ErrACConnectionNotFound        = newError("52003", "failed to find ac connection")
	ErrResourceNotFound            = newError("52004", "failed to find resource")
	ErrServerACOpsFailed           = newError("52005", "server ac operation failed")
	ErrAuthHandlerNotFound         = newError("52006", "failed to find auth handler")
	ErrBackendAuthRequired         = newError("52007", "server backend auth required")
	ErrUrlPathInvalid              = newError("52008", "client request url path is invalid")
	// ErrKnockHeaderTypeMismatch — emitted by the server-side Knock
	// HeaderType gate (#1154) when the AEAD-authenticated
	// body.HeaderType disagrees with the wire HeaderType. Signals
	// a potential MitM type-flip attack (or a misconfigured client
	// that deliberately lies about its own headerType). Kept
	// issue-number-free in the user-visible error text so agent
	// logs stay grep-friendly.
	ErrKnockHeaderTypeMismatch = newError("52009", "knock body HeaderType does not match wire HeaderType")
	// ErrKnockHeaderTypeLegacy — emitted by the same gate when the
	// body.HeaderType is the zero value (NHP_KPL sentinel), which
	// means the agent predates #1154 and isn't populating the
	// field. Distinct from the mismatch code so agent-side logs
	// can self-diagnose "upgrade your agent" vs "something is
	// tampering" without cross-referencing server-side metrics.
	// Kept issue-number-free in the user-visible error text (like
	// the mismatch code) so agent logs stay grep-friendly.
	ErrKnockHeaderTypeLegacy = newError("52010", "knock body HeaderType missing — upgrade agent")
	// ErrKnockHeaderTypeInternal — emitted by the Knock HeaderType
	// gate's fail-closed default branch (unknown verdict). Today
	// that branch is unreachable, but if a future PR adds a new
	// knockHeaderTypeVerdict constant and forgets to register it
	// in the switch, the gate rejects fail-closed AND surfaces a
	// distinct error so the agent log doesn't blame tampering for
	// what is actually a server-side dispatch-table bug.
	ErrKnockHeaderTypeInternal = newError("52011", "knock HeaderType gate internal error (unknown verdict)")
	// ErrLicensePubkeyMismatch — emitted by the server-side AC-license
	// pubkey-binding gate (#1155) when the AC's presented static
	// pubkey is not in the License.BoundPubKeys allowlist. Signals
	// that either (a) a stolen license key is being presented with
	// an attacker-chosen keypair, or (b) the license's allowlist is
	// out of date for a legitimate AC (rotation / new instance).
	// Agent-visible string stays issue-number-free so agent logs
	// are grep-friendly; the server log line carries the #1155
	// reference.
	ErrLicensePubkeyMismatch = newError("52012", "license does not permit this AC pubkey")
	// ErrLicensePubkeyUnbound — emitted by the same gate under strict
	// mode when the License.BoundPubKeys allowlist is empty. Empty
	// means the license was never provisioned with an expected
	// pubkey; permit mode accepts with a legacy warning, strict
	// rejects so operators cannot quietly keep shipping unbound
	// licenses once the gate is flipped.
	ErrLicensePubkeyUnbound = newError("52013", "license has no bound pubkey — provision BoundPubKeys")
	// ErrLicensePubkeyInternal — emitted by the gate's fail-closed
	// default branch (unknown verdict). Same mechanical pattern as
	// ErrKnockHeaderTypeInternal: a future PR adds a new verdict
	// constant and forgets to register it in the switch → gate
	// rejects fail-closed AND surfaces a distinct error so the
	// agent log doesn't blame the license for what is actually a
	// server-side dispatch-table bug.
	ErrLicensePubkeyInternal = newError("52014", "license pubkey gate internal error (unknown verdict)")
	// ErrACPubkeyCapExceeded — emitted by the AC pubkey-cap gate
	// (#1157 F3) under strict mode when registering this peer would
	// push the count of distinct static pubkeys for an acId above
	// MaxACConnsPerID. Pre-#1157 the cap was on total connections,
	// so an attacker presenting MaxACConnsPerID distinct pubkeys
	// (one per source IP) under one acId could FIFO-evict the
	// legitimate AC. The fix counts distinct pubkeys instead so the
	// cap costs an attacker N pubkeys per evicted slot and exposes N
	// attacker identities in the logs. Agent-visible string stays
	// issue-number-free so agent logs are grep-friendly.
	ErrACPubkeyCapExceeded = newError("52015", "AC pubkey cap exceeded for this AC ID")
	// ErrACPubkeyCapInternal — emitted by the same gate's
	// fail-closed default branch (unknown verdict). Same mechanical
	// pattern as ErrLicensePubkeyInternal / ErrKnockHeaderTypeInternal.
	ErrACPubkeyCapInternal = newError("52016", "AC pubkey cap gate internal error (unknown verdict)")
	// ErrLicenseCustomerMismatch — emitted by the license-vs-acId
	// customer cross-check gate (#1157 F4) under strict mode when
	// the License.CustomerID disagrees with the previously bound
	// CustomerID for the claimed acId. Pre-#1157 a license issued
	// to customer A could be presented with an acId that belongs to
	// customer B and would be accepted; the cross-check breaks
	// cross-customer impersonation by binding acId→customer at
	// first-registration (TOFU) and rejecting subsequent licenses
	// from a different customer. Agent-visible string stays
	// issue-number-free so agent logs are grep-friendly.
	ErrLicenseCustomerMismatch = newError("52017", "license customer does not own this AC ID")
	// ErrLicenseCustomerInternal — emitted by the same gate's
	// fail-closed default branch (unknown verdict).
	ErrLicenseCustomerInternal = newError("52018", "license customer gate internal error (unknown verdict)")
	// ErrACPubkeyRevoked — emitted by the AC-pubkey runtime-revocation
	// gate (#1507, follow-up from #1157 F5) under strict mode when the
	// presented static pubkey appears in ACAssignment.RevokedPubKeys
	// for the claimed acId. Lets an operator yank a specific AC
	// instance at runtime without rotating the entire license — the
	// pre-#1507 close-the-license workflow took effect only at the
	// next AC re-registration AND was an all-or-nothing toggle that
	// kicked legitimate ACs sharing the license. Agent-visible string
	// stays issue-number-free so agent logs are grep-friendly; the
	// server log line carries the #1507 reference.
	ErrACPubkeyRevoked = newError("52019", "AC pubkey revoked for this AC ID")
	// ErrACPubkeyRevokedInternal — emitted by the same gate's
	// fail-closed default branch (unknown verdict). Same mechanical
	// pattern as ErrACPubkeyCapInternal / ErrLicensePubkeyInternal: a
	// future PR adds a new verdict constant and forgets to register
	// it in the switch → gate rejects fail-closed AND surfaces a
	// distinct error so the agent log doesn't blame revocation for
	// what is actually a server-side dispatch-table bug.
	ErrACPubkeyRevokedInternal = newError("52020", "AC pubkey revoke gate internal error (unknown verdict)")
	// ErrServerTokenPersistFailed — emitted when AC operations have
	// succeeded but the server cannot persist the AC-issued ACK token
	// metadata needed for later cross-instance validation. Distinct from
	// ErrServerACOpsFailed so agent logs and on-call triage do not blame
	// the AC path for a server-side token-store dependency failure.
	ErrServerTokenPersistFailed = newError("52021", "server token persistence failed")
	// ErrServerDuplicateTransaction — emitted by the server's NHP_ART
	// replay dedupe (#1457, the mirror of the AC's #1123) when the
	// (sender_pubkey, txid, sendTime) triple was already processed inside
	// the cache TTL. The packet is dropped at the post-validation
	// chokepoint so a replayed ART cannot feed a stale access result into
	// a live knock flow. Message reads "replayed packet" rather than
	// "duplicate transaction id" alone so an oncall reading the error does
	// not infer the dedupe key is txid-only and chase the wrong direction.
	ErrServerDuplicateTransaction = newError("52022", "server duplicate transaction (replayed packet)")
	// ErrServerMissingPeerPubkey — fail-closed on the upstream invariant
	// that core.responder.validatePeer populates ppd.RemotePubKey before
	// the server dedupe hook runs. A wrong-length pubkey here means either
	// a parser regression or a test harness that bypasses validatePeer; in
	// both cases the server cannot scope replay-dedupe state and so refuses
	// the packet. Distinct from ErrServerDuplicateTransaction so an oncall
	// chasing a duplicate-spike alert is not misled by an upstream
	// invariant violation.
	ErrServerMissingPeerPubkey = newError("52023", "missing peer pubkey on server transaction")
	// ErrQurlSessionExpired — the qURL plugin's AuthWithNHP (#2208) got a deny
	// from qurl-service /authorize: the knock is cryptographically authenticated
	// but the client IP has no active session for the resource (session expired,
	// revoked, or never established from this IP). Distinct from
	// ErrBackendAuthRequired (52007, "supply backend credentials like a
	// passcode") because the agent's correct reaction is to RE-RESOLVE via the
	// qURL link to mint a fresh session, not to present a credential. The
	// js-agent (P6) branches on this code.
	ErrQurlSessionExpired = newError("52024", "qurl session expired or not authorized for this client")
	// ErrKnockRunIDInvalid rejects registered-agent UDP knocks before pubkey,
	// resource, or AC work when the authenticated body omits runId or carries a
	// noncanonical value. Generic/legacy and HTTP parsing may still omit runId;
	// the strict requirement is scoped to aspId=agent on native UDP paths. The
	// internal value-shape sentinel [ErrInvalidAgentKnockRunID] maps here at the
	// direct and forwarded server boundaries.
	ErrKnockRunIDInvalid = newError("52025", "registered-agent knock runId is missing or invalid")
	// ErrKnockRunAttemptInvalid rejects a registered-agent knock that cannot be
	// ordered within its authenticated RunID retry cycle. AC high-watermarks use
	// the positive ordinal to reject delayed attempts after a newer retry.
	ErrKnockRunAttemptInvalid = newError("52026", "registered-agent knock runAttempt is missing or invalid")
	// ErrHTTPAccessOperationUnsupported is the hard-cut response for the retired
	// internal HTTP pinhole-opening path. HTTP remains a transport for sealed NHP
	// packets and durable control-plane operations, not an admission protocol.
	ErrHTTPAccessOperationUnsupported = newError("52027", "HTTP access admission is not supported; use authenticated NHP")
	ErrACSessionControlNotReady       = newError("52028", "AC session-control boot flush is not ready")
	// ErrNativeSessionOperationRecoveryRequired denies an exact duplicate
	// registered-agent admission after the durable operation row already maps
	// the selector to a server session. The server must not rerun the plugin or
	// reproduce bearer-bearing ACK material; the client closes/reconciles the
	// mapped operation and advances RunAttempt.
	ErrNativeSessionOperationRecoveryRequired = newError("52029", "native session operation recovery required")

	// server: agent registration (52100+). Reject vocabulary for NHP-native
	// agent self-registration (NHP_OTP / NHP_REG / NHP_RAK). Reserved as its
	// own hundred-block — mirroring the agentsdk block at 51100 — so the flat
	// 520xx gate sequence above keeps appending without interleaving.
	// These travel to the agent in ServerRegisterAckMsg.ErrCode once the
	// registration dispatch and plugin land (agent-registration N2/N3); like
	// the gate errors above, the agent-visible strings stay issue-number-free
	// so agent logs are grep-friendly.

	// ErrRegistrationCredentialInvalid — the presented registration credential (OTP or bootstrap material) does not verify.
	ErrRegistrationCredentialInvalid = newError("52100", "registration credential invalid")
	// ErrRegistrationCredentialExpired — the credential's validity window has lapsed (or no live credential exists for this identity); the agent should request a fresh one.
	ErrRegistrationCredentialExpired = newError("52101", "registration credential expired")
	// ErrRegistrationAttemptsExceeded — too many failed credential presentations for this identity; distinct from rate limiting so lockout is not misread as load shedding.
	ErrRegistrationAttemptsExceeded = newError("52102", "registration attempts exceeded")
	// ErrRegistrationIdentityConflict — the requested identity (agent id / pubkey binding) is already registered to different key material.
	ErrRegistrationIdentityConflict = newError("52103", "registration identity conflict")
	// ErrRegistrationRateLimited — registration traffic from this source is being shed; retry later (load protection, not a verdict on the credential).
	ErrRegistrationRateLimited = newError("52104", "registration rate limited")
	// ErrRegistrationEmailUnavailable — the account has no deliverable email on file for the one-time code; the owner must attach one in the console (or register with a pre-issued bootstrap key).
	ErrRegistrationEmailUnavailable = newError("52105", "account email unavailable")
	// ErrRegistrationApiKeyInvalid — the API key presented to authorize the registration is unknown or malformed.
	ErrRegistrationApiKeyInvalid = newError("52106", "invalid api key")
	// ErrRegistrationDisabled — self-registration is administratively switched off for this server/service.
	ErrRegistrationDisabled = newError("52107", "registration disabled")
	// ErrRegistrationBootstrapKeyConsumed — the one-shot bootstrap key was already used; it cannot register a second agent.
	ErrRegistrationBootstrapKeyConsumed = newError("52108", "bootstrap key consumed")
	// ErrRegistrationInvalidInput — a registration request identifier is malformed or unknown (e.g. an invalid device_id, reachable via a client-side WithDeviceID override). Distinct from ErrRegistrationApiKeyInvalid so a bad device_id does not surface the misleading "invalid api key" string to the agent; both are terminal client errors (not load shedding), so neither should be retried.
	ErrRegistrationInvalidInput = newError("52109", "invalid registration input")
	// ErrAssignmentTicketInvalid — the assigned-cell activation ticket failed signature verification or disagreed with the authenticated pubkey, devId, cell, or generation.
	ErrAssignmentTicketInvalid = newError("52110", "assignment ticket invalid")
	// ErrAssignmentTicketExpired — the activation ticket expired; the agent must repeat one bounded initial enrollment transaction before retrying registration.
	ErrAssignmentTicketExpired = newError("52111", "assignment ticket expired")
	// ErrAgentRegistrationQuotaExceeded — activation would exceed the owner's registered-agent quota.
	ErrAgentRegistrationQuotaExceeded = newError("52112", "agent registration quota exceeded")

	// server: agent assignment (52200+). These are LRT verdicts from the
	// environment-level hub. retryAfterSeconds is valid only where the
	// ServerListResultMsg contract explicitly permits it.
	ErrAssignmentUnavailable      = newError("52200", "assignment unavailable")
	ErrAssignmentIdentityRejected = newError("52201", "identity rejected")
	ErrReassignmentInProgress     = newError("52202", "reassignment in progress")
	ErrAssignmentQuotaExceeded    = newError("52203", "assignment quota exceeded")
	ErrAssignmentRateLimited      = newError("52204", "assignment rate limited")
	ErrInvalidAssignmentRequest   = newError("52205", "invalid assignment request")

	// server: registered-agent completion (52300+). These are LRT verdicts
	// from the assigned cell after REG/RAK has bound the authenticated peer.
	ErrCompletionUnavailable         = newError("52300", "completion unavailable")
	ErrCompletionIdentityRejected    = newError("52301", "completion identity rejected")
	ErrDeviceCredentialQuotaExceeded = newError("52302", "device credential quota exceeded")
	ErrDeviceCredentialConflict      = newError("52303", "device credential conflict")
	ErrInvalidCompletionRequest      = newError("52304", "invalid completion request")

	// server: registered-agent connector resource resolution (52500+). These
	// are authenticated LRT verdicts from the assigned cell. The operation is
	// deliberately NHP-native; these codes are not HTTP status translations.
	ErrConnectorResourceUnavailable       = newError("52500", "connector resource temporarily unavailable")
	ErrConnectorResourceIdentityRejected  = newError("52501", "connector resource identity rejected")
	ErrConnectorResourceEntitlementDenied = newError("52502", "connector resource entitlement denied")
	ErrConnectorResourceIdentityConflict  = newError("52503", "connector resource identity conflict")
	ErrConnectorResourceQuotaExceeded     = newError("52504", "connector resource quota exceeded")
	ErrConnectorResourceRateLimited       = newError("52505", "connector resource rate limited")
	ErrInvalidConnectorResourceRequest    = newError("52506", "invalid connector resource request")

	// ac
	ErrACOperationFailed       = newError("53001", "ac operation failed")
	ErrACEmptyPassAddress      = newError("53002", "pass address is empty")
	ErrACIPSetNotFound         = newError("53003", "ipset not found")
	ErrACIPSetOperationFailed  = newError("53004", "ipset operation failed")
	ErrACTempPortListenFailed  = newError("53005", "temporary port listening failed")
	ErrACResolveTempPortFailed = newError("53006", "resolve temporary port failed")
	// ErrACDuplicateTransaction — emitted by the AC's NHP_AOP replay
	// dedupe (#1123) when the (sender_pubkey, txid, sendTime) triple
	// was already processed inside the cache TTL. The handler drops
	// the packet without sending NHP_ART so the response channel
	// cannot be used as a replay-success oracle. Message reads
	// "replayed packet" rather than "duplicate transaction id" alone
	// so an oncall reading the error doesn't infer the dedupe key
	// is txid-only and chase the wrong direction.
	ErrACDuplicateTransaction = newError("53007", "ac duplicate transaction (replayed packet)")
	// ErrACMissingPeerPubkey — fail-closed on the upstream invariant
	// that core.responder.validatePeer populates ppd.RemotePubKey
	// before the AC handler runs. A zero-length pubkey here means
	// either a parser regression or a test harness that bypasses
	// validatePeer; in both cases the AC cannot scope replay-dedupe
	// state and so refuses to process the packet. Distinct from
	// ErrACDuplicateTransaction so an oncall chasing a duplicate-
	// spike alert is not misled by an upstream invariant violation.
	ErrACMissingPeerPubkey = newError("53008", "missing peer pubkey on ac transaction")
	// ErrACInvalidOpenTime — defense-in-depth fail-closed against an
	// openTimeSec <= 0 reaching HandleAccessControl. ipset.Add maps the
	// timeout argument verbatim into `ipset add ... timeout N`, and the
	// kernel ipset treats `timeout 0` as PERMANENT (no expiry). The
	// httpac.go refresh handler already short-circuits at
	// RemainingFirewallSeconds() <= 0, so this gate fires only on a
	// regression — but a permanent firewall hole is the worst possible
	// outcome of such a regression, so we double-fence here. See #1942.
	ErrACInvalidOpenTime = newError("53009", "ac invalid openTime (must be > 0)")
	// ErrACSchedulerBreakerOpen — the L3 flush-on-expiry scheduler's
	// circuit breaker is open: too many flush errors within the
	// configured window. HandleAccessControl fails closed at admission
	// rather than admit a session that the AC cannot guarantee it can
	// later tear down. Distinct from ErrACInvalidOpenTime so an oncall
	// triaging an admission denial gets the actionable signal (check
	// scheduler health / recent flusher errors / kernel state) instead
	// of being misled toward an opnTime validation issue.
	ErrACSchedulerBreakerOpen = newError("53010", "ac L3 flush scheduler breaker open (fail-closed admission)")
	// ErrACNilEntry — programmer-error fail-closed: HandleAccessControl
	// was invoked with a nil *AccessEntry. Production callers always
	// pass the pre-stored tokenStore-bound entry (see admitAndIssueToken
	// in endpoints/ac/msghandler.go); non-zero rate signals a future
	// refactor dropped the entry pointer at a caller. Distinct from
	// ErrACEmptyPassAddress (which is a real wire-level admission
	// failure) so an oncall reading artMsg.ErrCode gets the actual
	// failure mode rather than being misdirected toward
	// srcAddrs/dstAddrs validation. See PR #2209.
	ErrACNilEntry                  = newError("53011", "ac HandleAccessControl called with nil entry (programmer error)")
	ErrACSessionControlLeaseClosed = newError("53012", "ac session-control lease is closed")

	// api
	ErrHttpRequestFailed           = newError("54001", "http request failed")
	ErrHttpResponseFormatError     = newError("54002", "http response format error")
	ErrHttpReturnedWithError       = newError("54003", "http returns with error")
	ErrHttpResourceAddressNotFound = newError("54004", "http resource address not found")

	// db
	ErrTEENotAuthorized        = newError("55001", "TEE is not authorized")
	ErrDataPrivateKeyStore     = newError("55002", "data private key store error")
	ErrEvidenceAppraisalFailed = newError("55003", "remote attestation appraisal failed")
	ErrEvidenceGetFailed       = newError("55004", "failed to get evidence")
	ErrDBOffline               = newError("55005", "data broker offline")
)
