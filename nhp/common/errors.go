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
