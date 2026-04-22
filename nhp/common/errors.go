package common

import (
	"errors"
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

func ErrorToErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.ErrorCode()
	}
	return ""
}

func ErrorToString(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Error()
	}
	return ""
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

	// ac
	ErrACOperationFailed       = newError("53001", "ac operation failed")
	ErrACEmptyPassAddress      = newError("53002", "pass address is empty")
	ErrACIPSetNotFound         = newError("53003", "ipset not found")
	ErrACIPSetOperationFailed  = newError("53004", "ipset operation failed")
	ErrACTempPortListenFailed  = newError("53005", "temporary port listening failed")
	ErrACResolveTempPortFailed = newError("53006", "resolve temporary port failed")

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
