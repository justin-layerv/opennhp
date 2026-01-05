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

func ErrorToErrorCode(err error) string {
	e, ok := err.(*Error)
	if ok {
		return e.ErrorCode()
	}
	return ""
}

func ErrorToString(err error) string {
	e, ok := err.(*Error)
	if ok {
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
