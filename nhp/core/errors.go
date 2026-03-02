package core

import (
	"errors"
	"strconv"
)

var errorMap map[int]*Error = make(map[int]*Error)

type Error struct {
	num         int
	msg         string
	extraErr    error
	hasExtraErr bool
}

func (e *Error) SetExtraError(err error) {
	e.extraErr = err
	if err != nil {
		e.hasExtraErr = true
	}
}

// implment NhpError interface
func (e *Error) Error() string {
	if e.hasExtraErr {
		e.hasExtraErr = false
		defer e.SetExtraError(nil)
		return e.msg + ": " + e.extraErr.Error()
	}
	return e.msg
}

func (e *Error) ErrorCode() string {
	return strconv.Itoa(e.num)
}

func (e *Error) ErrorNumber() int {
	return e.num
}

func newError(number int, msg string) *Error {
	e := &Error{
		num: number,
		msg: msg,
	}
	errorMap[e.num] = e
	return e
}

func ErrorToErrorNumber(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.ErrorNumber()
	}
	return -1
}

func ErrorToString(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Error()
	}
	return ""
}

func ErrorCodeToError(number int) *Error {
	e, found := errorMap[number]
	if found {
		return e
	}
	return nil // should not happen
}

// device sdk errors
var (
	ErrSuccess = newError(errNhpSuccess, "")

	// device
	ErrCipherNotSupported = newError(errNhpCipherNotSupported, "cipher scheme not supported")
	ErrNotApplicable      = newError(errNhpOperationNotApplicable, "operation not applicable")
	ErrCreateDeviceFailed = newError(errNhpCreateDeviceFailed, "failed to create nhp device")
	ErrCloseDeviceFailed  = newError(errNhpCloseDeviceFailed, "attempt to close a non-initialized nhp device")
	ErrRuntimePanic       = newError(errNhpSdkRuntimePanic, "runtime panic encountered")

	// initiator and encryption
	ErrWrongCipherScheme       = newError(errNhpWrongCipherScheme, "a wrong cipher scheme is used")
	ErrEmptyPeerPublicKey      = newError(errNhpEmptyPeerPublicKey, "remote peer public key is not set")
	ErrEphermalECDHPeerFailed  = newError(errNhpEphermalEcdhPeerFailed, "ephermal ECDH failed with peer")
	ErrDeviceECDHPeerFailed    = newError(errNhpDeviceEcdhPeerFailed, "device ECDH failed with peer")
	ErrIdentityTooLong         = newError(errNhpIdentityTooLong, "identity exceeds max length")
	ErrDataCompressionFailed   = newError(errNhpDataCompressionFailed, "data compression failed")
	ErrPacketSizeExceedsBuffer = newError(errNhpPacketSizeExceedsBuffer, "packet size longer than send buffer")

	// responder and decryption
	ErrCloseConnection                = newError(errNhpCloseConnection, "disengage nhp access immediately")
	ErrIncorrectPacketSize            = newError(errNhpIncorrectPacketSize, "incorrect packet size")
	ErrMessageTypeNotMatchDevice      = newError(errNhpMessageTypeNotMatchDevice, "message type does not match device")
	ErrServerOverload                 = newError(errNhpServerOverload, "the packet is dropped due to server overload")
	ErrHMACCheckFailed                = newError(errNhpHmacCheckFailed, "HMAC validation failed")
	ErrServerHMACCheckFailed          = newError(errNhpServerHmacCheckFailed, "server HMAC validation failed")
	ErrDeviceECDHEphermalFailed       = newError(errNhpDeviceEcdhEphermalFailed, "device ECDH failed with ephermal")
	ErrPeerIdentityVerificationFailed = newError(errNhpPeerIdentityVerificationFailed, "failed to verify peer's identity with apk")
	ErrAEADDecryptionFailed           = newError(errNhpAeadDecryptionFailed, "aead decryption failed")
	ErrDataDecompressionFailed        = newError(errNhpDataDecompressionFailed, "data decompression failed")
	ErrDeviceECDHObtainedPeerFailed   = newError(errNhpDeviceEcdhObtainedPeerFailed, "device ECDH failed with obtained peer")
	ErrServerRejectWithCookie         = newError(errNhpServerRejectWithCookie, "server overload, stop processing packet and return cookie")
	ErrReplayPacketReceived           = newError(errNhpReplayPacketReceived, "received replay packet, drop")
	ErrFloodPacketReceived            = newError(errNhpFloodPacketReceived, "received flood packet, drop")
	ErrStalePacketReceived            = newError(errNhpStalePacketReceived, "received stale packet, drop")
)
