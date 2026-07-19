package core

import (
	"strconv"
)

type Error struct {
	num      int
	msg      string
	extraErr error
}

// WithExtra returns a new Error with the same code and message, carrying the
// given extra error for context. Unlike the old SetExtraError, this does not
// mutate the receiver, so package-level sentinel errors remain safe for
// concurrent use.
func (e *Error) WithExtra(err error) *Error {
	return &Error{
		num:      e.num,
		msg:      e.msg,
		extraErr: err,
	}
}

// implment NhpError interface
func (e *Error) Error() string {
	if e.extraErr != nil {
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
	return &Error{
		num: number,
		msg: msg,
	}
}

// device sdk errors
var (
	ErrSuccess = newError(errNhpSuccess, "")

	// device
	ErrCipherNotSupported = newError(errNhpCipherNotSupported, "cipher scheme not supported")
	ErrCreateDeviceFailed = newError(errNhpCreateDeviceFailed, "failed to create nhp device")
	ErrCloseDeviceFailed  = newError(errNhpCloseDeviceFailed, "attempt to close a non-initialized nhp device")
	// ErrRuntimePanic's message text is load-bearing for the
	// server-async-runtime-panic CloudWatch log metric filter in
	// terraform/modules/monitoring/main.tf. Keep it in lockstep with the
	// msgToPacketRoutine recovery log in device.go and the Terraform pattern.
	ErrRuntimePanic = newError(errNhpSdkRuntimePanic, "runtime panic encountered")

	// initiator and encryption
	ErrWrongCipherScheme       = newError(errNhpWrongCipherScheme, "a wrong cipher scheme is used")
	ErrEmptyPeerPublicKey      = newError(errNhpEmptyPeerPublicKey, "remote peer public key is not set")
	ErrEphermalECDHPeerFailed  = newError(errNhpEphermalEcdhPeerFailed, "ephermal ECDH failed with peer")
	ErrDeviceECDHPeerFailed    = newError(errNhpDeviceEcdhPeerFailed, "device ECDH failed with peer")
	ErrIdentityTooLong         = newError(errNhpIdentityTooLong, "identity exceeds max length")
	ErrDataCompressionFailed   = newError(errNhpDataCompressionFailed, "data compression failed")
	ErrPacketSizeExceedsBuffer = newError(errNhpPacketSizeExceedsBuffer, "packet size longer than send buffer")

	// responder and decryption
	ErrCloseConnection           = newError(errNhpCloseConnection, "disengage nhp access immediately")
	ErrIncorrectPacketSize       = newError(errNhpIncorrectPacketSize, "incorrect packet size")
	ErrMessageTypeNotMatchDevice = newError(errNhpMessageTypeNotMatchDevice, "message type does not match device")
	ErrServerOverload            = newError(errNhpServerOverload, "the packet is dropped due to server overload")
	// Renamed from ErrHMACCheckFailed per #1126: the verified value is an
	// unkeyed header digest, not a MAC (see curve.HeaderCurve.HeaderDigest).
	// The message string + error code (32005/32006) are intentionally kept
	// as-is — "HMAC validation failed" is an operator-facing log breadcrumb
	// documented in terraform; renaming it would churn runbooks for no gain.
	ErrHeaderDigestCheckFailed        = newError(errNhpHmacCheckFailed, "HMAC validation failed")
	ErrServerHeaderDigestCheckFailed  = newError(errNhpServerHmacCheckFailed, "server HMAC validation failed")
	ErrDeviceECDHEphermalFailed       = newError(errNhpDeviceEcdhEphermalFailed, "device ECDH failed with ephermal")
	ErrPeerIdentityVerificationFailed = newError(errNhpPeerIdentityVerificationFailed, "failed to verify peer's identity with apk")
	ErrAEADDecryptionFailed           = newError(errNhpAeadDecryptionFailed, "aead decryption failed")
	ErrDataDecompressionFailed        = newError(errNhpDataDecompressionFailed, "data decompression failed")
	ErrDeviceECDHObtainedPeerFailed   = newError(errNhpDeviceEcdhObtainedPeerFailed, "device ECDH failed with obtained peer")
	ErrServerRejectWithCookie         = newError(errNhpServerRejectWithCookie, "server overload, stop processing packet and return cookie")
	ErrReplayPacketReceived           = newError(errNhpReplayPacketReceived, "received replay packet, drop")
	ErrFloodPacketReceived            = newError(errNhpFloodPacketReceived, "received flood packet, drop")
	ErrStalePacketReceived            = newError(errNhpStalePacketReceived, "received stale packet, drop")
	// ErrPeerNotFound's message text "peer not found in peer pool" is
	// LOAD-BEARING for the smoke regression fence in
	// tests/smoke/09_ac_redispatch_loop_test.go (regex:
	// /Refresh NHP_AOL to .* failed: peer not found in peer pool/).
	// A wording change here will silently break the #1680 regression
	// smoke fence — endpoints/ac/registration_reconcile_test.go's
	// TestACRegistration_SmokeLogSubstringsPresent reads this file
	// and asserts the substring is present at unit-test time, so
	// the build/lint will fail if the wording changes without a
	// lockstep update of the smoke regex. #1714 tracks replacing
	// the substring fence with stable structured tags.
	ErrPeerNotFound        = newError(errNhpPeerNotFound, "peer not found in peer pool")
	ErrPeerExpired         = newError(errNhpPeerExpired, "peer expired")
	ErrPeerAddressMismatch = newError(errNhpPeerAddressMismatch, "peer does not match its previous address")
	// ErrHubLSTCookieProofRequired is returned only on the exact opt-in
	// assignment-Hub LST path after a cryptographically valid source-unproven
	// request. A HubLSTCookieChallengeError wrapping this sentinel carries the
	// smaller encrypted COK datagram when reflection-safe emission is possible.
	ErrHubLSTCookieProofRequired = newError(errNhpHubLSTCookieProofRequired, "hub LST return-routability proof required")
	ErrInvalidHubLSTCookieProof  = newError(errNhpInvalidHubLSTCookieProof, "invalid hub LST cookie proof configuration")
	ErrInvalidHubLSTFlags        = newError(errNhpInvalidHubLSTFlags, "invalid hub LST header flags")
)
