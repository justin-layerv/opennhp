package core

// NHP error codes are pure Go constants matching nhpdevicedef.h for the
// upstream range. LayerV protocol extensions append new non-conflicting values
// here; the C bridge forwards every NhpError number without its own enum.
const (
	// General errors
	errNhpSuccess              = 0
	errNhpDeviceNotInitialized = 30000
	errNhpDeviceAlreadyCreated = 30001
	errNhpCipherNotSupported   = 30002
	errNhpCreateDeviceFailed   = 30004
	errNhpCloseDeviceFailed    = 30005
	errNhpSdkRuntimePanic      = 30006

	// Encryption errors
	errNhpWrongCipherScheme       = 31000
	errNhpEmptyPeerPublicKey      = 31001
	errNhpEphermalEcdhPeerFailed  = 31002
	errNhpDeviceEcdhPeerFailed    = 31003
	errNhpIdentityTooLong         = 31004
	errNhpDataCompressionFailed   = 31005
	errNhpPacketSizeExceedsBuffer = 31006

	// Decryption errors
	errNhpCloseConnection                = 32001
	errNhpIncorrectPacketSize            = 32002
	errNhpMessageTypeNotMatchDevice      = 32003
	errNhpServerOverload                 = 32004
	errNhpHmacCheckFailed                = 32005
	errNhpServerHmacCheckFailed          = 32006
	errNhpDeviceEcdhEphermalFailed       = 32007
	errNhpPeerIdentityVerificationFailed = 32008
	errNhpAeadDecryptionFailed           = 32009
	errNhpDataDecompressionFailed        = 32010
	errNhpDeviceEcdhObtainedPeerFailed   = 32011
	errNhpServerRejectWithCookie         = 32012
	errNhpReplayPacketReceived           = 32013
	errNhpFloodPacketReceived            = 32014
	errNhpStalePacketReceived            = 32015
	errNhpPeerNotFound                   = 32016
	errNhpPeerExpired                    = 32017
	errNhpPeerAddressMismatch            = 32018
	errNhpHubLSTCookieProofRequired      = 32019
	errNhpInvalidHubLSTCookieProof       = 32020
	errNhpInvalidHubLSTFlags             = 32021
	errNhpUnsupportedProtocolVersion     = 32022
)
