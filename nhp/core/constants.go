package core

// protocol
const ProtocolVersionMajor = 1
const ProtocolVersionMinor = 0

// device
const (
	MaxMemoryUsage         = 1 * 1024 * 1024 * 1024 // 1GB
	PacketBufferSize       = 4096
	PacketBufferPoolSize   = MaxMemoryUsage / PacketBufferSize
	AllocateTimeToOverload = 2 // 2 seconds
	SendQueueSize          = 10240
	RecvQueueSize          = 10240
)

// decompression
const (
	// MaxDecompressedBodySize caps the plaintext produced by inflating a
	// compressed NHP message body — a decompression-bomb guard (#1131).
	//
	// decryptBody is a post-authentication path (it runs only after the
	// handshake + AEAD succeed) and the whole packet arrives in one UDP datagram
	// read into a single PacketBufferSize buffer (recvPacketRoutine in
	// endpoints/server/udpserver.go; the WebRTC ingest in webrtcserver.go copies
	// into the same Buf), so the compressed body is always < 4 KiB and a single
	// packet can never inflate past ~4 MiB regardless of this constant. The guard
	// is therefore defense-in-depth, and the binding constraint is the largest
	// *legitimate* payload, not the bomb: set the ceiling so no real
	// single-packet body is ever rejected, while staying well under the former
	// 10 MiB.
	//
	// The worst legitimate case is a highly-repetitive AC resource list, where
	// zlib's ratio (not the byte size) is the variable. Measured at the wire
	// limit (~3.8 KiB compressed): distinct entries ~47 KiB (13x), realistic
	// repetition — one AC, sequential hosts/ports — ~73 KiB (20x), and a
	// pathological all-identical list ~1.05 MiB (283x). 1 MiB clears the
	// realistic worst by ~14x and even a 70x ratio (~280 KiB) by ~3.7x — only an
	// (illegitimate) list of thousands of near-duplicate resources could reach it
	// — while cutting a crafted bomb's per-packet decode 10x below the old
	// ceiling. Note the 283x case (~1.05 MiB) lands just *above* 1 MiB and is
	// rejected by design: it is not a legitimate resource list, so a field report
	// of a "rejected huge-but-valid list" should be investigated, not silenced by
	// raising this constant without re-examining the bomb tradeoff. A body
	// inflating past this is rejected with ErrDataDecompressionFailed. Distinct
	// from maxPooledBufferSize in zlibpool.go (16x = 64 KiB), which bounds
	// steady-state pool retention, not a single in-flight decode.
	MaxDecompressedBodySize = 256 * PacketBufferSize // 1 MiB

	// MaxDecompressedBodyWarnSize is 80% of MaxDecompressedBodySize. A successful
	// decode at or above this logs a throttled warning (decryptBody). The band
	// sits far above realistic traffic — the largest measured legitimate body is
	// ~73 KiB vs this ~819 KiB threshold — so a fire signals an anomalously high
	// compression ratio approaching the hard ceiling (a pathological near-
	// duplicate list or a decompression-bomb probe), not normal growth; silent in
	// practice.
	MaxDecompressedBodyWarnSize = MaxDecompressedBodySize * 4 / 5 // 80% = ~819 KiB
)

// session
const (
	MinimalRecvIntervalMs  = 20  // millisecond
	ThreatCountBeforeBlock = 1   // block at 2nd attempt
	CookieRegenerateTime   = 120 // second
	CookieRoundTripTimeMs  = 20  // millisecond
	FailureRetryInterval   = 10  // second
)

// transaction
const (
	AgentLocalTransactionResponseTimeoutMs  = 5 * 1000                                     // millisecond
	ServerLocalTransactionResponseTimeoutMs = AgentLocalTransactionResponseTimeoutMs - 300 // millisecond
	ACLocalTransactionResponseTimeoutMs     = ServerLocalTransactionResponseTimeoutMs      // millisecond

	RemoteTransactionProcessTimeoutMs   = 10 * 1000 // millisecond
	DELocalTransactionResponseTimeoutMs = 5 * 1000
)

// peer
const (
	MinimalPeerAddressHoldTime = 5 // second
)

// hostname resolve
const (
	MinimalNSLookupInterval = 300 // second
)

// packet
const (
	HeaderCommonSize      = 24
	SymmetricKeySize      = 32
	PrivateKeySize        = 32
	PublicKeySize         = 32
	PublicKeySizeEx       = 64
	HashSize              = 32
	CookieSize            = 32
	TimestampSize         = 8
	GCMNonceSize          = 12
	GCMTagSize            = 16
	PublicKeyBase64Size   = 44
	PublicKeyBase64SizeEx = 88
)

// noise
const (
	InitialChainKeyString = "NHP keygen v.20230421@clouddeep.cn"
	InitialHashString     = "NHP hashgen v.20230421@deepcloudsdp.com"
)

// Precomputed []byte views of the noise init strings. Both values are written
// into hash.Hash.Write / MixKey on every packet encrypt and decrypt, and the
// (string -> []byte) conversion otherwise allocates a fresh copy per packet.
// Keeping the package-level slices read-only avoids that per-packet allocation
// in the hot crypto path.
//
// Unexported on purpose: these hold cryptographic init material, and Go has no
// immutable slices — exporting them would let any importer silently corrupt
// every subsequent handshake via core.InitialHashBytes[0] = 0xFF. External
// callers that need the value can still use the exported string constants.
var (
	initialHashBytes     = []byte(InitialHashString)
	initialChainKeyBytes = []byte(InitialChainKeyString)
)
