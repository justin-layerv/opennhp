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
