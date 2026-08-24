package core

// protocol
const ProtocolVersionMajor = 1

// ProtocolVersionMinor 1 is the transcript that binds the serialized
// HeaderCommon (preamble, type, payload size, version, flags, counter) into the
// AEAD chain hash before the body AAD. Under 1.0 those bytes were covered only
// by the unkeyed HeaderDigest, which anyone holding the peer's static PUBLIC key
// can recompute, so the flag word and header type were forgeable in flight.
const ProtocolVersionMinor = 1

// MinimumRecvProtocolVersionMinor is the oldest minor whose body AAD this codec
// can reproduce. A 1.0 sender folds a shorter transcript, so its body tag can
// never verify here; receivers reject it on the version instead, otherwise a
// mixed-version rollout surfaces as an opaque AEAD failure that reads like key
// mismatch or corruption.
//
// THE RULE FOR ANY FUTURE MINOR — the receive gate pins the major and FLOORS the
// minor, so it admits every minor at or above this constant. That is deliberate
// (a compatible release must not strand deployed clients) and it is only sound
// while every admitted minor produces the SAME body AAD transcript. So:
//
//   - A minor that does NOT affect the AAD is the only kind safe to ship without
//     touching this constant. Admitting it silently is the point.
//   - A minor that DOES affect the AAD — anything that changes what is folded
//     into the chain hash, in what order, or in what serialization — MUST raise
//     this constant in the same change, or be a major bump instead.
//
// Getting that wrong cannot be repaired later: a fielded receiver at the old
// minor will ADMIT the new packet at this gate and then fail the body Open with
// ErrAEADDecryptionFailed — reintroducing exactly the opaque, unattributable
// failure this gate exists to remove, on nodes that can no longer be taught
// otherwise. The floor is a promise to already-deployed receivers, not just a
// switch for new ones.
//
// MIN_PROTOCOL_VERSION_MINOR in endpoints/js-agent/src/crypto/packet.ts is the
// same gate for the browser codec and moves in lockstep with this constant.
const MinimumRecvProtocolVersionMinor = 1

// device
const (
	MaxMemoryUsage   = 1 * 1024 * 1024 * 1024 // 1GB
	PacketBufferSize = 4096
	// RelayPacketBufferSize is reserved for the authenticated NHP_RLY outer
	// transport. A maximum-size direct NHP packet (4096 bytes) expands to at
	// most 5844 bytes when base64-wrapped with a request ID and a full textual
	// IPv6 source address, then sealed under the 240-byte Curve header and
	// 16-byte body tag. That headroom assumes a zoneless IPv6 string; native and
	// trusted-header ingress both normalize through net.IP, so a zone identifier
	// cannot reach SourceAddr. Six KiB carries the envelope without widening the
	// direct-agent packet limit or every device's pooled buffer. Relay buffers
	// come from a separate sync.Pool and therefore are not charged against the
	// standard device pool's overload accounting; callers must place them only
	// behind the relay/server admission and queue bounds documented at their
	// allocation sites.
	RelayPacketBufferSize  = 6 * 1024
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
	// handshake + AEAD succeed). Standard packets are capped at PacketBufferSize;
	// the only exception is the authenticated RelayPacketBufferSize outer
	// transport, which this implementation sends uncompressed. Even a malicious
	// authenticated relay's compressed 6 KiB envelope remains bounded here, so
	// the guard is defense-in-depth and the binding constraint is the largest
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
	// FailureRetryInterval is the agent's backoff after a failed knock before it
	// re-knocks (endpoints/agent/udpagent.go). The knock is user-facing core infra,
	// so this is DNS-fast at 2s rather than 10s: after a transient failure the agent
	// re-establishes access in a couple of seconds, not ten. Flood protection does
	// NOT rest on this backoff — the server's per-source-IP token-bucket rate limiter
	// (endpoints/server/ratelimiter.go) is the real defense: after the burst/2 starter
	// it bounds a single source IP to the configured token refill rate no matter how
	// fast that IP re-knocks, so a stuck/looping agent is capped server-side by the
	// bucket, not by this sleep — tightening it here does not weaken that posture.
	FailureRetryInterval = 2 // second
)

// staleness floor (#1464) — the maximum age, in seconds, that a
// received packet's AEAD-authenticated send timestamp may lag the
// local receive time before the packet is rejected as stale in
// nhp/core/responder.go. See recvStalenessFloor for the dispatch.
const (
	// DefaultRecvStalenessFloorSeconds is the historical, generous
	// floor applied to every (deviceType, peerType, msgType) the
	// AOP-specific override below does not match. Kept at 600 s so
	// agent→server knocks (which may traverse the public internet
	// with looser clock-calibration assumptions) are byte-for-byte
	// unchanged by #1464.
	DefaultRecvStalenessFloorSeconds = 600

	// HubLSTFutureSkewLimitSeconds is the maximum amount by which an
	// unregistered public Hub LST's authenticated send timestamp may lead the
	// Hub receive clock. Keep the responder gate and the endpoint replay cache
	// derived from this single protocol value.
	HubLSTFutureSkewLimitSeconds = 30

	// HubLSTReplayWindowSeconds is the inclusive interval during which an exact
	// public Hub LST can remain cryptographically valid: a packet accepted at
	// the future-skew boundary remains within the default past-staleness floor
	// through this full interval. Endpoint replay state must retain a digest at
	// the exact boundary and may expire it only after this interval.
	HubLSTReplayWindowSeconds = DefaultRecvStalenessFloorSeconds + HubLSTFutureSkewLimitSeconds

	// AOPRecvStalenessFloorSeconds is the tighter floor for NHP_AOP
	// (server→AC). recvStalenessFloor documents WHY AOP gets one (the
	// cross-restart replay window of #1464); this constant is the
	// canonical home for the VALUE. AOP is server→AC, intra-VPC (NLB,
	// sub-ms), both LayerV-controlled hosts running NTP, so 120 s is 2×
	// the one-direction wall-clock skew budget documented in
	// endpoints/ac/aop_replay_cache.go — comfortable margin against
	// clock-step-at-boot and recv-queue-delay false-rejects, which for
	// AOP drop the packet but do NOT block the connection (see
	// shouldEscalateStale) — while still shrinking the replay window 5×
	// versus the 600 s default.
	AOPRecvStalenessFloorSeconds = 120
)

// transaction
const (
	AgentLocalTransactionResponseTimeoutMs = 5 * 1000 // millisecond
	// ServerLocalTransactionResponseTimeoutMs is the wait for EVERY server-INITIATED
	// local transaction OTHER than the AC-open — Device.LocalTransactionTimeout returns
	// it for a NHP_SERVER device on all message types except NHP_AOP (see
	// nhp/core/transaction.go). That set includes the DB private-key-wrapping NHP_DWR
	// (a TEE/KMS crypto op with NO retry wrapper) and forwarded knocks NHP_FWD, neither
	// of which is intra-VPC-fast or idempotently retried — so this stays at the
	// historical 4.7s. The AC-open (NHP_AOP) is DNS-fast on its own, decoupled
	// constant below; do NOT lower this one to speed the knock (that was the #3046
	// review's blast-radius catch — it would risk failing a cold-TEE DB wrap at 1s).
	ServerLocalTransactionResponseTimeoutMs = AgentLocalTransactionResponseTimeoutMs - 300 // millisecond
	// ServerACOpenTransactionResponseTimeoutMs is the server→AC (NHP-AOP) wait — the
	// AC-open on the qURL knock hot path, user-facing core infra (click link → resource
	// opens) that must be DNS-fast. Routed ONLY to NHP_AOP by LocalTransactionTimeout,
	// so it does not touch the DB/forward paths above. The path is intra-VPC (server→AC
	// over the internal NLB, both LayerV-controlled), so a healthy AC ACKs in
	// sub-ms-to-low-ms and the happy path returns the instant that ACK lands — this
	// bounds only the FAILURE case (a torn-down ACK path during a blue/green AC
	// reassignment). Kept low at 1.5s (vs the old shared 4.7s) so a dead ACK path is
	// detected fast and the idempotent AC-open re-knock retry
	// (endpoints/server/ac_open_reknock_retry.go, which incurs this timeout twice:
	// initial + one retry) stays cheap — 2×1.5s + backoff ≈ 3.3s worst case, well inside
	// the agent's 5s wait above (the old shared 4.7s made the doubled retry ~10s, which
	// OVERRAN that 5s agent wait).
	//
	// WHY 1.5s and not 1s: this budget covers more than the network RTT. The AC applies
	// the ipset/eBPF rule (admitAndIssueToken → HandleAccessControl) BEFORE it sends the
	// NHP_ART ACK (endpoints/ac/msghandler.go::HandleUdpACOperations), so a slow datapath
	// write — ipset/eBPF map-lock contention under a knock burst, or an AC GC pause — is
	// inside this budget; a false timeout there tears down that AC conn (→ re-register +
	// reknock churn), and a single-conn AC with no sibling hard-fails 52005 with no
	// server-side recovery. 1.5s widens the margin over the datapath write vs a tighter
	// 1s while staying comfortably under the 5s budget; the idempotent retry absorbs the
	// client-facing failure. AC conn teardown/re-register rate is still the first-rollout
	// watch item (see the #3046 rollout-ledger entry); raise this constant (decoupled for
	// exactly that) if p99 datapath-write-under-burst approaches it. Fenced by
	// TestReknockRetryFitsKnockProcessingBudget.
	ServerACOpenTransactionResponseTimeoutMs = 1500 // millisecond (1.5s)
	// ACRegistrationTransactionResponseTimeoutMs bounds NHP_AOL registration.
	// The normal path returns as soon as AAK arrives; this is only a failure
	// ceiling. It exceeds the server's complete remote-transaction budget by one
	// second so the AC retains the temporary NLB peer/socket through direct
	// NHP_REV retries and the server's terminal response without adding a second
	// independent wait to the fast path.
	ACRegistrationTransactionResponseTimeoutMs = RemoteTransactionProcessTimeoutMs + 1000
	// ACLocalTransactionResponseTimeoutMs retains the existing fail-fast bound
	// for any other AC-initiated transaction.
	ACLocalTransactionResponseTimeoutMs = AgentLocalTransactionResponseTimeoutMs - 300 // millisecond

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
