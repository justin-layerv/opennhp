package server

import (
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	MaxACConnsPerID             = 10                              // max AC connections per AC ID (blue/green)
	MaxConcurrentConnection     = 20480                           // global cap on remoteConnectionMap and blockAddrMap entries; per-IP fairness via MaxAgentConnsPerIP
	OverloadConnectionThreshold = MaxConcurrentConnection * 4 / 5 // 80%
	// MaxAgentConnsPerIP: per-source-IP cap on agent UdpConn entries
	// (AC/DB bypass via the IP gate in admitNewConnection). 16 leaves
	// headroom for a small-office NAT (~10 simultaneous knockers);
	// evictions on legit traffic should be near-zero. Sustained
	// MetricAgentConnPerIPEvictions on a known-NAT IP argues for
	// raising the cap once #1526 makes it configurable.
	MaxAgentConnsPerIP              = 16
	BlockAddrRefreshRate            = 20                                   // 20 seconds
	BlockAddrExpireTime             = 90                                   // 90 seconds
	PreCheckThreatCountBeforeBlock  = 5                                    // block source address if packet precheck errors exceeds this count
	DefaultAgentConnectionTimeoutMs = common.ClientSideConnectionTimeoutMs // 30 seconds to delete idle connection
	DefaultACConnectionTimeoutMs    = common.ServerSideConnectionTimeoutMs // 300 seconds to delete idle connection
	DefaultDBConnectionTimeoutMs    = common.ServerSideConnectionTimeoutMs // 300 seconds to delete idle connection
	PacketQueueSizePerConnection    = 256
	// MaxConcurrentHandlers bounds in-flight agent-facing handler
	// goroutines dispatchReceivedMessage runs concurrently. Per-packet
	// async dispatch is deliberate (#1163: a slow handler must not
	// head-of-line-block the receive path), but the spawn was unbounded.
	// The fork's per-IP rate limiter (100 pps, ratelimiter.go) already
	// neutralizes upstream's stated single-peer threat, but it is keyed
	// on source IP: a spoofed-source or distributed knock flood bypasses
	// per-IP fairness, and MaxConcurrentConnection bounds only unique
	// remote addrs — not how many in-flight handlers exist across them.
	// In cloud mode an unknown agent's knock reaches HandleKnockRequest,
	// which holds its slot for the handler's full duration — dominated by
	// the AC-open round-trip, up to ~3.3s on the reknock-retry path (two
	// 1.5s transaction timeouts + defaultReknockRetryBackoff) and longer
	// still if a plugin/DDB call stalls — so under a flood handlers
	// accumulate faster than they retire and drive the process toward OOM.
	// This ceiling converts that tail from a crash into a graceful shed
	// (MetricHandlerBudgetExhausted). The total is partitioned below:
	// ordinary first-flight agent work can consume only
	// HandlerGeneralCapacity, while cookie-proven RKNs and authenticated
	// relay envelopes can fall back to the protected reserve. Filling the
	// general partition also enables overload-cookie mode, so a legitimate
	// direct client can progress from KNK to source-bound RKN and reach the
	// reserve instead of retrying an already-saturated KNK path.
	// The ceiling is load-bearing on every agent-facing handler being
	// TIME-BOUNDED (ServerACOpenTransactionResponseTimeoutMs and friends):
	// a slot only returns when fn returns, so a future handler that could
	// block forever would erode the effective budget monotonically. 4096
	// is sized to absorb a large legitimate burst even at a slow-AC hold
	// (budget/hold headroom) while capping worst-case in-flight goroutine
	// memory well under the box and sitting 5× below MaxConcurrentConnection;
	// it matches upstream OpenNHP bc499d7c (#1552 H2). The right value is
	// fleet-dependent (decrypt throughput × handler latency) — #3099 tracks
	// making it operator-tunable. Infra arms (AOL/DOL/FWD/FRT/RVA) are
	// intentionally NOT bounded — see dispatchReceivedMessage for the
	// per-arm trust rationale.
	MaxConcurrentHandlers = 4096

	// HandlerProtectedReserve is capacity a source-rotating/spoofed KNK flood
	// cannot consume. NHP_RKN reaches it only after core verifies its stateless
	// overload cookie (return-routability proof); NHP_RLY reaches it because its
	// outer Noise identity is a configured relay. Both prefer general capacity
	// when available, retaining the reserve for actual contention.
	HandlerProtectedReserve = MaxConcurrentHandlers / 4
	HandlerGeneralCapacity  = MaxConcurrentHandlers - HandlerProtectedReserve
)

// The general partition is derived from the total, so equality cannot drift.
// These assertions instead guard the two meaningful invariants: both
// partitions must retain at least one slot.
const (
	_ = uint(HandlerProtectedReserve - 1)
	_ = uint(HandlerGeneralCapacity - 1)
)

// Compile-time assertion that MaxAgentConnsPerIP ≥ 1. The eviction
// loop in admitNewConnection assumes a non-empty bucket implies a
// non-nil Front; if the cap is ever set to 0, this constant fails to
// compile. Replace with a config-load clamp once #1526 makes the cap
// dynamic.
const _ = uint(MaxAgentConnsPerIP - 1)

// http APIs
//
// Contract: `IdleTimeoutMs >= proxy_origin_keepalive + buffer` whenever this
// server runs behind a connection-pooling proxy. CloudFront's
// `origin_keepalive_timeout` is set to 30s in
// `terraform/main.tf::aws_cloudfront_distribution.qurl_resolve`, so 36s here
// keeps the documented 5s buffer with 1s of real slack above the contract
// floor. A lower value re-opens the resolve.qurl.link 502 race (CF reuses
// an idle conn the server has FIN'd; next POST gets RST; CF surfaces 502
// because POSTs aren't retried). LayerV diverges from upstream OpenNHP
// defaults (4500/5500/6000); see docs/UPSTREAM_SYNC.md.
const (
	DefaultHttpRequestReadTimeoutMs   = 30000 // millisecond
	DefaultHttpResponseWriteTimeoutMs = 30000 // millisecond
	DefaultHttpServerIdleTimeoutMs    = 36000 // millisecond
)

// broadcast
const (
	// DefaultBroadcastTimeout caps per-goroutine time in
	// processACOperationBroadcast — i.e., how long the server waits for an
	// AC peer to ACK an NHP-AOP. It's intentionally independent of the
	// HTTP envelope timeouts above (those bound CF↔server connection
	// state; this one bounds AC-side processing). It is only a BACKSTOP above
	// the per-AC AOP transaction timeout (ServerACOpenTransactionResponseTimeoutMs,
	// 1.5s): that transaction timeout MUST fire first so a dead AC surfaces the
	// ErrTransactionFailedByTimeout the reknock retry keys on (fenced by
	// TestBroadcastTimeoutExceedsTransactionTimeout). 3s keeps a comfortable 2×
	// margin over that 1.5s while still cutting off a wedged AC fast — AC startup
	// jitter is now absorbed by the fast idempotent retry, not a long wait here.
	DefaultBroadcastTimeout = 3 * time.Second
)

// knock
const (
	DefaultIpOpenTime              = 120 // second, align with ipset default timeout
	ACOpenCompensationTime         = 5   // second
	TokenStoreRefreshInterval      = common.TokenStoreRefreshInterval
	DefaultCookieTimeWindowSeconds = 60
)

// defaultReknockRetryBackoff is the pause broadcastACOpenWithReknock waits before it
// re-snapshots AC connections and retries an AC open whose every connection hit the
// transaction timeout (the blue/green reassignment-window transient,
// qurl-service#976). Sized to let processACOperation's conn.Close() prune the dead
// conn and the re-snapshot pick up a still-live SIBLING conn — NOT to let a brand-new
// AC registration land: a genuine re-register runs NHP_AOL + server-side bcrypt
// (the dedicated NHP_AOL failure ceiling exists for), which will not
// finish in 300ms. So the retry's recovery vector is an already-registered green conn
// (blue/green keeps several per acId via MaxACConnsPerID); a single-conn AC with no
// sibling deterministically hits NoFreshConns and relies on the client's next
// re-knock. The backoff also bounds the retry's ADDED latency:
// the 1.5s transaction timeout twice + this ≈ 3.3s. That is only the AC-open slice of
// the knock budget — the admission round-trips (prepare/authorize) and NHP
// transaction setup run BEFORE AC-open, so the real end-to-end headroom is the
// budget − (admission + setup); TestReknockRetryFitsKnockProcessingBudget fences the
// AC-open slice, which is necessary but not sufficient. The end-to-end bound is
// enforced separately by HttpKnockProcessingBudget (below): the reknock retry
// short-circuits when less than one transaction timeout of that budget remains, so a
// slow admission cannot let the doubled AC-open push a knock past the caller's
// budget.
//
// broadcastACOpenWithReknock reads UdpServer.reknockRetryBackoff and falls back to
// this const when that field is zero — the production default. Only tests set the
// field (via shortenReknockBackoff), so this const is always the production value and
// TestReknockRetryFitsKnockProcessingBudget can assert against it directly. Keeping the
// override per-instance (not a package var) means those tests mutate only their own
// server, so a future t.Parallel() reknock test cannot race it.
const defaultReknockRetryBackoff = 300 * time.Millisecond

// HttpKnockProcessingBudget is the wall-clock budget withKnockProcessingBudget
// stamps on an HTTP knock's context (see that helper for WHAT the deadline does and
// does not bound, and which paths carry it). The knock is user-facing core infra, so
// this is kept tight at 5s — comfortably above the worst-case AC-open (2×1.5s txn +
// 300ms backoff ≈ 3.3s) plus admission, and well UNDER qurl-service's knock-client
// budget so the server always returns a clean timeout before the caller gives up
// (the reknock retry additionally short-circuits when less than one transaction
// timeout of budget remains). TestReknockRetryFitsKnockProcessingBudget fences the
// AC-open slice against this.
//
// Cross-repo lockstep: qurl-service's knock client caps its HTTP call at
// internal/nhp.defaultTimeout (7s), deliberately kept a couple of seconds ABOVE
// this budget so that client receives the server's authoritative answer rather than
// racing it. If you raise this budget, raise that client timeout in lockstep (the
// coupling is comment-only — nothing across the two repos enforces it at build time).
const HttpKnockProcessingBudget = 5 * time.Second
