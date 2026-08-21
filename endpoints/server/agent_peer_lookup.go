// Package server — agent peer DDB+LRU lookup on knock receipt.
//
// In cloud mode the agent registry lives in the qurl-agent-keys
// DynamoDB table (PK=owner_id, SK=agent_id; pubkey-index GSI
// hashed on public_key). nhp-server discovers an agent on its
// first knock: the noise responder runs with
// DisableAgentPeerValidation=true so an unknown-but-registered
// agent's packet reaches HandleKnockRequest; the handler resolves
// ppd.RemotePubKey via this lookup, AddAgentPeer's the result, and
// subsequent knocks short-circuit through the in-process
// agentPeerMap.
//
// We deliberately don't distinguish "never registered" from
// "DDB read failed" on the wire — the agent sees the same generic
// reject in both cases, and the structured logs
// (event="agent_unknown_pubkey" vs event="agent_lookup_ddb_error")
// are the only place ops can tell them apart.
//
// Phase-1 revocation contract: once a knock from a registered
// agent succeeds, the resolved peer is written into the in-process
// agentPeerMap, where it has no TTL and no eviction path.
// Subsequent knocks short-circuit there before the 60s LRU TTL is
// consulted, so a deleted DDB row continues to be admitted until
// the nhp-server process restarts. This matches the operational
// cadence of an ASG rolling refresh; active-knock revocation
// across a running process is tracked as #1943 (see the godoc on
// agentPeerLookupCacheTTL).
//
// AC peer registry stays on etcd; migrating it to the same
// DDB+LRU pattern is a follow-up.
package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/layervai/nhp/internalauth"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sync/singleflight"
)

const (
	// agentPeerLookupCacheSize bounds the LRU at 2048 entries.
	// Per entry: 44B pubkey b64 + the *core.UdpPeer (PubKeyBase64 +
	// Type byte; queryAndCache deliberately leaves Ip/Hostname/Port/
	// keys empty — see the godoc on AgentPeerLookup) +
	// agentCacheEntry wrapper + LRU list/map overhead. Realistic
	// per-entry footprint is on the order of low hundreds of bytes,
	// so worst-case total is well under 1MB. Cap exists to bound
	// memory under a fuzz/scan storm, not to fit a strict envelope.
	agentPeerLookupCacheSize = 2048

	// agentPeerLookupCacheTTL bounds how long a cached resolve survives
	// in this lookup's LRU. The "Cache" in the name is deliberate:
	// this is NOT the full revocation horizon for a registered agent.
	// Once a knock succeeds,
	// resolveAgentPeerForKnock writes the peer into
	// UdpServer.agentPeerMap (no TTL, no eviction path), and every
	// subsequent knock from that pubkey short-circuits before
	// LookupAgentByPubKey is reached. So in practice an agent
	// registered before its DDB row was deleted continues to be
	// admitted until the nhp-server process restarts. Active-knock
	// revocation across a running process is tracked as #1943;
	// passive revocation (process restart) flushes both caches.
	agentPeerLookupCacheTTL = 60 * time.Second

	// unwrapMaxHops caps the depth of the storage decorator chain
	// walked by unwrapDynamoDBStorage. Today CreateStorageBackend
	// builds at most CachedStorage → LoggingStorage → MetricsStorage
	// → DynamoDBStorage (4 levels including the leaf), so the
	// bound has large headroom. Defends against a future cycle
	// (A → B → A) that the single-step self-loop check above
	// wouldn't catch.
	unwrapMaxHops = 16

	// agentPeerLookupIndexName is the GSI hashed on public_key. Defined in
	// internalauth so nhp-server and qurl-service compile against the same
	// contract instead of duplicating a string literal.
	agentPeerLookupIndexName = internalauth.QURLAgentKeysPubkeyIndexName

	// agentPeerLookupMaxProjectedRows bounds how many pubkey-index rows the
	// reader will inspect for one public_key. Normal state is exactly one row;
	// same-owner re-bootstrap duplicates are expected to be rare and small. If
	// a GSI partition exceeds this cap, the reader rejects fail-closed instead
	// of admitting before it can prove there is no hidden distinct-owner row.
	// Raising this cap must revisit DynamoDBOperationTimeout because the Query
	// and all candidate GetItems intentionally share one total resolve budget.
	agentPeerLookupMaxProjectedRows = 16

	// agentPeerLookupQueryLimit asks DynamoDB for one sentinel row beyond the
	// inspected-row cap. That keeps exactly agentPeerLookupMaxProjectedRows
	// same-owner candidates unambiguous while still rejecting 17+ candidates
	// before issuing base-table GetItems.
	agentPeerLookupQueryLimit = agentPeerLookupMaxProjectedRows + 1
)

// Lookup-error sentinels. HandleKnockRequest distinguishes these
// to emit different structured events but presents an identical
// reject to the wire.
var (
	// ErrAgentLookupRetryAfter wraps a transient DDB failure
	// (throttle, 5xx, network).
	ErrAgentLookupRetryAfter = errors.New("agent peer lookup: retry after transient ddb error")

	// ErrAgentUnknownPubkey indicates the pubkey is absent from
	// the pubkey-index GSI.
	ErrAgentUnknownPubkey = errors.New("agent peer lookup: unknown pubkey")

	// ErrAgentLookupStorageWrapperCycle indicates the storage
	// decorator chain hit unwrapMaxHops without finding a
	// *DynamoDBStorage — either a cycle (A→B→A) or a future
	// wrapper graph that legitimately exceeds the limit. Wired
	// into NewAgentPeerLookupFromStorage's error return so
	// UdpServer.Start fires MetricAgentLookupInitFailure instead
	// of silently falling back to "agent path disabled" in cloud
	// mode (where every agent knock would then reject at the
	// responder layer with no DDB-error counter to page on).
	// Sentinel name kept for callers using errors.Is; the message
	// covers both reachable causes so a future legitimate 17-deep
	// chain doesn't get a misleading "cycle" log line.
	ErrAgentLookupStorageWrapperCycle = errors.New("agent peer lookup: storage decorator chain exceeded unwrapMaxHops (cycle or chain too deep)")

	// ErrAgentLookupMalformedRow signals that DDB returned a row
	// whose attribute shape attributevalue.UnmarshalMap could not
	// parse into agentKeyRow — structurally a writer-side schema
	// regression, not a transient infra event. Wraps
	// ErrAgentLookupRetryAfter so the existing
	// MetricAgentLookupDDBError alarm still fires (a third counter
	// would inflate alarm cardinality for an exceedingly rare
	// case); the sentinel itself only drives a distinct log event
	// (event="agent_lookup_row_unmarshal_error") so triage doesn't
	// have to grep the err string to disambiguate from a DDB
	// outage. errors.Is(err, ErrAgentLookupRetryAfter) continues to
	// match — the resolve-handler switch checks this sentinel FIRST
	// so the more specific log line wins.
	ErrAgentLookupMalformedRow = errors.New("agent peer lookup: malformed row from ddb")

	// ErrAgentLookupSchemaMismatch signals that a qurl-agent-keys row
	// declared a schema_version this reader does not understand. This is
	// a writer/reader rollout contract failure, not a DDB outage and not
	// an auth-policy reject. The knock still receives the generic reject;
	// the distinct sentinel drives event="agent_lookup_schema_mismatch"
	// and MetricAgentLookupSchemaMismatch for operator triage.
	ErrAgentLookupSchemaMismatch = errors.New("agent peer lookup: unsupported qurl-agent-keys schema version")

	// ErrAgentLookupPubkeyCollision signals that the pubkey-index GSI
	// returned registration rows for more than one owner_id for a single
	// public_key. qurl-service #488 now enforces one-owner-per-pubkey on
	// writes; a distinct-owner collision here means legacy duplicate data,
	// manual table mutation, or a writer invariant regression. The reader
	// rejects fail-closed instead of admitting an arbitrary owner. Same-owner
	// duplicate agent_id rows are unambiguous for auth and tolerated.
	ErrAgentLookupPubkeyCollision = errors.New("agent peer lookup: qurl-agent-keys pubkey collision")

	// ErrAgentLookupPubkeyCandidateOverflow signals that the pubkey-index GSI
	// returned more same-owner candidates than the reader will inspect, or
	// indicated another page after the sentinel query. This is fail-closed for
	// the same reason as a true collision (an uninspected row could hide a
	// distinct owner), but it has its own event/metric so alarms can distinguish
	// "two owners share one key" from "one owner has too many sibling rows."
	ErrAgentLookupPubkeyCandidateOverflow = errors.New("agent peer lookup: qurl-agent-keys pubkey candidate overflow")

	// ErrAgentLookupInternal signals a programmer-error reachable
	// only via a future regression in this package — e.g., a
	// singleflight closure returning a non-*core.UdpPeer value
	// despite the contract. Structurally impossible today, but the
	// defensive type-assert path is real and a sentinel routing it
	// through "DDB outage" alarms would misclassify the next
	// regression as infrastructure trouble. Like
	// ErrAgentLookupMalformedRow this wraps ErrAgentLookupRetryAfter
	// to keep the existing reject metric firing (no new alarm
	// cardinality budget); the sentinel drives a distinct log
	// event="agent_lookup_internal_bug" so a triage operator
	// recognizes "code bug, page the on-call dev" rather than
	// "DDB outage, page the on-call SRE".
	ErrAgentLookupInternal = errors.New("agent peer lookup: internal invariant violated")
)

// AgentKeysQuerier is the narrow DDB surface AgentPeerLookup
// needs. Real callers wire this to a *dynamodb.Client; tests
// inject fakes. Kept independent of StorageBackend so the
// agent-peer cache TTL (60s, fixed) can evolve separately from
// the AC-assignment cache TTL (config-driven, adaptive).
type AgentKeysQuerier interface {
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
}

// counterIncrementer is the narrow metrics surface AgentPeerLookup
// uses for forensic counters (e.g. pubkey-collision detection).
// *metrics.Publisher satisfies this; tests can pass a fake or nil.
// IncrCounter on metrics.Publisher is nil-safe (matches the pattern
// in tokenstore.go and precheck_threat_cache.go), so a nil
// counterIncrementer field is fine — the metric simply doesn't
// emit.
type counterIncrementer interface {
	IncrCounter(name string)
}

// agentCacheEntry tags a cached peer with the time it was fetched
// (so getCached can enforce the per-entry TTL on top of the LRU)
// and the owner_id read from the strongly-consistent qurl-agent-keys
// base row. The metadata is surfaced in the agent_resolved log line
// via CachedOwnerID and is otherwise unused — the wire path operates
// on the *core.UdpPeer alone.
// ownerID should be non-empty on cached entries because decodeProjectedAgentKeyRows
// rejects missing base-table key attrs before the GetItem; empty CachedOwnerID
// returns therefore indicate cache miss/expiry, not a tolerated partial row.
type agentCacheEntry struct {
	peer      *core.UdpPeer
	fetchedAt time.Time
	ownerID   string
}

// agentKeyRow is the shared qurl-agent-keys row contract. The alias is only a
// transient DDB decode target; successful resolves cache the *core.UdpPeer plus
// owner_id/agent_id metadata, not the full registration row. The resolver consumes:
//
//   - PublicKey: the GSI hash key; load-bearing for the cache
//     pubkey identity.
//   - OwnerID, AgentID: free attributes the pubkey-index GSI's
//     KEYS_ONLY projection ships alongside public_key (the base
//     table's hash and range keys; see
//     terraform/modules/dynamodb/main.tf). Used to fetch the
//     strongly-consistent base row and to populate the
//     pubkey-collision ERROR log so triage can see which owner_ids
//     are colliding without a follow-up scan-query against DDB.
//   - SchemaVersion: the reader/writer rollout gate for structural
//     schema changes.
//
// Encoding contract: PublicKey is the same base64.StdEncoding
// form (padded, standard alphabet) that the noise responder
// produces from ppd.RemotePubKey at the call site in
// resolveAgentPeerForKnock — and the same form qurl-service's
// writer (PR-1a) stores in the qurl-agent-keys table. If the
// writer ever switches to URL-safe / unpadded b64, the
// agentPeerMap cache-warm short-circuit silently breaks (the
// cache lookup at nhpauth.go uses StdEncoding; AddAgentPeer
// would key on the un-normalized DDB form, so every knock
// re-queries DDB and the warm path never fires).
type agentKeyRow = internalauth.QURLAgentKeyRow

// AgentPeerLookup is the per-process resolver for agent pubkey →
// *UdpPeer. hashicorp/golang-lru/v2 is internally thread-safe;
// agentCacheEntry.fetchedAt is set once at Add and never mutated,
// so no extra locking is needed for the TTL check.
//
// sfGroup deduplicates concurrent DDB queries for the same pubkey.
// Without it, N simultaneous first-knocks for the same fresh agent
// would each issue an independent DDB Query and each construct a
// distinct *core.UdpPeer. Three concrete consequences:
//
//   - O(N) wasted DDB Queries per pubkey-window (cost amplifier; in
//     a misconfigured-agent retry storm this dominates the DDB bill).
//   - Each caller in resolveAgentPeerForKnock writes its own pointer
//     into agentPeerMap and the device peer map, so callers race for
//     "last writer wins" identity — a future change that reads back
//     the cached pointer (admin tooling, follow-up cache eviction)
//     would observe a different *core.UdpPeer from the one the
//     concurrent caller held.
//   - device.AddPeer's PeerGroup-promotion path (nhp/core/device.go
//     in AddPeer) does NOT trigger here, because the peers we build
//     in queryAndCache have empty Ip/Port/Hostname so
//     udpPeersShareAddress returns true and AddPeer takes the
//     overwrite branch. The singleflight is not what saves us from
//     PeerGroup promotion — udpPeersShareAddress's empty-vs-empty
//     equality is. If a future change populates Ip/Port at construct
//     time, that invariant breaks and singleflight becomes
//     load-bearing for PeerGroup avoidance too; flag in review.
//
// With singleflight keyed on pubKeyB64, the first goroutine resolves
// and the rest piggyback on the same *core.UdpPeer, so AddAgentPeer
// is invoked exactly once per pubkey-window.
//
// Singleflight error fan-out: when the winner gets a transient DDB
// error, every piggybacked caller receives the same error instead
// of independently retrying. This is the standard singleflight
// trade-off — the alternative is N parallel retries during a
// throttle event, which is worse. If this ever needs to change,
// singleflight.Group.DoChan + Forget on transient errors is the
// upgrade path.
//
// DoS bound: unknown-pubkey lookups are intentionally NOT cached
// (so a real bootstrap completes within RTT, not on TTL boundary).
// Combined with DisableAgentPeerValidation=true at the responder,
// an attacker reaching HandleKnockRequest with N unique random
// pubkeys forces N DDB Queries against the pubkey-index GSI. Random
// unknown pubkeys stop there; strongly-consistent base-table GetItem
// calls are only reached after the GSI has returned at least one
// projected row. A valid pre-cache pubkey in normal one-row state pays
// one extra read at most once per cache/agentPeerMap warmup window. An
// anomalous same-owner duplicate set can pay up to
// agentPeerLookupMaxProjectedRows GetItems before cache or fail-closed
// rejection. The UDP rate limiter (knock-pre-RL) caps incoming packets
// per single source IP, so the per-IP amplification bound is:
//
//	N(unique-pubkeys-per-window) × cost(GSI Query) ≤ per_ip_rate_limit × 1 Query
//	N(valid-pre-cache-pubkeys-per-window) × cost(GSI Query + GetItems) ≤ per_ip_rate_limit × (1 Query + agentPeerLookupMaxProjectedRows GetItems)
//
// IMPORTANT: this is a SINGLE-SOURCE-IP bound. A distributed
// attacker (botnet, or even a modestly large set of unique source
// IPs) bypasses the per-IP cap entirely — each new IP gets its
// own rate-limit budget — so aggregate Query cost scales linearly
// with the number of attacking IPs. The GSI must be sized for the
// per-IP budget × peak-distinct-source-IP product accordingly.
// Today qurl-agent-keys is PAY_PER_REQUEST, which absorbs this
// without tuning; a switch to provisioned capacity needs to
// revisit. A future hardening could negative-cache for 1–2s — long
// enough to absorb a burst, short enough that legitimate bootstrap
// is not delayed — tracked as #1945 with named trigger conditions
// (auth-failures rate threshold, DDB cost-ceiling alarm, a switch
// off PAY_PER_REQUEST, OR a single-tenant partition hot-spot:
// `qurl-agent-keys` partitions by `owner_id`, so one tenant under
// attack can absorb the per-partition PAY_PER_REQUEST budget for
// every other tenant keyed to that partition even when fleet-wide
// RCU consumption looks healthy. Per-partition throttling fires
// before the global RCU alarm in that scenario).
type AgentPeerLookup struct {
	cache   *lru.Cache[string, *agentCacheEntry]
	querier AgentKeysQuerier
	table   string
	ttl     time.Duration
	// now is injected so tests can advance the clock without sleeping.
	now func() time.Time
	// sfGroup deduplicates concurrent LRU-miss DDB queries on the
	// same pubkey. See struct godoc for the AddAgentPeer ordering
	// invariant this enforces.
	sfGroup singleflight.Group
	// onSingleflightEnter is a test-only hook invoked at every
	// caller's entry into sfGroup.Do (NOT just the winner's
	// closure body). Used by the singleflight tests to install a
	// barrier that confirms all N concurrent callers are committed
	// to a slot before the winner's DDB Query completes — without
	// it, a fast winner can populate the cache before piggybackers
	// enter, degrading the test to a cache-hit assertion. nil in
	// production.
	onSingleflightEnter func(pubKeyB64 string)
	// metrics is an optional counterIncrementer for forensic
	// counters (e.g. pubkey collision and candidate-overflow
	// guardrails). nil-safe: nil disables emission, behavior is
	// otherwise unchanged.
	metrics counterIncrementer
}

// NewAgentPeerLookup constructs an AgentPeerLookup wired to a
// DynamoDB Query client. tableName is the resolved
// qurl-agent-keys table name (templated in by terraform via
// storage.toml's AgentKeysTable). Pass nil querier to disable the
// lookup — LookupAgentByPubKey then returns ErrAgentUnknownPubkey
// immediately so the caller's reject path still fires.
func NewAgentPeerLookup(querier AgentKeysQuerier, tableName string) (*AgentPeerLookup, error) {
	// lru.New only fails on size <= 0; agentPeerLookupCacheSize is a
	// positive const so the err branch is unreachable today. Kept so
	// a future cache-size change (or upstream lru.New semantics
	// change) fails loud at construction.
	cache, err := lru.New[string, *agentCacheEntry](agentPeerLookupCacheSize)
	if err != nil {
		return nil, fmt.Errorf("agent peer lookup: lru init: %w", err)
	}
	return &AgentPeerLookup{
		cache:   cache,
		querier: querier,
		table:   tableName,
		ttl:     agentPeerLookupCacheTTL,
		now:     time.Now,
	}, nil
}

// SetMetrics attaches a counterIncrementer for forensic
// counters. Required to be called after construction because
// *metrics.Publisher is initialized later in UdpServer.Start than
// the lookup itself.
//
// SET-ONCE CONTRACT: the first non-nil call wires the publisher;
// subsequent calls with nil are IGNORED so a future caller that
// accidentally re-invokes SetMetrics(nil) (e.g., during a refactor
// that introduces a partial-reset path) doesn't silently dark the
// pubkey-collision counter. To genuinely reset, callers must
// explicitly call ClearMetrics — there is no such helper today
// because no legitimate use case has surfaced; if one does, add
// it loud rather than route through this setter.
//
// The first call may be nil (a test that constructs the lookup
// without a publisher), and a later non-nil call will then bind
// it — matches the construction-order in UdpServer.Start where
// the publisher is built after the lookup. So the rule is "ignore
// nil writes after the first non-nil write", not "ignore all nil
// writes."
func (l *AgentPeerLookup) SetMetrics(m counterIncrementer) {
	if l == nil {
		return
	}
	if m == nil && l.metrics != nil {
		log.Warning("AgentPeerLookup.SetMetrics: refusing to clear a wired counterIncrementer; forensic counters stay live (use a dedicated reset helper if this is intentional)")
		return
	}
	l.metrics = m
}

// LookupAgentByPubKey returns a *core.UdpPeer for pubKeyB64
// (standard padded base64 of the agent's 32-byte X25519 static
// public key). Cache hit (within TTL) returns the cached peer;
// miss queries the pubkey-index GSI. Errors and not-found
// results are NOT cached so retries / future bootstraps resolve
// without waiting for TTL expiry.
//
// Concurrent lookups for the same pubkey are deduplicated via
// singleflight: only one goroutine queries DDB; the rest wait and
// receive the same *core.UdpPeer (or the same error). This is
// load-bearing for AddAgentPeer correctness — see the godoc on
// AgentPeerLookup.sfGroup for why.
//
// Singleflight ctx capture: the singleflight closure captures the
// FIRST caller's ctx. This is safe today only because every live
// caller threads UdpServer.lifecycleCtx (resolveAgentPeerForKnock,
// see nhpauth.go) — all concurrent callers therefore share the same
// context and there is no caller-A-poisons-caller-B deadline risk.
// If a future caller threads a per-knock-derived context (per-call
// timeout, value-keyed deadline), this wrapper needs to be revisited
// (singleflight.Group.DoChan is the upgrade path).
//
// The returned *core.UdpPeer is a shared cache reference: every
// caller in a TTL window (including singleflight piggybackers)
// receives the same pointer. Mutation is permitted through the
// peer's documented internally-locked setters (e.g., UpdateRecv,
// SetTeePublicKey) — those are concurrency-safe by design and the
// only callers (resolveAgentPeerForKnock, plugin handlers) rely on
// the cached peer being the live registration. Do NOT mutate
// addressing-shape fields (PubKeyBase64, Type, Ip/Port/Hostname);
// those participate in device.AddPeer's equality check
// (udpPeersShareAddress) and changing them under the cache would
// silently desync the agentPeerMap and the device peer map.
func (l *AgentPeerLookup) LookupAgentByPubKey(ctx context.Context, pubKeyB64 string) (*core.UdpPeer, error) {
	if l == nil || pubKeyB64 == "" {
		return nil, ErrAgentUnknownPubkey
	}

	if peer := l.getCached(pubKeyB64); peer != nil {
		return peer, nil
	}

	if l.querier == nil {
		// Lookup disabled (no DDB client wired). Treat as unknown so
		// the caller rejects rather than crashes.
		return nil, ErrAgentUnknownPubkey
	}

	// Deduplicate concurrent lookups against the same pubkey. The
	// fn closure runs at most once per (pubkey, in-flight window):
	// re-checks the cache so a result populated by a winner that
	// just returned is reused, then hits DDB if still cold.
	//
	// onSingleflightEnter (test-only): allows a test to insert a
	// barrier here so it can confirm all N concurrent callers have
	// actually committed to a singleflight slot before the winner
	// completes Query. nil in production. Don't add production
	// logic that depends on this — it's intentionally a hole that
	// only Tests fill.
	if l.onSingleflightEnter != nil {
		l.onSingleflightEnter(pubKeyB64)
	}
	v, err, _ := l.sfGroup.Do(pubKeyB64, func() (any, error) {
		// Re-check the cache under the singleflight gate. If the
		// previous winner just populated it, skip the DDB hit
		// entirely — the gate widens the window where a fresh hit
		// is possible without an extra DDB call.
		if peer := l.getCached(pubKeyB64); peer != nil {
			return peer, nil
		}
		return l.queryAndCache(ctx, pubKeyB64)
	})
	if err != nil {
		return nil, err
	}
	peer, ok := v.(*core.UdpPeer)
	if !ok {
		// Defensive: singleflight.Do returns `any`; a type assertion
		// failure means a future change to queryAndCache regressed
		// the *core.UdpPeer | error contract. Wrap both sentinels:
		// ErrAgentLookupInternal drives the distinct
		// event="agent_lookup_internal_bug" log tag so triage routes
		// to the dev on-call (this is a code regression, not a DDB
		// outage); ErrAgentLookupRetryAfter keeps the existing
		// MetricAgentLookupDDBError counter firing without a new
		// alarm. Caller still gets a transient reject so a packet
		// retry has a chance to succeed if the regression is a
		// once-per-deploy fluke.
		return nil, fmt.Errorf("%w: %w: unexpected lookup result type %T", ErrAgentLookupInternal, ErrAgentLookupRetryAfter, v)
	}
	return peer, nil
}

// queryAndCache executes the DDB Query, decodes the row, and
// populates the LRU on success. Split out of LookupAgentByPubKey so
// the singleflight closure has a clean function-shaped body and a
// future direct caller (admin force-resolve, e.g.) can reuse the
// query+cache machinery without re-deriving it.
func (l *AgentPeerLookup) queryAndCache(ctx context.Context, pubKeyB64 string) (*core.UdpPeer, error) {
	queryCtx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	// Query a bounded candidate set from the KEYS_ONLY pubkey-index GSI while
	// keeping random-unknown pubkey misses at one Query and no base-table
	// GetItem. The query returns public_key plus the base-table owner_id/agent_id
	// key pair; the schema_version gate below uses a follow-up GetItem on the
	// base row. DDB GSIs do NOT enforce uniqueness, so qurl-service owns the
	// writer-side one-owner-per-pubkey claim invariant (#488, implemented by
	// qurl-service PR #1037). If two owners ever share a pubkey, the reader
	// rejects fail-closed instead of admitting whichever owner DDB returns first.
	//
	// qurl-service #1037 intentionally permits the SAME owner to hold one key
	// under multiple agent_id rows (sidecar re-bootstrap / sibling rows). Those
	// rows are one principal for auth, so the reader tries the bounded candidates
	// below and accepts the first current, schema-compatible base row. If the GSI
	// partition exceeds agentPeerLookupMaxProjectedRows, the reader rejects
	// fail-closed because the sentinel row or an uninspected page could hide a
	// distinct owner.
	out, err := l.querier.Query(queryCtx, &dynamodb.QueryInput{
		TableName:              aws.String(l.table),
		IndexName:              aws.String(agentPeerLookupIndexName),
		KeyConditionExpression: aws.String(internalauth.QURLAgentKeysPublicKeyAttr + " = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pubKeyB64},
		},
		Limit: aws.Int32(agentPeerLookupQueryLimit),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAgentLookupRetryAfter, err)
	}

	if len(out.Items) == 0 {
		return nil, ErrAgentUnknownPubkey
	}

	// Decode the bounded sentinel page before the overflow check so a
	// distinct-owner collision remains the sharper signal when a partition is
	// both cross-owner and over the same-owner candidate cap. The Query limit is
	// cap+1, so this never unmarshals more than the one sentinel row beyond the
	// inspected set.
	projectedRows, err := decodeProjectedAgentKeyRows(out.Items)
	if err != nil {
		return nil, err
	}

	if firstMeta, secondMeta, ok := distinctOwnerPubkeyCollision(projectedRows); ok {
		// Surface the conflicting owner_ids in the ERROR line — the
		// pubkey-index GSI's KEYS_ONLY projection ships owner_id and
		// agent_id at zero extra cost, and operators chasing a
		// cross-tenant squat need to know *which* owners are
		// colliding without a follow-up scan-query. This intentionally
		// fail-closes on the projected GSI rows before base-row GetItem:
		// cross-owner same-key registration is never a legitimate
		// steady state after qurl-service #1037, and any stale projection
		// self-heals once the GSI converges.
		log.Error("agent peer lookup: distinct-owner pubkey-collision detected on pubkey-index GSI: pubkey_b64_prefix=%q row_count=%d owner_id_first=%q agent_id_first=%q owner_id_second=%q agent_id_second=%q (qurl-agent-keys one-owner-per-pubkey invariant violated; rejecting fail-closed)",
			pubkeyLogPrefix(pubKeyB64), len(out.Items),
			firstMeta.OwnerID, firstMeta.AgentID,
			secondMeta.OwnerID, secondMeta.AgentID)
		if l.metrics != nil {
			l.metrics.IncrCounter(MetricAgentLookupPubkeyCollision)
		}
		// Do not cache fail-closed rows. Repeated bad knocks may re-read DDB,
		// but they stay bounded by the existing knock/source rate limits and
		// singleflight dedupes concurrent attempts for the same pubkey.
		return nil, fmt.Errorf("%w: pubkey_b64_prefix=%q row_count=%d", ErrAgentLookupPubkeyCollision, pubkeyLogPrefix(pubKeyB64), len(out.Items))
	}

	if len(projectedRows) > agentPeerLookupMaxProjectedRows || len(out.LastEvaluatedKey) != 0 {
		first := projectedRows[0]
		log.Error("agent peer lookup: pubkey-index GSI candidate set exceeds inspection cap: pubkey_b64_prefix=%q projected_row_count=%d candidate_limit=%d query_limit=%d has_more_candidates=%t first_owner_id=%q first_agent_id=%q (cannot prove one-owner-per-pubkey invariant across sentinel/uninspected rows; rejecting fail-closed)",
			pubkeyLogPrefix(pubKeyB64), len(projectedRows), agentPeerLookupMaxProjectedRows, agentPeerLookupQueryLimit, len(out.LastEvaluatedKey) != 0, first.OwnerID, first.AgentID)
		if l.metrics != nil {
			l.metrics.IncrCounter(MetricAgentLookupPubkeyCandidateOverflow)
		}
		// Treat an over-cap candidate set like an ambiguity: the reader cannot
		// safely cache a row until operators reconcile the data shape.
		return nil, fmt.Errorf("%w: pubkey_b64_prefix=%q candidate_limit=%d observed_candidates=%d has_more_candidates=%t", ErrAgentLookupPubkeyCandidateOverflow, pubkeyLogPrefix(pubKeyB64), agentPeerLookupMaxProjectedRows, len(projectedRows), len(out.LastEvaluatedKey) != 0)
	}

	var selectedRow *agentKeyRow
	// Examine every bounded same-owner candidate before caching. An explicit
	// unsupported schema_version on any current sibling means writer-first
	// contract drift for this pubkey, so the whole pubkey fails closed even if
	// another sibling row is still schema-compatible.
	for _, projected := range projectedRows {
		row, err := l.getAgentKeyBaseRow(queryCtx, projected)
		if err != nil {
			// Even after selecting a valid sibling, fail the resolve on
			// transient read uncertainty. Accepting early would skip the
			// unsupported-schema check on later same-owner siblings and
			// weaken the reader-first contract.
			return nil, err
		}
		if row == nil {
			// A same-owner duplicate can include a stale GSI projection for a
			// row that was already deleted/reconciled. Try the next projected
			// candidate before treating the pubkey as unknown.
			continue
		}
		if row.PublicKey != pubKeyB64 {
			// The GSI can be eventually consistent across a writer-side pubkey
			// rotation. Do not cache a base row that no longer owns the queried
			// key; a same-owner duplicate may still include a current sibling.
			continue
		}

		if !internalauth.IsSupportedQURLAgentKeysSchemaVersion(row.SchemaVersion) {
			if l.metrics != nil {
				l.metrics.IncrCounter(MetricAgentLookupSchemaMismatch)
			}
			// Do not cache fail-closed rows. Repeated bad knocks may re-read DDB,
			// but they stay bounded by the existing knock/source rate limits and
			// singleflight dedupes concurrent attempts for the same pubkey.
			return nil, fmt.Errorf("%w: owner_id=%q agent_id=%q got schema_version=%d want %d",
				ErrAgentLookupSchemaMismatch, row.OwnerID, row.AgentID, row.SchemaVersion, internalauth.QURLAgentKeysSchemaVersion)
		}
		if err := internalauth.ValidateQURLAgentKeyRow(*row); err != nil {
			if l.metrics != nil {
				l.metrics.IncrCounter(MetricAgentLookupSchemaMismatch)
			}
			return nil, fmt.Errorf("%w: owner_id=%q agent_id=%q invalid schema-v2 credential scope",
				ErrAgentLookupSchemaMismatch, row.OwnerID, row.AgentID)
		}

		if selectedRow == nil {
			selectedRow = row
		}
	}

	if selectedRow == nil {
		return nil, ErrAgentUnknownPubkey
	}

	// Ip/Port/Hostname intentionally empty — load-bearing for the
	// PeerGroup-avoidance invariant documented on AgentPeerLookup.
	// device.AddPeer's udpPeersShareAddress returns true for two
	// empty-vs-empty peers and takes the overwrite branch instead
	// of promoting to a PeerGroup. A future change that populates
	// Ip/Port here breaks that invariant and makes singleflight
	// load-bearing for PeerGroup avoidance too — see the godoc on
	// AgentPeerLookup before doing so.
	peer := &core.UdpPeer{
		PubKeyBase64: selectedRow.PublicKey,
		Type:         core.NHP_AGENT,
		// ExpireTime=0: this lookup's LRU is a cache, not a
		// revocation mechanism. See the package godoc + the
		// godoc on agentPeerLookupCacheTTL for the full
		// revocation contract (process-restart bounded by
		// agentPeerMap pinning; Phase-2 active-knock revocation
		// is tracked in #1943).
	}
	l.cache.Add(pubKeyB64, &agentCacheEntry{
		peer:      peer,
		fetchedAt: l.now(),
		ownerID:   selectedRow.OwnerID,
	})
	return peer, nil
}

func decodeProjectedAgentKeyRows(items []map[string]types.AttributeValue) ([]agentKeyRow, error) {
	projectedRows := make([]agentKeyRow, 0, len(items))
	for _, item := range items {
		var projected agentKeyRow
		if err := attributevalue.UnmarshalMap(item, &projected); err != nil {
			// Structurally a writer-side bug (qurl-service wrote a row
			// shape this reader can't parse), NOT a transient infra
			// event. Wrap both sentinels: ErrAgentLookupMalformedRow
			// drives a distinct event= tag in the resolve-handler log
			// (event="agent_lookup_row_unmarshal_error") so triage
			// doesn't have to grep the err string to disambiguate from
			// a real DDB outage; ErrAgentLookupRetryAfter keeps the
			// existing MetricAgentLookupDDBError alarm firing so a
			// third metric isn't needed for an exceedingly rare case
			// (the writer side MarshalMap's a fixed schema). The raw
			// err is preserved in the structured log line at the
			// caller so the underlying cause is recoverable.
			return nil, fmt.Errorf("%w: %w: %w", ErrAgentLookupMalformedRow, ErrAgentLookupRetryAfter, err)
		}

		if projected.PublicKey == "" {
			// A pubkey-index hit without a public_key attribute should
			// be impossible because public_key is the GSI hash key. Reject the
			// whole candidate set rather than skip this row: once the index key
			// contract is corrupt, admitting a sibling would trust a partial
			// projection we cannot prove is complete.
			return nil, fmt.Errorf("%w: %w: missing projected qurl-agent-keys public_key", ErrAgentLookupMalformedRow, ErrAgentLookupRetryAfter)
		}
		if projected.OwnerID == "" || projected.AgentID == "" {
			return nil, fmt.Errorf("%w: %w: missing projected qurl-agent-keys key attrs owner_id=%q agent_id=%q", ErrAgentLookupMalformedRow, ErrAgentLookupRetryAfter, projected.OwnerID, projected.AgentID)
		}
		projectedRows = append(projectedRows, projected)
	}
	return projectedRows, nil
}

func distinctOwnerPubkeyCollision(projectedRows []agentKeyRow) (agentKeyRow, agentKeyRow, bool) {
	if len(projectedRows) < 2 {
		return agentKeyRow{}, agentKeyRow{}, false
	}
	first := projectedRows[0]
	for _, candidate := range projectedRows[1:] {
		if candidate.OwnerID != first.OwnerID {
			return first, candidate, true
		}
	}
	return agentKeyRow{}, agentKeyRow{}, false
}

// getAgentKeyBaseRow fetches the authoritative base-table row for the
// projected (owner_id, agent_id) GSI hit. The caller uses it to gate
// schema_version, verify the row still owns the queried public_key after any
// GSI propagation lag, and populate cache metadata from the strongly-consistent
// source of truth. It uses the same timeout context as the preceding GSI Query:
// DynamoDBOperationTimeout is a total resolve budget, not a per-call budget.
func (l *AgentPeerLookup) getAgentKeyBaseRow(ctx context.Context, projected agentKeyRow) (*agentKeyRow, error) {
	out, err := l.querier.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(l.table),
		Key: map[string]types.AttributeValue{
			internalauth.QURLAgentKeysOwnerIDAttr: &types.AttributeValueMemberS{Value: projected.OwnerID},
			internalauth.QURLAgentKeysAgentIDAttr: &types.AttributeValueMemberS{Value: projected.AgentID},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: get qurl-agent-keys base row: %w", ErrAgentLookupRetryAfter, err)
	}
	if len(out.Item) == 0 {
		return nil, nil
	}

	var row agentKeyRow
	if err := attributevalue.UnmarshalMap(out.Item, &row); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrAgentLookupMalformedRow, ErrAgentLookupRetryAfter, err)
	}
	return &row, nil
}

// CachedOwnerID returns the owner_id cached from the strongly-consistent
// qurl-agent-keys base row for a previously-resolved pubkey, or "" if not
// present in the cache or expired. Used by the resolveAgentPeerForKnock caller
// to enrich the agent_resolved log line with the tenant owner; carrying the
// owner alongside the peer avoids a follow-up scan-query during triage. Empty
// return is non-fatal: an older row missing owner_id (or an evicted entry) just
// produces a log line without the owner_id field.
//
// Evicts expired entries on hit, matching getCached's semantics —
// without symmetry, a stale entry would linger in the LRU until
// getCached observes it (the LRU itself has no TTL of its own).
// The drop is best-effort: a concurrent caller racing the eviction
// just observes the empty-string return one cycle later.
func (l *AgentPeerLookup) CachedOwnerID(pubKeyB64 string) string {
	if l == nil {
		return ""
	}
	entry, ok := l.cache.Get(pubKeyB64)
	if !ok {
		return ""
	}
	if l.now().Sub(entry.fetchedAt) > l.ttl {
		l.cache.Remove(pubKeyB64)
		return ""
	}
	return entry.ownerID
}

// getCached returns a non-expired peer from the cache, or nil if
// the entry is missing OR expired. Expired entries are removed
// inline so the next call takes the DDB path.
func (l *AgentPeerLookup) getCached(pubKeyB64 string) *core.UdpPeer {
	entry, ok := l.cache.Get(pubKeyB64)
	if !ok {
		return nil
	}
	if l.now().Sub(entry.fetchedAt) > l.ttl {
		l.cache.Remove(pubKeyB64)
		return nil
	}
	return entry.peer
}

// invalidate drops a single pubkey from the cache so the next
// lookup re-queries DDB. Unexported — there is no production
// caller today; the only consumer is the concurrent-access test,
// which calls into it from the same package. Promote to exported
// when an admin "force re-resolve" path actually lands (currently
// tracked as part of #1943) rather than carrying speculative
// surface area on the public API.
func (l *AgentPeerLookup) invalidate(pubKeyB64 string) {
	if l == nil {
		return
	}
	l.cache.Remove(pubKeyB64)
}

// NewAgentPeerLookupFromStorage builds an AgentPeerLookup using
// the DynamoDB client embedded in a DynamoDBStorage. Returns nil
// + nil (no lookup, no error) when the storage isn't
// DynamoDB-backed or when AgentKeysTable is unset — both are
// valid "agent path disabled" states; HandleKnockRequest gates on
// a non-nil lookup.
//
// storage may be a *DynamoDBStorage directly OR a wrapper chain
// (CachedStorage → LoggingStorage → MetricsStorage →
// DynamoDBStorage); we walk the Backend() accessor each layer
// exposes.
func NewAgentPeerLookupFromStorage(storage StorageBackend) (*AgentPeerLookup, error) {
	ddb, err := unwrapDynamoDBStorage(storage)
	if err != nil {
		// Propagate ErrAgentLookupStorageWrapperCycle so the caller
		// in UdpServer.Start sets agentLookupInitFailed=true and
		// MetricAgentLookupInitFailure fires. This is the only
		// non-config-disable failure mode reachable today; previously
		// the metric was unreachable and the wrapper-cycle case
		// silently degraded to "agent path disabled."
		return nil, err
	}
	if ddb == nil {
		return nil, nil
	}
	if ddb.config.AgentKeysTable == "" {
		log.Info("Agent peer lookup disabled: AgentKeysTable not configured")
		return nil, nil
	}
	// *dynamodb.Client directly satisfies AgentKeysQuerier (same
	// Query signature) — no wrapper needed. Reuses the AWS SDK's
	// connection pool / IAM credentials / endpoint resolver from
	// storage init.
	return NewAgentPeerLookup(ddb.client, ddb.config.AgentKeysTable)
}

// unwrapDynamoDBStorage walks the storage decorator chain
// (CachedStorage / LoggingStorage / MetricsStorage) to find the
// underlying DynamoDBStorage. Returns (nil, nil) if no
// DynamoDBStorage is reached and no cycle was hit (e.g.,
// etcd-backed deployments). Returns
// (nil, ErrAgentLookupStorageWrapperCycle) when ANY broken
// wrapper graph is detected:
//
//   - Chain-too-deep / A→B→A cycle: hop count reaches
//     unwrapMaxHops without finding *DynamoDBStorage.
//   - Direct A→A self-loop: a wrapper's Backend() returns the
//     receiver.
//
// Both are misconfigs with the same operational consequence (the
// agent path is disabled in cloud mode → every agent knock fails
// at the responder layer), so the alarm signal is unified.
//
// The non-nil-error case is the "loud failure" path: callers
// (today NewAgentPeerLookupFromStorage) propagate the error so
// UdpServer.Start can fire MetricAgentLookupInitFailure instead
// of silently disabling the agent path. Without this, a cycle
// bug in cloud mode would reject every agent knock at the
// responder layer with no metric to alarm on.
//
// Bounded by unwrapMaxHops; today the chain is at most 4 levels
// deep so the cap has large headroom.
func unwrapDynamoDBStorage(s StorageBackend) (*DynamoDBStorage, error) {
	type unwrapper interface {
		Backend() StorageBackend
	}
	hops := 0
	for ; s != nil && hops < unwrapMaxHops; hops++ {
		if ddb, ok := s.(*DynamoDBStorage); ok {
			return ddb, nil
		}
		u, ok := s.(unwrapper)
		if !ok {
			return nil, nil
		}
		next := u.Backend()
		if next == s {
			// Direct A→A self-loop: a wrapper whose Backend() returns
			// itself. Treated as a real misconfig — same alarm posture
			// as the chain-too-deep / A→B→A cycle below: emit a Warning
			// AND return ErrAgentLookupStorageWrapperCycle so
			// MetricAgentLookupInitFailure pages on it. Previously this
			// branch returned (nil, nil) silently, which split the
			// "wrapper graph is broken" failure mode across two
			// reporting contracts (silent vs alarmed) for no semantic
			// difference between the two causes.
			log.Warning("unwrapDynamoDBStorage: direct self-loop in storage decorator chain (Backend() returns receiver); agent peer lookup will be disabled — same posture as the chain-too-deep / A→B→A cycle below")
			return nil, ErrAgentLookupStorageWrapperCycle
		}
		s = next
	}
	if hops >= unwrapMaxHops {
		// Hit the cycle/hop guard without finding *DynamoDBStorage.
		// Warning here PLUS the returned error give two signals:
		// the log line is the boot-time forensic; the error feeds
		// MetricAgentLookupInitFailure so an alarm pages even when
		// nobody reads the boot logs.
		log.Warning("unwrapDynamoDBStorage: hit max-hops limit (%d) without finding *DynamoDBStorage — wrapper cycle or chain too deep; agent peer lookup will be disabled", unwrapMaxHops)
		return nil, ErrAgentLookupStorageWrapperCycle
	}
	return nil, nil
}
