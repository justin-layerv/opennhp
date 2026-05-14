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

	// agentPeerLookupIndexName is the GSI hashed on public_key.
	// Owned by terraform/modules/dynamodb (qurl_agent_keys table);
	// any rename there must mirror here.
	agentPeerLookupIndexName = "pubkey-index"
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
// and the owner_id / agent_id projected for free by the pubkey-
// index GSI's KEYS_ONLY projection. The metadata is surfaced in
// the agent_resolved log line via CachedOwnerID and is otherwise
// unused — the wire path operates on the *core.UdpPeer alone.
// Empty strings are tolerated: an older writer row missing
// owner_id should not break resolution; it just means the log
// lacks the owner_id field for that pubkey.
type agentCacheEntry struct {
	peer      *core.UdpPeer
	fetchedAt time.Time
	ownerID   string
	agentID   string
}

// agentKeyRow mirrors the qurl-agent-keys row shape. Only fields
// that the resolver actually consumes are unmarshaled — keeps the
// cache footprint small. Today that's:
//
//   - PublicKey: the GSI hash key; load-bearing for the cache
//     pubkey identity.
//   - OwnerID, AgentID: free attributes the pubkey-index GSI's
//     KEYS_ONLY projection ships alongside public_key (the base
//     table's hash and range keys; see
//     terraform/modules/dynamodb/main.tf). Plumbed into the
//     agent_resolved log + the pubkey-collision WARN log so
//     triage can see which owner_id was admitted (or which two
//     are colliding) without a follow-up scan-query against DDB.
//
// Other bootstrap-only fields (registered_at, last_seen_at, etc.)
// are intentionally not unmarshaled.
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
type agentKeyRow struct {
	PublicKey string `dynamodbav:"public_key"`
	OwnerID   string `dynamodbav:"owner_id"`
	AgentID   string `dynamodbav:"agent_id"`
}

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
// pubkeys forces N DDB Queries against the pubkey-index GSI. The
// UDP rate limiter (knock-pre-RL) caps incoming packets per single
// source IP, so the per-IP bound on amplification is:
//
//	N(unique-pubkeys-per-window) × cost(GSI Query) ≤ per_ip_rate_limit × 1 Query
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
	// counters (e.g. MetricAgentLookupPubkeyCollision when the
	// pubkey-index GSI returns >1 row for the same key). nil-safe:
	// nil disables emission, behavior is otherwise unchanged.
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

	// Limit=2 honors whichever row DDB returns first on a pubkey
	// collision but ALSO lets us detect that a collision occurred.
	// DDB GSIs do NOT enforce uniqueness — pubkey uniqueness is
	// purely a writer-side contract.
	//
	// Writer-side contract (qurl-service PR-1a, repo qurl-service
	// #485, internal/repository/dynamodb/agent_keys_repo.go's
	// `Upsert`): on every write, the writer reads the pubkey-index
	// GSI; if the pubkey is already registered to a different
	// owner, it emits a WARN log (`agent bootstrap: cross-tenant
	// pubkey squatting detected`) and proceeds with the write. The
	// posture is WARN-only — the writer does NOT reject the
	// conflicting write — and the GSI read is eventually consistent,
	// so there is a false-negative window during a tight squat race.
	//
	// qurl-service #488 tracks the true uniqueness invariant
	// (TransactWriteItems against a claims sidecar table) that
	// closes this gap.
	//
	// If two rows ever share a pubkey, the resolver returns whichever
	// row DDB hands back first and admits the holder of the matching
	// private key; multi-tenant identity confusion would surface at
	// the qurl-service auth layer (where owner_id is the principal),
	// not here.
	//
	// Limit=2 (not Limit=1) is defense-in-depth: when the writer-side
	// soft check fails open, the reader still detects the collision
	// (Items > 1) and emits MetricAgentLookupPubkeyCollision + a WARN
	// log. The forensic signal lets operators see writer-side
	// invariant violations in real time without coupling the
	// detection to the qurl-service deploy. One extra projected
	// attribute set on the no-collision (Items == 1) path is
	// negligible.
	out, err := l.querier.Query(queryCtx, &dynamodb.QueryInput{
		TableName:              aws.String(l.table),
		IndexName:              aws.String(agentPeerLookupIndexName),
		KeyConditionExpression: aws.String("public_key = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pubKeyB64},
		},
		Limit: aws.Int32(2),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAgentLookupRetryAfter, err)
	}

	if len(out.Items) == 0 {
		return nil, ErrAgentUnknownPubkey
	}

	if len(out.Items) > 1 {
		// Defense-in-depth: the writer-side soft uniqueness check
		// (qurl-service #485, WARN-only) failed open. We still admit
		// Items[0] (the qurl-service auth layer enforces multi-tenant
		// separation by owner_id), but emit a forensic signal so
		// operators can see the invariant violation in real time. See
		// the MetricAgentLookupPubkeyCollision godoc.
		//
		// Surface the conflicting owner_ids in the WARN line — the
		// pubkey-index GSI's KEYS_ONLY projection ships owner_id and
		// agent_id at zero extra cost, and operators chasing a
		// cross-tenant squat need to know *which* owners are
		// colliding without a follow-up scan-query. Best-effort: if
		// unmarshal fails on either row, the corresponding
		// owner_id_* field is left "". The admit path that follows
		// still hard-fails on a real unmarshal error of Items[0].
		var firstMeta, secondMeta agentKeyRow
		_ = attributevalue.UnmarshalMap(out.Items[0], &firstMeta)
		_ = attributevalue.UnmarshalMap(out.Items[1], &secondMeta)
		log.Warning("agent peer lookup: pubkey-collision detected on pubkey-index GSI: pubkey_b64_prefix=%q row_count=%d owner_id_admitted=%q agent_id_admitted=%q owner_id_collision=%q agent_id_collision=%q (writer-side uniqueness invariant violated; qurl-service #488 tracks the hard fix)",
			pubkeyLogPrefix(pubKeyB64), len(out.Items),
			firstMeta.OwnerID, firstMeta.AgentID,
			secondMeta.OwnerID, secondMeta.AgentID)
		if l.metrics != nil {
			l.metrics.IncrCounter(MetricAgentLookupPubkeyCollision)
		}
	}

	var row agentKeyRow
	if err := attributevalue.UnmarshalMap(out.Items[0], &row); err != nil {
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

	if row.PublicKey == "" {
		// A pubkey-index hit without a public_key attribute should
		// be impossible (it's the GSI's hash key), but treat as
		// unknown rather than cache an empty peer.
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
		PubKeyBase64: row.PublicKey,
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
		ownerID:   row.OwnerID,
		agentID:   row.AgentID,
	})
	return peer, nil
}

// CachedOwnerID returns the owner_id projected by the pubkey-index
// GSI for a previously-resolved pubkey, or "" if not present in the
// cache or expired. Used by the resolveAgentPeerForKnock caller to
// enrich the agent_resolved log line with the tenant owner — the
// GSI's KEYS_ONLY projection ships owner_id at zero extra cost, and
// surfacing it on the resolved log avoids a follow-up scan-query
// during triage. Empty return is non-fatal: an older row missing
// owner_id (or an evicted entry) just produces a log line without
// the owner_id field.
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
