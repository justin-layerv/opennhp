// Package server — resource (auth-service-provider) DDB+LRU lookup on knock receipt.
//
// Per-process resolver for aspId → *AuthServiceProviderData, backed by
// the `nhp_resources` DynamoDB table (PK=customer_id, SK=resource_id;
// see terraform/modules/dynamodb/main.tf). Mirrors the shape of the
// agent-peer lookup at endpoints/server/agent_peer_lookup.go (#1833):
// bounded LRU, singleflight-deduplicated DDB queries, build-fresh-
// then-atomic-swap publish into UdpServer.authServiceMap so the
// existing FindAuthSvcProvider RLock read-path (and through it the
// agent plugin's helper.AspData read) sees the live catalog.
//
// Phase-1 freshness contract: once a lookup populates authServiceMap,
// the resolved pointer pins there until the next cache-miss re-runs
// the lookup. The LRU's 60s TTL bounds how long a stale row survives
// IN THE CACHE; it does NOT bound how long a deleted DDB row continues
// to be admitted from authServiceMap (FindAuthSvcProvider doesn't
// consult the LRU TTL). Active per-knock revocation is out of scope
// for #1976 — matches the agent-peer Phase-1 contract (process-restart
// bounded, ASG rolling-refresh cadence).
package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sync/singleflight"
)

const (
	// resourceLookupCacheSize bounds the LRU at 256 entries. Each
	// entry is a single *common.AuthServiceProviderData carrying that
	// aspId's full ResourceGroups map — heavier than the agent-peer
	// LRU entry's *UdpPeer, so the cap is an order of magnitude
	// smaller. Today only one aspId ("agent") is in active use; a
	// future schema with many distinct aspIds would still fit
	// comfortably under this cap. Bumped or made configurable when a
	// real multi-aspId deployment lands.
	resourceLookupCacheSize = 256

	// resourceLookupCacheTTL bounds how long a cached aspData survives
	// in this lookup's LRU. Matches agentPeerLookupCacheTTL by design:
	// operational triage shouldn't have to remember two different
	// freshness windows for two DDB-backed lookups. Once a lookup
	// populates s.authServiceMap, the *AuthServiceProviderData pointer
	// pins there independent of this TTL until the next cache-miss
	// triggers a re-resolve (typically on first knock after ~60s of
	// quiescence, or immediately when the cache evicts the entry under
	// memory pressure). See the package godoc's Phase-1 freshness
	// contract for the full revocation story.
	resourceLookupCacheTTL = 60 * time.Second

	// resourceLookupDirectCacheSize bounds the dynamic qURL direct-row cache.
	// These entries are one small *ResourceData each, so the cache can be much
	// wider than the ASP catalog cache without carrying the whole static
	// ResourceGroups map. It exists to protect the one-popular-qURL case: 256
	// resource_id-derived partitions spread aggregate traffic, but a single hot
	// q_ token still maps to one DynamoDB item.
	resourceLookupDirectCacheSize = 4096

	// resourceLookupDirectCacheTTL is intentionally short. qurl-service remains
	// the auth/token gate before it emits an internal knock; this cache only
	// keeps the routing row warm. The effective entry expiry is min(this TTL,
	// the row's app-level ttl) so an about-to-expire row cannot be kept alive by
	// the cache while DynamoDB TTL deletion catches up asynchronously.
	resourceLookupDirectCacheTTL = 5 * time.Second

	// resourceLookupDirectNegativeCacheTTL caps repeated DDB reads for one hot
	// revoked/expired/malformed qURL token. Keep it much shorter than the
	// positive cache so a just-created/repaired row is admitted quickly while a
	// bad token burst is flattened to roughly one consistent GetItem per second
	// per server process. Transient DDB errors are never negative-cached.
	resourceLookupDirectNegativeCacheTTL = 1 * time.Second

	// nhpSystemCustomerID is the 26-char nil-ULID (Crockford base32
	// alphabet, all zeros) partition that agent seed rows are written
	// under (terraform/resources.tf's `local.nhp_system_customer_id`).
	// System-owned static qURL tunnel-server rows also live here, but
	// qurl-service-owned dynamic q_ rows deliberately do not. A future
	// per-tenant schema would key by a real customer ULID instead. The
	// constant is duplicated from terraform's `local`; a drift on either
	// side surfaces as a cache miss that returns ErrResourceUnknownASP
	// (the resolver Queries an empty partition and finds no rows), which
	// then routes through MetricAuthFailure via ResolveAuthSvcProvider's
	// auth-policy branch. The drift fence lives at PR time via
	// `scripts/check-asp-and-ac-id-lockstep.sh` (wired into
	// `.github/workflows/validate-workflows.yml`) — a terraform-side
	// rename without renaming this const (or vice versa) fails CI loud
	// rather than silently routing through the auth-policy branch.
	// Documenting the duplication here is the same posture as
	// agentPeerLookupIndexName ↔ `terraform/modules/dynamodb/main.tf`'s
	// `pubkey-index` constant.
	nhpSystemCustomerID = "00000000000000000000000000"

	// nhpQURLDynamicCustomerIDPrefix is the reserved customer_id prefix for
	// qurl-service-owned dynamic q_ rows. LookupResource derives the final
	// partition as "<prefix>-<00..ff>" from resource_id, matching qurl-service's
	// writer-side helper. This keeps the direct lookup to one GetItem while
	// spreading high-volume dynamic rows across 256 DynamoDB partition keys.
	nhpQURLDynamicCustomerIDPrefix = "00000000000000000000000001"

	// Dynamic qURL rows use resource_id="q_..." and are resolved via exact
	// GetItem. The cached qURL ASP catalog is only for static qURL resources
	// such as qurl-tunnel-server and its per-AZ rows, all of which carry the
	// "qurl-" prefix. Keep the Query key-bounded to this prefix so a
	// mis-written qURL row in the static partition cannot enter the
	// ASP-level placement cache.
	qurlStaticResourcePrefix = "qurl-"
)

func qurlDynamicCustomerIDForResourceID(resourceID string) string {
	sum := sha256.Sum256([]byte(resourceID))
	return fmt.Sprintf("%s-%02x", nhpQURLDynamicCustomerIDPrefix, sum[0])
}

// Lookup-error sentinels. Wired into structured log events so triage
// can distinguish "DDB outage" from "unknown aspId" from "writer-side
// row regression" without grepping err.Error() strings.
var (
	// ErrResourceLookupRetryAfter wraps a transient DDB failure
	// (throttle, 5xx, network). Mirrors ErrAgentLookupRetryAfter.
	ErrResourceLookupRetryAfter = errors.New("resource lookup: retry after transient ddb error")

	// ErrResourceUnknownASP indicates no rows under the configured
	// customer partition carry the requested auth_service_id.
	ErrResourceUnknownASP = errors.New("resource lookup: unknown aspId")

	// ErrResourceUnknownResource indicates the requested resource_id
	// does not exist under the configured customer partition for the
	// requested auth_service_id.
	ErrResourceUnknownResource = errors.New("resource lookup: unknown resource")

	// ErrResourceLookupInternal signals a programmer-error reachable
	// only via a future regression in this package — e.g., a
	// singleflight closure returning a non-*common.AuthServiceProviderData
	// value despite the contract. Structurally impossible today.
	// Mirrors ErrAgentLookupInternal's posture: wraps
	// ErrResourceLookupRetryAfter so the existing alarm fires; the
	// sentinel drives a distinct event="resource_lookup_internal_bug"
	// tag so triage routes to dev on-call rather than SRE.
	ErrResourceLookupInternal = errors.New("resource lookup: internal invariant violated")
)

// resourcesQuerier is the narrow DDB surface ResourceLookup needs.
// Real callers wire this to a *dynamodb.Client; tests inject fakes.
// Independent of StorageBackend so the resource-cache TTL can evolve
// separately from the storage-layer cache TTLs.
type resourcesQuerier interface {
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
}

// aspDataApplier publishes a freshly-resolved *AuthServiceProviderData
// into the host UdpServer's authServiceMap via build-fresh-then-swap.
// Extracted as an interface so the lookup is testable without spinning
// up a full UdpServer — tests inject a capturing applier that records
// the writes.
type aspDataApplier interface {
	applyAspMapDelta(aspId string, asp *common.AuthServiceProviderData)
}

// resourceCacheEntry tags a cached aspData with the time it was
// fetched so getCached can enforce the per-entry TTL on top of the
// LRU. The LRU itself has no built-in TTL; entries linger until
// evicted by size pressure (rare given a cache of N ~= number of
// distinct aspIds, which is small) OR explicitly removed on TTL
// observation here.
type resourceCacheEntry struct {
	asp       *common.AuthServiceProviderData
	fetchedAt time.Time
}

type resourceDirectCacheKey struct {
	aspId      string
	resourceID string
}

type resourceDirectCacheEntry struct {
	resource *common.ResourceData
	expires  time.Time
	negative bool
}

// ResourceLookup is the per-process resolver for aspId →
// *common.AuthServiceProviderData. hashicorp/golang-lru/v2 is
// internally thread-safe; resourceCacheEntry.fetchedAt is set once at
// Add and never mutated, so no extra locking is needed for the TTL
// check.
//
// sfGroup deduplicates concurrent DDB queries for the same aspId.
// Without it, N simultaneous first-knocks for the same aspId (e.g.,
// every host in a customer's agent fleet coming online at once
// against a freshly-deployed nhp-server) would each issue an
// independent DDB Query against the system partition. The cost
// amplifier is the same shape as the agent-peer case — see that
// package's godoc on sfGroup for the full reasoning.
//
// DoS bound: an attacker probing N unique random aspIds forces N
// DDB Queries against the system partition. The DDB query is bounded
// in cost (single-partition Query) but every miss is an independent
// roundtrip. Today the UDP rate limiter (knock-pre-RL) caps incoming
// packets per source IP; a distributed attacker spreading across many
// source IPs scales linearly. Since the system partition is small
// and PAY_PER_REQUEST, this absorbs without tuning — same posture as
// the agent-peer lookup. A future hardening could negative-cache
// unknown aspIds for 1–2s; deferred until traffic justifies it.
type ResourceLookup struct {
	cache       *lru.Cache[string, *resourceCacheEntry]
	directCache *lru.Cache[resourceDirectCacheKey, *resourceDirectCacheEntry]
	querier     resourcesQuerier
	table       string
	customerID  string
	ttl         time.Duration
	applier     aspDataApplier
	now         func() time.Time
	sfGroup     singleflight.Group
	directGroup singleflight.Group
	metrics     counterIncrementer
	// onSingleflightEnter is a test-only hook invoked at every caller's
	// entry into sfGroup.Do (NOT just the winner's closure body).
	// Mirrors the agent-peer hook so the singleflight tests have a
	// barrier to confirm all N concurrent callers commit to a slot
	// before the winner's DDB Query completes. nil in production.
	onSingleflightEnter func(aspId string)
	// onDirectSingleflightEnter is the direct qURL-resource equivalent of
	// onSingleflightEnter. nil in production.
	onDirectSingleflightEnter func(aspId, resourceID string)
}

// NewResourceLookup constructs a ResourceLookup wired to a DynamoDB
// Query client. tableName is the resolved nhp_resources table name
// (templated in via storage.toml's ResourcesTable). customerID is
// the partition under which seed rows are written (today the system
// nil-ULID; a future multi-tenant schema would key by a real ULID).
// applier publishes resolved aspData into the host UdpServer's
// authServiceMap; pass nil in tests that only want to observe the
// resolver behavior (in production this is always the *UdpServer).
//
// Pass nil querier to disable the lookup — LookupAuthServiceProvider
// then returns ErrResourceUnknownASP immediately so the caller's
// reject path still fires without crashing on a nil-deref.
func NewResourceLookup(querier resourcesQuerier, tableName, customerID string, applier aspDataApplier) (*ResourceLookup, error) {
	cache, err := lru.New[string, *resourceCacheEntry](resourceLookupCacheSize)
	if err != nil {
		// lru.New only fails on size <= 0; the const is positive so this
		// branch is unreachable. Kept so a future size change (or
		// upstream semantics change) fails loud at construction.
		return nil, fmt.Errorf("resource lookup: lru init: %w", err)
	}
	directCache, err := lru.New[resourceDirectCacheKey, *resourceDirectCacheEntry](resourceLookupDirectCacheSize)
	if err != nil {
		return nil, fmt.Errorf("resource lookup: direct lru init: %w", err)
	}
	return &ResourceLookup{
		cache:       cache,
		directCache: directCache,
		querier:     querier,
		table:       tableName,
		customerID:  customerID,
		ttl:         resourceLookupCacheTTL,
		applier:     applier,
		now:         time.Now,
	}, nil
}

// SetMetrics attaches a counterIncrementer for forensic counters.
// Required to be called after construction because *metrics.Publisher
// is initialized later in UdpServer.Start than the lookup itself.
//
// SET-ONCE CONTRACT: matches AgentPeerLookup.SetMetrics — the first
// non-nil call wires the publisher; subsequent calls with nil are
// IGNORED so a future caller that accidentally re-invokes
// SetMetrics(nil) doesn't silently dark the counters. To genuinely
// reset, callers must explicitly call a dedicated helper (none today;
// add loud rather than route through this setter).
func (l *ResourceLookup) SetMetrics(m counterIncrementer) {
	if l == nil {
		return
	}
	if m == nil && l.metrics != nil {
		log.Warning("ResourceLookup.SetMetrics: refusing to clear a wired counterIncrementer; forensic counters stay live")
		return
	}
	l.metrics = m
}

// LookupAuthServiceProvider returns a *common.AuthServiceProviderData
// for aspId, populated from DDB on cache miss. Cache hits (within
// TTL) return the cached aspData; misses Query the system partition,
// filter for matching auth_service_id, build the aspData (including
// the inner ResourceGroups + Resources maps), apply it to the host
// UdpServer's authServiceMap via the configured applier, cache it,
// and return.
//
// Errors and not-found results are NOT cached so retries / future
// resource registrations resolve without waiting for TTL expiry.
// Mirrors the agent-peer lookup's negative-cache posture.
//
// Concurrent lookups for the same aspId are deduplicated via
// singleflight. The fn closure runs at most once per
// (aspId, in-flight window); piggybackers receive the same result.
// Singleflight error fan-out (transient DDB error → every piggybacked
// caller gets the same error) matches the agent-peer trade-off; see
// that package's godoc for the upgrade path.
//
// CONTRACT: callers MUST pass UdpServer.LifecycleCtx() (or a context
// derived from it that doesn't introduce a per-request deadline). The
// singleflight closure captures the FIRST caller's ctx; if a future
// caller threads a per-knock ctx with a tighter deadline, an early
// cancel would fail every piggybacker — even those whose own ctx is
// still alive. Today both production call sites
// (HandleKnockRequest, HandleForwardRequest) thread LifecycleCtx so
// every caller shares the same shutdown-only cancellation. A future
// caller wanting per-request ctx must switch to
// singleflight.Group.DoChan + per-caller `select { ctx.Done() }`.
func (l *ResourceLookup) LookupAuthServiceProvider(ctx context.Context, aspId string) (*common.AuthServiceProviderData, error) {
	if l == nil || aspId == "" {
		return nil, ErrResourceUnknownASP
	}

	if asp := l.getCached(aspId); asp != nil {
		// Re-publish on cache hit so a prior wipe of s.authServiceMap
		// (e.g., the TOML file-watcher's full-map replace in
		// `endpoints/server/config.go::updateResources`) self-heals on
		// the next knock without waiting for cache TTL eviction.
		// applyAspMapDelta short-circuits when the entry is already
		// installed under the same *AuthServiceProviderData pointer, so
		// the steady-state cost on hot knock paths is a single
		// pointer-compare under the write lock.
		if l.applier != nil {
			l.applier.applyAspMapDelta(aspId, asp)
		}
		return asp, nil
	}

	if l.querier == nil {
		// Lookup disabled (no DDB client wired). Treat as unknown so the
		// caller rejects rather than crashes — same posture as
		// LookupAgentByPubKey with nil querier.
		return nil, ErrResourceUnknownASP
	}

	if l.onSingleflightEnter != nil {
		l.onSingleflightEnter(aspId)
	}
	v, err, _ := l.sfGroup.Do(aspId, func() (any, error) {
		if asp := l.getCached(aspId); asp != nil {
			return asp, nil
		}
		return l.queryAndCache(ctx, aspId)
	})
	if err != nil {
		return nil, err
	}
	asp, ok := v.(*common.AuthServiceProviderData)
	if !ok {
		// Defensive: singleflight.Do returns `any`; a type-assertion
		// failure means a future change to queryAndCache regressed the
		// *AuthServiceProviderData | error contract. Wrap both sentinels
		// so the existing MetricResourceLookupDDBError alarm fires (no
		// new alarm cardinality) AND the structured log event tag
		// routes to dev on-call.
		return nil, fmt.Errorf("%w: %w: unexpected lookup result type %T", ErrResourceLookupInternal, ErrResourceLookupRetryAfter, v)
	}
	return asp, nil
}

// LookupResource returns one ResourceData by exact resource_id. It deliberately
// bypasses the aspId-level cache used by LookupAuthServiceProvider: dynamic
// qURL resources are minted continuously by qurl-service, so callers must keep
// this path scoped to those dynamic `q_...` IDs and leave static qURL tunnel
// resources on the ASP placement path. It still uses its own short direct-row
// cache plus singleflight: the first lookup reads the resource_id-derived
// dynamic qURL shard with strongly consistent GetItem, while repeated knocks
// for the same hot qURL stay in-process until the shorter of
// resourceLookupDirectCacheTTL or the row's app-level ttl. Direct rows must
// carry a live app-level ttl; DynamoDB TTL deletion is asynchronous, so
// expired-but-not-swept rows are rejected here before they become knockable
// ResourceData. Unknown/invalid direct rows are cached negatively for a much
// shorter window so one hot revoked/expired token cannot issue one consistent
// GetItem per knock.
//
// CONTRACT: callers MUST pass UdpServer.LifecycleCtx() or another
// shutdown-scoped context, not a per-request context. The singleflight closure
// captures the first caller's ctx; if that request context is canceled, every
// piggybacked caller would receive the same cancellation even if its own request
// is still live.
func (l *ResourceLookup) LookupResource(ctx context.Context, aspId, resourceID string) (*common.ResourceData, error) {
	if l == nil || aspId == "" || resourceID == "" || l.querier == nil {
		return nil, ErrResourceUnknownResource
	}
	if aspId != qurlInternalKnockAuthServiceID || !isQURLDynamicResourceID(resourceID) {
		return nil, ErrResourceUnknownResource
	}

	if res, ok := l.getCachedDirectResource(aspId, resourceID); ok {
		if res == nil {
			return nil, ErrResourceUnknownResource
		}
		return res, nil
	}

	if l.onDirectSingleflightEnter != nil {
		l.onDirectSingleflightEnter(aspId, resourceID)
	}
	v, err, _ := l.directGroup.Do(directResourceSingleflightKey(aspId, resourceID), func() (any, error) {
		if res, ok := l.getCachedDirectResource(aspId, resourceID); ok {
			if res == nil {
				return nil, ErrResourceUnknownResource
			}
			return res, nil
		}
		return l.lookupAndCacheDirectResource(ctx, aspId, resourceID)
	})
	if err != nil {
		return nil, err
	}
	res, ok := v.(*common.ResourceData)
	if !ok {
		return nil, fmt.Errorf("%w: %w: unexpected direct lookup result type %T", ErrResourceLookupInternal, ErrResourceLookupRetryAfter, v)
	}
	return res, nil
}

func (l *ResourceLookup) lookupAndCacheDirectResource(ctx context.Context, aspId, resourceID string) (*common.ResourceData, error) {
	queryCtx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	customerID := qurlDynamicCustomerIDForResourceID(resourceID)
	out, err := l.querier.GetItem(queryCtx, &dynamodb.GetItemInput{
		TableName:      aws.String(l.table),
		ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"customer_id": &types.AttributeValueMemberS{Value: customerID},
			"resource_id": &types.AttributeValueMemberS{Value: resourceID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResourceLookupRetryAfter, err)
	}
	if len(out.Item) == 0 {
		l.cacheNegativeDirectResource(aspId, resourceID)
		return nil, ErrResourceUnknownResource
	}

	var row Resource
	if err := attributevalue.UnmarshalMap(out.Item, &row); err != nil {
		log.Warning("resource lookup: malformed direct row in nhp_resources partition=%q resource_id=%q err=%v (writer-side schema regression — investigate)",
			customerID, resourceID, err)
		if l.metrics != nil {
			l.metrics.IncrCounter(MetricResourceLookupMalformedRow)
		}
		l.cacheNegativeDirectResource(aspId, resourceID)
		return nil, ErrResourceUnknownResource
	}
	resData, ok := l.resourceDataFromRow(aspId, row, true)
	if !ok {
		l.cacheNegativeDirectResource(aspId, resourceID)
		return nil, ErrResourceUnknownResource
	}
	l.cacheDirectResource(aspId, resourceID, row.TTL, resData)
	return resData, nil
}

func directResourceSingleflightKey(aspId, resourceID string) string {
	return aspId + "\x00" + resourceID
}

// queryAndCache Queries the system partition for all rows, filters
// by auth_service_id == aspId, assembles the *AuthServiceProviderData
// (one ResourceGroup per row, with inner Resources keyed identically),
// applies it to authServiceMap, and caches it.
//
// The Query is partition-bounded (single customer_id) so cost is
// O(rows-under-partition), not O(table). Dynamic qURL `q_` rows live in
// a separate partition read only by LookupResource/GetItem, so agent and
// static qURL ASP refreshes do not scale with qURL token count. For the qURL
// ASP, the key condition is still narrowed to static `qurl-` resources as a
// row-shape guard. A future per-tenant schema would partition by real
// customer_id and this query would still be small per-tenant.
//
// SkipAuth=true is stamped on the resulting *AuthServiceProviderData
// to match the contract the agent plugin fences on (see
// endpoints/server/staticplugins/agent/main.go::AuthWithNHP and
// TestResourceLookup_HappyPathMatchesPluginReadShape in
// resource_lookup_test.go, which fences this bridge's SkipAuth=true
// output against the agent plugin's `!res.SkipAuth` refuse path).
// The DDB schema doesn't carry a skip_auth column today because the
// agent flow has no backend-auth path; if a future ASP needs backend
// auth, this becomes a per-row field rather than a constant.
func (l *ResourceLookup) queryAndCache(ctx context.Context, aspId string) (*common.AuthServiceProviderData, error) {
	queryCtx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	// FilterExpression on auth_service_id keeps the wire response bounded to
	// rows for the requested aspId. DDB still consumes RCUs for every row that
	// matches the KeyConditionExpression (the filter applies post-Query), so
	// this is NOT a cost-control mechanism. The qURL ASP adds a sort-key prefix
	// condition below as a static-row shape fence; dynamic `q_` rows live in the
	// resource_id-derived dynamic shard partitions and are not visible to this
	// Query.
	keyCondition := "customer_id = :cid"
	values := map[string]types.AttributeValue{
		":cid": &types.AttributeValueMemberS{Value: l.customerID},
		":asp": &types.AttributeValueMemberS{Value: aspId},
	}
	if aspId == qurlInternalKnockAuthServiceID {
		keyCondition += " AND begins_with(resource_id, :rid_prefix)"
		values[":rid_prefix"] = &types.AttributeValueMemberS{Value: qurlStaticResourcePrefix}
	}
	out, err := l.querier.Query(queryCtx, &dynamodb.QueryInput{
		TableName:                 aws.String(l.table),
		KeyConditionExpression:    aws.String(keyCondition),
		FilterExpression:          aws.String("auth_service_id = :asp"),
		ExpressionAttributeValues: values,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResourceLookupRetryAfter, err)
	}

	if out.LastEvaluatedKey != nil {
		// DDB returns up to 1MB per Query page. Today the system
		// partition holds a handful of rows and won't approach this
		// limit; if a future tenant-per-partition schema lands and a
		// partition exceeds 1MB, this resolver silently returns
		// truncated results (the requested aspId might live on page 2,
		// surfacing as a head-scratching ErrResourceUnknownASP).
		//
		// Dedicated counter so alarms differentiate "infra trouble"
		// (DDBError) from "operationally-successful but truncated"
		// (Pagination). Tracked as #2120 for real pagination.
		log.Warning("resource lookup: nhp_resources Query for partition=%q returned a LastEvaluatedKey (paginated response); rows past page 1 are silently dropped — investigate partition size and add pagination if persistent",
			l.customerID)
		if l.metrics != nil {
			l.metrics.IncrCounter(MetricResourceLookupPagination)
		}
	}

	if len(out.Items) == 0 {
		return nil, ErrResourceUnknownASP
	}

	asp := &common.AuthServiceProviderData{
		AuthSvcId:      aspId,
		ResourceGroups: make(common.ResourceGroupMap),
		// SkipAuth is a property of the ResourceData (inner ResourceGroup),
		// not the top-level AspData — set per-group below.
	}

	matched := 0
	for _, item := range out.Items {
		var row Resource
		if err := attributevalue.UnmarshalMap(item, &row); err != nil {
			// Writer-side regression, not transient infra. Continue
			// processing remaining rows so a single bad row doesn't
			// dark the entire catalog; the structured log surfaces the
			// row id for triage.
			log.Warning("resource lookup: skipping malformed row in nhp_resources partition=%q err=%v (writer-side schema regression — investigate)",
				l.customerID, err)
			if l.metrics != nil {
				l.metrics.IncrCounter(MetricResourceLookupMalformedRow)
			}
			continue
		}
		resData, ok := l.resourceDataFromRow(aspId, row, false)
		if !ok {
			continue
		}
		matched++
		asp.ResourceGroups[row.ResourceID] = resData
	}

	if matched == 0 {
		// Partition had rows but none matched the requested aspId.
		// Treat as unknown so the caller's reject path fires;
		// negative result not cached (matches agent-peer posture).
		return nil, ErrResourceUnknownASP
	}

	l.cache.Add(aspId, &resourceCacheEntry{
		asp:       asp,
		fetchedAt: l.now(),
	})

	// Publish into the host UdpServer's authServiceMap so the existing
	// FindAuthSvcProvider RLock read-path picks it up. Build-fresh-
	// then-swap; see UdpServer.applyAspMapDelta. nil applier (tests
	// that only observe the resolver) skips this step.
	if l.applier != nil {
		l.applier.applyAspMapDelta(aspId, asp)
	}

	if l.metrics != nil {
		l.metrics.IncrCounter(MetricResourceLookupCacheMiss)
	}

	return asp, nil
}

func (l *ResourceLookup) resourceDataFromRow(aspId string, row Resource, direct bool) (*common.ResourceData, bool) {
	rowKind := "row"
	aspMismatchReason := "FilterExpression regression"
	aspMismatchMetric := MetricResourceLookupAspMismatch
	partitionID := l.customerID
	if direct {
		rowKind = "direct row"
		aspMismatchReason = "requested aspId mismatch"
		aspMismatchMetric = MetricResourceLookupDirectAspMismatch
		// Direct rows are exact-key GetItem results, so DDB already
		// bounds row.CustomerID to the derived shard partition.
		partitionID = row.CustomerID
	}
	if !direct && row.CustomerID != l.customerID {
		log.Warning("resource lookup: skipping cross-partition row partition=%q row.customer_id=%q aspId=%q resource_id=%q (KeyConditionExpression regression — investigate)",
			l.customerID, row.CustomerID, aspId, row.ResourceID)
		if l.metrics != nil {
			l.metrics.IncrCounter(MetricResourceLookupCrossPartition)
		}
		return nil, false
	}
	if row.AuthServiceID != aspId {
		log.Warning("resource lookup: skipping %s with mismatched auth_service_id partition=%q row.auth_service_id=%q requested aspId=%q resource_id=%q (%s)",
			rowKind, partitionID, row.AuthServiceID, aspId, row.ResourceID, aspMismatchReason)
		if l.metrics != nil {
			l.metrics.IncrCounter(aspMismatchMetric)
		}
		return nil, false
	}
	if row.ResourceID == "" {
		log.Warning("resource lookup: skipping %s with empty resource_id partition=%q aspId=%q ac_id=%q",
			rowKind, partitionID, aspId, row.ACID)
		if l.metrics != nil {
			l.metrics.IncrCounter(MetricResourceLookupMalformedRow)
		}
		return nil, false
	}
	if direct {
		nowUnix := l.now().Unix()
		switch {
		case row.TTL <= 0:
			log.Warning("resource lookup: skipping direct row with missing ttl partition=%q aspId=%q resource_id=%q",
				partitionID, aspId, row.ResourceID)
			if l.metrics != nil {
				l.metrics.IncrCounter(MetricResourceLookupMissingDirectTTL)
			}
			return nil, false
		case row.TTL <= nowUnix:
			log.Warning("resource lookup: skipping expired direct row partition=%q aspId=%q resource_id=%q ttl=%d now=%d",
				partitionID, aspId, row.ResourceID, row.TTL, nowUnix)
			if l.metrics != nil {
				l.metrics.IncrCounter(MetricResourceLookupExpiredDirectRow)
			}
			return nil, false
		}
	}
	if row.ResourceFQDN == "" {
		log.Warning("resource lookup: skipping %s with empty resource_fqdn partition=%q aspId=%q resource_id=%q ac_id=%q",
			rowKind, partitionID, aspId, row.ResourceID, row.ACID)
		if l.metrics != nil {
			l.metrics.IncrCounter(MetricResourceLookupMalformedRow)
		}
		return nil, false
	}
	if row.PortSuffix && (row.DestPort <= 0 || row.DestPort > 65535) {
		log.Warning("resource lookup: skipping %s with port_suffix=true but out-of-range dest_port=%d partition=%q aspId=%q resource_id=%q ac_id=%q",
			rowKind, row.DestPort, partitionID, aspId, row.ResourceID, row.ACID)
		if l.metrics != nil {
			l.metrics.IncrCounter(MetricResourceLookupMalformedRow)
		}
		return nil, false
	}

	openTime := row.OpenTime
	if openTime <= 0 {
		log.Warning("resource lookup: non-positive open_time=%d for aspId=%q resource_id=%q — using DefaultIpOpenTime",
			openTime, aspId, row.ResourceID)
		openTime = DefaultIpOpenTime
	}
	if int64(openTime) > int64(math.MaxUint32) {
		log.Warning("resource lookup: open_time=%d exceeds uint32 for aspId=%q resource_id=%q — clamping",
			openTime, aspId, row.ResourceID)
		openTime = math.MaxInt32
	}

	// Shape contract shared by the ASP Query and direct GetItem paths:
	// Hostname carries the customer-facing ingress, DestHost stays
	// informational, inner Resources keys match the outer ResourceGroup key,
	// and SkipAuth=true because this catalog path is post-auth.
	return &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: aspId,
			ResourceId:    row.ResourceID,
			OpenTime:      uint32(openTime),
			Resources: map[string]*common.ResourceInfo{
				row.ResourceID: {
					ACId:       row.ACID,
					Hostname:   row.ResourceFQDN,
					PortSuffix: row.PortSuffix,
					Addr: &common.NetAddress{
						Port:     row.DestPort,
						Protocol: "tcp",
					},
				},
			},
		},
		SkipAuth: true,
	}, true
}

// getCached returns a non-expired aspData from the cache, or nil if
// the entry is missing OR expired. Expired entries are removed inline
// so the next call takes the DDB path. Mirrors AgentPeerLookup.getCached.
func (l *ResourceLookup) getCached(aspId string) *common.AuthServiceProviderData {
	entry, ok := l.cache.Get(aspId)
	if !ok {
		return nil
	}
	if l.now().Sub(entry.fetchedAt) > l.ttl {
		l.cache.Remove(aspId)
		return nil
	}
	if l.metrics != nil {
		l.metrics.IncrCounter(MetricResourceLookupCacheHit)
	}
	return entry.asp
}

func (l *ResourceLookup) getCachedDirectResource(aspId, resourceID string) (*common.ResourceData, bool) {
	key := resourceDirectCacheKey{aspId: aspId, resourceID: resourceID}
	entry, ok := l.directCache.Get(key)
	if !ok {
		return nil, false
	}
	if !l.now().Before(entry.expires) {
		l.directCache.Remove(key)
		return nil, false
	}
	if entry.negative {
		return nil, true
	}
	return entry.resource, true
}

func (l *ResourceLookup) cacheDirectResource(aspId, resourceID string, rowTTL int64, resource *common.ResourceData) {
	if resource == nil || rowTTL <= 0 {
		return
	}
	now := l.now()
	expires := now.Add(resourceLookupDirectCacheTTL)
	if ttlExpires := time.Unix(rowTTL, 0); ttlExpires.Before(expires) {
		expires = ttlExpires
	}
	if !expires.After(now) {
		return
	}
	l.directCache.Add(resourceDirectCacheKey{aspId: aspId, resourceID: resourceID}, &resourceDirectCacheEntry{
		resource: resource,
		expires:  expires,
	})
}

func (l *ResourceLookup) cacheNegativeDirectResource(aspId, resourceID string) {
	expires := l.now().Add(resourceLookupDirectNegativeCacheTTL)
	l.directCache.Add(resourceDirectCacheKey{aspId: aspId, resourceID: resourceID}, &resourceDirectCacheEntry{
		expires:  expires,
		negative: true,
	})
}

// NewResourceLookupFromStorage builds a ResourceLookup using the
// DynamoDB client embedded in a DynamoDBStorage. Returns (nil, nil)
// when the storage isn't DynamoDB-backed or when ResourcesTable is
// unset — both are valid "resource lookup disabled" states; the host
// UdpServer falls back to FindAuthSvcProvider's existing TOML-loaded
// authServiceMap behavior.
//
// Mirrors NewAgentPeerLookupFromStorage's decorator-unwrap pattern
// so a single storage construction chain (CachedStorage →
// LoggingStorage → MetricsStorage → DynamoDBStorage) feeds both
// lookups via the same *DynamoDBStorage.
func NewResourceLookupFromStorage(storage StorageBackend, applier aspDataApplier) (*ResourceLookup, error) {
	ddb, err := unwrapDynamoDBStorage(storage)
	if err != nil {
		// Propagate the same wrapper-cycle sentinel the agent-peer
		// lookup returns so the caller's loud-failure metric path fires
		// once (one alarm covers a broken wrapper graph for both
		// lookups).
		return nil, err
	}
	if ddb == nil {
		return nil, nil
	}
	if ddb.config.ResourcesTable == "" {
		log.Info("Resource lookup disabled: ResourcesTable not configured")
		return nil, nil
	}
	return NewResourceLookup(ddb.client, ddb.config.ResourcesTable, nhpSystemCustomerID, applier)
}
