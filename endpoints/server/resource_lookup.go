// Package server — resource (auth-service-provider) DDB+LRU lookup on knock receipt.
//
// Per-process resolver for aspId → *AuthServiceProviderData, backed by
// the `nhp_resources` DynamoDB table (PK=customer_id, SK=resource_id;
// see terraform/modules/dynamodb/main.tf). Mirrors the shape of the
// agent-peer lookup at endpoints/server/agent_peer_lookup.go (#1833):
// bounded LRU, singleflight-deduplicated DDB queries, build-fresh-
// then-atomic-swap publish into UdpServer.authServiceMap so the
// existing FindAuthSvcProvider RLock read-path (and through it the
// layerv plugin's helper.AspData read) sees the live catalog.
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
	// smaller. Today only one aspId ("layerv") is in active use; a
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

	// nhpSystemCustomerID is the 26-char nil-ULID (Crockford base32
	// alphabet, all zeros) partition that FRPS seed rows are written
	// under (terraform/resources.tf's `local.nhp_system_customer_id`).
	// All current "layerv" resources share this partition; a future
	// per-tenant schema would key by a real customer ULID instead. The
	// constant is duplicated from terraform's `local`; a drift on either
	// side surfaces as a cache miss that returns ErrResourceUnknownASP
	// (the resolver Queries an empty partition and finds no rows), which
	// then routes through MetricAuthFailure via ResolveAuthSvcProvider's
	// auth-policy branch. The drift fence is filed as a follow-up CI
	// lint (#2121) so a terraform-side rename can't sneak past code
	// review. Documenting the duplication here is the same posture as
	// agentPeerLookupIndexName ↔ `terraform/modules/dynamodb/main.tf`'s
	// `pubkey-index` constant.
	nhpSystemCustomerID = "00000000000000000000000000"
)

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
	cache      *lru.Cache[string, *resourceCacheEntry]
	querier    resourcesQuerier
	table      string
	customerID string
	ttl        time.Duration
	applier    aspDataApplier
	now        func() time.Time
	sfGroup    singleflight.Group
	metrics    counterIncrementer
	// onSingleflightEnter is a test-only hook invoked at every caller's
	// entry into sfGroup.Do (NOT just the winner's closure body).
	// Mirrors the agent-peer hook so the singleflight tests have a
	// barrier to confirm all N concurrent callers commit to a slot
	// before the winner's DDB Query completes. nil in production.
	onSingleflightEnter func(aspId string)
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
	return &ResourceLookup{
		cache:      cache,
		querier:    querier,
		table:      tableName,
		customerID: customerID,
		ttl:        resourceLookupCacheTTL,
		applier:    applier,
		now:        time.Now,
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

// queryAndCache Queries the system partition for all rows, filters
// by auth_service_id == aspId, assembles the *AuthServiceProviderData
// (one ResourceGroup per row, with inner Resources keyed identically),
// applies it to authServiceMap, and caches it.
//
// The Query is partition-bounded (single customer_id) so cost is
// O(rows-under-partition), not O(table). Today the system partition
// holds only the small FRPS catalog (a few rows); a future
// per-tenant schema would partition by real customer_id and this
// query would still be small per-tenant.
//
// SkipAuth=true is stamped on the resulting *AuthServiceProviderData
// to match the contract the layerv plugin fences on (see
// endpoints/server/staticplugins/layerv/main.go::AuthWithNHP and
// the SkipAuth=true assertion in TestFRPSResourceTOMLOverlay_…
// in endpoints/server/config_test.go). The DDB schema doesn't carry
// a skip_auth column today because the agent-bootstrap flow has no
// backend-auth path; if a future ASP needs backend auth, this
// becomes a per-row field rather than a constant.
func (l *ResourceLookup) queryAndCache(ctx context.Context, aspId string) (*common.AuthServiceProviderData, error) {
	queryCtx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	// FilterExpression on auth_service_id keeps the wire response
	// bounded to rows for the requested aspId. DDB still consumes RCUs
	// for the full partition scan (the filter applies post-Query), so
	// this is NOT a cost-control mechanism — it's a transfer-size and
	// unmarshal-cost reduction that becomes load-bearing once the
	// partition holds rows for multiple aspIds (the multi-aspId schema
	// the godoc anticipates). Today the system partition only carries
	// "layerv" rows; the filter is a no-op against current data.
	out, err := l.querier.Query(queryCtx, &dynamodb.QueryInput{
		TableName:              aws.String(l.table),
		KeyConditionExpression: aws.String("customer_id = :cid"),
		FilterExpression:       aws.String("auth_service_id = :asp"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":cid": &types.AttributeValueMemberS{Value: l.customerID},
			":asp": &types.AttributeValueMemberS{Value: aspId},
		},
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
		// Defense-in-depth: KeyConditionExpression already constrains
		// rows to l.customerID, but a future regression in the query
		// expression (typo, missing :cid substitution, AWS SDK quirk)
		// could let cross-partition rows leak silently. A row from
		// the wrong partition has no business being inserted into
		// THIS partition's aspData; skip + count so the regression
		// surfaces in alarms rather than as a cross-tenant correctness
		// bug. Dedicated counter (not MetricResourceLookupMalformedRow)
		// because the alarm urgency is different — a cross-partition
		// row in a per-tenant schema is a potential cross-tenant leak
		// and should fire at threshold `> 0`, not the row-shape-drift
		// thresholds operators set on MalformedRow.
		if row.CustomerID != l.customerID {
			log.Warning("resource lookup: skipping cross-partition row partition=%q row.customer_id=%q aspId=%q resource_id=%q (KeyConditionExpression regression — investigate)",
				l.customerID, row.CustomerID, aspId, row.ResourceID)
			if l.metrics != nil {
				l.metrics.IncrCounter(MetricResourceLookupCrossPartition)
			}
			continue
		}
		if row.AuthServiceID != aspId {
			continue
		}
		if row.ResourceID == "" {
			// Defensive: a row without a resource_id can't be addressed
			// by an agent knock and would key the inner map on "".
			// Skip rather than poison the map. Fires the malformed-row
			// counter for parity with the UnmarshalMap branch — both
			// are writer-side regressions of the same severity, and an
			// operator dashboarding the counter should see either.
			log.Warning("resource lookup: skipping row with empty resource_id partition=%q aspId=%q ac_id=%q",
				l.customerID, aspId, row.ACID)
			if l.metrics != nil {
				l.metrics.IncrCounter(MetricResourceLookupMalformedRow)
			}
			continue
		}

		matched++

		// OpenTime: defend against writer-side regressions. Non-positive
		// → DefaultIpOpenTime (the TOML overlay can't emit 0; treating
		// 0 as a regression keeps the contract symmetric across both
		// loaders). Overflow comparison widens to int64 so a value
		// >MaxUint32 that fits in 64-bit int doesn't wrap to garbage
		// when cast to uint32. The clamp catches a future writer
		// regression (admin manual edit, schema migration default);
		// it isn't a portability fence — on 32-bit builds the
		// unmarshal would truncate before reaching here.
		openTime := row.OpenTime
		if openTime <= 0 {
			log.Warning("resource lookup: non-positive open_time=%d for aspId=%q resource_id=%q — using DefaultIpOpenTime",
				openTime, aspId, row.ResourceID)
			openTime = DefaultIpOpenTime
		}
		if int64(openTime) > int64(math.MaxUint32) {
			log.Warning("resource lookup: open_time=%d exceeds uint32 for aspId=%q resource_id=%q — clamping",
				openTime, aspId, row.ResourceID)
			// Use math.MaxInt32 instead of math.MaxUint32 to avoid a
			// signed-overflow on 32-bit builds where int(uint32(max))
			// truncates to -1. The downstream uint32 cast at the
			// ResourceGroup.OpenTime assignment widens it back, but
			// storing a positive int through the rest of the function
			// keeps the value sane for any future caller reading the
			// local. Caps at ~68 years (MaxInt32 seconds), still well
			// past any plausible OpenTime use.
			openTime = math.MaxInt32
		}

		// Mirror the TOML overlay's resource shape exactly so the
		// in-memory ResourceData this resolver produces is
		// indistinguishable from the one config.go::loadResources
		// would produce from the baked overlay:
		//   - Hostname carries the customer-facing ingress
		//     (ResourceFQDN); the layerv plugin's callback path
		//     (handleNhpOpenResource → ResourceData.DestHost()) falls
		//     back to Hostname when Addr.Ip is empty, so leaving Ip
		//     blank matches the overlay invariant.
		//   - row.DestHost is intentionally NOT propagated separately;
		//     today the TF writer collapses dest_host == resource_fqdn
		//     for FRPS (the agent dials FRPS directly) and DestHost()
		//     fall-back via Hostname covers the case. If a future row
		//     genuinely splits the two (proxy/gateway in front of the
		//     dial target), revisit so dest_host populates Addr.Ip.
		//   - Resources map keys MUST match the outer ResourceGroups
		//     key (per the overlay's inner-equals-outer invariant
		//     fenced by TestFRPSResourceTOMLOverlay_SchemaMatchesAuthSvcProviderMap).
		//   - SkipAuth=true matches the overlay's `SkipAuth = true`
		//     (terraform/resources.tf). The layerv plugin fences on
		//     this; a mismatch surfaces as ErrBackendAuthRequired
		//     (52007) on the first knock instead of dark-routing.
		resData := &common.ResourceData{
			ResourceGroup: common.ResourceGroup{
				AuthServiceId: aspId,
				ResourceId:    row.ResourceID,
				OpenTime:      uint32(openTime),
				Resources: map[string]*common.ResourceInfo{
					row.ResourceID: {
						ACId:     row.ACID,
						Hostname: row.ResourceFQDN,
						Addr: &common.NetAddress{
							Port:     row.DestPort,
							Protocol: "tcp",
						},
					},
				},
			},
			SkipAuth: true,
		}
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
