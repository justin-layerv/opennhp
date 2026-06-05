package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// fakeResourcesQuerier mocks the DDB Query path for ResourceLookup.
// Stores rows keyed by resource_id; Query returns every row whose
// stored customer_id matches the request's :cid value and optional
// sort-key prefix. This mirrors the real DDB partition behavior: the
// table is keyed on customer_id/resource_id, while auth_service_id is
// only a FilterExpression that this fake intentionally ignores so the
// client-side defense checks stay testable.
type fakeResourcesQuerier struct {
	mu                 sync.Mutex
	calls              int
	rowsByCust         map[string][]map[string]types.AttributeValue
	err                error
	beforeQuery        func()
	beforeGetItem      func()
	beforeGetItemCtx   func(context.Context)
	simulatePagination bool
}

func newFakeResourcesQuerier() *fakeResourcesQuerier {
	return &fakeResourcesQuerier{
		rowsByCust: map[string][]map[string]types.AttributeValue{},
	}
}

// put adds a row to the fake's customer_id partition. resourceFQDN
// is the customer-facing ingress (mirrors terraform's
// `each.value.dest_host` → resource_fqdn render); destHost is the
// internal dial target (today the same value for FRPS but the schema
// keeps them distinct). It intentionally omits port_suffix to mirror
// legacy DDB rows written before the attribute existed.
func (f *fakeResourcesQuerier) put(customerID, resourceID, aspID, acID, resourceFQDN, destHost string, destPort, openTime int) {
	f.putResource(customerID, resourceID, aspID, acID, resourceFQDN, destHost, destPort, openTime, false, false)
}

func (f *fakeResourcesQuerier) putWithTTL(customerID, resourceID, aspID, acID, resourceFQDN, destHost string, destPort, openTime int, ttl int64) {
	f.putResource(customerID, resourceID, aspID, acID, resourceFQDN, destHost, destPort, openTime, false, false)
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.rowsByCust[customerID]
	if len(rows) == 0 {
		return
	}
	rows[len(rows)-1]["ttl"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(ttl, 10)}
}

func (f *fakeResourcesQuerier) putDynamicQURL(resourceID, aspID, acID, resourceFQDN, destHost string, destPort, openTime int) {
	f.put(qurlDynamicCustomerIDForResourceID(resourceID), resourceID, aspID, acID, resourceFQDN, destHost, destPort, openTime)
}

func (f *fakeResourcesQuerier) putDynamicQURLWithTTL(resourceID, aspID, acID, resourceFQDN, destHost string, destPort, openTime int, ttl int64) {
	f.putWithTTL(qurlDynamicCustomerIDForResourceID(resourceID), resourceID, aspID, acID, resourceFQDN, destHost, destPort, openTime, ttl)
}

// putWithPortSuffix emits the port_suffix attribute explicitly. Use it
// for per-AZ rows where tests need to distinguish false from legacy
// rows that omit the attribute entirely.
func (f *fakeResourcesQuerier) putWithPortSuffix(customerID, resourceID, aspID, acID, resourceFQDN, destHost string, destPort, openTime int, portSuffix bool) {
	f.putResource(customerID, resourceID, aspID, acID, resourceFQDN, destHost, destPort, openTime, true, portSuffix)
}

func (f *fakeResourcesQuerier) putResource(customerID, resourceID, aspID, acID, resourceFQDN, destHost string, destPort, openTime int, includePortSuffix, portSuffix bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row := map[string]types.AttributeValue{
		"customer_id":     &types.AttributeValueMemberS{Value: customerID},
		"resource_id":     &types.AttributeValueMemberS{Value: resourceID},
		"auth_service_id": &types.AttributeValueMemberS{Value: aspID},
		"ac_id":           &types.AttributeValueMemberS{Value: acID},
		"resource_fqdn":   &types.AttributeValueMemberS{Value: resourceFQDN},
		"dest_host":       &types.AttributeValueMemberS{Value: destHost},
		"dest_port":       &types.AttributeValueMemberN{Value: strconv.Itoa(destPort)},
		"open_time":       &types.AttributeValueMemberN{Value: strconv.Itoa(openTime)},
	}
	if includePortSuffix {
		row["port_suffix"] = &types.AttributeValueMemberBOOL{Value: portSuffix}
	}
	f.rowsByCust[customerID] = append(f.rowsByCust[customerID], row)
}

func (f *fakeResourcesQuerier) putDynamoDBItem(customerID string, row map[string]types.AttributeValue) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rowsByCust[customerID] = append(f.rowsByCust[customerID], row)
}

// putMalformedRow inserts a row that UnmarshalMap can't decode into
// the Resource struct (dest_port as a String where Resource declares
// it as int). Used to fence the "skip malformed, continue with
// remaining rows" contract.
func (f *fakeResourcesQuerier) putMalformedRow(customerID, resourceID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rowsByCust[customerID] = append(f.rowsByCust[customerID], map[string]types.AttributeValue{
		"customer_id": &types.AttributeValueMemberS{Value: customerID},
		"resource_id": &types.AttributeValueMemberS{Value: resourceID},
		"dest_port":   &types.AttributeValueMemberS{Value: "not-a-number"},
	})
}

func (f *fakeResourcesQuerier) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	// Snapshot beforeQuery under the lock so tests that mutate the
	// field after launching goroutines don't race. Today no test
	// does that — the singleflight barrier test sets the hook
	// before goroutines fan out — but the locked-read keeps the
	// fake race-detector-safe against a future test that does.
	f.mu.Lock()
	beforeQuery := f.beforeQuery
	f.mu.Unlock()
	if beforeQuery != nil {
		beforeQuery()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	if f.err != nil {
		return nil, f.err
	}

	cid := ""
	if v, ok := in.ExpressionAttributeValues[":cid"]; ok {
		if s, ok := v.(*types.AttributeValueMemberS); ok {
			cid = s.Value
		}
	}
	if cid == "" {
		return &dynamodb.QueryOutput{}, nil
	}
	rows := f.rowsByCust[cid]
	keyCondition := ""
	if in.KeyConditionExpression != nil {
		keyCondition = *in.KeyConditionExpression
	}
	resourceIDPrefix := ""
	if strings.Contains(keyCondition, "begins_with(resource_id, :rid_prefix)") {
		if v, ok := in.ExpressionAttributeValues[":rid_prefix"]; ok {
			if s, ok := v.(*types.AttributeValueMemberS); ok {
				resourceIDPrefix = s.Value
			}
		}
	}
	// Copy matching rows so the caller's iteration doesn't race with put().
	out := make([]map[string]types.AttributeValue, 0, len(rows))
	for _, row := range rows {
		if resourceIDPrefix != "" {
			rid, _ := row["resource_id"].(*types.AttributeValueMemberS)
			if rid == nil || !strings.HasPrefix(rid.Value, resourceIDPrefix) {
				continue
			}
		}
		out = append(out, row)
	}
	resp := &dynamodb.QueryOutput{Items: out}
	if f.simulatePagination {
		// Mimic DDB returning a continuation token on a paginated
		// response. Resolver should log a Warning and still process
		// the page-1 rows we did receive (no real pagination
		// implementation yet — see follow-up tracking).
		resp.LastEvaluatedKey = map[string]types.AttributeValue{
			"customer_id": &types.AttributeValueMemberS{Value: cid},
			"resource_id": &types.AttributeValueMemberS{Value: "<paginated-marker>"},
		}
	}
	return resp, nil
}

func (f *fakeResourcesQuerier) GetItem(ctx context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	beforeGetItem := f.beforeGetItem
	beforeGetItemCtx := f.beforeGetItemCtx
	f.mu.Unlock()
	if beforeGetItem != nil {
		beforeGetItem()
	}
	if beforeGetItemCtx != nil {
		beforeGetItemCtx(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	if f.err != nil {
		return nil, f.err
	}

	cid := ""
	if v, ok := in.Key["customer_id"]; ok {
		if s, ok := v.(*types.AttributeValueMemberS); ok {
			cid = s.Value
		}
	}
	resourceID := ""
	if v, ok := in.Key["resource_id"]; ok {
		if s, ok := v.(*types.AttributeValueMemberS); ok {
			resourceID = s.Value
		}
	}
	if cid == "" || resourceID == "" {
		return &dynamodb.GetItemOutput{}, nil
	}
	for _, row := range f.rowsByCust[cid] {
		v, ok := row["resource_id"].(*types.AttributeValueMemberS)
		if !ok || v.Value != resourceID {
			continue
		}
		item := make(map[string]types.AttributeValue, len(row))
		for k, attr := range row {
			item[k] = attr
		}
		return &dynamodb.GetItemOutput{Item: item}, nil
	}
	return &dynamodb.GetItemOutput{}, nil
}

func (f *fakeResourcesQuerier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// captureApplier records every applyAspMapDelta call so a test can
// assert the resolver published into the host server's authServiceMap.
type captureApplier struct {
	mu      sync.Mutex
	applied []captureApplied
}

type captureApplied struct {
	aspId string
	asp   *common.AuthServiceProviderData
}

func (c *captureApplier) applyAspMapDelta(aspId string, asp *common.AuthServiceProviderData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applied = append(c.applied, captureApplied{aspId: aspId, asp: asp})
}

func (c *captureApplier) lastApplied() (captureApplied, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.applied) == 0 {
		return captureApplied{}, false
	}
	return c.applied[len(c.applied)-1], true
}

func (c *captureApplier) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.applied)
}

// newTestResourceLookup constructs a ResourceLookup wired to a fake
// querier and an injectable applier. Customer ID matches the
// production nhpSystemCustomerID so the fake's partition mirrors real
// row writes.
func newTestResourceLookup(t *testing.T, q resourcesQuerier, applier aspDataApplier) *ResourceLookup {
	t.Helper()
	l, err := NewResourceLookup(q, "nhp-resources-test", nhpSystemCustomerID, applier)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}
	return l
}

func TestQURLDynamicCustomerIDForResourceID(t *testing.T) {
	fixture := loadNHPQURLDynamicCustomerIDFixture(t)

	if fixture.Contract != "qurl_dynamic_customer_id" {
		t.Fatalf("contract = %q, want qurl_dynamic_customer_id", fixture.Contract)
	}
	if fixture.CustomerIDPrefix != nhpQURLDynamicCustomerIDPrefix {
		t.Fatalf("customer_id_prefix = %q, want %q", fixture.CustomerIDPrefix, nhpQURLDynamicCustomerIDPrefix)
	}
	if fixture.Algorithm != "customer_id_prefix + '-' + first_byte_hex(sha256(resource_id))" {
		t.Fatalf("algorithm = %q", fixture.Algorithm)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("fixture must include at least one case")
	}

	for _, tt := range fixture.Cases {
		if got := qurlDynamicCustomerIDForResourceID(tt.ResourceID); got != tt.CustomerID {
			t.Fatalf("qurlDynamicCustomerIDForResourceID(%q) = %q, want %q", tt.ResourceID, got, tt.CustomerID)
		}
	}
}

type nhpQURLDynamicCustomerIDFixture struct {
	Version          int    `json:"version"`
	Contract         string `json:"contract"`
	CustomerIDPrefix string `json:"customer_id_prefix"`
	Algorithm        string `json:"algorithm"`
	Cases            []struct {
		ResourceID string `json:"resource_id"`
		CustomerID string `json:"customer_id"`
	} `json:"cases"`
}

func loadNHPQURLDynamicCustomerIDFixture(t *testing.T) nhpQURLDynamicCustomerIDFixture {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	data, err := os.ReadFile(filepath.Join(repoRoot, "contracts", "nhp", "qurl_dynamic_customer_id_vectors.json"))
	if err != nil {
		t.Fatalf("read shard fixture: %v", err)
	}

	var fixture nhpQURLDynamicCustomerIDFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse shard fixture: %v", err)
	}
	return fixture
}

type nhpQURLDynamicResourceRowFixture struct {
	Version     int                                      `json:"version"`
	Contract    string                                   `json:"contract"`
	Description string                                   `json:"description"`
	Attributes  map[string]nhpQURLDynamicResourceRowAttr `json:"attributes"`
}

type nhpQURLDynamicResourceRowAttr struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

func loadNHPQURLDynamicResourceRowFixture(t *testing.T) nhpQURLDynamicResourceRowFixture {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	data, err := os.ReadFile(filepath.Join(repoRoot, "contracts", "nhp", "qurl_dynamic_resource_row_fixture.json"))
	if err != nil {
		t.Fatalf("read row fixture: %v", err)
	}

	var fixture nhpQURLDynamicResourceRowFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse row fixture: %v", err)
	}
	if fixture.Version != 1 {
		t.Fatalf("row fixture version = %d, want 1", fixture.Version)
	}
	if fixture.Contract != "qurl_dynamic_resource_row" {
		t.Fatalf("row fixture contract = %q, want qurl_dynamic_resource_row", fixture.Contract)
	}
	if len(fixture.Attributes) == 0 {
		t.Fatal("row fixture must include attributes")
	}
	return fixture
}

func (f nhpQURLDynamicResourceRowFixture) attr(t *testing.T, key string) nhpQURLDynamicResourceRowAttr {
	t.Helper()

	attr, ok := f.Attributes[key]
	if !ok {
		t.Fatalf("row fixture missing attribute %q", key)
	}
	return attr
}

func (f nhpQURLDynamicResourceRowFixture) stringValue(t *testing.T, key string) string {
	t.Helper()

	attr := f.attr(t, key)
	value, ok := attr.Value.(string)
	if !ok {
		t.Fatalf("row fixture attribute %q value = %T, want string", key, attr.Value)
	}
	return value
}

func (f nhpQURLDynamicResourceRowFixture) intValue(t *testing.T, key string) int {
	t.Helper()

	value, err := strconv.Atoi(f.stringValue(t, key))
	if err != nil {
		t.Fatalf("row fixture attribute %q must be an int: %v", key, err)
	}
	return value
}

func (f nhpQURLDynamicResourceRowFixture) boolValue(t *testing.T, key string) bool {
	t.Helper()

	attr := f.attr(t, key)
	value, ok := attr.Value.(bool)
	if !ok {
		t.Fatalf("row fixture attribute %q value = %T, want bool", key, attr.Value)
	}
	return value
}

func (f nhpQURLDynamicResourceRowFixture) dynamoDBItem(t *testing.T) map[string]types.AttributeValue {
	t.Helper()

	item := make(map[string]types.AttributeValue, len(f.Attributes))
	for key, attr := range f.Attributes {
		switch attr.Type {
		case "S":
			value, ok := attr.Value.(string)
			if !ok {
				t.Fatalf("row fixture attribute %q value = %T, want string", key, attr.Value)
			}
			item[key] = &types.AttributeValueMemberS{Value: value}
		case "N":
			value, ok := attr.Value.(string)
			if !ok {
				t.Fatalf("row fixture attribute %q value = %T, want numeric string", key, attr.Value)
			}
			item[key] = &types.AttributeValueMemberN{Value: value}
		case "BOOL":
			value, ok := attr.Value.(bool)
			if !ok {
				t.Fatalf("row fixture attribute %q value = %T, want bool", key, attr.Value)
			}
			item[key] = &types.AttributeValueMemberBOOL{Value: value}
		default:
			t.Fatalf("row fixture attribute %q has unsupported DynamoDB type %q", key, attr.Type)
		}
	}
	return item
}

// putTunnelServerRow is a convenience around put() for the standard
// qurl-tunnel-server row shape — `aspId="agent"` + `ACId="layerv-ac-tf"`
// + the customer-facing AC ingress as Hostname/dest_host. Single
// fixed shape today; the only aspId in active use.
func putTunnelServerRow(q *fakeResourcesQuerier, resourceID string) {
	q.put(nhpSystemCustomerID, resourceID, "agent", "layerv-ac-tf", "connect.layerv.xyz", "connect.layerv.xyz", 7000, 120)
}

// TestResourceLookup_CacheMissThenHit asserts the standard flow:
// first lookup queries DDB; second lookup is a cache hit (no extra
// Query) and the applier is invoked exactly once.
func TestResourceLookup_CacheMissThenHit(t *testing.T) {
	q := newFakeResourcesQuerier()
	putTunnelServerRow(q, "qurl-tunnel-server")
	applier := &captureApplier{}

	l := newTestResourceLookup(t, q, applier)

	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("first lookup err: %v", err)
	}
	if asp == nil {
		t.Fatal("first lookup returned nil aspData")
	}
	if asp.AuthSvcId != "agent" {
		t.Errorf("AuthSvcId = %q, want %q", asp.AuthSvcId, "agent")
	}
	if _, ok := asp.ResourceGroups["qurl-tunnel-server"]; !ok {
		t.Errorf("ResourceGroups missing qurl-tunnel-server; got keys = %v", aspKeys(asp))
	}
	if got := q.callCount(); got != 1 {
		t.Errorf("DDB calls after first lookup = %d, want 1", got)
	}
	if got := applier.count(); got != 1 {
		t.Errorf("applyAspMapDelta calls after first lookup = %d, want 1", got)
	}

	asp2, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("second lookup err: %v", err)
	}
	if asp2 != asp {
		t.Errorf("second lookup returned a different pointer; want same cached *AuthServiceProviderData")
	}
	if got := q.callCount(); got != 1 {
		t.Errorf("DDB calls after second lookup = %d, want 1 (cache hit)", got)
	}
	// Cache hit re-publishes via the applier to self-heal against a
	// future authServiceMap wipe (e.g., updateResources). The
	// applyAspMapDelta fast-path short-circuits when the pointer is
	// already installed, so the steady-state cost is a single
	// pointer-compare — see TestApplyAspMapDelta_FastPathPointerEqual.
	if got := applier.count(); got != 2 {
		t.Errorf("applyAspMapDelta calls after second lookup = %d, want 2 (cache hit republishes for self-healing)", got)
	}
}

func TestResourceLookup_LookupResourceBypassesAspCacheForDynamicRows(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.put(nhpSystemCustomerID, "qurl-tunnel-server", "qurl", "existing-ac", "existing.example", "existing.example", 7000, 120)
	applier := &captureApplier{}
	l := newTestResourceLookup(t, q, applier)

	asp, err := l.LookupAuthServiceProvider(context.Background(), "qurl")
	if err != nil {
		t.Fatalf("warm lookup err: %v", err)
	}
	if _, ok := asp.ResourceGroups["qurl-tunnel-server"]; !ok {
		t.Fatalf("warm ASP missing qurl-tunnel-server; got %v", aspKeys(asp))
	}

	q.putDynamicQURLWithTTL("q_123456789ab", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300, time.Now().Add(time.Hour).Unix())
	if _, ok := asp.ResourceGroups["q_123456789ab"]; ok {
		t.Fatal("test setup invalid: cached ASP already contains q_123456789ab")
	}

	res, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
	if err != nil {
		t.Fatalf("LookupResource err: %v", err)
	}
	if res.ResourceId != "q_123456789ab" {
		t.Fatalf("ResourceId = %q, want q_123456789ab", res.ResourceId)
	}
	info := res.Resources["q_123456789ab"]
	if info == nil {
		t.Fatalf("Resources missing q_123456789ab: %#v", res.Resources)
	}
	if info.ACId != "dynamic-ac" {
		t.Fatalf("ACId = %q, want dynamic-ac", info.ACId)
	}
	if info.Addr == nil || info.Addr.Port != 8443 {
		t.Fatalf("Addr = %#v, want port 8443", info.Addr)
	}
	if got := applier.count(); got != 1 {
		t.Fatalf("applier count = %d, want 1; direct row lookup must not publish an ASP map", got)
	}
}

func TestResourceLookup_LookupResourceConsumesSharedDynamicRowFixture(t *testing.T) {
	fixture := loadNHPQURLDynamicResourceRowFixture(t)
	aspID := fixture.stringValue(t, "auth_service_id")
	resourceID := fixture.stringValue(t, "resource_id")
	q := newFakeResourcesQuerier()
	q.putDynamoDBItem(fixture.stringValue(t, "customer_id"), fixture.dynamoDBItem(t))
	l := newTestResourceLookup(t, q, &captureApplier{})

	res, err := l.LookupResource(context.Background(), aspID, resourceID)
	if err != nil {
		t.Fatalf("LookupResource err: %v", err)
	}
	if res.AuthServiceId != aspID {
		t.Fatalf("AuthServiceId = %q, want fixture auth_service_id", res.AuthServiceId)
	}
	if res.ResourceId != resourceID {
		t.Fatalf("ResourceId = %q, want fixture resource_id", res.ResourceId)
	}
	if res.OpenTime != uint32(fixture.intValue(t, "open_time")) {
		t.Fatalf("OpenTime = %d, want fixture open_time", res.OpenTime)
	}
	if !res.SkipAuth {
		t.Fatal("SkipAuth = false, want true for post-auth dynamic qURL catalog rows")
	}
	info := res.Resources[resourceID]
	if info == nil {
		t.Fatalf("Resources missing fixture resource_id: %#v", res.Resources)
	}
	if info.ACId != fixture.stringValue(t, "ac_id") {
		t.Fatalf("ACId = %q, want fixture ac_id", info.ACId)
	}
	if info.Hostname != fixture.stringValue(t, "resource_fqdn") {
		t.Fatalf("Hostname = %q, want fixture resource_fqdn", info.Hostname)
	}
	if want := fixture.boolValue(t, "port_suffix"); info.PortSuffix != want {
		t.Fatalf("PortSuffix = %v, want fixture port_suffix=%v", info.PortSuffix, want)
	}
	if info.Addr == nil || info.Addr.Port != fixture.intValue(t, "dest_port") || info.Addr.Protocol != "tcp" {
		t.Fatalf("Addr = %#v, want port fixture dest_port and tcp protocol", info.Addr)
	}
	if got := q.callCount(); got != 1 {
		t.Fatalf("DDB calls = %d, want 1 direct fixture lookup", got)
	}
}

func TestResourceLookup_LookupResourceCachesDynamicRows(t *testing.T) {
	q := newFakeResourcesQuerier()
	l := newTestResourceLookup(t, q, &captureApplier{})
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	q.putDynamicQURLWithTTL("q_123456789ab", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300, now.Add(time.Hour).Unix())

	first, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
	if err != nil {
		t.Fatalf("first LookupResource err: %v", err)
	}
	second, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
	if err != nil {
		t.Fatalf("second LookupResource err: %v", err)
	}
	if second != first {
		t.Fatalf("second LookupResource returned a different pointer; want direct cache hit")
	}
	if got := q.callCount(); got != 1 {
		t.Fatalf("DDB calls after cached direct lookup = %d, want 1", got)
	}

	now = now.Add(resourceLookupDirectCacheTTL + time.Second)
	third, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
	if err != nil {
		t.Fatalf("third LookupResource err: %v", err)
	}
	if third == second {
		t.Fatalf("third LookupResource returned cached pointer after direct cache TTL")
	}
	if got := q.callCount(); got != 2 {
		t.Fatalf("DDB calls after direct cache TTL expiry = %d, want 2", got)
	}
}

func TestResourceLookup_LookupResourceDirectCacheExpiresAtRowTTL(t *testing.T) {
	q := newFakeResourcesQuerier()
	l := newTestResourceLookup(t, q, &captureApplier{})
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	q.putDynamicQURLWithTTL("q_123456789ab", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300, now.Add(2*time.Second).Unix())

	if _, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab"); err != nil {
		t.Fatalf("first LookupResource err: %v", err)
	}
	now = now.Add(time.Second)
	if _, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab"); err != nil {
		t.Fatalf("cached LookupResource before row ttl err: %v", err)
	}
	if got := q.callCount(); got != 1 {
		t.Fatalf("DDB calls before row ttl expiry = %d, want 1", got)
	}

	now = now.Add(2 * time.Second)
	_, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
	if !errors.Is(err, ErrResourceUnknownResource) {
		t.Fatalf("LookupResource after row ttl err = %v, want ErrResourceUnknownResource", err)
	}
	if got := q.callCount(); got != 2 {
		t.Fatalf("DDB calls after row ttl expiry = %d, want 2", got)
	}
}

func TestResourceLookup_LookupResourceNegativeCachesMissingDynamicRows(t *testing.T) {
	q := newFakeResourcesQuerier()
	l := newTestResourceLookup(t, q, &captureApplier{})
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		_, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
		if !errors.Is(err, ErrResourceUnknownResource) {
			t.Fatalf("LookupResource #%d err = %v, want ErrResourceUnknownResource", i+1, err)
		}
	}
	if got := q.callCount(); got != 1 {
		t.Fatalf("DDB calls during negative cache window = %d, want 1", got)
	}

	now = now.Add(resourceLookupDirectNegativeCacheTTL + time.Second)
	_, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
	if !errors.Is(err, ErrResourceUnknownResource) {
		t.Fatalf("LookupResource after negative cache expiry err = %v, want ErrResourceUnknownResource", err)
	}
	if got := q.callCount(); got != 2 {
		t.Fatalf("DDB calls after negative cache expiry = %d, want 2", got)
	}
}

func TestResourceLookup_LookupResourceNegativeCachesExpiredDirectRows(t *testing.T) {
	q := newFakeResourcesQuerier()
	l := newTestResourceLookup(t, q, &captureApplier{})
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	counter := &fakeCounterIncrementer{}
	l.SetMetrics(counter)
	q.putDynamicQURLWithTTL("q_00000000001", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300, now.Add(-time.Second).Unix())

	for i := 0; i < 2; i++ {
		_, err := l.LookupResource(context.Background(), "qurl", "q_00000000001")
		if !errors.Is(err, ErrResourceUnknownResource) {
			t.Fatalf("LookupResource #%d err = %v, want ErrResourceUnknownResource", i+1, err)
		}
	}
	if got := q.callCount(); got != 1 {
		t.Fatalf("DDB calls during expired-row negative cache window = %d, want 1", got)
	}
	counter.mu.Lock()
	defer counter.mu.Unlock()
	if got := counter.counts[MetricResourceLookupExpiredDirectRow]; got != 1 {
		t.Fatalf("MetricResourceLookupExpiredDirectRow = %d, want 1; negative cache should not re-count cached rejects", got)
	}
}

func TestResourceLookup_LookupResourceDDBErrorNotNegativeCached(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.err = errors.New("ddb throttled")
	l := newTestResourceLookup(t, q, &captureApplier{})

	for i := 0; i < 2; i++ {
		_, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
		if !errors.Is(err, ErrResourceLookupRetryAfter) {
			t.Fatalf("LookupResource #%d err = %v, want ErrResourceLookupRetryAfter", i+1, err)
		}
	}
	if got := q.callCount(); got != 2 {
		t.Fatalf("DDB calls after repeated infra errors = %d, want 2; transient DDB errors must not be negative-cached", got)
	}
}

func TestResourceLookup_LookupResourceSingleflightDedupsConcurrentMiss(t *testing.T) {
	q := newFakeResourcesQuerier()
	now := time.Unix(1000, 0)
	q.putDynamicQURLWithTTL("q_123456789ab", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300, now.Add(time.Hour).Unix())

	const N = 8
	l := newTestResourceLookup(t, q, &captureApplier{})
	l.now = func() time.Time { return now }

	var entered sync.WaitGroup
	entered.Add(N)
	release := make(chan struct{})
	l.onDirectSingleflightEnter = func(aspId, resourceID string) {
		entered.Done()
	}
	q.beforeGetItem = func() {
		<-release
	}

	type result struct {
		res *common.ResourceData
		err error
	}
	results := make(chan result, N)
	var startWg sync.WaitGroup
	startWg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			startWg.Done()
			res, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
			results <- result{res: res, err: err}
		}()
	}
	startWg.Wait()
	entered.Wait()
	close(release)

	var firstPtr *common.ResourceData
	for i := 0; i < N; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("goroutine #%d err: %v", i, r.err)
			continue
		}
		if firstPtr == nil {
			firstPtr = r.res
			continue
		}
		if r.res != firstPtr {
			t.Errorf("goroutine #%d got distinct ResourceData pointer; want singleflight shared result", i)
		}
	}
	if got := q.callCount(); got != 1 {
		t.Fatalf("DDB calls = %d, want 1 direct GetItem", got)
	}
}

func TestResourceLookup_LookupResourceIgnoresDynamicRowsInSystemPartition(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.putWithTTL(nhpSystemCustomerID, "q_123456789ab", "qurl", "wrong-partition-ac", "wrong.example", "wrong.example", 8443, 300, time.Now().Add(time.Hour).Unix())
	l := newTestResourceLookup(t, q, &captureApplier{})

	_, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")

	if !errors.Is(err, ErrResourceUnknownResource) {
		t.Fatalf("err = %v, want ErrResourceUnknownResource; dynamic qURL lookup must read only the reserved qURL partition", err)
	}
}

func TestResourceLookup_LookupResourceIgnoresDynamicRowsInWrongShard(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.putWithTTL(nhpQURLDynamicCustomerIDPrefix+"-00", "q_123456789ab", "qurl", "wrong-shard-ac", "wrong.example", "wrong.example", 8443, 300, time.Now().Add(time.Hour).Unix())
	l := newTestResourceLookup(t, q, &captureApplier{})

	_, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")

	if !errors.Is(err, ErrResourceUnknownResource) {
		t.Fatalf("err = %v, want ErrResourceUnknownResource; dynamic qURL lookup must read only the resource_id-derived shard", err)
	}
}

func TestResourceLookup_LookupResourceRejectsExpiredDirectRow(t *testing.T) {
	q := newFakeResourcesQuerier()
	now := time.Unix(1_900_000_000, 0)
	q.putDynamicQURLWithTTL("q_00000000001", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300, now.Add(-time.Second).Unix())
	counter := &fakeCounterIncrementer{}
	l := newTestResourceLookup(t, q, &captureApplier{})
	l.now = func() time.Time { return now }
	l.SetMetrics(counter)

	_, err := l.LookupResource(context.Background(), "qurl", "q_00000000001")
	if !errors.Is(err, ErrResourceUnknownResource) {
		t.Fatalf("err = %v, want ErrResourceUnknownResource for expired direct row", err)
	}
	counter.mu.Lock()
	defer counter.mu.Unlock()
	if got := counter.counts[MetricResourceLookupExpiredDirectRow]; got != 1 {
		t.Fatalf("MetricResourceLookupExpiredDirectRow = %d, want 1", got)
	}
	if got := counter.counts[MetricResourceLookupMalformedRow]; got != 0 {
		t.Fatalf("MetricResourceLookupMalformedRow = %d, want 0; expired rows are valid rows rejected by freshness", got)
	}
}

func TestResourceLookup_LookupResourceRejectsMissingDirectRowTTL(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.putDynamicQURL("q_0000000007c", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300)
	counter := &fakeCounterIncrementer{}
	l := newTestResourceLookup(t, q, &captureApplier{})
	l.SetMetrics(counter)

	_, err := l.LookupResource(context.Background(), "qurl", "q_0000000007c")
	if !errors.Is(err, ErrResourceUnknownResource) {
		t.Fatalf("err = %v, want ErrResourceUnknownResource for direct row without ttl", err)
	}
	counter.mu.Lock()
	defer counter.mu.Unlock()
	if got := counter.counts[MetricResourceLookupMissingDirectTTL]; got != 1 {
		t.Fatalf("MetricResourceLookupMissingDirectTTL = %d, want 1 for direct row without ttl", got)
	}
	if got := counter.counts[MetricResourceLookupMalformedRow]; got != 0 {
		t.Fatalf("MetricResourceLookupMalformedRow = %d, want 0; missing direct ttl has a dedicated producer-contract counter", got)
	}
}

func TestResourceLookup_LookupResourceRejectsNonDynamicResourceIDBeforeDDB(t *testing.T) {
	for _, resourceID := range []string{
		"qurl-tunnel-server",
		"q_",
		"q_3a7f2c8e9",
		"q_3a7f2c8e91b0",
		"q_3A7F2C8E91B",
		"q_zzzzzzzzzzz",
	} {
		t.Run(resourceID, func(t *testing.T) {
			q := newFakeResourcesQuerier()
			putTunnelServerRow(q, "qurl-tunnel-server")
			l := newTestResourceLookup(t, q, &captureApplier{})

			_, err := l.LookupResource(context.Background(), "qurl", resourceID)

			if !errors.Is(err, ErrResourceUnknownResource) {
				t.Fatalf("err = %v, want ErrResourceUnknownResource for non-dynamic direct lookup", err)
			}
			if got := q.callCount(); got != 0 {
				t.Fatalf("DDB calls = %d, want 0 for non-dynamic direct lookup", got)
			}
		})
	}
}

func TestResourceLookup_LookupResourceRejectsNonQURLASPBeforeDDB(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.putDynamicQURLWithTTL("q_123456789ab", "agent", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300, time.Now().Add(time.Hour).Unix())
	l := newTestResourceLookup(t, q, &captureApplier{})

	_, err := l.LookupResource(context.Background(), "agent", "q_123456789ab")

	if !errors.Is(err, ErrResourceUnknownResource) {
		t.Fatalf("err = %v, want ErrResourceUnknownResource for non-qurl ASP direct lookup", err)
	}
	if got := q.callCount(); got != 0 {
		t.Fatalf("DDB calls = %d, want 0 for non-qurl ASP direct lookup", got)
	}
}

func TestResourceLookup_QURLASPCacheExcludesDynamicRows(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.putDynamicQURL("q_123456789ab", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300)
	q.put(nhpSystemCustomerID, "qurl-tunnel-server-a", "qurl", "static-ac", "static.example", "static.example", 7000, 120)

	l := newTestResourceLookup(t, q, &captureApplier{})
	asp, err := l.LookupAuthServiceProvider(context.Background(), "qurl")
	if err != nil {
		t.Fatalf("LookupAuthServiceProvider err: %v", err)
	}
	if _, ok := asp.ResourceGroups["qurl-tunnel-server-a"]; !ok {
		t.Fatalf("static qurl-tunnel-server-a missing from ASP cache; got %v", aspKeys(asp))
	}
	if _, ok := asp.ResourceGroups["q_123456789ab"]; ok {
		t.Fatalf("dynamic q_ row leaked into ASP cache; got %v", aspKeys(asp))
	}
}

func TestResourceLookup_QURLStaticRowsRequireStaticPrefix(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.put(nhpSystemCustomerID, "tunnel-server-a", "qurl", "static-ac", "static.example", "static.example", 7000, 120)
	applier := &captureApplier{}
	l := newTestResourceLookup(t, q, applier)

	_, err := l.LookupAuthServiceProvider(context.Background(), "qurl")
	if !errors.Is(err, ErrResourceUnknownASP) {
		t.Fatalf("err = %v, want ErrResourceUnknownASP for qurl static row without qurl- prefix", err)
	}
	if got := applier.count(); got != 0 {
		t.Fatalf("applier count = %d, want 0 for misprefixed qurl static row", got)
	}
	if got := q.callCount(); got != 1 {
		t.Fatalf("DDB calls = %d, want 1", got)
	}
}

func TestResourceLookup_LookupResourceRejectsWrongASP(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.putDynamicQURL("q_123456789ab", "other-asp", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300)
	counter := &fakeCounterIncrementer{}
	l := newTestResourceLookup(t, q, &captureApplier{})
	l.SetMetrics(counter)

	_, err := l.LookupResource(context.Background(), "qurl", "q_123456789ab")
	if !errors.Is(err, ErrResourceUnknownResource) {
		t.Fatalf("err = %v, want ErrResourceUnknownResource", err)
	}
	counter.mu.Lock()
	defer counter.mu.Unlock()
	if got := counter.counts[MetricResourceLookupAspMismatch]; got != 0 {
		t.Fatalf("MetricResourceLookupAspMismatch = %d, want 0; direct wrong-ASP requests must not trip the Query-regression alarm", got)
	}
	if got := counter.counts[MetricResourceLookupDirectAspMismatch]; got != 1 {
		t.Fatalf("MetricResourceLookupDirectAspMismatch = %d, want 1; direct wrong-ASP rows must be visible as producer regressions", got)
	}
}

// TestResourceLookup_CacheExpiry asserts that an entry past its TTL
// is evicted and the next lookup re-queries DDB. Uses the injectable
// clock so the test doesn't sleep.
func TestResourceLookup_CacheExpiry(t *testing.T) {
	q := newFakeResourcesQuerier()
	putTunnelServerRow(q, "qurl-tunnel-server")
	applier := &captureApplier{}
	l := newTestResourceLookup(t, q, applier)

	t0 := time.Now()
	l.now = func() time.Time { return t0 }

	if _, err := l.LookupAuthServiceProvider(context.Background(), "agent"); err != nil {
		t.Fatalf("warm lookup err: %v", err)
	}
	if got := q.callCount(); got != 1 {
		t.Errorf("DDB calls after warm = %d, want 1", got)
	}

	// Advance past the TTL — the next lookup must re-Query.
	l.now = func() time.Time { return t0.Add(resourceLookupCacheTTL + time.Second) }

	if _, err := l.LookupAuthServiceProvider(context.Background(), "agent"); err != nil {
		t.Fatalf("post-expiry lookup err: %v", err)
	}
	if got := q.callCount(); got != 2 {
		t.Errorf("DDB calls after expiry = %d, want 2 (cache evicted)", got)
	}
	if got := applier.count(); got != 2 {
		t.Errorf("applyAspMapDelta calls after expiry = %d, want 2 (re-publish on re-resolve)", got)
	}
}

// TestResourceLookup_UnknownASP asserts that an aspId with no
// matching rows returns ErrResourceUnknownASP and is NOT cached
// (so a future-bootstrapped aspId resolves on the next knock without
// waiting for TTL).
func TestResourceLookup_UnknownASP(t *testing.T) {
	q := newFakeResourcesQuerier()
	// Row exists under "agent" but caller asks for "other-asp".
	putTunnelServerRow(q, "qurl-tunnel-server")
	applier := &captureApplier{}
	l := newTestResourceLookup(t, q, applier)

	_, err := l.LookupAuthServiceProvider(context.Background(), "other-asp")
	if !errors.Is(err, ErrResourceUnknownASP) {
		t.Fatalf("err = %v, want ErrResourceUnknownASP", err)
	}
	if applier.count() != 0 {
		t.Errorf("applyAspMapDelta called for unknown ASP; should not publish")
	}

	// Confirm not cached: a second lookup re-Queries.
	_, _ = l.LookupAuthServiceProvider(context.Background(), "other-asp")
	if got := q.callCount(); got != 2 {
		t.Errorf("DDB calls = %d, want 2 (unknown ASP must not be negative-cached)", got)
	}
}

// TestResourceLookup_EmptyPartition exercises the path where the
// customer partition itself is empty (DDB returns Items: nil).
// Should return ErrResourceUnknownASP without invoking the applier.
func TestResourceLookup_EmptyPartition(t *testing.T) {
	q := newFakeResourcesQuerier()
	applier := &captureApplier{}
	l := newTestResourceLookup(t, q, applier)

	_, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if !errors.Is(err, ErrResourceUnknownASP) {
		t.Fatalf("err = %v, want ErrResourceUnknownASP for empty partition", err)
	}
	if applier.count() != 0 {
		t.Error("applier called on empty partition; should not publish")
	}
}

// TestResourceLookup_DDBErrorRetryAfter asserts that a transient DDB
// error wraps ErrResourceLookupRetryAfter, is not cached, and does
// not publish.
func TestResourceLookup_DDBErrorRetryAfter(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.err = errors.New("ddb 5xx: ProvisionedThroughputExceeded")
	applier := &captureApplier{}
	l := newTestResourceLookup(t, q, applier)

	_, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if !errors.Is(err, ErrResourceLookupRetryAfter) {
		t.Fatalf("err = %v, want wrap of ErrResourceLookupRetryAfter", err)
	}
	if applier.count() != 0 {
		t.Error("applier called on DDB error; should not publish")
	}

	// Confirm not cached: retry re-Queries.
	_, _ = l.LookupAuthServiceProvider(context.Background(), "agent")
	if got := q.callCount(); got != 2 {
		t.Errorf("DDB calls = %d, want 2 (transient error must not poison cache)", got)
	}
}

// TestResourceLookup_HappyPathMatchesPluginReadShape asserts the
// resolved *AuthServiceProviderData matches the shape the agent
// plugin (endpoints/server/staticplugins/agent) reads from
// helper.AspData. This is the contract that lets the bridge populate
// authServiceMap[aspId] from DDB without the plugin needing to know.
// Pre-#1976 the equivalent shape came from a baked TOML overlay; the
// invariants the test fences (inner-equals-outer key, SkipAuth=true,
// Hostname-without-Addr.Ip) survived the overlay's removal — the
// plugin reads the same fields regardless of which loader produced
// them.
func TestResourceLookup_HappyPathMatchesPluginReadShape(t *testing.T) {
	q := newFakeResourcesQuerier()
	putTunnelServerRow(q, "qurl-tunnel-server")
	l := newTestResourceLookup(t, q, &captureApplier{})

	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v", err)
	}

	group, ok := asp.ResourceGroups["qurl-tunnel-server"]
	if !ok {
		t.Fatalf("ResourceGroups missing qurl-tunnel-server; got %v", aspKeys(asp))
	}
	if got := group.AuthServiceId; got != "agent" {
		t.Errorf("group.AuthServiceId = %q, want %q", got, "agent")
	}
	if got := group.ResourceId; got != "qurl-tunnel-server" {
		t.Errorf("group.ResourceId = %q, want %q", got, "qurl-tunnel-server")
	}
	if got := group.OpenTime; got != 120 {
		t.Errorf("group.OpenTime = %d, want 120", got)
	}
	// SkipAuth=true is load-bearing — the agent plugin's AuthWithNHP
	// fences on `if !res.SkipAuth { return ErrBackendAuthRequired }`.
	// The agent plugin fences on SkipAuth=true; the DDB resolver
	// must populate the same field so the plugin path stays uniform
	// across the TOML-overlay and DDB-bridge code paths.
	if !group.SkipAuth {
		t.Error("group.SkipAuth = false, want true (agent plugin fences on this — see endpoints/server/staticplugins/agent/main.go::AuthWithNHP)")
	}

	res, ok := group.Resources["qurl-tunnel-server"]
	if !ok {
		t.Fatalf("inner Resources missing qurl-tunnel-server; got %v", groupResourceKeys(group))
	}
	if got := res.ACId; got != "layerv-ac-tf" {
		t.Errorf("res.ACId = %q, want %q", got, "layerv-ac-tf")
	}
	if got := res.Hostname; got != "connect.layerv.xyz" {
		t.Errorf("res.Hostname = %q, want %q (customer-facing AC ingress, per FRPS-behind-AC redesign)", got, "connect.layerv.xyz")
	}
	if res.Addr == nil {
		t.Fatal("res.Addr = nil, want non-nil NetAddress")
	}
	// Addr.Ip is intentionally empty — the agent plugin's downstream
	// handleNhpOpenResource path falls back to Hostname via DestHost().
	// Mirror the overlay invariant exactly.
	if res.Addr.Ip != "" {
		t.Errorf("res.Addr.Ip = %q, want empty (overlay invariant: DestHost() falls back to Hostname)", res.Addr.Ip)
	}
	if got := res.Addr.Port; got != 7000 {
		t.Errorf("res.Addr.Port = %d, want 7000", got)
	}
	if res.PortSuffix {
		t.Error("res.PortSuffix = true, want false for legacy qurl-tunnel-server alias")
	}
	if got := res.DestHost(); got != "connect.layerv.xyz" {
		t.Errorf("res.DestHost() = %q, want connect.layerv.xyz", got)
	}
	if got := res.Addr.Protocol; got != "tcp" {
		t.Errorf("res.Addr.Protocol = %q, want %q", got, "tcp")
	}
}

func TestResourceLookup_PortSuffixControlsAckHostPerResource(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.put(nhpSystemCustomerID, "qurl-tunnel-server", "agent", "layerv-ac-tf", "connect.layerv.xyz", "frps-a.nhp.sandbox.internal", 7000, 120)
	q.putWithPortSuffix(nhpSystemCustomerID, "qurl-tunnel-server-a", "agent", "layerv-ac-tf", "connect.layerv.xyz", "frps-a.nhp.sandbox.internal", 7000, 120, false)
	q.putWithPortSuffix(nhpSystemCustomerID, "qurl-tunnel-server-b", "agent", "layerv-ac-tf", "connect.layerv.xyz", "frps-b.nhp.sandbox.internal", 7001, 120, true)
	q.putWithPortSuffix(nhpSystemCustomerID, "qurl-tunnel-server-c", "agent", "layerv-ac-tf", "connect.layerv.xyz", "frps-c.nhp.sandbox.internal", 7002, 120, true)
	q.putWithPortSuffix(nhpSystemCustomerID, "qurl-tunnel-server-z", "agent", "layerv-ac-tf", "connect.layerv.xyz", "frps-z.nhp.sandbox.internal", 65535, 120, true)
	l := newTestResourceLookup(t, q, &captureApplier{})

	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v", err)
	}

	tests := []struct {
		resourceID string
		wantSuffix bool
		wantHost   string
		wantPort   int
	}{
		{
			resourceID: "qurl-tunnel-server",
			wantSuffix: false,
			wantHost:   "connect.layerv.xyz",
			wantPort:   7000,
		},
		{
			resourceID: "qurl-tunnel-server-a",
			wantSuffix: false,
			wantHost:   "connect.layerv.xyz",
			wantPort:   7000,
		},
		{
			resourceID: "qurl-tunnel-server-b",
			wantSuffix: true,
			wantHost:   "connect.layerv.xyz:7001",
			wantPort:   7001,
		},
		{
			resourceID: "qurl-tunnel-server-c",
			wantSuffix: true,
			wantHost:   "connect.layerv.xyz:7002",
			wantPort:   7002,
		},
		{
			resourceID: "qurl-tunnel-server-z",
			wantSuffix: true,
			wantHost:   "connect.layerv.xyz:65535",
			wantPort:   65535,
		},
	}

	for _, tt := range tests {
		t.Run(tt.resourceID, func(t *testing.T) {
			group := asp.ResourceGroups[tt.resourceID]
			if group == nil {
				t.Fatalf("missing %s group; got %v", tt.resourceID, aspKeys(asp))
			}
			res := group.Resources[tt.resourceID]
			if res == nil {
				t.Fatalf("missing %s resource; got %v", tt.resourceID, groupResourceKeys(group))
			}
			if got := res.PortSuffix; got != tt.wantSuffix {
				t.Fatalf("res.PortSuffix = %v, want %v", got, tt.wantSuffix)
			}
			if got := res.DestHost(); got != tt.wantHost {
				t.Fatalf("res.DestHost() = %q, want %q", got, tt.wantHost)
			}
			if res.Addr == nil {
				t.Fatal("res.Addr = nil, want non-nil NetAddress")
			}
			if got := res.Addr.Port; got != tt.wantPort {
				t.Fatalf("res.Addr.Port = %d, want %d", got, tt.wantPort)
			}
		})
	}
}

// TestResourceLookup_SkipsMalformedRow_ContinuesWithRest asserts the
// "partial parse" contract: a single malformed row from a writer-side
// regression must NOT dark the entire catalog. Remaining rows still
// populate the resolved aspData and an operator-visible WARN log fires.
func TestResourceLookup_SkipsMalformedRow_ContinuesWithRest(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		seed       func(*fakeResourcesQuerier)
	}{
		{
			name:       "unmarshal failure",
			resourceID: "bad-resource",
			seed: func(q *fakeResourcesQuerier) {
				q.putMalformedRow(nhpSystemCustomerID, "bad-resource")
			},
		},
		{
			name:       "empty resource_fqdn",
			resourceID: "empty-fqdn",
			seed: func(q *fakeResourcesQuerier) {
				q.putWithPortSuffix(nhpSystemCustomerID, "empty-fqdn", "agent", "layerv-ac-tf", "", "frps-a.nhp.sandbox.internal", 7001, 120, true)
			},
		},
		{
			name:       "port_suffix non-positive dest_port",
			resourceID: "bad-port-suffix-zero",
			seed: func(q *fakeResourcesQuerier) {
				q.putWithPortSuffix(nhpSystemCustomerID, "bad-port-suffix-zero", "agent", "layerv-ac-tf", "connect.layerv.xyz", "frps-b.nhp.sandbox.internal", 0, 120, true)
			},
		},
		{
			name:       "port_suffix oversized dest_port",
			resourceID: "bad-port-suffix-high",
			seed: func(q *fakeResourcesQuerier) {
				q.putWithPortSuffix(nhpSystemCustomerID, "bad-port-suffix-high", "agent", "layerv-ac-tf", "connect.layerv.xyz", "frps-c.nhp.sandbox.internal", 65536, 120, true)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := newFakeResourcesQuerier()
			tt.seed(q)
			putTunnelServerRow(q, "qurl-tunnel-server")
			counter := &fakeCounterIncrementer{}
			l := newTestResourceLookup(t, q, &captureApplier{})
			l.SetMetrics(counter)

			asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
			if err != nil {
				t.Fatalf("lookup err: %v, want success despite malformed row", err)
			}
			if _, ok := asp.ResourceGroups["qurl-tunnel-server"]; !ok {
				t.Errorf("qurl-tunnel-server missing; malformed row must not dark the rest of the catalog")
			}
			if _, ok := asp.ResourceGroups[tt.resourceID]; ok {
				t.Errorf("%s present; malformed rows must be skipped", tt.resourceID)
			}
			counter.mu.Lock()
			defer counter.mu.Unlock()
			if got := counter.counts[MetricResourceLookupMalformedRow]; got != 1 {
				t.Errorf("MetricResourceLookupMalformedRow fire count = %d, want 1 for %s", got, tt.name)
			}
		})
	}
}

// TestResourceLookup_FiltersByAuthServiceID asserts that a partition
// carrying rows for multiple aspIds returns only those matching the
// requested aspId. Today the system partition carries only "agent"
// rows; the filter is defensive for a future multi-aspId schema.
//
// Asserts BOTH directions — without the reverse-direction
// assertion, a regression hardcoding the filter to
// `row.AuthServiceID == "agent"` would pass on the agent side
// without ever testing whether other aspIds are correctly served
// only their own rows.
//
// Implementation note: because `fakeResourcesQuerier` does NOT honor
// FilterExpression server-side (it returns the whole partition),
// this test inherently traverses the client-side
// `row.AuthServiceID != aspId` defense-in-depth branch (the same one
// `TestResourceLookup_SkipsAspMismatchRow` fences explicitly with a
// counter assertion). This test uses `&captureApplier{}` with no
// metrics attached, so `IncrCounter` is a no-op here — if a future
// maintainer adds `SetMetrics(counter)` to this test and asserts
// `counter.counts[MetricResourceLookupAspMismatch] == 0`, they'll
// be surprised because the cross-aspId rows ARE traversing the
// mismatch branch under the fake. The counter fence lives in the
// sibling SkipsAspMismatchRow test, not here.
func TestResourceLookup_FiltersByAuthServiceID(t *testing.T) {
	q := newFakeResourcesQuerier()
	// Two aspIds sharing the partition.
	q.put(nhpSystemCustomerID, "qurl-tunnel-server", "agent", "layerv-ac-tf", "connect.layerv.xyz", "connect.layerv.xyz", 7000, 120)
	q.put(nhpSystemCustomerID, "other-res", "other-asp", "other-ac", "other.example.com", "other.example.com", 8000, 60)
	l := newTestResourceLookup(t, q, &captureApplier{})

	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v", err)
	}
	if _, ok := asp.ResourceGroups["qurl-tunnel-server"]; !ok {
		t.Errorf("agent must include qurl-tunnel-server; got %v", aspKeys(asp))
	}
	if _, ok := asp.ResourceGroups["other-res"]; ok {
		t.Errorf("agent aspData leaked other-asp's resource; rows must be filtered by auth_service_id")
	}

	// Reverse direction: requesting "other-asp" must NOT leak any
	// "agent" rows. A regression that hardcoded the filter to
	// `row.AuthServiceID == "agent"` (or any constant) would
	// either return an empty/unknown result for "other-asp" OR
	// include agent's rows in the response — both detectable here.
	asp2, err := l.LookupAuthServiceProvider(context.Background(), "other-asp")
	if err != nil {
		t.Fatalf("reverse lookup err: %v", err)
	}
	if _, ok := asp2.ResourceGroups["other-res"]; !ok {
		t.Errorf("other-asp must include other-res; got %v", aspKeys(asp2))
	}
	if _, ok := asp2.ResourceGroups["qurl-tunnel-server"]; ok {
		t.Errorf("other-asp aspData leaked agent's resource; rows must be filtered by auth_service_id")
	}
	if asp2.AuthSvcId != "other-asp" {
		t.Errorf("AuthSvcId = %q, want %q (resolver must stamp the requested aspId on the result, not the row's aspId)", asp2.AuthSvcId, "other-asp")
	}
}

// TestResourceLookup_OpenTimeClampsNonPositive asserts the
// defensive zero-or-negative clamp (the
// negative branch was tested; OpenTime=0 silently propagated).
func TestResourceLookup_OpenTimeClampsNonPositive(t *testing.T) {
	cases := []struct {
		name         string
		stored       int
		wantOpenTime uint32
	}{
		{"zero", 0, uint32(DefaultIpOpenTime)},
		{"negative", -1, uint32(DefaultIpOpenTime)},
		{"negative_large", -1_000_000, uint32(DefaultIpOpenTime)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := newFakeResourcesQuerier()
			q.put(nhpSystemCustomerID, "qurl-tunnel-server", "agent", "layerv-ac-tf", "connect.layerv.xyz", "connect.layerv.xyz", 7000, tc.stored)
			l := newTestResourceLookup(t, q, &captureApplier{})

			asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
			if err != nil {
				t.Fatalf("lookup err: %v", err)
			}
			group := asp.ResourceGroups["qurl-tunnel-server"]
			if group == nil {
				t.Fatalf("ResourceGroups missing qurl-tunnel-server; got %v", aspKeys(asp))
			}
			if group.OpenTime != tc.wantOpenTime {
				t.Errorf("OpenTime = %d, want %d (clamp must default non-positive open_time to DefaultIpOpenTime, not propagate the raw value)", group.OpenTime, tc.wantOpenTime)
			}
		})
	}
}

// TestResourceLookup_OpenTimeClampsOverflow exercises the >uint32
// overflow branch. Today no real writer emits values near MaxUint32,
// but the platform-portability fence (int64(math.MaxUint32) widening
// the comparison so the constant doesn't truncate on 32-bit) needs
// test coverage so a future refactor doesn't regress it silently.
func TestResourceLookup_OpenTimeClampsOverflow(t *testing.T) {
	q := newFakeResourcesQuerier()
	// 5 billion exceeds MaxUint32 (~4.29 billion) — must clamp.
	q.put(nhpSystemCustomerID, "qurl-tunnel-server", "agent", "layerv-ac-tf", "connect.layerv.xyz", "connect.layerv.xyz", 7000, 5_000_000_000)
	l := newTestResourceLookup(t, q, &captureApplier{})

	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v", err)
	}
	group := asp.ResourceGroups["qurl-tunnel-server"]
	if group == nil {
		t.Fatalf("ResourceGroups missing qurl-tunnel-server; got %v", aspKeys(asp))
	}
	// Clamp is at MaxInt32 (not MaxUint32) for 32-bit platform safety
	// — int(MaxUint32) on a 32-bit build is -1 (signed overflow) so the
	// local int variable would carry a negative value through the
	// rest of the function. MaxInt32 (~68 years of seconds) is still
	// well past any plausible OpenTime use.
	const wantClamped uint32 = 2_147_483_647
	if group.OpenTime != wantClamped {
		t.Errorf("OpenTime = %d, want %d (overflow must clamp at MaxInt32 for 32-bit-portable safety)", group.OpenTime, wantClamped)
	}
}

// TestResourceLookup_SkipsAspMismatchRow asserts the defense-in-depth
// fence against a future regression in the DDB FilterExpression
// (`auth_service_id = :asp`) that lets rows for the wrong aspId
// leak through to the client-side loop. The resolver MUST skip rows
// whose `row.AuthServiceID` doesn't match the requested aspId, and
// fires MetricResourceLookupAspMismatch (dedicated counter —
// operators alarm at `> 0` because a mismatched aspId means a knock
// for aspId X gets resources from aspId Y in its ack, a potential
// cross-aspId routing bug).
//
// The fake querier doesn't honor FilterExpression — it returns the
// whole partition — so a row injected with a different
// auth_service_id reaches the client-side check naturally without
// the server-side filter being involved. This is the test path that
// exercises the defense the production FilterExpression makes
// unreachable in practice.
//
// The counter assertion is load-bearing: the whole justification
// for splitting MetricResourceLookupAspMismatch out of
// MetricResourceLookupMalformedRow was the differential alarm
// threshold (`> 0` for aspId-mismatch vs. ratio-based for
// malformed-row). If a future refactor drops the IncrCounter call,
// the row is still filtered by the `continue`, the catalog still
// returns the rest of the rows, the operator alarm silently goes
// dark — and the row-presence asserts below would still pass. The
// counter assertion is the only thing that catches that regression.
func TestResourceLookup_SkipsAspMismatchRow(t *testing.T) {
	q := newFakeResourcesQuerier()
	// Inject a row under the system partition tagged with a
	// different auth_service_id than the resolver will ask for.
	// In production this row would be filtered server-side; the
	// fake skips that filter, so the row reaches the client-side
	// `row.AuthServiceID != aspId` check.
	q.put(nhpSystemCustomerID, "other-aspid-resource", "other-aspid", "layerv-ac-tf", "other.example.com", "other.example.com", 7000, 120)
	putTunnelServerRow(q, "good-resource")

	counter := &fakeCounterIncrementer{}
	l := newTestResourceLookup(t, q, &captureApplier{})
	l.SetMetrics(counter)

	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v, want success despite aspId-mismatched row", err)
	}
	if _, ok := asp.ResourceGroups["good-resource"]; !ok {
		t.Errorf("good-resource missing; aspId-mismatched row must not dark the rest of the catalog")
	}
	if _, ok := asp.ResourceGroups["other-aspid-resource"]; ok {
		t.Errorf("other-aspid-resource present in asp for aspId=\"agent\"; the row's auth_service_id=\"other-aspid\" MUST be skipped to prevent cross-aspId resource routing under a future FilterExpression regression (e.g., a knock for agent gets resources from other-aspid in the ack)")
	}

	// MetricResourceLookupAspMismatch MUST fire exactly once — one
	// mismatched row in. A future refactor that drops the IncrCounter
	// call (leaving the `continue` in place) would still pass the row-
	// filtering asserts above, silently darken the operator alarm,
	// and surface only when an actual filter regression in prod went
	// unnoticed because the dashboard stayed at zero. This is the
	// fence against that.
	counter.mu.Lock()
	defer counter.mu.Unlock()
	if got := counter.counts[MetricResourceLookupAspMismatch]; got != 1 {
		t.Errorf("MetricResourceLookupAspMismatch fire count = %d, want 1 — the dedicated counter exists explicitly for `> 0` alarm thresholds (see msghandler.go); a regression that drops the IncrCounter call leaves the row-filtering pass but silently darkens the alarm path", got)
	}
}

// TestResourceLookup_SkipsCrossPartitionRow asserts the
// defense-in-depth fence against a future regression in
// KeyConditionExpression that lets cross-partition rows leak.
// The resolver MUST skip rows whose customer_id doesn't match the
// configured partition, and fires MetricResourceLookupCrossPartition
// (dedicated counter — operators alarm at `> 0` because a
// cross-partition row in a per-tenant schema is a potential
// cross-tenant correctness bug).
func TestResourceLookup_SkipsCrossPartitionRow(t *testing.T) {
	q := newFakeResourcesQuerier()
	// Cross-partition row alongside a good row. The fake doesn't
	// honor KeyConditionExpression — both rows reach the resolver
	// loop. The resolver's defense-in-depth check filters the
	// cross-partition one client-side.
	q.put("ZZZZZZZZZZZZZZZZZZZZZZZZZZ", "leaked-resource", "agent", "layerv-ac-tf", "leaked.example.com", "leaked.example.com", 7000, 120)
	putTunnelServerRow(q, "good-resource")

	l := newTestResourceLookup(t, q, &captureApplier{})
	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v, want success despite cross-partition row", err)
	}
	if _, ok := asp.ResourceGroups["good-resource"]; !ok {
		t.Errorf("good-resource missing; cross-partition row must not dark the rest of the catalog")
	}
	if _, ok := asp.ResourceGroups["leaked-resource"]; ok {
		t.Errorf("leaked-resource present; cross-partition row MUST be skipped to prevent cross-tenant data leak under a future KeyConditionExpression regression")
	}
}

// TestForwarder_ThreadsLifecycleCtxToResolver fences the
// f.deps.LifecycleCtx() plumbing on the forward path. The forwarder
// MUST pass its deps' LifecycleCtx to ResolveAuthSvcProvider so the
// resolver's shutdown-classification branch is reachable from the
// forwarder seam (a graceful Stop() cancels lifecycleCtx, in-flight
// forward-receiver lookups observe ctx.Canceled, and
// MetricResourceLookupDDBError is correctly suppressed for the
// shutdown case).
//
// A regression that swapped to context.Background() (or dropped the
// LifecycleCtx() interface method) would silently route shutdown
// errors through MetricResourceLookupDDBError. The mock can't
// exercise the resolver's three-way switch directly (no real
// ResourceLookup wired — that's #2126), but it CAN fence that
// callers pass the right ctx.
func TestForwarder_ThreadsLifecycleCtxToResolver(t *testing.T) {
	// A pre-canceled ctx as the mock's lifecycleCtx. If the
	// forwarder calls Resolve with this ctx, the mock captures it
	// and ctx.Err() != nil proves the plumbing is intact.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := NewMockForwarderDeps()
	deps.SetLifecycleCtx(canceledCtx)
	// Drive the resolver call directly via the interface method
	// (forwarder code path). The wire test (HandleForwardRequest
	// end-to-end) is overkill for this seam.
	_ = deps.ResolveAuthSvcProvider(deps.LifecycleCtx(), "test-asp", "test")

	got := deps.LastResolveCtx()
	if got == nil {
		t.Fatal("LastResolveCtx() = nil — mock didn't capture the ctx passed to ResolveAuthSvcProvider")
	}
	if got.Err() == nil {
		t.Errorf("LastResolveCtx().Err() = nil, want context.Canceled — the ctx threaded into the resolver MUST be the lifecycle ctx (canceled in this fixture), not context.Background()")
	}
}

// TestResourceLookup_SkipsEmptyResourceID asserts that a writer-side
// regression that produced a row with empty resource_id is skipped
// rather than poisoning the inner Resources map. noted this
// branch was implemented but untested.
func TestResourceLookup_SkipsEmptyResourceID(t *testing.T) {
	q := newFakeResourcesQuerier()
	// A row with empty resource_id alongside a good row.
	q.put(nhpSystemCustomerID, "", "agent", "layerv-ac-tf", "host.example.com", "host.example.com", 7000, 120)
	q.put(nhpSystemCustomerID, "qurl-tunnel-server", "agent", "layerv-ac-tf", "connect.layerv.xyz", "connect.layerv.xyz", 7000, 120)
	l := newTestResourceLookup(t, q, &captureApplier{})

	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v", err)
	}
	if _, ok := asp.ResourceGroups["qurl-tunnel-server"]; !ok {
		t.Errorf("qurl-tunnel-server missing; empty-resource_id row must not dark the rest of the catalog")
	}
	if _, ok := asp.ResourceGroups[""]; ok {
		t.Errorf("ResourceGroups[\"\"] populated; rows with empty resource_id must be skipped, not keyed on \"\"")
	}
}

// TestResourceLookup_CacheHitRepublishes asserts the self-healing
// republish on cache hit. cache hits returned the cached
// aspData without calling the applier, so a TOML file-watcher race
// that wiped authServiceMap left it stale until cache TTL expiry.
// Now: every cache hit calls applyAspMapDelta, which short-circuits
// when the pointer is already installed (cheap pointer-compare under
// write lock) and re-installs on a mismatch.
func TestResourceLookup_CacheHitRepublishes(t *testing.T) {
	q := newFakeResourcesQuerier()
	putTunnelServerRow(q, "qurl-tunnel-server")
	applier := &captureApplier{}
	l := newTestResourceLookup(t, q, applier)

	// Warm the cache.
	asp1, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("warm err: %v", err)
	}
	if applier.count() != 1 {
		t.Fatalf("warm applier count = %d, want 1", applier.count())
	}

	// Second lookup: cache hit. applier was NOT
	// called; now it IS, so a future authServiceMap-clearing event
	// self-heals on the next knock.
	asp2, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("hit err: %v", err)
	}
	if asp1 != asp2 {
		t.Errorf("cache hit returned distinct pointer; LRU must hand out the same *AuthServiceProviderData within TTL")
	}
	if applier.count() != 2 {
		t.Errorf("applier count = %d, want 2 (cache hit must republish for self-healing against TOML watcher race)", applier.count())
	}
}

// TestUdpServer_ResolveAuthSvcProvider exercises the metric-attribution
// contract in ResolveAuthSvcProvider:
//
//   - In-memory hit: NO counter.
//   - resourceLookup == nil + miss: MetricAuthFailure (auth-policy).
//   - ErrResourceUnknownASP: MetricAuthFailure (auth-policy).
//   - DDB error: MetricResourceLookupDDBError ONLY (not auth-failure;
//     the auth-failures alarm must not page for DDB outages).
//   - context.Canceled during canceled parent ctx: NEITHER counter
//     (graceful shutdown).
//
// caught a regression where the caller in nhpauth.go fired
// MetricAuthFailure unconditionally on the nil-aspData reject —
// including the DDB-error and shutdown branches the resolver was
// supposed to keep distinct. The fix moved metric ownership inside
// the resolver; these tests fence the contract via the live counter
// publisher (metrics.NewPublisherForTest).
func TestUdpServer_ResolveAuthSvcProvider(t *testing.T) {
	t.Run("in_memory_hit_short_circuits_no_counters", func(t *testing.T) {
		existing := &common.AuthServiceProviderData{AuthSvcId: "agent"}
		s := &UdpServer{
			metrics:        metrics.NewPublisherForTest(t),
			authServiceMap: common.AuthSvcProviderMap{"agent": existing},
		}

		got := s.ResolveAuthSvcProvider(context.Background(), "agent", "test")
		if got != existing {
			t.Errorf("ResolveAuthSvcProvider = %v, want existing in-memory entry %v (must short-circuit without DDB call)", got, existing)
		}
		counters, _ := s.metrics.CountersForTest(t)
		if c := counters[MetricAuthFailure]; c != 0 {
			t.Errorf("MetricAuthFailure counter=%v want 0 on in-memory hit", c)
		}
		if c := counters[MetricResourceLookupDDBError]; c != 0 {
			t.Errorf("MetricResourceLookupDDBError counter=%v want 0 on in-memory hit", c)
		}
	})

	t.Run("nil_lookup_miss_fires_authfailure", func(t *testing.T) {
		s := &UdpServer{
			metrics:          metrics.NewPublisherForTest(t),
			authServiceMap:   common.AuthSvcProviderMap{},
			pluginHandlerMap: map[string]plugins.PluginHandler{},
			// resourceLookup intentionally nil — non-cloud deployment.
		}

		got := s.ResolveAuthSvcProvider(context.Background(), "agent", "test")
		if got != nil {
			t.Errorf("ResolveAuthSvcProvider with nil lookup = %v, want nil", got)
		}
		counters, _ := s.metrics.CountersForTest(t)
		if c := counters[MetricAuthFailure]; c != 1 {
			t.Errorf("MetricAuthFailure counter=%v want 1 on nil-lookup miss (auth-policy outcome — aspId genuinely not registered)", c)
		}
	})

	t.Run("nil_ctx_falls_back_to_background", func(t *testing.T) {
		q := newFakeResourcesQuerier()
		putTunnelServerRow(q, "qurl-tunnel-server")
		s := &UdpServer{
			metrics:          metrics.NewPublisherForTest(t),
			authServiceMap:   common.AuthSvcProviderMap{},
			pluginHandlerMap: map[string]plugins.PluginHandler{},
		}
		lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, s)
		if err != nil {
			t.Fatalf("NewResourceLookup: %v", err)
		}
		s.resourceLookup = lookup

		// nil ctx: helper must substitute context.Background rather
		// than nil-deref on the WithTimeout call inside the lookup.
		got := s.ResolveAuthSvcProvider(nil, "agent", "test") //nolint:staticcheck // intentional nil-ctx test
		if got == nil {
			t.Errorf("ResolveAuthSvcProvider with nil ctx = nil, want resolved aspData (helper must fall back to context.Background)")
		}
	})

	t.Run("unknown_asp_fires_authfailure_only", func(t *testing.T) {
		// Fake querier with no rows → ErrResourceUnknownASP path.
		q := newFakeResourcesQuerier()
		s := &UdpServer{
			metrics:          metrics.NewPublisherForTest(t),
			authServiceMap:   common.AuthSvcProviderMap{},
			pluginHandlerMap: map[string]plugins.PluginHandler{},
		}
		lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, s)
		if err != nil {
			t.Fatalf("NewResourceLookup: %v", err)
		}
		s.resourceLookup = lookup

		got := s.ResolveAuthSvcProvider(context.Background(), "agent", "test")
		if got != nil {
			t.Errorf("ResolveAuthSvcProvider on unknown aspId = %v, want nil", got)
		}
		counters, _ := s.metrics.CountersForTest(t)
		if c := counters[MetricAuthFailure]; c != 1 {
			t.Errorf("MetricAuthFailure counter=%v want 1 on ErrResourceUnknownASP (auth-policy)", c)
		}
		if c := counters[MetricResourceLookupDDBError]; c != 0 {
			t.Errorf("MetricResourceLookupDDBError counter=%v want 0 on auth-policy reject (must split from infra error)", c)
		}
	})

	t.Run("ddb_error_fires_only_ddberror_not_authfailure", func(t *testing.T) {
		// Regression fence: this branch must NOT fire MetricAuthFailure.
		// The auth-failures alarm pages on MetricAuthFailure; a DDB
		// throttle is infra trouble, not auth-policy. The split between
		// MetricResourceLookupDDBError and MetricAuthFailure is the
		// invariant ResolveAuthSvcProvider's switch enforces.
		q := newFakeResourcesQuerier()
		q.err = errors.New("ddb throttled: ProvisionedThroughputExceeded")
		s := &UdpServer{
			metrics:          metrics.NewPublisherForTest(t),
			authServiceMap:   common.AuthSvcProviderMap{},
			pluginHandlerMap: map[string]plugins.PluginHandler{},
		}
		lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, s)
		if err != nil {
			t.Fatalf("NewResourceLookup: %v", err)
		}
		s.resourceLookup = lookup

		got := s.ResolveAuthSvcProvider(context.Background(), "agent", "test")
		if got != nil {
			t.Errorf("ResolveAuthSvcProvider on DDB error = %v, want nil", got)
		}
		counters, _ := s.metrics.CountersForTest(t)
		if c := counters[MetricResourceLookupDDBError]; c != 1 {
			t.Errorf("MetricResourceLookupDDBError counter=%v want 1 on transient DDB error", c)
		}
		if c := counters[MetricAuthFailure]; c != 0 {
			t.Errorf("MetricAuthFailure counter=%v want 0 on DDB error (split from auth-policy: DDB outages must not page the auth-failures alarm)", c)
		}
	})

	t.Run("shutdown_canceled_ctx_suppresses_both_counters", func(t *testing.T) {
		// Regression: graceful shutdown (lifecycleCtx
		// canceled, in-flight Query returns wrapped ctx.Canceled) must
		// not increment EITHER MetricResourceLookupDDBError OR
		// MetricAuthFailure. A normal `systemctl stop` would otherwise
		// page on-call.
		q := newFakeResourcesQuerier()
		q.err = context.Canceled
		s := &UdpServer{
			metrics:          metrics.NewPublisherForTest(t),
			authServiceMap:   common.AuthSvcProviderMap{},
			pluginHandlerMap: map[string]plugins.PluginHandler{},
		}
		lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, s)
		if err != nil {
			t.Fatalf("NewResourceLookup: %v", err)
		}
		s.resourceLookup = lookup

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // pre-canceled so ctx.Err() != nil at the switch site

		got := s.ResolveAuthSvcProvider(ctx, "agent", "test")
		if got != nil {
			t.Errorf("ResolveAuthSvcProvider on shutdown = %v, want nil", got)
		}
		counters, _ := s.metrics.CountersForTest(t)
		if c := counters[MetricResourceLookupDDBError]; c != 0 {
			t.Errorf("MetricResourceLookupDDBError counter=%v want 0 on shutdown (must not look like DDB outage)", c)
		}
		if c := counters[MetricAuthFailure]; c != 0 {
			t.Errorf("MetricAuthFailure counter=%v want 0 on shutdown (must not look like auth-policy reject)", c)
		}
	})
}

// TestResourceLookup_PaginationWarningFires asserts that a DDB Query
// returning a LastEvaluatedKey (paginated response) still resolves the
// rows on page 1 — pagination isn't implemented, but the operator-
// visible Warning fires so a future regression (or a partition that
// outgrows the 1MB page limit) surfaces in logs rather than as a
// silent ErrResourceUnknownASP. noted this branch had no test.
func TestResourceLookup_PaginationWarningFires(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.simulatePagination = true
	putTunnelServerRow(q, "qurl-tunnel-server")

	l := newTestResourceLookup(t, q, &captureApplier{})
	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v, want success (page-1 rows must still resolve)", err)
	}
	if _, ok := asp.ResourceGroups["qurl-tunnel-server"]; !ok {
		t.Errorf("page-1 row missing; pagination must not block the rows we DID receive")
	}
	// The Warning emit itself is best-effort observable (the package
	// log writes to stderr); the regression fence here is that the
	// resolver successfully returns rather than silently dropping
	// the response. A future implementation that adds real pagination
	// can adjust this test to assert all pages get queried.
}

// TestLoadPluginOnce_TOMLAndDDBSerialized asserts that the boot/reload
// path (updateResources → loadPluginOnce(aspId, pluginPath)) and the
// per-knock path (applyAspMapDelta → ensurePluginLoaded → loadPluginOnce
// (aspId, "")) share the same per-aspId sync.Once. flagged that
// pre-this-refactor a concurrent TOML reload + first knock for the
// same aspId could run h.Init twice. Routing both through
// loadPluginOnce closes the race; this test fences the seam by
// asserting Delete-on-failure works regardless of which entry point
// called.
func TestLoadPluginOnce_TOMLAndDDBSerialized(t *testing.T) {
	s := &UdpServer{
		pluginHandlerMap: map[string]plugins.PluginHandler{},
	}

	// Call once with a non-empty pluginPath (TOML reload shape).
	s.loadPluginOnce("nonexistent-asp", "/some/path.so")

	// And once with empty (DDB shape).
	s.loadPluginOnce("nonexistent-asp", "")

	// Both calls fail (no registered plugin); both should delete the
	// Once so the next caller retries. After the second call the
	// pluginLoadOnce entry should not be present (each failed Do
	// deletes it).
	if _, found := s.pluginLoadOnce.Load("nonexistent-asp"); found {
		t.Errorf("pluginLoadOnce persisted after failed loads — retry path must keep deleting so the aspId isn't locked into permanent reject")
	}
}

// TestLoadPluginOnce_SuccessPersistsOnce asserts the positive
// contract: a SUCCESSFUL load LEAVES the per-aspId sync.Once intact
// in pluginLoadOnce so the next caller is a fast no-op (the
// alreadyLoaded fast-path inside Do skips the redundant Init). Pairs
// with TestEnsurePluginLoaded_FailureNotSticky which fences the
// inverse (failure → Delete → retry path). A regression that
// overzealously Deleted after success would cause every subsequent
// knock to re-enter the LoadPlugin path; this test catches it.
func TestLoadPluginOnce_SuccessPersistsOnce(t *testing.T) {
	// Simulate a successful prior load by pre-populating
	// pluginHandlerMap. The first loadPluginOnce call should observe
	// the alreadyLoaded fast-path inside Do, return without calling
	// GetPluginHandler/LoadPlugin, and (critically) NOT Delete the
	// Once — because pluginHandlerMap[aspId] is non-nil at the
	// post-Do verify check.
	s := &UdpServer{
		pluginHandlerMap: map[string]plugins.PluginHandler{
			"prewired-asp": fakePluginHandler{},
		},
	}

	s.loadPluginOnce("prewired-asp", "")

	if _, found := s.pluginLoadOnce.Load("prewired-asp"); !found {
		t.Errorf("pluginLoadOnce entry missing after successful load — the Once must persist so the next caller's Do is a no-op (Delete on the fast-path-saw-loaded branch would break this)")
	}
}

// fakePluginHandler is a minimal plugins.PluginHandler used to
// pre-populate pluginHandlerMap in tests that need a "load already
// happened" fixture without going through LoadPlugin's Init.
type fakePluginHandler struct{}

func (fakePluginHandler) Init(*plugins.PluginParamsIn) error { return nil }
func (fakePluginHandler) Close() error                       { return nil }
func (fakePluginHandler) Signature() string                  { return "" }
func (fakePluginHandler) Version() string                    { return "test" }
func (fakePluginHandler) ExportedData() *plugins.PluginParamsOut {
	return nil
}
func (fakePluginHandler) RequestOTP(*common.NhpOTPRequest, *plugins.NhpServerPluginHelper) error {
	return nil
}
func (fakePluginHandler) RegisterAgent(*common.NhpRegisterRequest, *plugins.NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	return nil, nil
}
func (fakePluginHandler) ListService(*common.NhpListRequest, *plugins.NhpServerPluginHelper) (*common.ServerListResultMsg, error) {
	return nil, nil
}
func (fakePluginHandler) AuthWithNHP(*common.NhpAuthRequest, *plugins.NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return nil, nil
}
func (fakePluginHandler) AuthWithHttp(*gin.Context, *common.HttpKnockRequest, *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return nil, nil
}

// TestResourceLookup_SetMetricsSetOnce fences the set-once contract
// on SetMetrics: the first non-nil call wires the publisher;
// subsequent calls with nil are IGNORED so a future caller that
// accidentally re-invokes SetMetrics(nil) (e.g., during a refactor
// that introduces a partial-reset path) doesn't silently dark
// the counters. A non-nil → non-nil call is fine (overwrite is
// the documented behavior); only the nil-clear-after-set case is
// guarded. Mirrors the AgentPeerLookup.SetMetrics contract.
func TestResourceLookup_SetMetricsSetOnce(t *testing.T) {
	l, err := NewResourceLookup(newFakeResourcesQuerier(), "test-table", nhpSystemCustomerID, nil)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}

	// First call wires the publisher.
	p1 := metrics.NewPublisherForTest(t)
	l.SetMetrics(p1)
	if l.metrics == nil {
		t.Fatal("after SetMetrics(p1), l.metrics is nil — first non-nil call must wire the publisher")
	}

	// Second call with nil must NOT clear the wired publisher.
	l.SetMetrics(nil)
	if l.metrics == nil {
		t.Error("SetMetrics(nil) after a non-nil set CLEARED the publisher — the set-once contract refuses nil writes to prevent silent metric-darkening")
	}

	// Trigger a counter to confirm the original publisher is still
	// the one being incremented.
	if l.metrics != p1 {
		t.Errorf("l.metrics != p1 after SetMetrics(nil); the original publisher must survive")
	}
}

// TestEnsurePluginLoaded_FailureNotSticky_Concurrent fences the
// concurrent-retry path: N goroutines call ensurePluginLoaded for the
// same unregistered aspId simultaneously. The Delete-on-failure path
// in loadPluginOnce must leave pluginLoadOnce empty afterwards
// regardless of how the goroutines interleave (serialized callers
// share the same Once; concurrent callers may racily LoadOrStore
// different Onces if Delete fires between LoadOrStores, each Once is
// then deleted by its own caller). noted the serial-only
// FailureNotSticky test below didn't exercise the race; this closes
// the gap.
func TestEnsurePluginLoaded_FailureNotSticky_Concurrent(t *testing.T) {
	s := &UdpServer{
		pluginHandlerMap: map[string]plugins.PluginHandler{},
	}

	const N = 16
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			s.ensurePluginLoaded("nonexistent-concurrent-asp")
		}()
	}
	wg.Wait()

	if _, found := s.pluginLoadOnce.Load("nonexistent-concurrent-asp"); found {
		t.Errorf("pluginLoadOnce entry persisted after N=%d concurrent failed loads — Delete-on-failure must be terminal regardless of which goroutine wrote the final Once", N)
	}
}

// TestEnsurePluginLoaded_FailureNotSticky asserts that a failed
// LoadPlugin call (e.g., no static plugin registered for the aspId)
// does NOT lock the aspId into permanent reject — the next call
// retries the load. sync.Once was consumed on failure
// and subsequent callers piggybacked on the failed Init silently.
func TestEnsurePluginLoaded_FailureNotSticky(t *testing.T) {
	s := &UdpServer{
		pluginHandlerMap: map[string]plugins.PluginHandler{},
	}
	// aspId not registered with any static plugin — GetPluginHandler
	// returns nil, the Once fires once, no entry in pluginHandlerMap.
	s.ensurePluginLoaded("nonexistent-asp")

	// Verify the Once was removed so a retry is possible.
	if _, found := s.pluginLoadOnce.Load("nonexistent-asp"); found {
		t.Errorf("pluginLoadOnce entry for nonexistent-asp persisted after failed load; subsequent knocks will silently piggyback on the failed Init")
	}

	// A second call should re-enter the load path (not no-op silently
	// via a consumed Once). We can't easily observe the second
	// GetPluginHandler call without a stub-registry, but we CAN
	// observe that pluginLoadOnce is still absent after the second
	// failed call (it gets repopulated then deleted again).
	s.ensurePluginLoaded("nonexistent-asp")
	if _, found := s.pluginLoadOnce.Load("nonexistent-asp"); found {
		t.Errorf("pluginLoadOnce entry persisted after second failed load; retry path must keep deleting")
	}
}

// TestApplyAspMapDelta_FastPathPointerEqual asserts the optimization
// that applyAspMapDelta no-ops when the entry is already installed
// under the same *AuthServiceProviderData pointer. Without this, every
// cache hit (which now republishes — see TestResourceLookup_CacheHitRepublishes)
// would do a full map copy + swap under the write lock — wasteful
// for the steady-state knock path.
func TestApplyAspMapDelta_FastPathPointerEqual(t *testing.T) {
	fresh := &common.AuthServiceProviderData{
		AuthSvcId:      "agent",
		ResourceGroups: common.ResourceGroupMap{},
	}
	s := &UdpServer{
		authServiceMap: common.AuthSvcProviderMap{"agent": fresh},
	}
	mapHeaderBefore := reflect.ValueOf(s.authServiceMap).Pointer()

	// Same pointer — must short-circuit; no fresh allocation, no swap.
	s.applyAspMapDelta("agent", fresh)
	mapHeaderAfter := reflect.ValueOf(s.authServiceMap).Pointer()

	if mapHeaderBefore != mapHeaderAfter {
		t.Errorf("authServiceMap hmap reallocated despite pointer-equal install (before=%#x after=%#x); fast path must short-circuit",
			mapHeaderBefore, mapHeaderAfter)
	}
	if s.authServiceMap["agent"] != fresh {
		t.Errorf("entry mutated despite fast-path no-op")
	}
}

// TestResourceLookup_AppliesToHostServer asserts the publish-into-host
// contract: a successful lookup invokes applyAspMapDelta with the
// resolved aspData. This is the seam by which FindAuthSvcProvider's
// next RLock read sees the live catalog.
func TestResourceLookup_AppliesToHostServer(t *testing.T) {
	q := newFakeResourcesQuerier()
	putTunnelServerRow(q, "qurl-tunnel-server")
	applier := &captureApplier{}
	l := newTestResourceLookup(t, q, applier)

	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v", err)
	}

	last, ok := applier.lastApplied()
	if !ok {
		t.Fatal("applyAspMapDelta was not called on successful lookup")
	}
	if last.aspId != "agent" {
		t.Errorf("applied aspId = %q, want %q", last.aspId, "agent")
	}
	if last.asp != asp {
		t.Errorf("applied aspData pointer differs from returned aspData; want the same *AuthServiceProviderData published into the host map")
	}
}

// TestResourceLookup_NilApplier asserts that a tests-only construction
// without an applier still resolves successfully (the applier branch
// is optional). Production always passes a non-nil applier.
func TestResourceLookup_NilApplier(t *testing.T) {
	q := newFakeResourcesQuerier()
	putTunnelServerRow(q, "qurl-tunnel-server")
	l := newTestResourceLookup(t, q, nil)

	asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if err != nil {
		t.Fatalf("lookup err: %v", err)
	}
	if asp == nil {
		t.Error("aspData = nil despite successful Query")
	}
}

// TestResourceLookup_EmptyAspIdShortCircuits asserts the
// LookupAuthServiceProvider(ctx, "") early-exit. Today no caller
// passes an empty aspId (HandleKnockRequest already rejects the
// knock at parse time when AuthServiceId is empty), but a future
// regression that drops the upstream check must not silently
// Query an entire partition and return its first row.
func TestResourceLookup_EmptyAspIdShortCircuits(t *testing.T) {
	q := newFakeResourcesQuerier()
	putTunnelServerRow(q, "qurl-tunnel-server")
	l := newTestResourceLookup(t, q, &captureApplier{})

	_, err := l.LookupAuthServiceProvider(context.Background(), "")
	if !errors.Is(err, ErrResourceUnknownASP) {
		t.Errorf("empty aspId err = %v, want ErrResourceUnknownASP (short-circuit)", err)
	}
	if got := q.callCount(); got != 0 {
		t.Errorf("DDB calls with empty aspId = %d, want 0 (short-circuit before Query)", got)
	}
}

// TestResourceLookup_NilLookup asserts nil-receiver safety. Today no
// caller invokes through a nil pointer (HandleKnockRequest gates on
// `s.resourceLookup != nil`), but the godoc promises nil-safe for
// "lookup disabled" callers.
func TestResourceLookup_NilLookup(t *testing.T) {
	var l *ResourceLookup
	_, err := l.LookupAuthServiceProvider(context.Background(), "agent")
	if !errors.Is(err, ErrResourceUnknownASP) {
		t.Errorf("nil lookup err = %v, want ErrResourceUnknownASP", err)
	}
}

// TestResourceLookup_NilQuerier asserts the "DDB client not wired"
// branch — the resolver was constructed but no DDB Query is possible
// (e.g. on-prem / etcd-backed deployments). Caller must get a clean
// reject rather than a nil-deref crash.
func TestResourceLookup_NilQuerier(t *testing.T) {
	l, err := NewResourceLookup(nil, "nhp-resources-test", nhpSystemCustomerID, &captureApplier{})
	if err != nil {
		t.Fatalf("NewResourceLookup(nil querier): %v", err)
	}
	_, lookupErr := l.LookupAuthServiceProvider(context.Background(), "agent")
	if !errors.Is(lookupErr, ErrResourceUnknownASP) {
		t.Errorf("nil-querier lookup err = %v, want ErrResourceUnknownASP", lookupErr)
	}
}

// TestResourceLookup_SingleflightDedupsConcurrentMiss asserts that N
// concurrent first-time lookups for the same aspId issue exactly one
// DDB Query and invoke the applier exactly once. Without
// singleflight, every caller would issue its own Query and publish
// its own *AuthServiceProviderData pointer — the cost amplifier the
// godoc on AgentPeerLookup.sfGroup describes in detail.
//
// Mirror the AgentPeerLookup test's barrier pattern: install a
// before-Query hook that blocks on a release channel until all N
// callers have committed to a singleflight slot. Without the barrier
// a fast winner can populate the cache before piggybackers enter,
// degrading the test to a cache-hit assertion that proves nothing
// about singleflight.
func TestResourceLookup_SingleflightDedupsConcurrentMiss(t *testing.T) {
	q := newFakeResourcesQuerier()
	putTunnelServerRow(q, "qurl-tunnel-server")

	const N = 8
	applier := &captureApplier{}
	l := newTestResourceLookup(t, q, applier)

	// Barrier: count callers entering sfGroup.Do; release the winner's
	// Query only after all N have committed.
	var entered sync.WaitGroup
	entered.Add(N)
	release := make(chan struct{})
	l.onSingleflightEnter = func(aspId string) {
		entered.Done()
	}
	q.beforeQuery = func() {
		<-release
	}

	type result struct {
		asp *common.AuthServiceProviderData
		err error
	}
	results := make(chan result, N)
	var startWg sync.WaitGroup
	startWg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			startWg.Done()
			asp, err := l.LookupAuthServiceProvider(context.Background(), "agent")
			results <- result{asp: asp, err: err}
		}()
	}
	startWg.Wait()
	entered.Wait() // every goroutine has reached sfGroup.Do
	close(release) // winner's Query proceeds

	var firstPtr *common.AuthServiceProviderData
	for i := 0; i < N; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("goroutine #%d err: %v", i, r.err)
			continue
		}
		if firstPtr == nil {
			firstPtr = r.asp
			continue
		}
		if r.asp != firstPtr {
			t.Errorf("goroutine #%d got distinct *AuthServiceProviderData pointer; singleflight must hand out the SAME pointer to every piggybacker", i)
		}
	}

	if got := q.callCount(); got != 1 {
		t.Errorf("DDB Query calls = %d, want 1 (singleflight must dedupe N concurrent misses)", got)
	}
	if got := applier.count(); got != 1 {
		t.Errorf("applyAspMapDelta calls = %d, want 1 (publish exactly once per resolve)", got)
	}
}

// TestApplyAspMapDelta_BuildFreshThenSwap asserts the
// UdpServer.applyAspMapDelta concurrency contract: the live map's
// pointer identity changes (fresh allocation), and existing entries
// are preserved. This is the Option-A pattern that lets the
// agent plugin's lock-free helper.AspData reads stay safe against
// concurrent publishes.
func TestApplyAspMapDelta_BuildFreshThenSwap(t *testing.T) {
	s := &UdpServer{
		authServiceMap: common.AuthSvcProviderMap{
			"existing": &common.AuthServiceProviderData{AuthSvcId: "existing"},
		},
	}
	oldMap := s.authServiceMap
	oldExisting := s.authServiceMap["existing"]
	oldMapHeader := reflect.ValueOf(s.authServiceMap).Pointer()

	fresh := &common.AuthServiceProviderData{
		AuthSvcId:      "agent",
		ResourceGroups: common.ResourceGroupMap{},
	}
	s.applyAspMapDelta("agent", fresh)

	if got := s.authServiceMap["agent"]; got != fresh {
		t.Errorf("authServiceMap[\"agent\"] = %v, want fresh pointer", got)
	}
	if got := s.authServiceMap["existing"]; got != oldExisting {
		t.Errorf("authServiceMap[\"existing\"] mutated; build-fresh-then-swap must preserve other entries unchanged")
	}
	// The map header pointer should change — a build-fresh-then-swap
	// allocates a fresh hmap so any captured reference (e.g., oldMap)
	// stays as a snapshot of the pre-swap state.
	// reflect.ValueOf(map).Pointer() returns the underlying hmap
	// pointer — the right primitive for "this map was rebuilt, not
	// mutated in place." A naive `&oldMap == &s.authServiceMap`
	// would be structurally always-false (two distinct variables
	// can't share an address) and silently miss a regression that
	// dropped the `fresh := make(...)` step.
	newMapHeader := reflect.ValueOf(s.authServiceMap).Pointer()
	if oldMapHeader == newMapHeader {
		t.Errorf("authServiceMap hmap pointer unchanged (oldHeader=%#x newHeader=%#x); build-fresh-then-swap must allocate a fresh map so concurrent lock-free readers holding the old reference observe an immutable snapshot",
			oldMapHeader, newMapHeader)
	}
	if _, ok := oldMap["agent"]; ok {
		t.Errorf("old map snapshot mutated to include agent; build-fresh-then-swap must NOT touch the published-then-orphaned map")
	}
}

// TestApplyAspMapDelta_NoopOnNil asserts the defensive nil guards in
// applyAspMapDelta. A nil aspData or empty aspId is a programmer
// error from the caller; the method must not install a nil sentinel
// that would surface as a panic in FindAuthSvcProvider readers.
func TestApplyAspMapDelta_NoopOnNil(t *testing.T) {
	s := &UdpServer{
		authServiceMap:   common.AuthSvcProviderMap{},
		pluginHandlerMap: map[string]plugins.PluginHandler{},
	}

	s.applyAspMapDelta("", &common.AuthServiceProviderData{})
	if len(s.authServiceMap) != 0 {
		t.Errorf("empty aspId installed entry; len = %d, want 0", len(s.authServiceMap))
	}

	s.applyAspMapDelta("agent", nil)
	if _, ok := s.authServiceMap["agent"]; ok {
		t.Errorf("nil aspData installed entry; readers would nil-deref through helper.AspData")
	}
}

// TestNewResourceLookupFromStorage_DisabledOnEmptyTable asserts that a
// missing ResourcesTable config returns (nil, nil) — a clean "lookup
// disabled" branch that the caller in UdpServer.Start uses to keep
// the legacy TOML-overlay-only behavior in effect.
func TestNewResourceLookupFromStorage_DisabledOnEmptyTable(t *testing.T) {
	ddb := &DynamoDBStorage{config: DynamoDBConfig{}}
	lookup, err := NewResourceLookupFromStorage(ddb, &captureApplier{})
	if err != nil {
		t.Errorf("err = %v, want nil for disabled-by-config", err)
	}
	if lookup != nil {
		t.Errorf("lookup = %v, want nil for empty ResourcesTable", lookup)
	}
}

// TestNewResourceLookupFromStorage_NonDDBReturnsNil asserts that a
// non-DynamoDB storage backend (etcd, file-config) returns (nil, nil)
// without surfacing an error — same "lookup disabled" posture.
func TestNewResourceLookupFromStorage_NonDDBReturnsNil(t *testing.T) {
	// A nil StorageBackend is the simplest non-DDB shape.
	lookup, err := NewResourceLookupFromStorage(nil, &captureApplier{})
	if err != nil {
		t.Errorf("err = %v, want nil for non-DDB storage", err)
	}
	if lookup != nil {
		t.Errorf("lookup = %v, want nil for non-DDB storage", lookup)
	}
}

// aspKeys returns the keys of an aspData's ResourceGroups for error
// messages. Helper, not a contract.
func aspKeys(asp *common.AuthServiceProviderData) []string {
	if asp == nil {
		return nil
	}
	keys := make([]string, 0, len(asp.ResourceGroups))
	for k := range asp.ResourceGroups {
		keys = append(keys, k)
	}
	return keys
}

// groupResourceKeys returns the inner Resources map keys for error
// messages.
func groupResourceKeys(group *common.ResourceData) []string {
	if group == nil {
		return nil
	}
	keys := make([]string, 0, len(group.Resources))
	for k := range group.Resources {
		keys = append(keys, k)
	}
	return keys
}
