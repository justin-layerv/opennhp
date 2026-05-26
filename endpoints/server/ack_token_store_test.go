package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

type recordingACKTokenStore struct {
	err     error
	errCall int
	calls   int
	token   string
	tokens  []string
	entry   *ACTokenEntry
	loadErr error
}

func (s *recordingACKTokenStore) StoreACToken(_ context.Context, token string, entry *ACTokenEntry) error {
	s.calls++
	s.token = token
	s.tokens = append(s.tokens, token)
	s.entry = entry
	if s.err != nil && (s.errCall == 0 || s.calls == s.errCall) {
		return s.err
	}
	return nil
}

func (s *recordingACKTokenStore) LoadACToken(context.Context, string) (*ACTokenEntry, bool, error) {
	return nil, false, s.loadErr
}

func TestACKTokenHash_DoesNotPersistRawToken(t *testing.T) {
	const rawToken = "raw-ac-token-secret"

	got := hashACKToken(rawToken)
	if got == rawToken {
		t.Fatal("hashACKToken returned the raw token")
	}
	if len(got) != 64 {
		t.Fatalf("hashACKToken length = %d, want 64 hex chars", len(got))
	}
	if strings.Contains(got, rawToken) {
		t.Fatalf("hashACKToken output contains raw token material: %q", got)
	}
	if got != hashACKToken(rawToken) {
		t.Fatal("hashACKToken is not deterministic")
	}
}

func TestACKTokenItemRoundTrip(t *testing.T) {
	expire := time.Now().Add(60 * time.Second).UTC().Round(time.Nanosecond)
	entry := &ACTokenEntry{
		User: &common.AgentUser{
			UserId:         "user-1",
			DeviceId:       "device-1",
			OrganizationId: "org-1",
			AuthServiceId:  "asp-1",
			OwnerId:        "owner-1",
		},
		ResourceId: "resource-1",
		KnockSrcIP: "203.0.113.12",
		RunID:      "run-1",
		OpenTime:   60,
		ExpireTime: expire,
	}

	item := ackTokenItemFromEntry("raw-token", entry)
	if item.TokenHash == "" || item.TokenHash == "raw-token" {
		t.Fatalf("TokenHash = %q, want hashed token", item.TokenHash)
	}
	if item.TTL != expire.Unix()+ackTokenTTLGraceSeconds {
		t.Fatalf("TTL = %d, want %d", item.TTL, expire.Unix()+ackTokenTTLGraceSeconds)
	}
	if item.OpenTime != 60 {
		t.Fatalf("OpenTime = %d, want 60", item.OpenTime)
	}

	got := ackTokenEntryFromItem(item)
	if got.User == nil {
		t.Fatal("round-tripped entry User is nil")
	}
	if got.User.UserId != "user-1" || got.User.OwnerId != "owner-1" {
		t.Fatalf("round-tripped user = %+v, want user_id and owner_id preserved", got.User)
	}
	if got.ResourceId != "resource-1" {
		t.Fatalf("ResourceId = %q, want resource-1", got.ResourceId)
	}
	if got.KnockSrcIP != "203.0.113.12" {
		t.Fatalf("KnockSrcIP = %q, want 203.0.113.12", got.KnockSrcIP)
	}
	if got.RunID != "run-1" {
		t.Fatalf("RunID = %q, want run-1", got.RunID)
	}
	if got.OpenTime != 60 {
		t.Fatalf("OpenTime = %d, want 60", got.OpenTime)
	}
	if !got.ExpireTime.Equal(expire) {
		t.Fatalf("ExpireTime = %v, want %v", got.ExpireTime, expire)
	}
}

func TestACKTokenItemRoundTrip_NilUserPreserved(t *testing.T) {
	expire := time.Now().Add(60 * time.Second).UTC().Round(time.Nanosecond)
	entry := &ACTokenEntry{
		User:       nil,
		ResourceId: "resource-no-user",
		KnockSrcIP: "203.0.113.13",
		RunID:      "run-no-user",
		OpenTime:   30,
		ExpireTime: expire,
	}

	got := ackTokenEntryFromItem(ackTokenItemFromEntry("raw-token-no-user", entry))
	if got.User != nil {
		t.Fatalf("round-tripped entry User = %+v, want nil", got.User)
	}
	if got.ResourceId != "resource-no-user" {
		t.Fatalf("ResourceId = %q, want resource-no-user", got.ResourceId)
	}
	if got.KnockSrcIP != "203.0.113.13" {
		t.Fatalf("KnockSrcIP = %q, want 203.0.113.13", got.KnockSrcIP)
	}
	if got.RunID != "run-no-user" {
		t.Fatalf("RunID = %q, want run-no-user", got.RunID)
	}
	if got.OpenTime != 30 {
		t.Fatalf("OpenTime = %d, want 30", got.OpenTime)
	}
	if !got.ExpireTime.Equal(expire) {
		t.Fatalf("ExpireTime = %v, want %v", got.ExpireTime, expire)
	}
	if got.ACTokens == nil || len(got.ACTokens) != 0 {
		t.Fatalf("ACTokens = %+v, want non-nil empty map", got.ACTokens)
	}
}

func TestACKTokenItemRoundTrip_EmptyUserPreserved(t *testing.T) {
	expire := time.Now().Add(60 * time.Second).UTC().Round(time.Nanosecond)
	entry := &ACTokenEntry{
		User:       &common.AgentUser{},
		ResourceId: "resource-empty-user",
		KnockSrcIP: "203.0.113.14",
		RunID:      "run-empty-user",
		OpenTime:   30,
		ExpireTime: expire,
	}

	item := ackTokenItemFromEntry("raw-token-empty-user", entry)
	if !item.UserPresent {
		t.Fatal("UserPresent = false, want true for non-nil empty user")
	}
	got := ackTokenEntryFromItem(item)
	if got.User == nil {
		t.Fatal("round-tripped entry User is nil, want non-nil empty user")
	}
	if got.User.UserId != "" || got.User.OwnerId != "" {
		t.Fatalf("round-tripped user = %+v, want empty identity fields", got.User)
	}
}

func TestACKTokenItem_DynamoDBAttributeValueRoundTrip(t *testing.T) {
	expire := time.Now().Add(60 * time.Second).UTC().Round(time.Nanosecond)
	entry := &ACTokenEntry{
		User:       &common.AgentUser{},
		ResourceId: "resource-ddb-av",
		KnockSrcIP: "203.0.113.15",
		RunID:      "run-ddb-av",
		OpenTime:   45,
		ExpireTime: expire,
	}

	av, err := attributevalue.MarshalMap(ackTokenItemFromEntry("raw-token-ddb-av", entry))
	if err != nil {
		t.Fatalf("MarshalMap: %v", err)
	}
	if _, ok := av["user_present"]; !ok {
		t.Fatalf("MarshalMap did not include user_present for non-nil empty User: keys=%v", av)
	}
	var item persistedACKTokenItem
	if err := attributevalue.UnmarshalMap(av, &item); err != nil {
		t.Fatalf("UnmarshalMap: %v", err)
	}
	got := ackTokenEntryFromItem(item)
	if got.User == nil {
		t.Fatal("DynamoDB attributevalue round-trip User is nil, want non-nil empty user")
	}
	if got.ResourceId != "resource-ddb-av" || got.OpenTime != 45 || !got.ExpireTime.Equal(expire) {
		t.Fatalf("round-tripped entry = %+v, want resource/open/expire preserved", got)
	}
}

func TestDynamoDBACKTokenStore_StoreLoadRoundTripWithSDKClient(t *testing.T) {
	const (
		tableName = "ack-tokens-test"
		rawToken  = "raw-token-sdk-roundtrip"
	)
	var capturedItem map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if strings.Contains(string(body), rawToken) {
			t.Fatalf("request body persisted raw token: %s", body)
		}

		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.PutItem":
			var req struct {
				TableName string                     `json:"TableName"`
				Item      map[string]json.RawMessage `json:"Item"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("decode PutItem request: %v body=%s", err, body)
			}
			if req.TableName != tableName {
				t.Fatalf("PutItem table = %q, want %q", req.TableName, tableName)
			}
			if _, ok := req.Item["user_present"]; !ok {
				t.Fatalf("PutItem item missing user_present: keys=%v", req.Item)
			}
			capturedItem = req.Item
			_, _ = w.Write([]byte(`{}`))
		case "DynamoDB_20120810.GetItem":
			var req struct {
				TableName      string                                `json:"TableName"`
				ConsistentRead bool                                  `json:"ConsistentRead"`
				Key            map[string]map[string]json.RawMessage `json:"Key"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("decode GetItem request: %v body=%s", err, body)
			}
			if req.TableName != tableName {
				t.Fatalf("GetItem table = %q, want %q", req.TableName, tableName)
			}
			if !req.ConsistentRead {
				t.Fatal("GetItem ConsistentRead=false, want true")
			}
			keyValue := strings.Trim(string(req.Key["token_hash"]["S"]), `"`)
			if keyValue != hashACKToken(rawToken) {
				t.Fatalf("GetItem token_hash = %q, want hash of raw token", keyValue)
			}
			if capturedItem == nil {
				t.Fatal("GetItem before PutItem captured an item")
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"Item": capturedItem}); err != nil {
				t.Fatalf("encode GetItem response: %v", err)
			}
		default:
			t.Fatalf("unexpected DynamoDB target %q body=%s", r.Header.Get("X-Amz-Target"), body)
		}
	}))
	defer server.Close()

	cfg := aws.Config{
		Region:      "us-east-2",
		Credentials: credentials.NewStaticCredentialsProvider("test-access-key", "test-secret-key", ""),
		EndpointResolverWithOptions: aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...any) (aws.Endpoint, error) {
				return aws.Endpoint{URL: server.URL, SigningRegion: region}, nil
			},
		),
		HTTPClient: server.Client(),
	}
	storage := &DynamoDBStorage{
		client: dynamodb.NewFromConfig(cfg),
		config: DynamoDBConfig{AckTokensTable: tableName},
	}
	expire := time.Now().Add(60 * time.Second).UTC().Round(time.Nanosecond)
	entry := &ACTokenEntry{
		User:       &common.AgentUser{},
		ResourceId: "resource-sdk",
		KnockSrcIP: "203.0.113.16",
		RunID:      "run-sdk",
		OpenTime:   55,
		ExpireTime: expire,
	}

	if err := storage.StoreACToken(context.Background(), rawToken, entry); err != nil {
		t.Fatalf("StoreACToken: %v", err)
	}
	got, found, err := storage.LoadACToken(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("LoadACToken: %v", err)
	}
	if !found {
		t.Fatal("LoadACToken found=false, want true")
	}
	if got.User == nil {
		t.Fatal("LoadACToken User=nil, want non-nil empty user")
	}
	if got.ResourceId != entry.ResourceId || got.KnockSrcIP != entry.KnockSrcIP || got.RunID != entry.RunID || got.OpenTime != entry.OpenTime || !got.ExpireTime.Equal(expire) {
		t.Fatalf("LoadACToken entry = %+v, want fields from %+v", got, entry)
	}
}

func TestStoreACToken_PersistsToSharedStore(t *testing.T) {
	shared := &recordingACKTokenStore{}
	s := &UdpServer{
		tokenStore:    common.NewTokenStore[*ACTokenEntry](),
		ackTokenStore: shared,
		metrics:       metrics.NewPublisherForTest(t),
	}
	entry := &ACTokenEntry{
		ResourceId: "resource-1",
		ExpireTime: time.Now().Add(60 * time.Second),
	}

	if err := s.storeACToken(context.Background(), "ac-token", entry); err != nil {
		t.Fatalf("storeACToken err=%v, want nil", err)
	}
	if shared.calls != 1 {
		t.Fatalf("shared store calls = %d, want 1", shared.calls)
	}
	if shared.token != "ac-token" || shared.entry != entry {
		t.Fatalf("shared store recorded token=%q entry=%p, want token ac-token entry %p", shared.token, shared.entry, entry)
	}
	if got := s.VerifyAccessToken("ac-token"); got != entry {
		t.Fatalf("local tokenStore entry = %p, want %p", got, entry)
	}
}

func TestPublishACKTokens_SharedStoreFailureFailsClosed(t *testing.T) {
	shared := &recordingACKTokenStore{err: errors.New("dynamodb write failed")}
	s := &UdpServer{
		tokenStore:    common.NewTokenStore[*ACTokenEntry](),
		ackTokenStore: shared,
		metrics:       metrics.NewPublisherForTest(t),
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-1"}
	ackMsg := &common.ServerKnockAckMsg{
		ACTokens: map[string]string{
			"resource-1": "ac-token",
			"resource-2": "ac-token-2",
		},
	}

	err := s.PublishACKTokens(context.Background(), knkMsg, ackMsg, "203.0.113.44", 60, "owner-1")
	if err == nil {
		t.Fatal("PublishACKTokens err=nil, want shared-store failure")
	}
	if !strings.Contains(err.Error(), "persist ACK token metadata") {
		t.Fatalf("PublishACKTokens err=%v, want persist context", err)
	}
	if shared.calls != 1 {
		t.Fatalf("shared store calls = %d, want 1", shared.calls)
	}
	if shared.token != "ac-token" && shared.token != "ac-token-2" {
		t.Fatalf("shared store token = %q, want one of the ACK tokens", shared.token)
	}
	if got := s.VerifyAccessToken("ac-token"); got != nil {
		t.Fatalf("local tokenStore entry = %+v, want nil after shared-store failure", got)
	}
	if got := s.VerifyAccessToken("ac-token-2"); got != nil {
		t.Fatalf("second local tokenStore entry = %+v, want nil after shared-store failure", got)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricACKTokenSharedStoreWriteFailure]; got != 1 {
		t.Fatalf("%s counter = %v, want 1", MetricACKTokenSharedStoreWriteFailure, got)
	}
	if got := counters[MetricKnockPinholeOrphaned]; got != 1 {
		t.Fatalf("%s counter = %v, want 1", MetricKnockPinholeOrphaned, got)
	}
}

func TestPublishACKTokens_SharedStoreSecondWriteFailureStillFailsClosed(t *testing.T) {
	shared := &recordingACKTokenStore{err: errors.New("dynamodb write failed"), errCall: 2}
	s := &UdpServer{
		tokenStore:    common.NewTokenStore[*ACTokenEntry](),
		ackTokenStore: shared,
		metrics:       metrics.NewPublisherForTest(t),
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-1"}
	ackMsg := &common.ServerKnockAckMsg{
		ACTokens: map[string]string{
			"resource-1": "ac-token",
			"resource-2": "ac-token-2",
		},
	}

	err := s.PublishACKTokens(context.Background(), knkMsg, ackMsg, "203.0.113.44", 60, "owner-1")
	if err == nil {
		t.Fatal("PublishACKTokens err=nil, want second shared-store write failure")
	}
	if shared.calls != 2 {
		t.Fatalf("shared store calls = %d, want 2", shared.calls)
	}
	for _, token := range []string{"ac-token", "ac-token-2"} {
		if got := s.VerifyAccessToken(token); got != nil {
			t.Fatalf("local tokenStore entry for %q = %+v, want nil after partial shared-store failure", token, got)
		}
	}
	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricACKTokenSharedStoreWriteFailure]; got != 1 {
		t.Fatalf("%s counter = %v, want 1 failed write", MetricACKTokenSharedStoreWriteFailure, got)
	}
	if got := counters[MetricKnockPinholeOrphaned]; got != 1 {
		t.Fatalf("%s counter = %v, want 1 failed ACK publication", MetricKnockPinholeOrphaned, got)
	}
}
