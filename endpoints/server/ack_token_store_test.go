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
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/OpenNHP/opennhp/endpoints/internal/acktoken"
	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

// NOTE: the ACK-token marshaling / hashing unit tests moved to
// endpoints/internal/acktoken (acktoken_test.go) alongside the types they
// exercise. The tests below cover the server-side DynamoDBStorage read/write
// path and PublishACKTokens, which stay in package server.

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
			if keyValue != acktoken.HashToken(rawToken) {
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
	sessionExpire := expire.Add(-5 * time.Second)
	entry := &ACTokenEntry{
		User:                &common.AgentUser{},
		ResourceId:          "q_catalog-sdk",
		ProtectedResourceId: "public-resource-sdk",
		KnockSrcIP:          "203.0.113.16",
		RunID:               "run-sdk",
		SessionId:           0x0123456789abcdef,
		OpenTime:            55,
		SessionExpireTime:   sessionExpire,
		ExpireTime:          expire,
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
	if got.ResourceId != entry.ResourceId || got.ProtectedResourceId != entry.ProtectedResourceId || got.KnockSrcIP != entry.KnockSrcIP || got.RunID != entry.RunID || got.SessionId != entry.SessionId || got.OpenTime != entry.OpenTime || !got.SessionExpireTime.Equal(sessionExpire) || !got.ExpireTime.Equal(expire) {
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

func TestPublishACKTokens_PreservesRunIDInSharedAndLocalStores(t *testing.T) {
	const wantRunID = "0123456789abcdef"

	shared := &recordingACKTokenStore{}
	s := &UdpServer{
		tokenStore:    common.NewTokenStore[*ACTokenEntry](),
		ackTokenStore: shared,
		metrics:       metrics.NewPublisherForTest(t),
	}
	knkMsg := &common.AgentKnockMsg{
		UserId:              "agent-1",
		AuthServiceId:       common.RegisteredAgentAuthServiceID,
		ResourceId:          "resource-1",
		ProtectedResourceId: testProtectedResourceID,
		RunID:               wantRunID,
		NHPSessionId:        1,
		NHPSessionIssuedAt:  time.Now(),
	}
	ackMsg := &common.ServerKnockAckMsg{
		SessionId: 1,
		ACTokens:  map[string]string{"resource-1": "ac-token"},
	}

	if err := s.PublishACKTokens(context.Background(), knkMsg, ackMsg, "203.0.113.44", 60, "owner-1"); err != nil {
		t.Fatalf("PublishACKTokens: %v", err)
	}
	if shared.calls != 1 || shared.entry == nil {
		t.Fatalf("shared store calls = %d entry = %+v, want one persisted entry", shared.calls, shared.entry)
	}
	if shared.entry.RunID != wantRunID {
		t.Fatalf("shared store RunID = %q, want authenticated knock RunID %q", shared.entry.RunID, wantRunID)
	}
	local := s.VerifyAccessToken("ac-token")
	if local == nil {
		t.Fatal("local tokenStore entry = nil, want persisted entry")
	}
	if local.RunID != wantRunID {
		t.Fatalf("local tokenStore RunID = %q, want authenticated knock RunID %q", local.RunID, wantRunID)
	}
	if local != shared.entry {
		t.Fatal("shared and local stores did not receive the same immutable entry")
	}
}

func TestPublishACKTokens_SharedStoreFailureFailsClosed(t *testing.T) {
	shared := &recordingACKTokenStore{err: errors.New("dynamodb write failed")}
	s := &UdpServer{
		tokenStore:    common.NewTokenStore[*ACTokenEntry](),
		ackTokenStore: shared,
		metrics:       metrics.NewPublisherForTest(t),
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-1", ResourceId: "public-resource", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	ackMsg := &common.ServerKnockAckMsg{
		SessionId: 1,
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
	knkMsg := &common.AgentKnockMsg{UserId: "user-1", ResourceId: "public-resource", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	ackMsg := &common.ServerKnockAckMsg{
		SessionId: 1,
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
