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
)

func TestSessionControlStartupFailsClosedWithoutDueIndexQuery(t *testing.T) {
	sentinel := errors.New("due index unavailable")
	fake := newSessionControlSessionDynamoFake()
	fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
		return nil, sentinel
	}
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	err := store.PingSessionControl(context.Background())
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "mandatory due-index") {
		t.Fatalf("PingSessionControl() = %v, want mandatory due-index failure", err)
	}
}

func TestNewSessionControlStoreFromStoragePerformsStrongCompositeKeyRead(t *testing.T) {
	const tableName = "nhp-session-control-test"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		target := r.Header.Get("X-Amz-Target")
		if requests == 2 {
			if target != "DynamoDB_20120810.Query" || !strings.Contains(string(body), sessionControlDueIndexName) {
				t.Fatalf("due-index startup probe target/body = %q/%s", target, body)
			}
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if target != "DynamoDB_20120810.GetItem" {
			t.Fatalf("DynamoDB target = %q, want GetItem; body=%s", target, body)
		}
		var req struct {
			TableName      string                                `json:"TableName"`
			ConsistentRead bool                                  `json:"ConsistentRead"`
			Key            map[string]map[string]json.RawMessage `json:"Key"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode GetItem: %v body=%s", err, body)
		}
		if req.TableName != tableName || !req.ConsistentRead {
			t.Fatalf("GetItem table/consistency = %q/%t", req.TableName, req.ConsistentRead)
		}
		if got := strings.Trim(string(req.Key["pk"]["S"]), `"`); got != sessionControlHealthPK {
			t.Fatalf("pk = %q, want %q", got, sessionControlHealthPK)
		}
		if got := strings.Trim(string(req.Key["sk"]["S"]), `"`); got != "META" {
			t.Fatalf("sk = %q, want META", got)
		}
		_, _ = w.Write([]byte(`{}`))
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
	ddb := &DynamoDBStorage{
		client: dynamodb.NewFromConfig(cfg),
		config: DynamoDBConfig{SessionControlTable: tableName},
	}
	wrapped := NewCachedStorage(ddb, CacheConfig{MaxEntries: 10, DefaultTTL: 60})
	store, err := NewSessionControlStoreFromStorage(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("NewSessionControlStoreFromStorage() error = %v", err)
	}
	dynamoStore, ok := store.(*dynamoSessionControlStore)
	if !ok {
		t.Fatalf("store = %T, want isolated *dynamoSessionControlStore", store)
	}
	if dynamoStore.client != ddb.client || dynamoStore.tableName != tableName || dynamoStore.nowUTC == nil {
		t.Fatalf("dynamo session-control store wiring = %#v", dynamoStore)
	}
	if requests != 2 {
		t.Fatalf("session-control startup probes = %d, want strong base read plus due-index query", requests)
	}
}

func TestNewSessionControlStoreFromStorageFailsClosedWhenUnavailable(t *testing.T) {
	t.Run("non-dynamodb-backend", func(t *testing.T) {
		if _, err := NewSessionControlStoreFromStorage(context.Background(), NewMemoryStorage()); err == nil {
			t.Fatal("NewSessionControlStoreFromStorage() succeeded without DynamoDB authority")
		}
	})

	t.Run("table-not-configured", func(t *testing.T) {
		ddb := &DynamoDBStorage{client: &dynamodb.Client{}}
		if _, err := NewSessionControlStoreFromStorage(context.Background(), ddb); err == nil || !strings.Contains(err.Error(), "SessionControlTable") {
			t.Fatalf("NewSessionControlStoreFromStorage() error = %v, want missing SessionControlTable", err)
		}
	})
}

func TestDefaultStorageConfigIncludesSessionControlAuthority(t *testing.T) {
	if got := DefaultStorageConfig().DynamoDB.SessionControlTable; got != "nhp-session-control" {
		t.Fatalf("default SessionControlTable = %q, want nhp-session-control", got)
	}
}
