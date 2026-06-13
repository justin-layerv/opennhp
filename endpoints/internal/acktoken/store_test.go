package acktoken

import (
	"context"
	"encoding/json"
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

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestNewDynamoDBReader_TableRequired(t *testing.T) {
	if _, err := NewDynamoDBReader(context.Background(), "us-east-2", "", ""); err == nil {
		t.Fatal("empty table should error")
	}
	r, err := NewDynamoDBReader(context.Background(), "us-east-2", "ack-tokens", "http://127.0.0.1:0")
	if err != nil {
		t.Fatalf("construct with table: %v", err)
	}
	if r == nil || r.client == nil {
		t.Fatal("reader/client nil after successful construct")
	}
}

func TestDynamoDBReader_LoadACToken_PureBranches(t *testing.T) {
	// Empty token short-circuits to (nil, false, nil) before any network call.
	r, err := NewDynamoDBReader(context.Background(), "us-east-2", "ack-tokens", "http://127.0.0.1:0")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	got, found, err := r.LoadACToken(context.Background(), "")
	if got != nil || found || err != nil {
		t.Fatalf("empty token = (%v, %v, %v), want (nil, false, nil)", got, found, err)
	}

	// Nil client → loud error (never a silent miss).
	if _, _, err := (&DynamoDBReader{table: "ack-tokens"}).LoadACToken(context.Background(), "tok"); err == nil {
		t.Fatal("nil client should error")
	}
	// Nil receiver → loud error.
	var nilReader *DynamoDBReader
	if _, _, err := nilReader.LoadACToken(context.Background(), "tok"); err == nil {
		t.Fatal("nil reader should error")
	}
}

// TestDynamoDBReader_LoadACToken_GetItemRoundTrip exercises the actual
// GetItem → unmarshal → EntryFromItem path against an HTTP-mocked DynamoDB,
// mirroring the server's TestDynamoDBACKTokenStore_StoreLoadRoundTripWithSDKClient
// but read-only. Asserts the strong-consistency read, the sha256(token) key
// (raw token never on the wire), and hit/miss decoding.
func TestDynamoDBReader_LoadACToken_GetItemRoundTrip(t *testing.T) {
	const (
		tableName = "ack-tokens-test"
		rawToken  = "raw-reader-token-roundtrip"
	)
	expire := time.Now().Add(time.Minute).UTC().Round(time.Nanosecond)
	storedAV, err := attributevalue.MarshalMap(ItemFromEntry(rawToken, &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u-1", OwnerId: "o-1"},
		ResourceId: "res-1",
		KnockSrcIP: "203.0.113.9",
		RunID:      "run-1",
		OpenTime:   60,
		ExpireTime: expire,
	}))
	if err != nil {
		t.Fatalf("marshal stored item: %v", err)
	}

	// Seed via a real PutItem so the SDK produces correct DynamoDB wire JSON;
	// the mock captures that exact wire Item and echoes it back on GetItem
	// (hand-encoding types.AttributeValue does not yield the wire protocol).
	var capturedItem json.RawMessage
	var capturedHash string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if strings.Contains(string(body), rawToken) {
			t.Fatalf("request body leaked raw token: %s", body)
		}
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.PutItem":
			var req struct {
				TableName string
				Item      json.RawMessage
			}
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("decode PutItem: %v", err)
			}
			var attrs map[string]map[string]json.RawMessage
			if err := json.Unmarshal(req.Item, &attrs); err != nil {
				t.Fatalf("decode PutItem Item: %v", err)
			}
			capturedHash = strings.Trim(string(attrs["token_hash"]["S"]), `"`)
			capturedItem = req.Item
			_, _ = w.Write([]byte(`{}`))
		case "DynamoDB_20120810.GetItem":
			var req struct {
				TableName      string
				ConsistentRead bool
				Key            map[string]map[string]json.RawMessage
			}
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("decode GetItem: %v body=%s", err, body)
			}
			if req.TableName != tableName {
				t.Fatalf("GetItem table = %q, want %q", req.TableName, tableName)
			}
			if !req.ConsistentRead {
				t.Fatal("GetItem ConsistentRead=false, want true")
			}
			getHash := strings.Trim(string(req.Key["token_hash"]["S"]), `"`)
			if capturedItem != nil && getHash == capturedHash {
				_, _ = w.Write([]byte(`{"Item":` + string(capturedItem) + `}`))
			} else {
				_, _ = w.Write([]byte(`{}`)) // miss: no Item
			}
		default:
			t.Fatalf("unexpected DynamoDB target %q", r.Header.Get("X-Amz-Target"))
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
	reader := &DynamoDBReader{client: dynamodb.NewFromConfig(cfg), table: tableName}

	// Seed the mock with the wire-format item.
	if _, err := reader.client.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      storedAV,
	}); err != nil {
		t.Fatalf("seed PutItem: %v", err)
	}

	// Hit.
	got, found, err := reader.LoadACToken(context.Background(), rawToken)
	if err != nil || !found {
		t.Fatalf("hit: err=%v found=%v", err, found)
	}
	if got.User == nil || got.User.UserId != "u-1" || got.User.OwnerId != "o-1" ||
		got.KnockSrcIP != "203.0.113.9" || got.RunID != "run-1" || got.OpenTime != 60 || !got.ExpireTime.Equal(expire) {
		t.Fatalf("hit entry = %+v, want fields preserved", got)
	}

	// Miss: a token that was never stored hashes to a different key.
	got, found, err = reader.LoadACToken(context.Background(), "a-token-that-was-never-stored")
	if err != nil || found || got != nil {
		t.Fatalf("miss: got=%v found=%v err=%v, want (nil,false,nil)", got, found, err)
	}
}
