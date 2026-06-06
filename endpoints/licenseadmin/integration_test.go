//go:build integration

package licenseadmin

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Integration coverage for the DynamoDB write path against a real (local)
// DynamoDB. Build-tagged so it never runs in the default unit suite.
//
// NOT RUN IN CI — operator/local-only. CI has no DynamoDB Local service, and
// the project's only integration runner (tests/integration) targets deployed
// infra, not this module. The CI-enforced coverage of the write path is the
// unit test on buildBoundPubKeysUpdate (the exact condition/update expressions
// and SET-vs-REMOVE branches); this suite additionally proves those expressions
// behave against a live DynamoDB and is meant for local pre-merge verification.
//
// To run:
//
//	docker run -d -p 8000:8000 amazon/dynamodb-local
//	NHP_LICENSE_ADMIN_TEST_ENDPOINT=http://localhost:8000 \
//	  go test -tags=integration ./endpoints/licenseadmin/
//
// Skipped (not failed) when the endpoint env var is unset.

func integrationEndpoint(t *testing.T) string {
	t.Helper()
	ep := os.Getenv("NHP_LICENSE_ADMIN_TEST_ENDPOINT")
	if ep == "" {
		t.Skip("set NHP_LICENSE_ADMIN_TEST_ENDPOINT (e.g. http://localhost:8000) to run integration tests")
	}
	return ep
}

func rawClient(t *testing.T, endpoint string) *dynamodb.Client {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-2"),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, region string, _ ...any) (aws.Endpoint, error) {
				return aws.Endpoint{URL: endpoint, SigningRegion: "us-east-2"}, nil
			})),
	)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return dynamodb.NewFromConfig(cfg)
}

func setupTable(t *testing.T, raw *dynamodb.Client, table string) {
	t.Helper()
	ctx := context.Background()
	_, _ = raw.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(table)})
	_, err := raw.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(table),
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("license_key_sha256"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("license_key_sha256"), KeyType: types.KeyTypeHash},
		},
	})
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	if err := dynamodb.NewTableExistsWaiter(raw).Wait(ctx,
		&dynamodb.DescribeTableInput{TableName: aws.String(table)}, 30*time.Second); err != nil {
		t.Fatalf("wait table active: %v", err)
	}
	t.Cleanup(func() {
		_, _ = raw.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(table)})
	})
}

func seedItem(t *testing.T, raw *dynamodb.Client, table string, item map[string]types.AttributeValue) {
	t.Helper()
	if _, err := raw.PutItem(context.Background(),
		&dynamodb.PutItemInput{TableName: aws.String(table), Item: item}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func rawBoundPubKeys(t *testing.T, raw *dynamodb.Client, table, sha string) (types.AttributeValue, bool) {
	t.Helper()
	out, err := raw.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key:       map[string]types.AttributeValue{"license_key_sha256": &types.AttributeValueMemberS{Value: sha}},
	})
	if err != nil {
		t.Fatalf("raw get: %v", err)
	}
	v, ok := out.Item["bound_pubkeys"]
	return v, ok
}

func TestIntegrationClientWritePath(t *testing.T) {
	ep := integrationEndpoint(t)
	raw := rawClient(t, ep)
	const table = "nhp-licenses-itest"
	setupTable(t, raw, table)

	client, err := NewClient(context.Background(), Config{Region: "us-east-2", LicensesTable: table, Endpoint: ep})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()
	k1, k2 := testPubkeyB64(1), testPubkeyB64(2)

	// Not-found.
	if _, err := client.GetLicense(ctx, "deadbeef"); !errors.Is(err, ErrLicenseNotFound) {
		t.Fatalf("expected ErrLicenseNotFound, got %v", err)
	}

	// Normal row with updated_at.
	const sha = "1111111111111111111111111111111111111111111111111111111111111111"
	seedItem(t, raw, table, map[string]types.AttributeValue{
		"license_key_sha256": &types.AttributeValueMemberS{Value: sha},
		"updated_at":         &types.AttributeValueMemberN{Value: "1000"},
	})

	// Set → stored as a List of 2 the reader unmarshals back to []string.
	if _, err := client.UpdateBoundPubKeys(ctx, sha, []string{k1, k2}, 1000); err != nil {
		t.Fatalf("set: %v", err)
	}
	lic, err := client.GetLicense(ctx, sha)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(lic.BoundPubKeys) != 2 || lic.BoundPubKeys[0] != k1 || lic.BoundPubKeys[1] != k2 {
		t.Fatalf("bound = %v", lic.BoundPubKeys)
	}
	if v, ok := rawBoundPubKeys(t, raw, table, sha); !ok {
		t.Fatal("bound_pubkeys absent after set")
	} else if l, isL := v.(*types.AttributeValueMemberL); !isL || len(l.Value) != 2 {
		t.Fatalf("bound_pubkeys not a List of 2: %#v", v)
	}

	// Stale optimistic lock → conflict.
	if _, err := client.UpdateBoundPubKeys(ctx, sha, []string{k1}, 1000); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("expected ErrConcurrentModification on stale write, got %v", err)
	}

	// Remove all → attribute absent (matches omitempty / verdictLicenseUnbound).
	if _, err := client.UpdateBoundPubKeys(ctx, sha, nil, lic.UpdatedAt); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if lic2, _ := client.GetLicense(ctx, sha); len(lic2.BoundPubKeys) != 0 {
		t.Fatalf("expected unbound, got %v", lic2.BoundPubKeys)
	}
	if _, ok := rawBoundPubKeys(t, raw, table, sha); ok {
		t.Fatal("bound_pubkeys should be absent after remove")
	}

	// Legacy row with NO updated_at → bind with expected 0 succeeds.
	const legacy = "2222222222222222222222222222222222222222222222222222222222222222"
	seedItem(t, raw, table, map[string]types.AttributeValue{
		"license_key_sha256": &types.AttributeValueMemberS{Value: legacy},
	})
	if legacyLic, _ := client.GetLicense(ctx, legacy); legacyLic.UpdatedAt != 0 {
		t.Fatalf("expected updated_at 0 for legacy row, got %d", legacyLic.UpdatedAt)
	}
	if _, err := client.UpdateBoundPubKeys(ctx, legacy, []string{k1}, 0); err != nil {
		t.Fatalf("legacy bind: %v", err)
	}

	// Non-existent license → conflict (attribute_exists guard) and NO row created.
	if _, err := client.UpdateBoundPubKeys(ctx, "absent", []string{k1}, 0); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("expected ErrConcurrentModification for absent row, got %v", err)
	}
	if _, err := client.GetLicense(ctx, "absent"); !errors.Is(err, ErrLicenseNotFound) {
		t.Fatalf("absent row must not have been created, got %v", err)
	}
}
