package qurlexpiry

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestQurlExpiryContract_LoadsStrictly(t *testing.T) {
	contract, err := loadQurlExpiryContract(qurlExpiryContractJSON)
	if err != nil {
		t.Fatalf("load qURL expiry contract: %v", err)
	}
	wantPaths := []string{
		"internal/repository/dynamodb/schema.go",
		"internal/repository/dynamodb/webhook_event_dedupe_repo.go",
		"internal/repository/dynamodb/resource_repo.go",
		"internal/repository/dynamodb/qurl_repo.go",
		"cmd/qurl-scanner/resource_close.go",
		"internal/service/qurl_bootstrap_bundle.go",
		"internal/domain/webhook.go",
	}
	gotPaths := slices.Clone(contract.SourceOfTruth.Paths)
	slices.Sort(gotPaths)
	slices.Sort(wantPaths)
	if !slices.Equal(gotPaths, wantPaths) {
		t.Fatalf("source paths = %v, want %v", gotPaths, wantPaths)
	}
	if contract.SchemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", contract.SchemaVersion)
	}
	// These exact anchors intentionally duplicate the manifest values. For
	// legitimate mirror changes, update the manifest from qurl-service first,
	// then review these anchors with the same verified_commit.
	wantFields := []struct {
		name string
		got  string
		want string
	}{
		{"source_of_truth.repository", contract.SourceOfTruth.Repository, "layervai/qurl-service"},
		{"events.qurl_expired", contract.Events.QurlExpired, "qurl.expired"},
		{"events.resource_closed", contract.Events.ResourceClosed, "resource.closed"},
		{"webhook_dedupe.table", contract.WebhookDedupe.Table, "qurl-webhook-event-dedupe"},
		{"webhook_dedupe.partition_key", contract.WebhookDedupe.PartitionKey, "pk"},
		{"webhook_dedupe.event_type_attribute", contract.WebhookDedupe.EventTypeAttribute, "event_type"},
		{"webhook_dedupe.primary_id_attribute", contract.WebhookDedupe.PrimaryIDAttribute, "primary_id"},
		{"webhook_dedupe.pk_algorithm", contract.WebhookDedupe.PKAlgorithm, "sha256_lenprefixed_event_type_primary_id_v1"},
		{"resources.table", contract.Resources.Table, "qurl-resources"},
		{"resources.partition_key", contract.Resources.PartitionKey, "resource_id"},
		{"resources.sort_key", contract.Resources.SortKey, "sk"},
		{"resources.resource_sort_key_value", contract.Resources.ResourceSortKeyValue, "RESOURCE"},
		{"resources.tombstoned_at_attribute", contract.Resources.TombstonedAtAttribute, "resource_tombstoned_at"},
		{"resources.tombstone_ttl_attribute", contract.Resources.TombstoneTTLAttribute, "tombstone_ttl"},
		{"access_tokens.table", contract.AccessTokens.Table, "qurl-access-tokens"},
		{"access_tokens.resource_index", contract.AccessTokens.ResourceIndex, "resource-token-index"},
		{"access_tokens.resource_index_partition_key", contract.AccessTokens.ResourceIndexPartitionKey, "resource_id"},
		{"access_tokens.qurl_id_projection_attribute", contract.AccessTokens.QURLIDProjectionAttribute, "nhp_resource_id"},
		{"sessions.table", contract.Sessions.Table, "qurl-sessions"},
		{"sessions.partition_key", contract.Sessions.PartitionKey, "resource_id"},
		{"sessions.ttl_attribute", contract.Sessions.TTLAttribute, "ttl"},
		{"sessions.ttl_placeholder", contract.Sessions.TTLPlaceholder, "#ttl"},
		{"sessions.active_filter_expression", contract.Sessions.ActiveFilterExpression, "#ttl > :now"},
		{"qurl_link.access_token_prefix", contract.QURLLink.AccessTokenPrefix, "at_"},
		{"qurl_link.bootstrap_fragment_prefix", contract.QURLLink.BootstrapFragmentPrefix, "qv1."},
		{"qurl_link.bootstrap_access_token_field", contract.QURLLink.BootstrapAccessTokenField, "access_token"},
	}
	for _, field := range wantFields {
		if field.got != field.want {
			t.Fatalf("%s = %q, want %q", field.name, field.got, field.want)
		}
	}

	wantDedupeVectorPKs := map[string]string{
		"qurl.expired/q_contract_123":    "b796bbf9008ed60293234b98a48c93e4b8465632ff7bd6e943dd706a49449bc2",
		"resource.closed/r_contract_456": "c2d63c64adeeada351584fdadc6ba2a696edc4c4d1d9bf527cf2c92a402dc09e",
	}
	if len(contract.WebhookDedupe.Vectors) != len(wantDedupeVectorPKs) {
		t.Fatalf("webhook_dedupe.vectors length = %d, want %d", len(contract.WebhookDedupe.Vectors), len(wantDedupeVectorPKs))
	}
	// Length plus unique key matching proves full vector coverage.
	for _, vector := range contract.WebhookDedupe.Vectors {
		key := vector.EventType + "/" + vector.PrimaryID
		wantPK, ok := wantDedupeVectorPKs[key]
		if !ok {
			t.Fatalf("webhook_dedupe.vectors has unexpected vector %s", key)
		}
		if vector.PK != wantPK {
			t.Fatalf("webhook_dedupe.vectors[%s].pk = %q, want %q", key, vector.PK, wantPK)
		}
		delete(wantDedupeVectorPKs, key)
	}
}

func TestExtractAccessTokenFromQURLLink(t *testing.T) {
	legacyPrefix := expiryContract.QURLLink.AccessTokenPrefix
	bundlePrefix := expiryContract.QURLLink.BootstrapFragmentPrefix
	bundleField := expiryContract.QURLLink.BootstrapAccessTokenField

	encodeBundle := func(bundle map[string]any) string {
		t.Helper()
		payload, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		return "https://qurl.link/#" + bundlePrefix + base64.RawURLEncoding.EncodeToString(payload)
	}

	tests := []struct {
		name    string
		link    string
		want    string
		wantErr string
	}{
		{
			name: "legacy token",
			link: "https://qurl.link/#" + legacyPrefix + "contracttoken",
			want: legacyPrefix + "contracttoken",
		},
		{
			name:    "legacy token prefix only",
			link:    "https://qurl.link/#" + legacyPrefix,
			wantErr: "empty " + legacyPrefix + " token",
		},
		{
			name: "bootstrap bundle",
			link: encodeBundle(map[string]any{
				bundleField: legacyPrefix + "from_bundle",
			}),
			want: legacyPrefix + "from_bundle",
		},
		{
			name:    "invalid url",
			link:    "https://[::1",
			wantErr: "parse qurl_link",
		},
		{
			name:    "unsupported fragment",
			link:    "https://qurl.link/#token_without_known_prefix",
			wantErr: "does not carry an " + legacyPrefix + " token or " + bundlePrefix + " bundle",
		},
		{
			name:    "bad bundle base64",
			link:    "https://qurl.link/#" + bundlePrefix + "not base64",
			wantErr: "decode " + bundlePrefix + " qurl_link fragment",
		},
		{
			name:    "bundle is not json",
			link:    "https://qurl.link/#" + bundlePrefix + base64.RawURLEncoding.EncodeToString([]byte("{")),
			wantErr: "parse " + bundlePrefix + " qurl_link bundle",
		},
		{
			name:    "missing access token",
			link:    encodeBundle(map[string]any{}),
			wantErr: "missing " + bundleField,
		},
		{
			name: "non-string access token",
			link: encodeBundle(map[string]any{
				bundleField: 123,
			}),
			wantErr: "parse " + bundlePrefix + " qurl_link bundle " + bundleField,
		},
		{
			name: "empty access token",
			link: encodeBundle(map[string]any{
				bundleField: "",
			}),
			wantErr: "empty " + bundleField,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractAccessTokenFromQURLLink(tt.link)
			if tt.wantErr == "" {
				if err != nil || got != tt.want {
					t.Fatalf("extractAccessTokenFromQURLLink() = %q, %v; want %q, nil", got, err, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("extractAccessTokenFromQURLLink() = %q, want error containing %q", got, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("extractAccessTokenFromQURLLink() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestQurlExpiryContract_RejectsInvalidMirrorValues(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, doc map[string]any)
		wantErr string
	}{
		{
			name: "wrong pk algorithm",
			mutate: func(t *testing.T, doc map[string]any) {
				webhookDedupe := objectField(t, doc, "webhook_dedupe")
				webhookDedupe["pk_algorithm"] = "sha256_broken"
			},
			wantErr: "webhook dedupe algorithm",
		},
		{
			name: "wrong vector pk",
			mutate: func(t *testing.T, doc map[string]any) {
				webhookDedupe := objectField(t, doc, "webhook_dedupe")
				vectors, ok := webhookDedupe["vectors"].([]any)
				if !ok || len(vectors) == 0 {
					t.Fatal("fixture webhook_dedupe.vectors is not a non-empty array")
				}
				vector, ok := vectors[0].(map[string]any)
				if !ok {
					t.Fatal("fixture webhook_dedupe.vectors[0] is not an object")
				}
				vector["pk"] = strings.Repeat("0", 64)
			},
			wantErr: "webhook dedupe vector qurl.expired/q_contract_123 pk",
		},
		{
			name: "missing required field",
			mutate: func(t *testing.T, doc map[string]any) {
				sessions := objectField(t, doc, "sessions")
				sessions["ttl_attribute"] = ""
			},
			wantErr: "missing sessions.ttl_attribute",
		},
		{
			name: "active filter placeholder mismatch",
			mutate: func(t *testing.T, doc map[string]any) {
				sessions := objectField(t, doc, "sessions")
				sessions["ttl_placeholder"] = "#expires"
			},
			wantErr: "active_filter_expression",
		},
		{
			name: "short verified commit",
			mutate: func(t *testing.T, doc map[string]any) {
				source := objectField(t, doc, "source_of_truth")
				source["verified_commit"] = "b8db7aa"
			},
			wantErr: "verified_commit has length",
		},
		{
			name: "non-hex verified commit",
			mutate: func(t *testing.T, doc map[string]any) {
				source := objectField(t, doc, "source_of_truth")
				source["verified_commit"] = "zzzz7aa94089f229fb744dfd17a142df2845a248"
			},
			wantErr: "verified_commit is not hex",
		},
		{
			name: "empty source paths",
			mutate: func(t *testing.T, doc map[string]any) {
				source := objectField(t, doc, "source_of_truth")
				source["paths"] = []any{}
			},
			wantErr: "source_of_truth.paths is empty",
		},
		{
			name: "duplicate source path",
			mutate: func(t *testing.T, doc map[string]any) {
				source := objectField(t, doc, "source_of_truth")
				paths, ok := source["paths"].([]any)
				if !ok || len(paths) == 0 {
					t.Fatal("fixture source_of_truth.paths is not a non-empty array")
				}
				source["paths"] = append(paths, paths[0])
			},
			wantErr: "source_of_truth.paths has duplicate path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := mutatedQurlExpiryContractJSON(t, tt.mutate)
			if _, err := loadQurlExpiryContract(mutated); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("loadQurlExpiryContract() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestQurlExpiryContract_RejectsUnknownFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, doc map[string]any)
	}{
		{
			name: "top-level",
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["unexpected"] = true
			},
		},
		{
			name: "nested source_of_truth",
			mutate: func(t *testing.T, doc map[string]any) {
				sourceOfTruth := objectField(t, doc, "source_of_truth")
				sourceOfTruth["unexpected"] = true
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := mutatedQurlExpiryContractJSON(t, tt.mutate)
			if _, err := loadQurlExpiryContract(mutated); err == nil {
				t.Fatalf("loadQurlExpiryContract accepted an unknown %s field", tt.name)
			}
		})
	}
}

func TestQurlExpiryContract_AcceptsSHA256VerifiedCommit(t *testing.T) {
	mutated := mutatedQurlExpiryContractJSON(t, func(t *testing.T, doc map[string]any) {
		source := objectField(t, doc, "source_of_truth")
		source["verified_commit"] = strings.Repeat("a", 64)
	})
	if _, err := loadQurlExpiryContract(mutated); err != nil {
		t.Fatalf("loadQurlExpiryContract() with 64-hex verified_commit: %v", err)
	}
}

func mutatedQurlExpiryContractJSON(t *testing.T, mutate func(t *testing.T, doc map[string]any)) []byte {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal(qurlExpiryContractJSON, &doc); err != nil {
		t.Fatalf("parse fixture for mutation: %v", err)
	}
	mutate(t, doc)

	mutated, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal mutated fixture: %v", err)
	}
	return mutated
}

func objectField(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()

	field, ok := doc[name].(map[string]any)
	if !ok {
		t.Fatalf("fixture %s is not an object", name)
	}
	return field
}
