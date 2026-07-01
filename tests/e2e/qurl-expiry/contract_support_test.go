package qurlexpiry

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	_ "embed"
)

//go:embed qurl_expiry_contract.json
var qurlExpiryContractJSON []byte

const (
	qurlExpiryContractArtifact              = "nhp-qurl-expiry-e2e-contract"
	qurlExpiryContractSchemaVersion         = 1
	qurlExpiryVerifiedCommitSHA1HexLength   = 40
	qurlExpiryVerifiedCommitSHA256HexLength = 64
)

var expiryContract = mustLoadQurlExpiryContract(qurlExpiryContractJSON)

type qurlExpiryContract struct {
	Artifact      string                  `json:"artifact"`
	SchemaVersion int                     `json:"schema_version"`
	Issue         string                  `json:"issue"`
	Description   string                  `json:"description"`
	SourceOfTruth qurlExpirySourceOfTruth `json:"source_of_truth"`
	Events        qurlExpiryEvents        `json:"events"`
	WebhookDedupe qurlExpiryWebhookDedupe `json:"webhook_dedupe"`
	Resources     qurlExpiryResourceTable `json:"resources"`
	AccessTokens  qurlExpiryAccessToken   `json:"access_tokens"`
	Sessions      qurlExpirySessionTable  `json:"sessions"`
	QURLLink      qurlExpiryQURLLink      `json:"qurl_link"`
}

type qurlExpirySourceOfTruth struct {
	Repository     string   `json:"repository"`
	Ref            string   `json:"ref"`
	VerifiedCommit string   `json:"verified_commit"`
	Paths          []string `json:"paths"`
}

type qurlExpiryEvents struct {
	QurlExpired    string `json:"qurl_expired"`
	ResourceClosed string `json:"resource_closed"`
}

type qurlExpiryWebhookDedupe struct {
	Table              string                          `json:"table"`
	PartitionKey       string                          `json:"partition_key"`
	EventTypeAttribute string                          `json:"event_type_attribute"`
	PrimaryIDAttribute string                          `json:"primary_id_attribute"`
	PKAlgorithm        string                          `json:"pk_algorithm"`
	Vectors            []qurlExpiryWebhookDedupeVector `json:"vectors"`
}

type qurlExpiryWebhookDedupeVector struct {
	EventType string `json:"event_type"`
	PrimaryID string `json:"primary_id"`
	PK        string `json:"pk"`
}

type qurlExpiryResourceTable struct {
	Table                 string `json:"table"`
	PartitionKey          string `json:"partition_key"`
	SortKey               string `json:"sort_key"`
	ResourceSortKeyValue  string `json:"resource_sort_key_value"`
	TombstonedAtAttribute string `json:"tombstoned_at_attribute"`
	TombstoneTTLAttribute string `json:"tombstone_ttl_attribute"`
}

type qurlExpiryAccessToken struct {
	Table                     string `json:"table"`
	ResourceIndex             string `json:"resource_index"`
	ResourceIndexPartitionKey string `json:"resource_index_partition_key"`
	QURLIDProjectionAttribute string `json:"qurl_id_projection_attribute"`
}

type qurlExpirySessionTable struct {
	Table                  string `json:"table"`
	PartitionKey           string `json:"partition_key"`
	TTLAttribute           string `json:"ttl_attribute"`
	TTLPlaceholder         string `json:"ttl_placeholder"`
	ActiveFilterExpression string `json:"active_filter_expression"`
}

type qurlExpiryQURLLink struct {
	AccessTokenPrefix         string `json:"access_token_prefix"`
	BootstrapFragmentPrefix   string `json:"bootstrap_fragment_prefix"`
	BootstrapAccessTokenField string `json:"bootstrap_access_token_field"`
}

func mustLoadQurlExpiryContract(data []byte) *qurlExpiryContract {
	contract, err := loadQurlExpiryContract(data)
	if err != nil {
		panic(err)
	}
	return contract
}

func loadQurlExpiryContract(data []byte) (*qurlExpiryContract, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var contract qurlExpiryContract
	if err := dec.Decode(&contract); err != nil {
		return nil, fmt.Errorf("parse qURL expiry contract: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse qURL expiry contract: trailing JSON value")
	}
	if err := contract.validate(); err != nil {
		return nil, err
	}
	return &contract, nil
}

func (c *qurlExpiryContract) validate() error {
	if c.Artifact != qurlExpiryContractArtifact {
		return fmt.Errorf("qURL expiry contract artifact = %q, want %q", c.Artifact, qurlExpiryContractArtifact)
	}
	if c.SchemaVersion != qurlExpiryContractSchemaVersion {
		return fmt.Errorf("qURL expiry contract schema_version = %d, want %d", c.SchemaVersion, qurlExpiryContractSchemaVersion)
	}
	if c.Issue == "" {
		return errors.New("qURL expiry contract missing issue")
	}
	if c.SourceOfTruth.Repository == "" || c.SourceOfTruth.Ref == "" {
		return errors.New("qURL expiry contract missing source_of_truth repository/ref")
	}
	// An empty verified_commit is caught by the length check below.
	commitLength := len(c.SourceOfTruth.VerifiedCommit)
	if commitLength != qurlExpiryVerifiedCommitSHA1HexLength && commitLength != qurlExpiryVerifiedCommitSHA256HexLength {
		return fmt.Errorf("qURL expiry contract source_of_truth.verified_commit has length %d, want %d or %d", commitLength, qurlExpiryVerifiedCommitSHA1HexLength, qurlExpiryVerifiedCommitSHA256HexLength)
	}
	if _, err := hex.DecodeString(c.SourceOfTruth.VerifiedCommit); err != nil {
		return fmt.Errorf("qURL expiry contract source_of_truth.verified_commit is not hex: %w", err)
	}
	if len(c.SourceOfTruth.Paths) == 0 {
		return errors.New("qURL expiry contract source_of_truth.paths is empty")
	}
	seenPaths := map[string]struct{}{}
	for _, path := range c.SourceOfTruth.Paths {
		if strings.TrimSpace(path) == "" {
			return errors.New("qURL expiry contract source_of_truth.paths has empty path")
		}
		if _, ok := seenPaths[path]; ok {
			return fmt.Errorf("qURL expiry contract source_of_truth.paths has duplicate path %s", path)
		}
		seenPaths[path] = struct{}{}
	}
	if c.Events.QurlExpired == "" || c.Events.ResourceClosed == "" {
		return errors.New("qURL expiry contract missing event names")
	}
	if c.WebhookDedupe.PKAlgorithm != "sha256_lenprefixed_event_type_primary_id_v1" {
		return fmt.Errorf("qURL expiry contract webhook dedupe algorithm = %q", c.WebhookDedupe.PKAlgorithm)
	}
	// The strict test pins exact values; validate keeps the e2e harness from
	// starting with empty names before any test body can report a cleaner error.
	required := []struct {
		name  string
		value string
	}{
		{"webhook_dedupe.table", c.WebhookDedupe.Table},
		{"webhook_dedupe.partition_key", c.WebhookDedupe.PartitionKey},
		{"webhook_dedupe.event_type_attribute", c.WebhookDedupe.EventTypeAttribute},
		{"webhook_dedupe.primary_id_attribute", c.WebhookDedupe.PrimaryIDAttribute},
		{"resources.table", c.Resources.Table},
		{"resources.partition_key", c.Resources.PartitionKey},
		{"resources.sort_key", c.Resources.SortKey},
		{"resources.resource_sort_key_value", c.Resources.ResourceSortKeyValue},
		{"resources.tombstoned_at_attribute", c.Resources.TombstonedAtAttribute},
		{"resources.tombstone_ttl_attribute", c.Resources.TombstoneTTLAttribute},
		{"access_tokens.table", c.AccessTokens.Table},
		{"access_tokens.resource_index", c.AccessTokens.ResourceIndex},
		{"access_tokens.resource_index_partition_key", c.AccessTokens.ResourceIndexPartitionKey},
		{"access_tokens.qurl_id_projection_attribute", c.AccessTokens.QURLIDProjectionAttribute},
		{"sessions.table", c.Sessions.Table},
		{"sessions.partition_key", c.Sessions.PartitionKey},
		{"sessions.ttl_attribute", c.Sessions.TTLAttribute},
		{"sessions.ttl_placeholder", c.Sessions.TTLPlaceholder},
		{"sessions.active_filter_expression", c.Sessions.ActiveFilterExpression},
		{"qurl_link.access_token_prefix", c.QURLLink.AccessTokenPrefix},
		{"qurl_link.bootstrap_fragment_prefix", c.QURLLink.BootstrapFragmentPrefix},
		{"qurl_link.bootstrap_access_token_field", c.QURLLink.BootstrapAccessTokenField},
	}
	for _, field := range required {
		if field.value == "" {
			return fmt.Errorf("qURL expiry contract missing %s", field.name)
		}
	}
	if !strings.Contains(c.Sessions.ActiveFilterExpression, c.Sessions.TTLPlaceholder) {
		return fmt.Errorf("qURL expiry contract sessions.active_filter_expression %q does not use ttl_placeholder %q", c.Sessions.ActiveFilterExpression, c.Sessions.TTLPlaceholder)
	}
	if len(c.WebhookDedupe.Vectors) == 0 {
		return errors.New("qURL expiry contract webhook_dedupe.vectors is empty")
	}
	// Vectors are a local mirror fence. Regenerate manifest values from
	// qurl-service output when upstream changes, not from this helper alone.
	for _, vector := range c.WebhookDedupe.Vectors {
		if vector.EventType == "" || vector.PrimaryID == "" || vector.PK == "" {
			return errors.New("qURL expiry contract webhook dedupe vector has empty field")
		}
		if got := webhookEventDedupePK(vector.EventType, vector.PrimaryID); got != vector.PK {
			return fmt.Errorf("qURL expiry contract webhook dedupe vector %s/%s pk = %s, want %s", vector.EventType, vector.PrimaryID, got, vector.PK)
		}
	}
	return nil
}

func extractAccessTokenFromQURLLink(qurlLink string) (string, error) {
	parsed, err := url.Parse(qurlLink)
	if err != nil {
		return "", fmt.Errorf("parse qurl_link: %w", err)
	}
	fragment := parsed.Fragment
	if strings.HasPrefix(fragment, expiryContract.QURLLink.AccessTokenPrefix) {
		if len(fragment) == len(expiryContract.QURLLink.AccessTokenPrefix) {
			return "", fmt.Errorf("qurl_link fragment has empty %s token", expiryContract.QURLLink.AccessTokenPrefix)
		}
		// qurl-service stores and indexes the full legacy at_ token string.
		return fragment, nil
	}
	if !strings.HasPrefix(fragment, expiryContract.QURLLink.BootstrapFragmentPrefix) {
		return "", fmt.Errorf("qurl_link fragment does not carry an %s token or %s bundle", expiryContract.QURLLink.AccessTokenPrefix, expiryContract.QURLLink.BootstrapFragmentPrefix)
	}

	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(fragment, expiryContract.QURLLink.BootstrapFragmentPrefix))
	if err != nil {
		return "", fmt.Errorf("decode %s qurl_link fragment: %w", expiryContract.QURLLink.BootstrapFragmentPrefix, err)
	}
	var bundle map[string]json.RawMessage
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return "", fmt.Errorf("parse %s qurl_link bundle: %w", expiryContract.QURLLink.BootstrapFragmentPrefix, err)
	}
	raw, ok := bundle[expiryContract.QURLLink.BootstrapAccessTokenField]
	if !ok {
		return "", fmt.Errorf("%s qurl_link bundle missing %s", expiryContract.QURLLink.BootstrapFragmentPrefix, expiryContract.QURLLink.BootstrapAccessTokenField)
	}
	var accessToken string
	if err := json.Unmarshal(raw, &accessToken); err != nil {
		return "", fmt.Errorf("parse %s qurl_link bundle %s: %w", expiryContract.QURLLink.BootstrapFragmentPrefix, expiryContract.QURLLink.BootstrapAccessTokenField, err)
	}
	if accessToken == "" {
		return "", fmt.Errorf("%s qurl_link bundle has empty %s", expiryContract.QURLLink.BootstrapFragmentPrefix, expiryContract.QURLLink.BootstrapAccessTokenField)
	}
	return accessToken, nil
}

func webhookEventDedupePK(eventType, primaryID string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d:%s:%d:%s", len(eventType), eventType, len(primaryID), primaryID)
	return hex.EncodeToString(h.Sum(nil))
}
