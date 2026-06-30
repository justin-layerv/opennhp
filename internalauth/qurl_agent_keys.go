package internalauth

const (
	// QURLAgentKeysSchemaVersion is the current qurl-agent-keys registration row
	// schema understood by nhp-server and qurl-service.
	QURLAgentKeysSchemaVersion = 1

	// QURLAgentKeysLegacySchemaVersion is the implicit version for rows written
	// before schema_version existed. nhp-server accepts this during rollout so a
	// reader deploy cannot strand existing agents before the writer/backfill lands.
	QURLAgentKeysLegacySchemaVersion = 0

	QURLAgentKeysOwnerIDAttr       = "owner_id"
	QURLAgentKeysAgentIDAttr       = "agent_id"
	QURLAgentKeysPublicKeyAttr     = "public_key"
	QURLAgentKeysSchemaVersionAttr = "schema_version"
	QURLAgentKeysRegisteredAtAttr  = "registered_at"
	QURLAgentKeysLastSeenAtAttr    = "last_seen_at"
	QURLAgentKeysHostnameAttr      = "hostname"
	QURLAgentKeysVersionAttr       = "version"
	QURLAgentKeysTTLAttr           = "ttl"

	// QURLAgentKeysPubkeyIndexName is the GSI nhp-server queries on first knock.
	QURLAgentKeysPubkeyIndexName = "pubkey-index"
)

// QURLAgentKeyRow is the shared DynamoDB contract for qurl-agent-keys
// registration rows. qurl-service writes it; nhp-server reads it by querying
// QURLAgentKeysPubkeyIndexName on PublicKey.
type QURLAgentKeyRow struct {
	OwnerID   string `dynamodbav:"owner_id"`
	AgentID   string `dynamodbav:"agent_id"`
	PublicKey string `dynamodbav:"public_key"`
	// Intentionally no omitempty: qurl-service writers must emit an explicit
	// schema_version, and 0 is a meaningful legacy value for nhp-server readers.
	SchemaVersion int    `dynamodbav:"schema_version"`
	RegisteredAt  string `dynamodbav:"registered_at,omitempty"`
	LastSeenAt    string `dynamodbav:"last_seen_at,omitempty"`
	Hostname      string `dynamodbav:"hostname,omitempty"`
	Version       string `dynamodbav:"version,omitempty"`
	TTL           int64  `dynamodbav:"ttl,omitempty"`
}

// IsSupportedQURLAgentKeysSchemaVersion reports whether nhp-server can consume
// a qurl-agent-keys registration row with the given schema_version. Keep this
// support set additive during future reader-first schema bumps: a v2 reader must
// still accept legacy/v1 rows while writers roll forward.
func IsSupportedQURLAgentKeysSchemaVersion(version int) bool {
	return version == QURLAgentKeysLegacySchemaVersion || version == QURLAgentKeysSchemaVersion
}
