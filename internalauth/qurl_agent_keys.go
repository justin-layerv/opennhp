package internalauth

import "errors"

const (
	// QURLAgentKeysSchemaVersion is the current qurl-agent-keys registration row
	// schema understood by nhp-server and qurl-service.
	QURLAgentKeysSchemaVersion = 2

	QURLAgentKeysOwnerIDAttr                  = "owner_id"
	QURLAgentKeysAgentIDAttr                  = "agent_id"
	QURLAgentKeysPublicKeyAttr                = "public_key"
	QURLAgentKeysSchemaVersionAttr            = "schema_version"
	QURLAgentKeysRegisteredAtAttr             = "registered_at"
	QURLAgentKeysLastSeenAtAttr               = "last_seen_at"
	QURLAgentKeysHostnameAttr                 = "hostname"
	QURLAgentKeysVersionAttr                  = "version"
	QURLAgentKeysTTLAttr                      = "ttl"
	QURLAgentKeysEnrollmentCredentialKindAttr = "enrollment_credential_kind"
	QURLAgentKeysConnectorIDClaimAttr         = "connector_id_claim"
	QURLAgentKeysPublicKeyClaimOwnerAttr      = "claim_owner"
	QURLAgentKeysPublicKeyClaimSchemeAttr     = "claim_scheme"
	QURLAgentKeysPublicKeyClaimAgentID        = "claim"
	QURLAgentKeysPublicKeyClaimOwnerPrefix    = "pubkeyclaim#"
	QURLAgentKeysPublicKeyClaimScheme         = "pubkey_owner_v1"

	// QURLAgentKeysPubkeyIndexName is the GSI nhp-server queries on first knock.
	QURLAgentKeysPubkeyIndexName = "pubkey-index"
)

// QURLEnrollmentCredentialKind records the credential scope proven when the
// registration row was created. It is authorization data, not display
// metadata; unknown values fail closed.
type QURLEnrollmentCredentialKind string

const (
	QURLEnrollmentCredentialKindAccount            QURLEnrollmentCredentialKind = "account"
	QURLEnrollmentCredentialKindBootstrap          QURLEnrollmentCredentialKind = "bootstrap"
	QURLEnrollmentCredentialKindConnectorBootstrap QURLEnrollmentCredentialKind = "connector_bootstrap"
)

var ErrInvalidQURLAgentKeyRow = errors.New("internalauth: invalid qurl agent key row")

// QURLAgentKeyRow is the shared DynamoDB contract for qurl-agent-keys
// registration rows. qurl-service writes it; nhp-server reads it by querying
// QURLAgentKeysPubkeyIndexName on PublicKey.
type QURLAgentKeyRow struct {
	OwnerID   string `dynamodbav:"owner_id"`
	AgentID   string `dynamodbav:"agent_id"`
	PublicKey string `dynamodbav:"public_key"`
	// Intentionally no omitempty: qurl-service writers must emit an explicit
	// schema_version, and a missing/zero value fails closed at every reader.
	SchemaVersion            int                          `dynamodbav:"schema_version"`
	RegisteredAt             string                       `dynamodbav:"registered_at,omitempty"`
	LastSeenAt               string                       `dynamodbav:"last_seen_at,omitempty"`
	Hostname                 string                       `dynamodbav:"hostname,omitempty"`
	Version                  string                       `dynamodbav:"version,omitempty"`
	TTL                      int64                        `dynamodbav:"ttl,omitempty"`
	EnrollmentCredentialKind QURLEnrollmentCredentialKind `dynamodbav:"enrollment_credential_kind"`
	ConnectorIDClaim         string                       `dynamodbav:"connector_id_claim,omitempty"`
}

// IsSupportedQURLAgentKeysSchemaVersion reports whether nhp-server can consume
// a qurl-agent-keys registration row with the given schema_version. Keep this
// support set deliberately contains only v2. This pre-production breaking
// transition has no compatibility window: v0/v1 rows lack the credential scope
// required for Connector resource authorization and therefore fail closed.
func IsSupportedQURLAgentKeysSchemaVersion(version int) bool {
	return version == QURLAgentKeysSchemaVersion
}

// ValidateQURLAgentKeyRow enforces the schema-v2 credential/claim relation.
// connector_id_claim is present exactly for connector_bootstrap credentials;
// account and ordinary bootstrap credentials must remain owner-wide and carry
// no connector claim.
func ValidateQURLAgentKeyRow(row QURLAgentKeyRow) error {
	if !IsSupportedQURLAgentKeysSchemaVersion(row.SchemaVersion) {
		return ErrInvalidQURLAgentKeyRow
	}
	switch row.EnrollmentCredentialKind {
	case QURLEnrollmentCredentialKindAccount, QURLEnrollmentCredentialKindBootstrap:
		if row.ConnectorIDClaim != "" {
			return ErrInvalidQURLAgentKeyRow
		}
	case QURLEnrollmentCredentialKindConnectorBootstrap:
		if row.ConnectorIDClaim == "" {
			return ErrInvalidQURLAgentKeyRow
		}
	default:
		return ErrInvalidQURLAgentKeyRow
	}
	return nil
}
