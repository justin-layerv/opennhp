package internalauth

import (
	"reflect"
	"strings"
	"testing"
)

func TestQURLAgentKeyRowDynamoDBContract(t *testing.T) {
	rowType := reflect.TypeOf(QURLAgentKeyRow{})
	want := map[string]string{
		"OwnerID":                  QURLAgentKeysOwnerIDAttr,
		"AgentID":                  QURLAgentKeysAgentIDAttr,
		"PublicKey":                QURLAgentKeysPublicKeyAttr,
		"SchemaVersion":            QURLAgentKeysSchemaVersionAttr,
		"RegisteredAt":             QURLAgentKeysRegisteredAtAttr,
		"LastSeenAt":               QURLAgentKeysLastSeenAtAttr,
		"Hostname":                 QURLAgentKeysHostnameAttr,
		"Version":                  QURLAgentKeysVersionAttr,
		"TTL":                      QURLAgentKeysTTLAttr,
		"EnrollmentCredentialKind": QURLAgentKeysEnrollmentCredentialKindAttr,
		"ConnectorIDClaim":         QURLAgentKeysConnectorIDClaimAttr,
	}

	for fieldName, attr := range want {
		field, ok := rowType.FieldByName(fieldName)
		if !ok {
			t.Fatalf("QURLAgentKeyRow missing field %s", fieldName)
		}
		got := strings.Split(field.Tag.Get("dynamodbav"), ",")[0]
		if got != attr {
			t.Errorf("%s dynamodbav attr=%q want %q", fieldName, got, attr)
		}
	}
}

func TestQURLAgentKeysSchemaVersionSupport(t *testing.T) {
	if !IsSupportedQURLAgentKeysSchemaVersion(QURLAgentKeysSchemaVersion) {
		t.Fatal("current schema version must be accepted")
	}
	for _, version := range []int{0, 1, QURLAgentKeysSchemaVersion + 1} {
		if IsSupportedQURLAgentKeysSchemaVersion(version) {
			t.Fatalf("schema version %d must fail closed", version)
		}
	}
}

func TestValidateQURLAgentKeyRowCredentialScope(t *testing.T) {
	tests := []struct {
		name  string
		kind  QURLEnrollmentCredentialKind
		claim string
		valid bool
	}{
		{"account", QURLEnrollmentCredentialKindAccount, "", true},
		{"bootstrap", QURLEnrollmentCredentialKindBootstrap, "", true},
		{"connector bootstrap", QURLEnrollmentCredentialKindConnectorBootstrap, "prod-dashboard", true},
		{"unknown", "future", "", false},
		{"account with claim", QURLEnrollmentCredentialKindAccount, "prod-dashboard", false},
		{"bootstrap with claim", QURLEnrollmentCredentialKindBootstrap, "prod-dashboard", false},
		{"connector missing claim", QURLEnrollmentCredentialKindConnectorBootstrap, "", false},
		{"connector claim format remains repository scoped", QURLEnrollmentCredentialKindConnectorBootstrap, "service-owned opaque claim", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := QURLAgentKeyRow{SchemaVersion: QURLAgentKeysSchemaVersion, EnrollmentCredentialKind: test.kind, ConnectorIDClaim: test.claim}
			if got := ValidateQURLAgentKeyRow(row) == nil; got != test.valid {
				t.Fatalf("ValidateQURLAgentKeyRow valid=%t want %t", got, test.valid)
			}
		})
	}
	for _, version := range []int{0, 1, 3} {
		if err := ValidateQURLAgentKeyRow(QURLAgentKeyRow{SchemaVersion: version, EnrollmentCredentialKind: QURLEnrollmentCredentialKindAccount}); err == nil {
			t.Fatalf("schema version %d unexpectedly accepted", version)
		}
	}
}
