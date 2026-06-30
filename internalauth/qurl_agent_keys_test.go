package internalauth

import (
	"reflect"
	"strings"
	"testing"
)

func TestQURLAgentKeyRowDynamoDBContract(t *testing.T) {
	rowType := reflect.TypeOf(QURLAgentKeyRow{})
	want := map[string]string{
		"OwnerID":       QURLAgentKeysOwnerIDAttr,
		"AgentID":       QURLAgentKeysAgentIDAttr,
		"PublicKey":     QURLAgentKeysPublicKeyAttr,
		"SchemaVersion": QURLAgentKeysSchemaVersionAttr,
		"RegisteredAt":  QURLAgentKeysRegisteredAtAttr,
		"LastSeenAt":    QURLAgentKeysLastSeenAtAttr,
		"Hostname":      QURLAgentKeysHostnameAttr,
		"Version":       QURLAgentKeysVersionAttr,
		"TTL":           QURLAgentKeysTTLAttr,
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
	if !IsSupportedQURLAgentKeysSchemaVersion(QURLAgentKeysLegacySchemaVersion) {
		t.Fatal("legacy schema version must remain accepted until writer/backfill rollout completes")
	}
	if !IsSupportedQURLAgentKeysSchemaVersion(QURLAgentKeysSchemaVersion) {
		t.Fatal("current schema version must be accepted")
	}
	if IsSupportedQURLAgentKeysSchemaVersion(QURLAgentKeysSchemaVersion + 1) {
		t.Fatal("future schema version must reject until this module explicitly supports it")
	}
}
