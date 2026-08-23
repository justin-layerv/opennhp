package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// Canonical unpadded base64url P-256 DER SPKI from the Connector-resource
// conformance fixture. Keep routing/knock identifiers visibly different in
// tests so identity cross-wires cannot hide behind equal placeholder strings.
const testProtectedResourceID = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"

func TestConnectorACKTokenKeepsPublicRoutingAndKnockIdentitiesDistinct(t *testing.T) {
	artifact, err := conformance.ConnectorResourceLSTV1()
	if err != nil {
		t.Fatalf("load Connector-resource conformance: %v", err)
	}
	ids := artifact.Fixtures
	if ids.ResourceID != testProtectedResourceID {
		t.Fatalf("test public resource fixture drifted: %q", ids.ResourceID)
	}
	if ids.ResourceID == ids.ConnectorRoutingID || ids.ResourceID == ids.KnockResourceID || ids.ConnectorRoutingID == ids.KnockResourceID {
		t.Fatalf("fixture identities must be pairwise distinct: public=%q routing=%q knock=%q", ids.ResourceID, ids.ConnectorRoutingID, ids.KnockResourceID)
	}

	issuedAt := time.Now()
	knock := &common.AgentKnockMsg{
		UserId:             ids.AgentID,
		AuthServiceId:      common.RegisteredAgentAuthServiceID,
		ResourceId:         ids.KnockResourceID,
		RunID:              "0123456789abcdef",
		NHPSessionId:       77,
		NHPSessionIssuedAt: issuedAt,
	}
	resolved := &common.ResourceData{ResourcePublicKeyB64: ids.ResourceID}
	if err := bindRegisteredAgentProtectedResource(knock, resolved); err != nil {
		t.Fatalf("bind registered-agent public resource: %v", err)
	}
	if knock.ProtectedResourceId != ids.ResourceID || knock.ResourceId != ids.KnockResourceID {
		t.Fatalf("bound knock identities = protected %q knock %q, want %q / %q", knock.ProtectedResourceId, knock.ResourceId, ids.ResourceID, ids.KnockResourceID)
	}

	router, signer, server := newTokenValidateRouter(t, true)
	ack := &common.ServerKnockAckMsg{SessionId: 77, ACTokens: map[string]string{ids.KnockResourceID: "connector-token"}}
	if err := server.PublishACKTokens(context.Background(), knock, ack, "203.0.113.77", 60, "owner-77"); err != nil {
		t.Fatalf("PublishACKTokens: %v", err)
	}
	stored := server.VerifyAccessToken("connector-token")
	if stored == nil {
		t.Fatal("connector token was not stored")
	}
	if stored.ResourceId != ids.KnockResourceID || stored.ProtectedResourceId != ids.ResourceID {
		t.Fatalf("stored identities = catalog %q protected %q, want knock %q public %q", stored.ResourceId, stored.ProtectedResourceId, ids.KnockResourceID, ids.ResourceID)
	}
	if stored.ResourceId == ids.ConnectorRoutingID || stored.ProtectedResourceId == ids.ConnectorRoutingID {
		t.Fatalf("ConnectorRoutingID %q crossed into ACK-token identities", ids.ConnectorRoutingID)
	}

	body := `{"token":"connector-token","agent_run_id":"0123456789abcdef"}`
	rec := doValidateRequest(t, router, body, signValidate(t, signer, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("token validate status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var validated internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &validated); err != nil {
		t.Fatalf("decode validate response: %v", err)
	}
	if !validated.Valid || validated.ResourceId != ids.ResourceID {
		t.Fatalf("validate response = %+v, want signed public resource %q", validated, ids.ResourceID)
	}
}

func TestBindRegisteredAgentProtectedResourceFailsClosed(t *testing.T) {
	base := func() *common.AgentKnockMsg {
		return &common.AgentKnockMsg{AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "connector-knock-1"}
	}
	for name, resource := range map[string]*common.ResourceData{
		"missing":   {},
		"malformed": {ResourcePublicKeyB64: "connector-routing-id"},
	} {
		t.Run(name, func(t *testing.T) {
			knock := base()
			if err := bindRegisteredAgentProtectedResource(knock, resource); err == nil {
				t.Fatal("binding accepted invalid resolved public resource")
			}
			if knock.ProtectedResourceId != "" {
				t.Fatalf("failed binding retained protected resource %q", knock.ProtectedResourceId)
			}
		})
	}
	crossWired := base()
	crossWired.ResourceId = testProtectedResourceID
	if err := bindRegisteredAgentProtectedResource(crossWired, &common.ResourceData{ResourcePublicKeyB64: testProtectedResourceID}); err == nil {
		t.Fatal("binding accepted public resource copied into the knock-routing field")
	}

	generic := &common.AgentKnockMsg{AuthServiceId: "legacy", ResourceId: "legacy-resource", ProtectedResourceId: testProtectedResourceID}
	if err := bindRegisteredAgentProtectedResource(generic, &common.ResourceData{ResourcePublicKeyB64: testProtectedResourceID}); err != nil {
		t.Fatalf("generic binding: %v", err)
	}
	if generic.ProtectedResourceId != "" {
		t.Fatalf("generic knock retained protected-resource assertion %q", generic.ProtectedResourceId)
	}
}
