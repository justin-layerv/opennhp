package connectorcell

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"strings"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

func connectorResourceTestID(t *testing.T) string {
	t.Helper()
	x, y := elliptic.P256().ScalarBaseMult([]byte{7})
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func connectorResourceRequestBody(t *testing.T, expected *string) []byte {
	t.Helper()
	data := map[string]any{
		"query": connectorResourceQuery, "version": 1,
		"request_nonce": base64.RawURLEncoding.EncodeToString(make([]byte, connectorResourceNonceBytes)),
		"connector_id":  "prod-dashboard",
	}
	if expected != nil {
		data["expected_resource_id"] = *expected
	}
	body, err := json.Marshal(map[string]any{
		"usrId": "agent-1", "devId": "agent-1", "aspId": "agent", "usrData": data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestDecodeConnectorResourceRequestStrict(t *testing.T) {
	peer := make([]byte, x25519KeyBytes)
	resourceID := connectorResourceTestID(t)
	for _, expected := range []*string{nil, &resourceID} {
		request, routed, rejection, err := decodeRoutedConnectorResourceRequest(connectorResourceRequestBody(t, expected), peer)
		if err != nil || !routed || rejection != "" {
			t.Fatalf("decodeRoutedConnectorResourceRequest routed=%t rejection=%q err=%v", routed, rejection, err)
		}
		if request.AgentID != "agent-1" || request.ConnectorID != "prod-dashboard" ||
			(request.ExpectedResourceID == nil) != (expected == nil) {
			t.Fatalf("decoded request = %#v", request)
		}
	}

	valid := string(connectorResourceRequestBody(t, nil))
	tests := []string{
		strings.Replace(valid, `"usrId":"agent-1"`, `"usrId":"other"`, 1),
		strings.Replace(valid, `"aspId":"agent"`, `"aspId":"qurl"`, 1),
		strings.Replace(valid, `"version":1`, `"version":2`, 1),
		strings.Replace(valid, `"request_nonce":"`, `"request_nonce":"AA`, 1),
		strings.Replace(valid, `"connector_id":"prod-dashboard"`, `"connector_id":"Bad"`, 1),
		strings.Replace(valid, `"usrId":"agent-1"`, `"usrId":"agent-1","usrId":"agent-1"`, 1),
		strings.TrimSuffix(valid, "}") + `,"unknown":true}`,
		valid + ` {}`,
	}
	for index, body := range tests {
		if _, _, _, err := decodeRoutedConnectorResourceRequest([]byte(body), peer); err == nil {
			t.Fatalf("invalid case %d accepted: %s", index, body)
		}
	}
}

func TestConnectorResourceIntentClaimsMalformedExactOperation(t *testing.T) {
	body := []byte(`{"usrData":{"query":"connector_resource"},"aspId":"agent","broken":`)
	if !IsConnectorResourceIntent(body) {
		t.Fatal("exact operation was not conservatively claimed")
	}
	if _, routed, _, err := decodeRoutedConnectorResourceRequest(body, make([]byte, x25519KeyBytes)); !routed || err == nil {
		t.Fatalf("routed=%t err=%v", routed, err)
	}
	ordinary := []byte(`{"usrId":"a1","devId":"a1","aspId":"agent","usrData":{"query":"agent_credential_recovery"}}`)
	if IsConnectorResourceIntent(ordinary) {
		t.Fatal("credential recovery collided with connector resource route")
	}
}

func TestEncodeConnectorResourceErrorsFrozen(t *testing.T) {
	tests := []struct {
		kind  ConnectorResourceError
		retry uint32
		want  string
	}{
		{ConnectorResourceErrorUnavailable, 0, `{"errCode":"52500","errMsg":"connector resource temporarily unavailable"}`},
		{ConnectorResourceErrorUnavailable, 5, `{"errCode":"52500","errMsg":"connector resource temporarily unavailable","retryAfterSeconds":5}`},
		{ConnectorResourceErrorIdentityRejected, 0, `{"errCode":"52501","errMsg":"connector resource identity rejected"}`},
		{ConnectorResourceErrorEntitlementDenied, 0, `{"errCode":"52502","errMsg":"connector resource entitlement denied"}`},
		{ConnectorResourceErrorIdentityConflict, 0, `{"errCode":"52503","errMsg":"connector resource identity conflict"}`},
		{ConnectorResourceErrorQuota, 0, `{"errCode":"52504","errMsg":"connector resource quota exceeded"}`},
		{ConnectorResourceErrorRateLimited, 17, `{"errCode":"52505","errMsg":"connector resource rate limited","retryAfterSeconds":17}`},
		{ConnectorResourceErrorInvalidRequest, 0, connectorResourceInvalidRequestJSON},
	}
	for _, test := range tests {
		body, err := EncodeConnectorResourceError(test.kind, test.retry)
		if err != nil || string(body) != test.want {
			t.Fatalf("kind=%d body=%s err=%v want=%s", test.kind, body, err, test.want)
		}
		if _, err := conformance.ParseConnectorResourceLSTV1ResultBody(body, nil); err != nil {
			t.Fatalf("kind=%d output rejected by pinned conformance: %v", test.kind, err)
		}
	}
	if _, err := EncodeConnectorResourceError(ConnectorResourceErrorRateLimited, 0); err == nil {
		t.Fatal("zero rate-limit retry accepted")
	}
	if _, err := EncodeConnectorResourceError(ConnectorResourceErrorIdentityRejected, 1); err == nil {
		t.Fatal("terminal error accepted retry")
	}
}

func TestConnectorResourceCRIDMustMatchResourceID(t *testing.T) {
	const resourceID = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"
	const matching = "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha"
	const wrongKeyValid = "aeqq3ixwrzh6k32picwqxzdkc4dkzenxwozcpcw2fstb5uug22dn3akqpppq"
	if !validCRIDForResource(matching, resourceID) {
		t.Fatal("matching full CRID rejected")
	}
	if validCRIDForResource(wrongKeyValid, resourceID) {
		t.Fatal("valid CRID for a different resource key accepted")
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	truncated := testConnectorResourceCRID(t, 0x02, der, conformance.CRIDV1TruncatedDigestLength)
	if !validCRIDForResource(truncated, resourceID) {
		t.Fatal("registered truncated CRID rejected")
	}
	unsupported := testConnectorResourceCRID(t, 0x7f, der, conformance.CRIDV1FullDigestLength)
	if validCRIDForResource(unsupported, resourceID) {
		t.Fatal("unsupported CRID version accepted")
	}
}

func TestConnectorResourceKnockResourceIDConformanceBound(t *testing.T) {
	if !validKnockResourceID(strings.Repeat("k", 64)) {
		t.Fatal("64-byte knock_resource_id rejected")
	}
	if validKnockResourceID(strings.Repeat("k", 65)) {
		t.Fatal("65-byte knock_resource_id accepted")
	}
}

func testConnectorResourceCRID(t *testing.T, version byte, der []byte, digestLength int) string {
	t.Helper()
	message := append([]byte(conformance.CRIDV1DomainSeparationPrefix+string(conformance.CRIDV1DomainSeparator)), der...)
	digest := sha256.Sum256(message)
	payload := append([]byte{version}, digest[:digestLength]...)
	checksum := make([]byte, conformance.CRIDV1ChecksumLength)
	binary.BigEndian.PutUint32(checksum, crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli)))
	return base32.NewEncoding(conformance.CRIDV1Alphabet).WithPadding(base32.NoPadding).EncodeToString(append(payload, checksum...))
}

type connectorResourceAuthorityFunc func(context.Context, []byte) ([]byte, error)

func (fn connectorResourceAuthorityFunc) ResolveConnectorResource(ctx context.Context, payload []byte) ([]byte, error) {
	return fn(ctx, payload)
}

func TestConnectorResourceHandlerPrivateBoundary(t *testing.T) {
	resourceID := connectorResourceTestID(t)
	peer := make([]byte, x25519KeyBytes)
	handler, err := NewConnectorResourceHandler(connectorResourceAuthorityFunc(func(_ context.Context, payload []byte) ([]byte, error) {
		text := string(payload)
		if strings.Contains(text, "request_nonce") || !strings.Contains(text, `"cell_request_id":"`) || !strings.Contains(text, `"authenticated_peer_public_key_b64":"`) {
			t.Fatalf("private request = %s", text)
		}
		return []byte(`{"version":1,"result":{"agent_id":"agent-1","connector_id":"prod-dashboard","resource_id":"` + resourceID + `","connector_routing_id":"c-` + strings.Repeat("a", 52) + `","knock_resource_id":"qurl-tunnel-server","found_existing":false}}`), nil
	}), "sandbox")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()
	result, handled := handler.HandleDirect(ctx, connectorResourceRequestBody(t, nil), peer)
	if !handled || result.Classification != ClassificationSuccess || !strings.Contains(string(result.Body), `"errCode":"0"`) || strings.Contains(string(result.Body), "request_nonce") {
		t.Fatalf("handled=%t result=%#v body=%s", handled, result, result.Body)
	}
	request, err := conformance.ParseConnectorResourceLSTV1RequestBody(connectorResourceRequestBody(t, nil), "agent-1")
	if err != nil {
		t.Fatalf("request rejected by pinned conformance: %v", err)
	}
	if _, err := conformance.ParseConnectorResourceLSTV1ResultBody(result.Body, request); err != nil {
		t.Fatalf("success output rejected by pinned conformance: %v", err)
	}
}

func TestConnectorResourceCellRequestIDMatchesConformanceKAT(t *testing.T) {
	peer := "AjPwBu9L7RROoKW7RscGfHwqzsX4zIEfPfWf3NWsdhQ="
	nonce := "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8"
	got, ok := deriveConnectorResourceCellRequestID("sandbox", peer, nonce)
	const want = "57b3dac2005f8c49f56e9b23bda0f5f17f0be91bf5f8e853155f53d0ed9f1e4a"
	if !ok || got != want || len(got) != connectorResourceCellRequestIDHexBytes {
		t.Fatalf("cell_request_id = %q, %t; want %q", got, ok, want)
	}
	peerRaw, err := base64.StdEncoding.Strict().DecodeString(peer)
	if err != nil {
		t.Fatal(err)
	}
	peerRaw[0] ^= 0xff
	otherPeer := base64.StdEncoding.EncodeToString(peerRaw)
	nonceRaw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil {
		t.Fatal(err)
	}
	nonceRaw[0] ^= 0xff
	otherNonce := base64.RawURLEncoding.EncodeToString(nonceRaw)
	for _, scoped := range []struct{ environment, peer, nonce string }{
		{"prod", peer, nonce},
		{"sandbox", otherPeer, nonce},
		{"sandbox", peer, otherNonce},
	} {
		derived, ok := deriveConnectorResourceCellRequestID(scoped.environment, scoped.peer, scoped.nonce)
		if !ok || derived == got {
			t.Fatalf("scope change did not change replay key: %#v -> %q, %t", scoped, derived, ok)
		}
	}
	for _, test := range []struct{ environment, peer, nonce string }{
		{"Sandbox", peer, nonce},
		{"sandbox", base64.StdEncoding.EncodeToString(make([]byte, 31)), nonce},
		{"sandbox", peer, "AA"},
	} {
		if _, ok := deriveConnectorResourceCellRequestID(test.environment, test.peer, test.nonce); ok {
			t.Fatalf("invalid derivation input accepted: %#v", test)
		}
	}
}
