//go:build smoke

package smoke

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

// Capability added in PR #2746.
func TestQurlCreate_ReturnsQV1BootstrapBundle(t *testing.T) {
	if !qurlLinkJSAgentEnabledEnvs[testConfig.Environment] {
		t.Skipf("qurl.link JS agent is not enabled in %q", testConfig.Environment)
	}

	ctx := context.Background()
	minted, err := MintQURL(ctx, t, MintOptions{
		Label:     "qv1-bootstrap-bundle",
		TargetURL: "https://example.com",
		ExpiresIn: "60s",
	})
	if err != nil {
		t.Fatalf("MintQURL: %v", err)
	}
	t.Cleanup(func() {
		DeleteQURL(context.Background(), t, minted.Data.ResourceID)
	})

	bundle, ok := minted.BootstrapBundle()
	if !ok {
		t.Fatalf("qurl_link %q is not a qv1 bootstrap bundle", minted.Data.QURLLink)
	}
	if bundle.Version != 1 {
		t.Fatalf("bundle version = %d, want 1", bundle.Version)
	}
	// minted.AccessToken() decodes the same qv1 fragment bundle holds, so a
	// cross-check here would be tautological; assert the embedded token shape
	// directly instead.
	if !strings.HasPrefix(bundle.AccessToken, "at_") {
		t.Fatalf("bundle access_token = %q, want at_ prefix", bundle.AccessToken)
	}
	if !strings.HasPrefix(bundle.NHPResourceID, "q_") {
		t.Fatalf("bundle nhp_resource_id = %q, want q_ prefix", bundle.NHPResourceID)
	}
	if bundle.AuthServiceID != "qurl" {
		t.Fatalf("bundle auth_service_id = %q, want qurl", bundle.AuthServiceID)
	}
	if !slices.Contains(qurlLinkJSAgentNetworkOrigins[testConfig.Environment], bundle.RelayURL) {
		t.Fatalf("bundle relay_url = %q, want one of %v", bundle.RelayURL, qurlLinkJSAgentNetworkOrigins[testConfig.Environment])
	}

	privateKey := mustDecodeX25519Key(t, bundle.AgentPrivateKeyB64, "agent_private_key_b64")
	publicKey := mustDecodeX25519Key(t, bundle.AgentPublicKeyB64, "agent_public_key_b64")
	_ = mustDecodeX25519Key(t, bundle.ServerPublicKeyB64, "server_public_key_b64")

	derivedPrivateKey, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("derive qURL bundle public key: %v", err)
	}
	if got := derivedPrivateKey.PublicKey().Bytes(); !slices.Equal(got, publicKey) {
		t.Fatalf("agent_public_key_b64 does not match agent_private_key_b64")
	}
}

func mustDecodeX25519Key(t *testing.T, encoded, fieldName string) []byte {
	t.Helper()

	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatalf("%s is not strict std-base64: %v", fieldName, err)
	}
	if len(raw) != 32 {
		t.Fatalf("%s decoded to %d bytes, want 32", fieldName, len(raw))
	}
	return raw
}
