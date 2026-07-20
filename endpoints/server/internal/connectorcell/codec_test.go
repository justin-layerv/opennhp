package connectorcell

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

func TestCompletionGoldenRequestAndPrivateWire(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request, rejection, err := DecodeCompletionRequest(
		[]byte(vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].RequestBodyJSON),
		decodedPeer(t, vectors),
	)
	if err != nil || rejection != "" {
		t.Fatalf("DecodeCompletionRequest = %#v, %q, %v", request, rejection, err)
	}
	if request.AgentID != vectors.Fixtures.AgentID || request.RecoveryGrant != vectors.Fixtures.RecoveryGrant ||
		request.DeviceAPIKey != vectors.Fixtures.DeviceAPIKeyCandidate ||
		request.AuthenticatedPeerPublicKeyB64 != vectors.Fixtures.AuthenticatedPeerPublicKeyB64 {
		t.Fatalf("request drift: %#v", request)
	}
	payload, err := encodeAuthorityRequest(request)
	if err != nil {
		t.Fatalf("encodeAuthorityRequest: %v", err)
	}
	if got, want := string(payload), vectors.PrivateOperations[conformance.AgentCredentialRecoveryCompleteOperation].RequestBodyJSON; got != want {
		t.Fatalf("private request drift:\n got: %s\nwant: %s", got, want)
	}
	assertAuthorityRequestMatchesJSONMarshal(t, request, payload)
}

func TestMaximumAuthorityRequestUsesOneExactBuffer(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := CompletionRequest{
		AgentID:                       "a" + strings.Repeat("-", 62) + "a",
		AuthenticatedPeerPublicKeyB64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, x25519KeyBytes)),
		RecoveryGrant: conformance.AgentCredentialRecoveryGrantPrefix + strings.Repeat(
			"A", conformance.AgentCredentialRecoveryMaxGrantBytes-len(conformance.AgentCredentialRecoveryGrantPrefix)),
		DeviceAPIKey: vectors.Fixtures.DeviceAPIKeyCandidate,
	}
	wantBytes := authorityRequestBytes(request, strconv.Itoa(conformance.ConnectorAuthorityLambdaRequestVersion))
	if wantBytes > conformance.ConnectorAuthorityLambdaMaxRequestBytes {
		t.Fatalf("max recovery request %d exceeds private request ceiling %d", wantBytes, conformance.ConnectorAuthorityLambdaMaxRequestBytes)
	}
	body, err := encodeAuthorityRequest(request)
	if err != nil {
		t.Fatalf("encodeAuthorityRequest: %v", err)
	}
	if len(body) != wantBytes || cap(body) != wantBytes {
		t.Fatalf("body len/cap = %d/%d, want exact single buffer %d", len(body), cap(body), wantBytes)
	}
	assertAuthorityRequestMatchesJSONMarshal(t, request, body)
	clear(body)
}

func TestEncodeAuthorityRequestRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := CompletionRequest{
		AgentID:                       "Agent-invalid",
		AuthenticatedPeerPublicKeyB64: vectors.Fixtures.AuthenticatedPeerPublicKeyB64,
		RecoveryGrant:                 vectors.Fixtures.RecoveryGrant,
		DeviceAPIKey:                  vectors.Fixtures.DeviceAPIKeyCandidate,
	}
	if body, err := encodeAuthorityRequest(request); body != nil || !errors.Is(err, ErrInvalidAuthorityRequest) {
		t.Fatalf("encodeAuthorityRequest = %q, %v; want nil, ErrInvalidAuthorityRequest", body, err)
	}
}

func TestAuthorityRequestConformancePrefixNeedsNoJSONEscaping(t *testing.T) {
	t.Parallel()
	prefix := conformance.AgentCredentialRecoveryGrantPrefix
	if prefix == "" || strings.ContainsAny(prefix, "\"\\<>&") {
		t.Fatalf("recovery-grant prefix %q is not safe for the owned JSON encoder", prefix)
	}
	for _, value := range []byte(prefix) {
		if value < 0x20 || value > 0x7e {
			t.Fatalf("recovery-grant prefix %q contains non-printable JSON input", prefix)
		}
	}
}

func FuzzAuthorityRequestOwnedEncoderMatchesJSONMarshal(f *testing.F) {
	f.Add([]byte("agent"), []byte("peer"), []byte("grant"), []byte("key"), false)
	f.Fuzz(func(t *testing.T, agentSeed, peerSeed, grantSeed, keySeed []byte, testKey bool) {
		const (
			agentAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
			endAlphabet   = "abcdefghijklmnopqrstuvwxyz0123456789"
			grantAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
		)
		agent := make([]byte, 2+len(agentSeed)%63)
		for index := range agent {
			alphabet := agentAlphabet
			if index == 0 || index == len(agent)-1 {
				alphabet = endAlphabet
			}
			agent[index] = seededAlphabetByte(agentSeed, index, alphabet)
		}
		peer := make([]byte, x25519KeyBytes)
		key := make([]byte, deviceAPIKeySecretBytes)
		for index := range peer {
			peer[index] = seededByte(peerSeed, index)
			key[index] = seededByte(keySeed, index)
		}
		grantSuffix := make([]byte, 1+len(grantSeed)%256)
		for index := range grantSuffix {
			grantSuffix[index] = seededAlphabetByte(grantSeed, index, grantAlphabet)
		}
		keyPrefix := "lv_live_"
		if testKey {
			keyPrefix = "lv_test_"
		}
		request := CompletionRequest{
			AgentID:                       string(agent),
			AuthenticatedPeerPublicKeyB64: base64.StdEncoding.EncodeToString(peer),
			RecoveryGrant:                 conformance.AgentCredentialRecoveryGrantPrefix + string(grantSuffix),
			DeviceAPIKey:                  keyPrefix + base64.RawURLEncoding.EncodeToString(key),
		}
		body, err := encodeAuthorityRequest(request)
		if err != nil {
			t.Fatalf("encode valid generated request: %v", err)
		}
		assertAuthorityRequestMatchesJSONMarshal(t, request, body)
		clear(body)
	})
}

func seededAlphabetByte(seed []byte, index int, alphabet string) byte {
	return alphabet[int(seededByte(seed, index))%len(alphabet)]
}

func seededByte(seed []byte, index int) byte {
	if len(seed) == 0 {
		return byte(index * 31)
	}
	return seed[index%len(seed)]
}

func assertAuthorityRequestMatchesJSONMarshal(t *testing.T, request CompletionRequest, got []byte) {
	t.Helper()
	want, err := json.Marshal(struct {
		Version                          int    `json:"version"`
		AuthenticatedPeerPublicKeyBase64 string `json:"authenticated_peer_public_key_b64"`
		AgentID                          string `json:"agent_id"`
		RecoveryGrant                    string `json:"recovery_grant"`
		DeviceAPIKey                     string `json:"device_api_key"`
	}{
		Version:                          conformance.ConnectorAuthorityLambdaRequestVersion,
		AuthenticatedPeerPublicKeyBase64: request.AuthenticatedPeerPublicKeyB64,
		AgentID:                          request.AgentID,
		RecoveryGrant:                    request.RecoveryGrant,
		DeviceAPIKey:                     request.DeviceAPIKey,
	})
	if err != nil {
		t.Fatalf("json.Marshal authority request: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("manual authority request differs from encoding/json:\n got: %s\nwant: %s", got, want)
	}
}

func TestCompletionRequestRejectsMatchConformance(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	for _, test := range vectors.RequestRejects {
		if test.Phase != conformance.AgentCredentialRecoveryCellPhase {
			continue
		}
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			request, rejection, err := DecodeCompletionRequest([]byte(test.BodyJSON), decodedPeer(t, vectors))
			if !errors.Is(err, ErrInvalidCompletionRequest) || request != (CompletionRequest{}) {
				t.Fatalf("DecodeCompletionRequest = %#v, %q, %v", request, rejection, err)
			}
			if string(rejection) != test.RejectClass {
				t.Fatalf("rejection = %q, want %q", rejection, test.RejectClass)
			}
		})
	}
}

func TestCompletionPublicResultsMatchConformance(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	body, err := EncodeCompletionSuccess(vectors.Fixtures.DeviceAPIKeyID)
	if err != nil || string(body) != vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].SuccessBodyJSON {
		t.Fatalf("success = %s, %v", body, err)
	}
	kinds := map[string]CompletionError{
		"52410": CompletionErrorUnavailable,
		"52411": CompletionErrorGrantRejected,
		"52412": CompletionErrorIdentityRejected,
		"52413": CompletionErrorConflict,
		"52414": CompletionErrorInvalidRequest,
	}
	for _, test := range vectors.ErrorCases {
		if test.Phase != conformance.AgentCredentialRecoveryCellPhase {
			continue
		}
		body, err := EncodeCompletionError(kinds[test.ErrCode])
		if err != nil || string(body) != test.BodyJSON {
			t.Fatalf("%s = %s, %v; want %s", test.Name, body, err, test.BodyJSON)
		}
	}
	if body, err := EncodeCompletionError(0); body != nil || !errors.Is(err, ErrInvalidCompletionError) {
		t.Fatalf("unknown error = %q, %v", body, err)
	}
}

func TestCompletionAuthorityResponseFailsClosed(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"version":1,"error":{"code":"unavailable","retry_after_seconds":5}}`,
		`{"version":1,"result":{"device_api_key_id":"key_RcV8mP3qTn5W"},"error":{"code":"unavailable"}}`,
		`{"version":1,"result":{"device_api_key_id":"key_RcV8mP3qTn5W","device_api_key":"secret"}}`,
		`{"version":1,"result":{"device_api_key_id":"key_bad"}}`,
		`{"version":2,"error":{"code":"unavailable"}}`,
		`{"version":1,"error":{"code":"unavailable"}} trailing`,
	} {
		if public, _, err := decodeAuthorityResponse([]byte(body)); public != nil || !errors.Is(err, ErrInvalidAuthorityResponse) {
			t.Fatalf("decodeAuthorityResponse(%s) = %q, %v", body, public, err)
		}
	}
}

func TestCompletionCodecRejectsBoundaryDrift(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	valid := vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].RequestBodyJSON
	tests := []struct {
		name string
		body []byte
		peer []byte
		err  error
		kind RequestRejection
	}{
		{name: "peer", body: []byte(valid), peer: make([]byte, 31), err: ErrInvalidAuthenticatedPeer, kind: RequestRejectionPeer},
		{name: "oversize", body: make([]byte, conformance.AgentCredentialRecoveryMaxBodyBytes+1), peer: decodedPeer(t, vectors), err: ErrCompletionRequestTooLarge, kind: RequestRejectionBodySize},
		{name: "trailing", body: []byte(valid + `{}`), peer: decodedPeer(t, vectors), err: ErrInvalidCompletionRequest, kind: RequestRejectionBodyParse},
		{name: "padded key", body: []byte(strings.Replace(valid, vectors.Fixtures.DeviceAPIKeyCandidate, vectors.Fixtures.DeviceAPIKeyCandidate+"=", 1)), peer: decodedPeer(t, vectors), err: ErrInvalidCompletionRequest, kind: RequestRejectionSemantic},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, rejection, err := DecodeCompletionRequest(test.body, test.peer)
			if request != (CompletionRequest{}) || rejection != test.kind || !errors.Is(err, test.err) {
				t.Fatalf("result = %#v, %q, %v", request, rejection, err)
			}
		})
	}
	if body, err := EncodeCompletionSuccess("key_bad"); body != nil || !errors.Is(err, ErrInvalidCompletionSuccess) {
		t.Fatalf("invalid success = %q, %v", body, err)
	}
	testKeyRequest := strings.Replace(valid, "lv_live_", "lv_test_", 1)
	if _, _, err := DecodeCompletionRequest([]byte(testKeyRequest), decodedPeer(t, vectors)); err != nil {
		t.Fatalf("canonical test-environment candidate rejected: %v", err)
	}
}

func TestValidAgentIDLocksConformanceBounds(t *testing.T) {
	t.Parallel()
	// qurl-conformance v0.9.0 encodes the agent-id contract ONLY as the
	// unexported var connectorAuthorityAgentIDPattern
	// (`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`); it exposes no agent-id
	// min/max/alphabet constant to assert the local bound against. Lock the
	// literal [2,64]-length + lowercase-alphanumeric-ends /
	// lowercase-alphanumeric-or-hyphen-middle intent so an upstream bounds
	// change is caught by more than the single golden fixture exercised in
	// TestCompletionGoldenRequestAndPrivateWire.
	const minLen, maxLen = 2, 64
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{"below-min-length", strings.Repeat("a", minLen-1), false},             // 1 byte
		{"at-min-length", strings.Repeat("a", minLen), true},                   // 2 bytes
		{"at-max-length", "a" + strings.Repeat("-", maxLen-2) + "a", true},     // 64 bytes
		{"above-max-length", "a" + strings.Repeat("-", maxLen-1) + "a", false}, // 65 bytes
		{"typical-valid", "agent-01", true},
		{"uppercase-start-rejected", "Agent1", false},
		{"underscore-middle-rejected", "a_b", false},
		{"hyphen-end-rejected", "a-", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validAgentID(test.id); got != test.want {
				t.Fatalf("validAgentID(%q) [len %d] = %v, want %v", test.id, len(test.id), got, test.want)
			}
		})
	}
}

func TestDeviceAPIKeySecretBytesMatchesConformanceCandidate(t *testing.T) {
	t.Parallel()
	// qurl-conformance validates the device-key candidate with the unexported
	// isConnectorAuthorityAPIKey (51-byte total, 32-byte secret) and keeps its
	// agentAssignmentDeviceKeySecretBytes = 32 unexported, so no secret-length
	// constant is importable. Derive the expected secret length from the golden
	// DeviceAPIKeyCandidate itself and pin deviceAPIKeySecretBytes to it, making
	// validAPIKey's currently-emergent 32-byte guard explicit rather than a
	// second hardcoded 32.
	candidate := recoveryVectors(t).Fixtures.DeviceAPIKeyCandidate
	if !strings.HasPrefix(candidate, "lv_live_") && !strings.HasPrefix(candidate, "lv_test_") {
		t.Fatalf("conformance DeviceAPIKeyCandidate %q lacks the expected lv_live_/lv_test_ prefix", candidate)
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(candidate[len("lv_live_"):])
	if err != nil {
		t.Fatalf("decode conformance DeviceAPIKeyCandidate secret from %q: %v", candidate, err)
	}
	if len(secret) != deviceAPIKeySecretBytes {
		t.Fatalf("deviceAPIKeySecretBytes = %d, but conformance DeviceAPIKeyCandidate secret decodes to %d bytes", deviceAPIKeySecretBytes, len(secret))
	}
}

func recoveryVectors(t *testing.T) *conformance.AgentCredentialRecoveryFile {
	t.Helper()
	vectors, err := conformance.AgentCredentialRecovery()
	if err != nil {
		t.Fatalf("AgentCredentialRecovery: %v", err)
	}
	return vectors
}

func decodedPeer(t *testing.T, vectors *conformance.AgentCredentialRecoveryFile) []byte {
	t.Helper()
	peer, err := base64.StdEncoding.Strict().DecodeString(vectors.Fixtures.AuthenticatedPeerPublicKeyB64)
	if err != nil {
		t.Fatalf("decode peer: %v", err)
	}
	return peer
}
