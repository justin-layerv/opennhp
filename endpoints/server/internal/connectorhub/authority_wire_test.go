package connectorhub

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

func TestEncodeAuthorityRequestConformanceGolden(t *testing.T) {
	t.Parallel()
	vectors := authorityVectors(t)
	for _, test := range []struct {
		name      string
		mode      Mode
		operation string
	}{
		{name: "issue", mode: ModeEnroll, operation: conformance.ConnectorAuthorityOperationIssueAssignment},
		{name: "refresh", mode: ModeRefresh, operation: conformance.ConnectorAuthorityOperationRefreshAssignment},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := authorityFixtureRequest(vectors, test.mode)
			got, err := encodeAuthorityRequest(request)
			if err != nil {
				t.Fatalf("encodeAuthorityRequest() error = %v", err)
			}
			want := vectors.Operations[test.operation].RequestGolden.BodyJSON
			if string(got) != want {
				t.Fatalf("private request drift:\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

func TestEncodeAuthorityRequestRejectsContractViolationsWithoutReflection(t *testing.T) {
	t.Parallel()
	vectors := authorityVectors(t)
	secret := vectors.Fixtures.Credential
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "unknown mode", mutate: func(request *Request) { request.Mode = 99 }},
		{name: "invalid agent", mutate: func(request *Request) { request.AgentID = "Agent-secret" }},
		{name: "invalid peer", mutate: func(request *Request) { request.AuthenticatedPeerPublicKeyB64 = "secret" }},
		{name: "invalid request id", mutate: func(request *Request) { request.hubRequestID = strings.Repeat("A", 64) }},
		{name: "invalid credential", mutate: func(request *Request) { request.Credential = "credential-secret" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := authorityFixtureRequest(vectors, ModeEnroll)
			test.mutate(&request)
			_, err := encodeAuthorityRequest(request)
			if !errors.Is(err, ErrInvalidAuthorityRequest) {
				t.Fatalf("error = %v, want ErrInvalidAuthorityRequest", err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "credential-secret") || strings.Contains(err.Error(), "Agent-secret") {
				t.Fatalf("error reflected private request data: %q", err)
			}
		})
	}
}

func TestValidAuthorityAPIKeyAcceptsOnlyClosedCanonicalPrefixes(t *testing.T) {
	t.Parallel()
	live := authorityVectors(t).Fixtures.Credential
	encoded := strings.TrimPrefix(live, "lv_live_")
	for _, value := range []string{live, "lv_test_" + encoded} {
		if !validAuthorityAPIKey(value) {
			t.Fatalf("validAuthorityAPIKey(%q) = false, want true", value[:8])
		}
	}
	if validAuthorityAPIKey("lv_prod_" + encoded) {
		t.Fatal("validAuthorityAPIKey accepted unversioned production prefix")
	}
	const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(base64URLAlphabet, encoded[len(encoded)-1])
	if last < 0 || last&3 != 0 {
		t.Fatalf("fixture has unexpected canonical final sextet %q", encoded[len(encoded)-1])
	}
	nonCanonicalPadBits := encoded[:len(encoded)-1] + string(base64URLAlphabet[last+1])
	if validAuthorityAPIKey("lv_live_" + nonCanonicalPadBits) {
		t.Fatal("validAuthorityAPIKey accepted non-zero trailing pad bits")
	}
}

func TestDecodeAuthorityResponseConformancePublicMappings(t *testing.T) {
	t.Parallel()
	vectors := authorityVectors(t)
	for _, test := range []struct {
		name      string
		mode      Mode
		operation string
	}{
		{name: "issue", mode: ModeEnroll, operation: conformance.ConnectorAuthorityOperationIssueAssignment},
		{name: "refresh", mode: ModeRefresh, operation: conformance.ConnectorAuthorityOperationRefreshAssignment},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := authorityFixtureRequest(vectors, test.mode)
			for _, mapping := range vectors.Operations[test.operation].PublicMappingCases {
				if mapping.MappingSource != conformance.ConnectorAuthorityMappingSourceResponse {
					continue
				}
				t.Run(mapping.Name, func(t *testing.T) {
					t.Parallel()
					body, kind, err := decodeAuthorityResponse(request, []byte(mapping.PrivateResponseBodyJSON))
					if err != nil {
						t.Fatalf("decodeAuthorityResponse() error = %v", err)
					}
					wantKind := authorityResponseSemanticError
					if mapping.PrivateOutcome == "success" {
						wantKind = authorityResponseSuccess
					}
					if kind != wantKind || string(body) != mapping.NHPBodyJSON {
						t.Fatalf("response = kind %v body %s, want kind %v body %s", kind, body, wantKind, mapping.NHPBodyJSON)
					}
				})
			}
		})
	}
}

func TestDecodeAuthorityResponseRejectsAllConformanceProducerRejects(t *testing.T) {
	t.Parallel()
	vectors := authorityVectors(t)
	for _, test := range []struct {
		name      string
		mode      Mode
		operation string
	}{
		{name: "issue", mode: ModeEnroll, operation: conformance.ConnectorAuthorityOperationIssueAssignment},
		{name: "refresh", mode: ModeRefresh, operation: conformance.ConnectorAuthorityOperationRefreshAssignment},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := authorityFixtureRequest(vectors, test.mode)
			for _, reject := range vectors.Operations[test.operation].ResponseProducerRejects {
				t.Run(reject.Name, func(t *testing.T) {
					t.Parallel()
					_, _, err := decodeAuthorityResponse(request, authorityRejectBody(t, reject))
					if !errors.Is(err, ErrInvalidAuthorityResponse) {
						t.Fatalf("error = %v, want ErrInvalidAuthorityResponse", err)
					}
				})
			}
		})
	}
}

func TestDecodeAuthorityResponseRejectsNestedDriftAndCrossAgentResult(t *testing.T) {
	t.Parallel()
	vectors := authorityVectors(t)
	issue := vectors.Operations[conformance.ConnectorAuthorityOperationIssueAssignment].SuccessGolden.BodyJSON
	refresh := vectors.Operations[conformance.ConnectorAuthorityOperationRefreshAssignment].SuccessGolden.BodyJSON
	tests := []struct {
		name    string
		request Request
		body    string
	}{
		{
			name:    "duplicate registration key",
			request: authorityFixtureRequest(vectors, ModeEnroll),
			body:    strings.Replace(issue, `"key_kind":"account"`, `"key_kind":"account","key\u005fkind":"agent"`, 1),
		},
		{
			name:    "unknown endpoint field",
			request: authorityFixtureRequest(vectors, ModeRefresh),
			// The needle must track the conformance vectors' endpoint port, which
			// moved to 443 in v0.11.0. A stale needle matches nothing and silently
			// turns this rejection case into a no-op on a valid body.
			body: strings.Replace(refresh, `"port":443`, `"port":443,"url":"https://forbidden.example"`, 1),
		},
		{
			name:    "cross agent result",
			request: authorityFixtureRequest(vectors, ModeRefresh),
			body:    strings.Replace(refresh, `"agent_id":"agent-conform"`, `"agent_id":"agent-other"`, 1),
		},
		{
			name:    "noncanonical UTC timestamp",
			request: authorityFixtureRequest(vectors, ModeRefresh),
			body:    strings.Replace(refresh, `"2026-07-16T12:00:00Z"`, `"2026-07-16T12:00:00+00:00"`, 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := decodeAuthorityResponse(test.request, []byte(test.body))
			if !errors.Is(err, ErrInvalidAuthorityResponse) {
				t.Fatalf("error = %v, want ErrInvalidAuthorityResponse", err)
			}
			if strings.Contains(err.Error(), "agent-other") || strings.Contains(err.Error(), "forbidden") {
				t.Fatalf("error reflected rejected response: %q", err)
			}
		})
	}
}

func authorityVectors(t *testing.T) *conformance.ConnectorAuthorityLambdaFile {
	t.Helper()
	vectors, err := conformance.ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("load Connector Authority vectors: %v", err)
	}
	return vectors
}

func authorityFixtureRequest(vectors *conformance.ConnectorAuthorityLambdaFile, mode Mode) Request {
	request := Request{
		Mode: mode, AgentID: vectors.Fixtures.AgentID,
		AuthenticatedPeerPublicKeyB64: vectors.Fixtures.AuthenticatedPeerPublicKeyB64,
		hubRequestID:                  vectors.Fixtures.HubRequestID,
	}
	if mode == ModeEnroll {
		request.Credential = vectors.Fixtures.Credential
	}
	return request
}

func authorityRejectBody(t *testing.T, reject conformance.ConnectorAuthorityLambdaRejectCase) []byte {
	t.Helper()
	if reject.DerivedBodyBytes == 0 {
		return []byte(reject.BodyJSON)
	}
	fill, err := hex.DecodeString(reject.BodyFillByteHex)
	if err != nil || len(fill) != 1 {
		t.Fatalf("decode reject fill byte: %v", err)
	}
	return bytes.Repeat(fill, reject.DerivedBodyBytes)
}

func decodedAuthorityPeer(t *testing.T, vectors *conformance.ConnectorAuthorityLambdaFile) []byte {
	t.Helper()
	peer, err := base64.StdEncoding.Strict().DecodeString(vectors.Fixtures.AuthenticatedPeerPublicKeyB64)
	if err != nil {
		t.Fatalf("decode authority peer: %v", err)
	}
	return peer
}
