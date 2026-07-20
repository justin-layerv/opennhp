package connectorhub

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

func TestRecoveryHandlerConformancePublicMappings(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := vectors.PublicExchanges[conformance.AgentCredentialRecoveryHubPhase].RequestBodyJSON
	peer := decodedRecoveryPeer(t, vectors)
	for _, mapping := range vectors.PrivateOperations[conformance.AgentCredentialRecoveryIssueOperation].PublicMappings {
		t.Run(mapping.Name, func(t *testing.T) {
			t.Parallel()
			authority := &fakeHubAuthority{}
			admission := &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}}
			classification := ClassificationAuthoritySemanticError
			requestBody := request
			wantCalls := 0
			switch mapping.MappingSource {
			case "authority_response":
				authority.recoveryResponse = []byte(mapping.PrivateResponseBodyJSON)
				wantCalls = 1
				if mapping.PrivateOutcome == "success" {
					classification = ClassificationSuccess
				}
			case "nhp_preinvoke":
				classification = ClassificationRequestRejected
				switch mapping.Name {
				case "malformed_credential":
					requestBody = strings.Replace(request, vectors.Fixtures.RecoveryCredential, "lv_live_bad", 1)
				case "rate_limited":
					admission.result = AdmissionResult{Decision: AdmissionRateLimited, RetryAfterSeconds: 60}
					classification = ClassificationRateLimited
				default:
					t.Fatalf("unhandled pre-invoke mapping %q", mapping.Name)
				}
			default:
				t.Fatalf("unknown mapping source %q", mapping.MappingSource)
			}

			handler := mustHandler(t, authority, admission)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := handler.HandleAssignment(ctx, []byte(requestBody), peer)
			if result.Classification != classification || string(result.Body) != mapping.NHPBodyJSON {
				t.Fatalf("result = %q %s, want %q %s", result.Classification, result.Body, classification, mapping.NHPBodyJSON)
			}
			if got := authority.recoveryCallCount(); got != wantCalls {
				t.Fatalf("recovery calls = %d, want %d", got, wantCalls)
			}
			if issue, refresh := authority.callCounts(); issue != 0 || refresh != 0 {
				t.Fatalf("wrong authority operation invoked: issue=%d refresh=%d", issue, refresh)
			}
		})
	}
}

func TestRecoveryHandlerRequestRejectsNeverReachAuthority(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	peer := decodedRecoveryPeer(t, vectors)
	wantRecovery, _ := EncodeRecoveryError(RecoveryErrorInvalidRequest)
	wantRefresh, _ := EncodeRefreshError(AssignmentErrorInvalidRequest, nil)
	for _, test := range vectors.RequestRejects {
		if test.Phase != conformance.AgentCredentialRecoveryHubPhase {
			continue
		}
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			authority := &fakeHubAuthority{}
			handler := mustHandler(t, authority, &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := handler.HandleAssignment(ctx, []byte(test.BodyJSON), peer)
			want := wantRecovery
			if test.Name == "reject_hub_request_wrong_mode" {
				want = wantRefresh
			}
			if result.Classification != ClassificationRequestRejected || !bytes.Equal(result.Body, want) {
				t.Fatalf("result = %q %s, want request_rejected %s", result.Classification, result.Body, want)
			}
			if result.RequestRejection != RequestRejection(test.RejectClass) {
				t.Fatalf("rejection = %q, want conformance class %q", result.RequestRejection, test.RejectClass)
			}
			if authority.recoveryCallCount() != 0 {
				t.Fatal("rejected recovery request reached recovery authority")
			}
			if issue, refresh := authority.callCounts(); issue != 0 || refresh != 0 {
				t.Fatalf("rejected recovery request reached assignment authority: %d/%d", issue, refresh)
			}
		})
	}
}

func TestRecoveryHandlerWipesOwnedAuthorityBuffers(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := []byte(vectors.PublicExchanges[conformance.AgentCredentialRecoveryHubPhase].RequestBodyJSON)
	validResponse := []byte(vectors.PrivateOperations[conformance.AgentCredentialRecoveryIssueOperation].SuccessBodyJSON)
	tests := []struct {
		name     string
		response []byte
		err      error
	}{
		{name: "success", response: validResponse},
		{name: "transport error", response: []byte(`{"private":"recovery-secret"}`), err: errors.New("transport")},
		{name: "invalid response", response: []byte(`{"private":"recovery-secret"}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := &retainingRecoveryAuthority{response: bytes.Clone(test.response), err: test.err}
			handler := mustHandler(t, authority, &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := handler.HandleAssignment(ctx, request, decodedRecoveryPeer(t, vectors))
			if len(result.Body) == 0 {
				t.Fatal("handler returned no public body")
			}
			if !allZero(authority.payload) {
				t.Fatalf("owned Authority request was not wiped: %q", authority.payload)
			}
			if !allZero(authority.response) {
				t.Fatalf("owned Authority response was not wiped: %q", authority.response)
			}
		})
	}
}

type retainingRecoveryAuthority struct {
	payload  []byte
	response []byte
	err      error
}

func (a *retainingRecoveryAuthority) IssueAssignment(context.Context, []byte) ([]byte, error) {
	panic("unexpected IssueAssignment")
}

func (a *retainingRecoveryAuthority) RefreshAssignment(context.Context, []byte) ([]byte, error) {
	panic("unexpected RefreshAssignment")
}

func (a *retainingRecoveryAuthority) IssueCredentialRecovery(_ context.Context, payload []byte) ([]byte, error) {
	a.payload = payload
	return a.response, a.err
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func TestRecoveryHandlerFailsClosedWithoutRetry(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := vectors.PublicExchanges[conformance.AgentCredentialRecoveryHubPhase].RequestBodyJSON
	peer := decodedRecoveryPeer(t, vectors)
	want, _ := EncodeRecoveryError(RecoveryErrorUnavailable)
	tests := []struct {
		name           string
		response       []byte
		authorityError error
		classification Classification
	}{
		{name: "transport", authorityError: errors.New("credential-secret"), classification: ClassificationAuthorityInvocationFailed},
		{name: "malformed response", response: []byte(`{"version":1,"error":{"code":"future"}}`), classification: ClassificationAuthorityResponseRejected},
		{name: "empty response", classification: ClassificationAuthorityResponseRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authority := &fakeHubAuthority{recoveryResponse: test.response, recoveryErr: test.authorityError}
			handler := mustHandler(t, authority, &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := handler.HandleAssignment(ctx, []byte(request), peer)
			if result.Classification != test.classification || !bytes.Equal(result.Body, want) || authority.recoveryCallCount() != 1 {
				t.Fatalf("result = %#v calls=%d, want %q %s and one call", result, authority.recoveryCallCount(), test.classification, want)
			}
			if strings.Contains(string(result.Body), "secret") {
				t.Fatal("private failure detail reached public recovery result")
			}
		})
	}
}

func TestRecoveryHandlerRejectsContractDivergentAdmission(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := vectors.PublicExchanges[conformance.AgentCredentialRecoveryHubPhase].RequestBodyJSON
	want, _ := EncodeRecoveryError(RecoveryErrorUnavailable)
	for _, admission := range []AdmissionResult{
		{Decision: AdmissionRegistrationDisabled},
		{Decision: AdmissionRateLimited, RetryAfterSeconds: 59},
		{Decision: AdmissionRateLimited, RetryAfterSeconds: 61},
	} {
		authority := &fakeHubAuthority{}
		handler := mustHandler(t, authority, &fakeAdmissionGate{result: admission})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		result := handler.HandleAssignment(ctx, []byte(request), decodedRecoveryPeer(t, vectors))
		cancel()
		if result.Classification != ClassificationAdmissionUnavailable || !bytes.Equal(result.Body, want) || authority.recoveryCallCount() != 0 {
			t.Fatalf("admission %#v produced %#v", admission, result)
		}
	}
}
