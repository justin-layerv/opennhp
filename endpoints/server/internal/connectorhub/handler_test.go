package connectorhub

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

func TestHandlerConformancePublicMappings(t *testing.T) {
	t.Parallel()
	authorityContract := authorityVectors(t)
	assignmentContract := assignmentVectors(t)

	for _, operation := range []struct {
		name       string
		contractID string
		mode       Mode
		request    string
	}{
		{
			name: "issue", contractID: conformance.ConnectorAuthorityOperationIssueAssignment, mode: ModeEnroll,
			request: strings.Replace(assignmentContract.InitialAssignment.Request.BodyJSON,
				conformance.AgentAssignmentBootstrapCredentialFixture, authorityContract.Fixtures.Credential, 1),
		},
		{
			name: "refresh", contractID: conformance.ConnectorAuthorityOperationRefreshAssignment, mode: ModeRefresh,
			request: assignmentContract.RefreshAssignment.Request.BodyJSON,
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()
			for _, mapping := range authorityContract.Operations[operation.contractID].PublicMappingCases {
				t.Run(mapping.Name, func(t *testing.T) {
					t.Parallel()
					authority := &fakeHubAuthority{}
					admission := &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}}
					classification := ClassificationAuthoritySemanticError
					if mapping.MappingSource == conformance.ConnectorAuthorityMappingSourceResponse {
						if operation.mode == ModeEnroll {
							authority.issueResponse = []byte(mapping.PrivateResponseBodyJSON)
						} else {
							authority.refreshResponse = []byte(mapping.PrivateResponseBodyJSON)
						}
						if mapping.PrivateOutcome == "success" {
							classification = ClassificationSuccess
						}
					} else {
						switch mapping.Name {
						case "registration_disabled":
							admission.result = AdmissionResult{Decision: AdmissionRegistrationDisabled}
							classification = ClassificationRegistrationDisabled
						case "assignment_rate_limited":
							admission.result = AdmissionResult{Decision: AdmissionRateLimited, RetryAfterSeconds: 60}
							classification = ClassificationRateLimited
						default:
							t.Fatalf("unhandled pre-invoke mapping %q", mapping.Name)
						}
					}

					handler, err := NewHandler(testHubEnvironment, authority, admission)
					if err != nil {
						t.Fatalf("NewHandler() error = %v", err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					result := handler.HandleAssignment(ctx, []byte(operation.request), decodedAuthorityPeer(t, authorityContract))
					if result.Classification != classification || string(result.Body) != mapping.NHPBodyJSON {
						t.Fatalf("result = %q %s, want %q %s", result.Classification, result.Body, classification, mapping.NHPBodyJSON)
					}

					issueCalls, refreshCalls := authority.callCounts()
					wantCalls := 0
					if mapping.MappingSource == conformance.ConnectorAuthorityMappingSourceResponse {
						wantCalls = 1
					}
					if operation.mode == ModeEnroll && (issueCalls != wantCalls || refreshCalls != 0) {
						t.Fatalf("authority calls issue/refresh = %d/%d, want %d/0", issueCalls, refreshCalls, wantCalls)
					}
					if operation.mode == ModeRefresh && (issueCalls != 0 || refreshCalls != wantCalls) {
						t.Fatalf("authority calls issue/refresh = %d/%d, want 0/%d", issueCalls, refreshCalls, wantCalls)
					}
				})
			}
		})
	}
}

func TestHandlerSendsExactDerivedOperationRequestOnce(t *testing.T) {
	t.Parallel()
	authorityContract := authorityVectors(t)
	assignmentContract := assignmentVectors(t)
	for _, test := range []struct {
		name     string
		mode     Mode
		request  string
		response string
	}{
		{
			name: "issue", mode: ModeEnroll,
			request: strings.Replace(assignmentContract.InitialAssignment.Request.BodyJSON,
				conformance.AgentAssignmentBootstrapCredentialFixture, authorityContract.Fixtures.Credential, 1),
			response: authorityContract.Operations[conformance.ConnectorAuthorityOperationIssueAssignment].SuccessGolden.BodyJSON,
		},
		{
			name: "refresh", mode: ModeRefresh, request: assignmentContract.RefreshAssignment.Request.BodyJSON,
			response: authorityContract.Operations[conformance.ConnectorAuthorityOperationRefreshAssignment].SuccessGolden.BodyJSON,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			peer := decodedAuthorityPeer(t, authorityContract)
			decoded, err := DecodeAssignmentRequest(testHubEnvironment, []byte(test.request), peer)
			if err != nil {
				t.Fatalf("DecodeAssignmentRequest() error = %v", err)
			}
			wantPayload, err := encodeAuthorityRequest(decoded)
			if err != nil {
				t.Fatalf("encodeAuthorityRequest() error = %v", err)
			}

			authority := &fakeHubAuthority{issueResponse: []byte(test.response), refreshResponse: []byte(test.response)}
			handler := mustHandler(t, authority, &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := handler.HandleAssignment(ctx, []byte(test.request), peer)
			if result.Classification != ClassificationSuccess {
				t.Fatalf("classification = %q, want success", result.Classification)
			}
			issuePayloads, refreshPayloads := authority.payloadCopies()
			gotPayloads := issuePayloads
			if test.mode == ModeRefresh {
				gotPayloads = refreshPayloads
			}
			if len(gotPayloads) != 1 || !bytes.Equal(gotPayloads[0], wantPayload) {
				t.Fatalf("authority payloads = %q, want one exact %q", gotPayloads, wantPayload)
			}
			if test.mode == ModeEnroll && len(refreshPayloads) != 0 || test.mode == ModeRefresh && len(issuePayloads) != 0 {
				t.Fatal("handler invoked the wrong separately-permissioned operation")
			}
		})
	}
}

func TestAssignmentHandlerWipesOwnedAuthorityBuffers(t *testing.T) {
	t.Parallel()
	authorityContract := authorityVectors(t)
	assignmentContract := assignmentVectors(t)
	for _, test := range []struct {
		name     string
		mode     Mode
		request  string
		response string
	}{
		{
			name: "issue", mode: ModeEnroll,
			request: strings.Replace(assignmentContract.InitialAssignment.Request.BodyJSON,
				conformance.AgentAssignmentBootstrapCredentialFixture, authorityContract.Fixtures.Credential, 1),
			response: authorityContract.Operations[conformance.ConnectorAuthorityOperationIssueAssignment].SuccessGolden.BodyJSON,
		},
		{
			name: "refresh", mode: ModeRefresh, request: assignmentContract.RefreshAssignment.Request.BodyJSON,
			response: authorityContract.Operations[conformance.ConnectorAuthorityOperationRefreshAssignment].SuccessGolden.BodyJSON,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authority := &retainingAssignmentAuthority{mode: test.mode, response: []byte(test.response)}
			handler := mustHandler(t, authority, &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := handler.HandleAssignment(ctx, []byte(test.request), decodedAuthorityPeer(t, authorityContract))
			if result.Classification != ClassificationSuccess {
				t.Fatalf("classification = %q, want success", result.Classification)
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

func TestHandlerFailsClosedWithoutRetry(t *testing.T) {
	t.Parallel()
	authorityContract := authorityVectors(t)
	assignmentContract := assignmentVectors(t)
	request := assignmentContract.RefreshAssignment.Request.BodyJSON
	wantUnavailable, err := EncodeRefreshError(AssignmentErrorUnavailable, nil)
	if err != nil {
		t.Fatalf("encode unavailable: %v", err)
	}

	tests := []struct {
		name           string
		response       []byte
		authorityError error
		classification Classification
	}{
		{name: "transport", authorityError: errors.New("sdk payload secret"), classification: ClassificationAuthorityInvocationFailed},
		{name: "malformed response", response: []byte(`{"version":1,"error":{"code":"future-secret"}}`), classification: ClassificationAuthorityResponseRejected},
		{name: "empty response", classification: ClassificationAuthorityResponseRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authority := &fakeHubAuthority{refreshResponse: test.response, refreshErr: test.authorityError}
			handler := mustHandler(t, authority, &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := handler.HandleAssignment(ctx, []byte(request), decodedAuthorityPeer(t, authorityContract))
			if result.Classification != test.classification || !bytes.Equal(result.Body, wantUnavailable) {
				t.Fatalf("result = %q %s, want %q %s", result.Classification, result.Body, test.classification, wantUnavailable)
			}
			issueCalls, refreshCalls := authority.callCounts()
			if issueCalls != 0 || refreshCalls != 1 {
				t.Fatalf("authority calls = %d/%d, want 0/1 without retry", issueCalls, refreshCalls)
			}
			if strings.Contains(string(result.Body), "secret") || strings.Contains(string(result.Classification), "secret") {
				t.Fatalf("public result reflected private failure: %#v", result)
			}
		})
	}
}

func TestHandlerRejectsInvalidInputAndDeadlineBeforeAuthority(t *testing.T) {
	t.Parallel()
	authorityContract := authorityVectors(t)
	assignmentContract := assignmentVectors(t)
	peer := decodedAuthorityPeer(t, authorityContract)
	wantInvalid, _ := EncodeRefreshError(AssignmentErrorInvalidRequest, nil)
	wantEnrollInvalid, _ := EncodeEnrollError(EnrollErrorInvalidAssignmentRequest, nil)
	if !bytes.Equal(wantEnrollInvalid, wantInvalid) {
		t.Fatalf("enroll invalid-request body = %s, want shared 52205 body %s", wantEnrollInvalid, wantInvalid)
	}
	wantUnavailable, _ := EncodeRefreshError(AssignmentErrorUnavailable, nil)

	tests := []struct {
		name           string
		ctx            func() (context.Context, context.CancelFunc)
		request        string
		wantBody       []byte
		classification Classification
		rejection      RequestRejection
		wantAdmissions int
	}{
		{
			name: "malformed request", ctx: liveTestContext, request: `{}`,
			wantBody: wantInvalid, classification: ClassificationRequestRejected, rejection: RequestRejectionMissingField,
		},
		{
			name: "malformed identifiable enroll keeps shared 52205 wire", ctx: liveTestContext,
			request:  `{"usrId":"","devId":"agent-conform","aspId":"agent","usrData":{"query":"cell_assignment","version":1,"mode":"enroll","credential":"opaque"}}`,
			wantBody: wantEnrollInvalid, classification: ClassificationRequestRejected, rejection: RequestRejectionMissingField,
		},
		{
			name: "missing deadline", ctx: func() (context.Context, context.CancelFunc) { return context.Background(), func() {} },
			request:  assignmentContract.RefreshAssignment.Request.BodyJSON,
			wantBody: wantUnavailable, classification: ClassificationDeadlineRejected,
		},
		{
			name: "expired deadline", ctx: expiredTestContext, request: assignmentContract.RefreshAssignment.Request.BodyJSON,
			wantBody: wantUnavailable, classification: ClassificationDeadlineRejected,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authority := &fakeHubAuthority{}
			admission := &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}}
			handler := mustHandler(t, authority, admission)
			ctx, cancel := test.ctx()
			defer cancel()
			result := handler.HandleAssignment(ctx, []byte(test.request), peer)
			if result.Classification != test.classification || result.RequestRejection != test.rejection || !bytes.Equal(result.Body, test.wantBody) {
				t.Fatalf("result = %q/%q %s, want %q/%q %s", result.Classification, result.RequestRejection, result.Body, test.classification, test.rejection, test.wantBody)
			}
			if issue, refresh := authority.callCounts(); issue != 0 || refresh != 0 {
				t.Fatalf("authority called before validation: %d/%d", issue, refresh)
			}
			if got := admission.callCount(); got != test.wantAdmissions {
				t.Fatalf("admission calls = %d, want %d", got, test.wantAdmissions)
			}
		})
	}
}

func TestHandlerRejectsNoncanonicalEnrollCredentialBeforeAuthority(t *testing.T) {
	t.Parallel()
	authorityContract := authorityVectors(t)
	assignmentContract := assignmentVectors(t)
	// The public assignment artifact deliberately treats its conspicuous
	// conformance credential as opaque transport data; it does not satisfy the
	// stricter private Authority API-key grammar. Never add a production bypass
	// for that synthetic value: cross-boundary success tests substitute the
	// private artifact's canonical credential, while this test pins fail-closed
	// behavior for the unchanged public fixture.
	authority := &fakeHubAuthority{}
	admission := &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}}
	handler := mustHandler(t, authority, admission)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := handler.HandleAssignment(ctx, []byte(assignmentContract.InitialAssignment.Request.BodyJSON), decodedAuthorityPeer(t, authorityContract))
	want, _ := EncodeEnrollError(EnrollErrorInvalidInput, nil)
	if result.Classification != ClassificationRequestRejected || result.RequestRejection != RequestRejectionSemantic || !bytes.Equal(result.Body, want) {
		t.Fatalf("result = %q %s, want request rejection %s", result.Classification, result.Body, want)
	}
	if issue, refresh := authority.callCounts(); issue != 0 || refresh != 0 {
		t.Fatalf("authority received noncanonical credential: %d/%d", issue, refresh)
	}
}

func TestHandlerDeadlineExpiringDuringAdmissionStopsBeforeAuthority(t *testing.T) {
	t.Parallel()
	authorityContract := authorityVectors(t)
	request := assignmentVectors(t).RefreshAssignment.Request.BodyJSON
	authority := &fakeHubAuthority{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	admission := &fakeAdmissionGate{
		result: AdmissionResult{Decision: AdmissionAllow},
		after:  cancel,
	}
	handler := mustHandler(t, authority, admission)

	result := handler.HandleAssignment(ctx, []byte(request), decodedAuthorityPeer(t, authorityContract))
	want, _ := EncodeRefreshError(AssignmentErrorUnavailable, nil)
	if result.Classification != ClassificationDeadlineRejected || !bytes.Equal(result.Body, want) {
		t.Fatalf("result = %q %s, want deadline rejection %s", result.Classification, result.Body, want)
	}
	if got := admission.callCount(); got != 1 {
		t.Fatalf("admission calls = %d, want 1", got)
	}
	if issue, refresh := authority.callCounts(); issue != 0 || refresh != 0 {
		t.Fatalf("authority called after admission exhausted deadline: %d/%d", issue, refresh)
	}
}

func TestHandlerInvalidAdmissionDecisionsFailClosed(t *testing.T) {
	t.Parallel()
	authorityContract := authorityVectors(t)
	request := assignmentVectors(t).RefreshAssignment.Request.BodyJSON
	want, _ := EncodeRefreshError(AssignmentErrorUnavailable, nil)
	tests := []AdmissionResult{
		{},
		{Decision: AdmissionAllow, RetryAfterSeconds: 1},
		{Decision: AdmissionRegistrationDisabled},
		{Decision: AdmissionRateLimited},
		{Decision: AdmissionUnavailable, RetryAfterSeconds: 1},
	}
	for index, admissionResult := range tests {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			t.Parallel()
			authority := &fakeHubAuthority{}
			handler := mustHandler(t, authority, &fakeAdmissionGate{result: admissionResult})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := handler.HandleAssignment(ctx, []byte(request), decodedAuthorityPeer(t, authorityContract))
			if result.Classification != ClassificationAdmissionUnavailable || !bytes.Equal(result.Body, want) {
				t.Fatalf("result = %q %s, want admission unavailable %s", result.Classification, result.Body, want)
			}
			if issue, refresh := authority.callCounts(); issue != 0 || refresh != 0 {
				t.Fatalf("authority called after invalid admission: %d/%d", issue, refresh)
			}
		})
	}
}

func TestHandlerConstructorAndAdmissionSurfaceFailClosed(t *testing.T) {
	t.Parallel()
	authority := &fakeHubAuthority{}
	admission := &fakeAdmissionGate{}
	for _, test := range []struct {
		name        string
		environment string
		authority   HubAuthority
		admission   AdmissionGate
	}{
		{name: "invalid environment", environment: "Production-secret", authority: authority, admission: admission},
		{name: "missing authority", environment: testHubEnvironment, admission: admission},
		{name: "missing admission", environment: testHubEnvironment, authority: authority},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewHandler(test.environment, test.authority, test.admission)
			if !errors.Is(err, ErrInvalidHandlerConfiguration) || strings.Contains(err.Error(), test.environment) {
				t.Fatalf("error = %v, want opaque ErrInvalidHandlerConfiguration", err)
			}
		})
	}

	typeOfAdmission := reflect.TypeOf(AdmissionRequest{})
	for index := range typeOfAdmission.NumField() {
		name := strings.ToLower(typeOfAdmission.Field(index).Name)
		if strings.Contains(name, "credential") || strings.Contains(name, "agent") || strings.Contains(name, "raw") {
			t.Fatalf("admission surface unexpectedly retains %q", typeOfAdmission.Field(index).Name)
		}
	}
}

func TestClassifiedBodyInternalFailureIsNotTransmittable(t *testing.T) {
	t.Parallel()
	result := classifiedBody([]byte("must-not-survive"), errors.New("encode failure"), ClassificationSuccess)
	if result.Classification != ClassificationInternalFailure || result.Body != nil || result.RequestRejection != "" {
		t.Fatalf("result = %#v, want bodyless internal failure", result)
	}
}

func mustHandler(t *testing.T, authority HubAuthority, admission AdmissionGate) *Handler {
	t.Helper()
	handler, err := NewHandler(testHubEnvironment, authority, admission)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func liveTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second)
}

func expiredTestContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	return ctx, cancel
}

type fakeAdmissionGate struct {
	mu     sync.Mutex
	result AdmissionResult
	calls  []AdmissionRequest
	after  func()
}

func (f *fakeAdmissionGate) AdmitAssignment(_ context.Context, request AdmissionRequest) AdmissionResult {
	f.mu.Lock()
	f.calls = append(f.calls, request)
	result, after := f.result, f.after
	f.mu.Unlock()
	if after != nil {
		after()
	}
	return result
}

func (f *fakeAdmissionGate) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type fakeHubAuthority struct {
	mu sync.Mutex

	issueResponse    []byte
	refreshResponse  []byte
	recoveryResponse []byte
	issueErr         error
	refreshErr       error
	recoveryErr      error
	issuePayloads    [][]byte
	refreshPayloads  [][]byte
	recoveryPayloads [][]byte
}

type retainingAssignmentAuthority struct {
	mode     Mode
	payload  []byte
	response []byte
}

func (a *retainingAssignmentAuthority) IssueAssignment(_ context.Context, payload []byte) ([]byte, error) {
	if a.mode != ModeEnroll {
		panic("unexpected IssueAssignment")
	}
	a.payload = payload
	return a.response, nil
}

func (a *retainingAssignmentAuthority) RefreshAssignment(_ context.Context, payload []byte) ([]byte, error) {
	if a.mode != ModeRefresh {
		panic("unexpected RefreshAssignment")
	}
	a.payload = payload
	return a.response, nil
}

func (a *retainingAssignmentAuthority) IssueCredentialRecovery(context.Context, []byte) ([]byte, error) {
	panic("unexpected IssueCredentialRecovery")
}

func (f *fakeHubAuthority) IssueAssignment(_ context.Context, payload []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issuePayloads = append(f.issuePayloads, bytes.Clone(payload))
	return bytes.Clone(f.issueResponse), f.issueErr
}

func (f *fakeHubAuthority) RefreshAssignment(_ context.Context, payload []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshPayloads = append(f.refreshPayloads, bytes.Clone(payload))
	return bytes.Clone(f.refreshResponse), f.refreshErr
}

func (f *fakeHubAuthority) IssueCredentialRecovery(_ context.Context, payload []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recoveryPayloads = append(f.recoveryPayloads, bytes.Clone(payload))
	return bytes.Clone(f.recoveryResponse), f.recoveryErr
}

func (f *fakeHubAuthority) recoveryCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.recoveryPayloads)
}

func (f *fakeHubAuthority) callCounts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.issuePayloads), len(f.refreshPayloads)
}

func (f *fakeHubAuthority) payloadCopies() ([][]byte, [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return clonePayloads(f.issuePayloads), clonePayloads(f.refreshPayloads)
}

func clonePayloads(payloads [][]byte) [][]byte {
	cloned := make([][]byte, len(payloads))
	for index := range payloads {
		cloned[index] = bytes.Clone(payloads[index])
	}
	return cloned
}
