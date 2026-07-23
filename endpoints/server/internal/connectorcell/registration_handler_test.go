package connectorcell

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

func TestNewRegistrationHandlerRejectsNilAuthority(t *testing.T) {
	t.Parallel()
	if handler, err := NewRegistrationHandler(nil); handler != nil || !errors.Is(err, ErrInvalidHandlerConfiguration) {
		t.Fatalf("NewRegistrationHandler(nil) = %#v, %v", handler, err)
	}
}

func TestRegistrationHandlerConformanceMappings(t *testing.T) {
	t.Parallel()
	assignment := mustAgentAssignment(t)
	authorityVectors := mustConnectorAuthority(t)
	peer := registrationPeer(t, authorityVectors)
	otpBody := authorityCompatibleOTPBody(assignment, authorityVectors)

	for _, operation := range []struct {
		name string
		call func(*testing.T, *RegistrationHandler) RegistrationResult
	}{
		{
			name: conformance.ConnectorAuthorityOperationIssueRegistrationOTP,
			call: func(t *testing.T, handler *RegistrationHandler) RegistrationResult {
				return handler.HandleOTP(liveContext(t), []byte(otpBody), peer, authorityVectors.Fixtures.ObservedSourceAddress)
			},
		},
		{
			name: conformance.ConnectorAuthorityOperationActivateRegistration,
			call: func(t *testing.T, handler *RegistrationHandler) RegistrationResult {
				return handler.HandleRegistration(liveContext(t), []byte(assignment.AssignedCellRegistration.Request.BodyJSON), peer)
			},
		},
		{
			name: conformance.ConnectorAuthorityOperationCompleteRegistration,
			call: func(t *testing.T, handler *RegistrationHandler) RegistrationResult {
				return handler.HandleRegistrationCompletion(liveContext(t), []byte(assignment.RegistrationCompletion.Request.BodyJSON), peer)
			},
		},
	} {
		operation := operation
		for _, mapping := range authorityVectors.Operations[operation.name].PublicMappingCases {
			mapping := mapping
			t.Run(operation.name+"/"+mapping.Name, func(t *testing.T) {
				t.Parallel()
				authority := &fakeRegistrationAuthority{operation: operation.name, response: []byte(mapping.PrivateResponseBodyJSON)}
				result := operation.call(t, mustRegistrationHandler(t, authority))
				wantClass := ClassificationAuthoritySemanticError
				if mapping.PrivateOutcome == "success" {
					wantClass = ClassificationSuccess
				}
				if result.Action != RegistrationAction(mapping.NHPAction) || string(result.Body) != mapping.NHPBodyJSON ||
					result.RecoveryAction != RegistrationRecoveryAction(mapping.RecoveryAction) || result.Classification != wantClass ||
					authority.callCount() != 1 || !authority.buffersCleared() {
					t.Fatalf("result=%#v calls=%d cleared=%v", result, authority.callCount(), authority.buffersCleared())
				}
			})
		}
	}
}

func TestRegistrationHandlerPublicRejectsNeverReachAuthority(t *testing.T) {
	t.Parallel()
	assignment := mustAgentAssignment(t)
	authorityVectors := mustConnectorAuthority(t)
	peer := registrationPeer(t, authorityVectors)

	for _, test := range assignment.AccountCredentialOTP.RequestCases {
		if test.RejectClass == "wrong_phase" {
			continue
		}
		t.Run("otp/"+test.Name, func(t *testing.T) {
			authority := &fakeRegistrationAuthority{}
			result := mustRegistrationHandler(t, authority).HandleOTP(
				liveContext(t), []byte(test.BodyJSON), peer, authorityVectors.Fixtures.ObservedSourceAddress,
			)
			if result.Action != RegistrationActionNoApplicationReply || result.Body != nil ||
				result.Classification != ClassificationRequestRejected || authority.callCount() != 0 {
				t.Fatalf("result=%#v calls=%d", result, authority.callCount())
			}
		})
	}

	for _, test := range assignment.RequestCases {
		test := test
		switch test.Phase {
		case "assigned_cell_registration":
			t.Run("registration/"+test.Name, func(t *testing.T) {
				authority := &fakeRegistrationAuthority{}
				result := mustRegistrationHandler(t, authority).HandleRegistration(liveContext(t), []byte(test.BodyJSON), peer)
				if result.Action != RegistrationActionEmitRAK || string(result.Body) != registrationInvalidRequestRAKJSON ||
					result.Classification != ClassificationRequestRejected || authority.callCount() != 0 {
					t.Fatalf("result=%#v calls=%d", result, authority.callCount())
				}
			})
		case "registration_completion":
			t.Run("completion/"+test.Name, func(t *testing.T) {
				authority := &fakeRegistrationAuthority{}
				result := mustRegistrationHandler(t, authority).HandleRegistrationCompletion(liveContext(t), []byte(test.BodyJSON), peer)
				if result.Action != RegistrationActionEmitLRT || string(result.Body) != registrationCompletionInvalidJSON ||
					result.Classification != ClassificationRequestRejected || authority.callCount() != 0 {
					t.Fatalf("result=%#v calls=%d", result, authority.callCount())
				}
			})
		}
	}
}

func TestRegistrationHandlerPrivateResponseRejectPolicies(t *testing.T) {
	t.Parallel()
	assignment := mustAgentAssignment(t)
	authorityVectors := mustConnectorAuthority(t)
	peer := registrationPeer(t, authorityVectors)
	otpBody := authorityCompatibleOTPBody(assignment, authorityVectors)

	tests := []struct {
		name       string
		operation  string
		request    func(*testing.T, *RegistrationHandler) RegistrationResult
		wantAction RegistrationAction
		wantBody   string
		wantRetry  RegistrationRecoveryAction
	}{
		{
			name: "otp", operation: conformance.ConnectorAuthorityOperationIssueRegistrationOTP,
			request: func(t *testing.T, handler *RegistrationHandler) RegistrationResult {
				return handler.HandleOTP(liveContext(t), []byte(otpBody), peer, authorityVectors.Fixtures.ObservedSourceAddress)
			},
			wantAction: RegistrationActionNoApplicationReply, wantRetry: RegistrationRecoveryNone,
		},
		{
			name: "activation", operation: conformance.ConnectorAuthorityOperationActivateRegistration,
			request: func(t *testing.T, handler *RegistrationHandler) RegistrationResult {
				return handler.HandleRegistration(liveContext(t), []byte(assignment.AssignedCellRegistration.Request.BodyJSON), peer)
			},
			wantAction: RegistrationActionDropNoReply, wantRetry: RegistrationRecoveryPendingExact,
		},
		{
			name: "completion", operation: conformance.ConnectorAuthorityOperationCompleteRegistration,
			request: func(t *testing.T, handler *RegistrationHandler) RegistrationResult {
				return handler.HandleRegistrationCompletion(liveContext(t), []byte(assignment.RegistrationCompletion.Request.BodyJSON), peer)
			},
			wantAction: RegistrationActionEmitLRT, wantBody: registrationCompletionRetryJSON, wantRetry: RegistrationRecoveryNone,
		},
	}
	for _, test := range tests {
		test := test
		for _, reject := range authorityVectors.Operations[test.operation].ResponseProducerRejects {
			reject := reject
			t.Run(test.name+"/"+reject.Name, func(t *testing.T) {
				authority := &fakeRegistrationAuthority{operation: test.operation, response: connectorAuthorityRejectBody(t, reject)}
				result := test.request(t, mustRegistrationHandler(t, authority))
				if result.Action != test.wantAction || string(result.Body) != test.wantBody || result.RecoveryAction != test.wantRetry ||
					result.Classification != ClassificationAuthorityResponseRejected || authority.callCount() != 1 || !authority.buffersCleared() {
					t.Fatalf("result=%#v calls=%d cleared=%v", result, authority.callCount(), authority.buffersCleared())
				}
			})
		}
	}
}

func TestRegistrationHandlerDeadlineAndInvocationPolicies(t *testing.T) {
	t.Parallel()
	assignment := mustAgentAssignment(t)
	authorityVectors := mustConnectorAuthority(t)
	peer := registrationPeer(t, authorityVectors)
	otpBody := authorityCompatibleOTPBody(assignment, authorityVectors)

	tests := []struct {
		name       string
		operation  string
		call       func(context.Context, *RegistrationHandler) RegistrationResult
		wantAction RegistrationAction
		wantBody   string
		wantRetry  RegistrationRecoveryAction
	}{
		{
			name: "otp", operation: conformance.ConnectorAuthorityOperationIssueRegistrationOTP,
			call: func(ctx context.Context, handler *RegistrationHandler) RegistrationResult {
				return handler.HandleOTP(ctx, []byte(otpBody), peer, authorityVectors.Fixtures.ObservedSourceAddress)
			},
			wantAction: RegistrationActionNoApplicationReply, wantRetry: RegistrationRecoveryNone,
		},
		{
			name: "activation", operation: conformance.ConnectorAuthorityOperationActivateRegistration,
			call: func(ctx context.Context, handler *RegistrationHandler) RegistrationResult {
				return handler.HandleRegistration(ctx, []byte(assignment.AssignedCellRegistration.Request.BodyJSON), peer)
			},
			wantAction: RegistrationActionDropNoReply, wantRetry: RegistrationRecoveryPendingExact,
		},
		{
			name: "completion", operation: conformance.ConnectorAuthorityOperationCompleteRegistration,
			call: func(ctx context.Context, handler *RegistrationHandler) RegistrationResult {
				return handler.HandleRegistrationCompletion(ctx, []byte(assignment.RegistrationCompletion.Request.BodyJSON), peer)
			},
			wantAction: RegistrationActionEmitLRT, wantBody: registrationCompletionRetryJSON, wantRetry: RegistrationRecoveryNone,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name+"/deadline", func(t *testing.T) {
			authority := &fakeRegistrationAuthority{}
			result := test.call(context.Background(), mustRegistrationHandler(t, authority))
			if result.Action != test.wantAction || string(result.Body) != test.wantBody || result.RecoveryAction != test.wantRetry ||
				result.Classification != ClassificationDeadlineRejected || authority.callCount() != 0 {
				t.Fatalf("result=%#v calls=%d", result, authority.callCount())
			}
		})
		t.Run(test.name+"/invoke", func(t *testing.T) {
			authority := &fakeRegistrationAuthority{operation: test.operation, err: errors.New("private failure")}
			result := test.call(liveContext(t), mustRegistrationHandler(t, authority))
			if result.Action != test.wantAction || string(result.Body) != test.wantBody || result.RecoveryAction != test.wantRetry ||
				result.Classification != ClassificationAuthorityInvocationFailed || authority.callCount() != 1 || !authority.buffersCleared() {
				t.Fatalf("result=%#v calls=%d cleared=%v", result, authority.callCount(), authority.buffersCleared())
			}
		})
		t.Run(test.name+"/canceled_after_return", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			authority := &fakeRegistrationAuthority{
				operation: test.operation,
				response:  []byte(authorityVectors.Operations[test.operation].SuccessGolden.BodyJSON),
				afterCall: cancel,
			}
			result := test.call(ctx, mustRegistrationHandler(t, authority))
			if result.Action != test.wantAction || string(result.Body) != test.wantBody || result.RecoveryAction != test.wantRetry ||
				result.Classification != ClassificationAuthorityInvocationFailed || authority.callCount() != 1 || !authority.buffersCleared() {
				t.Fatalf("result=%#v calls=%d cleared=%v", result, authority.callCount(), authority.buffersCleared())
			}
		})
	}
}

func TestRegistrationHandlerRejectsMalformedOTPCredentialsWithoutAuthority(t *testing.T) {
	t.Parallel()
	assignment := mustAgentAssignment(t)
	authorityVectors := mustConnectorAuthority(t)
	peer := registrationPeer(t, authorityVectors)
	valid := authorityCompatibleOTPBody(assignment, authorityVectors)
	publicCredential := assignment.AccountCredentialOTP.EnrollmentBinding.RequestCredential
	for _, test := range []struct {
		name       string
		credential string
	}{
		{name: "public opaque credential", credential: publicCredential},
		{name: "wrong prefix", credential: "sk_live_" + authorityVectors.Fixtures.Credential[8:]},
		{name: "wrong length", credential: authorityVectors.Fixtures.Credential + "A"},
		{name: "padded", credential: authorityVectors.Fixtures.Credential + "="},
		{name: "invalid alphabet", credential: authorityVectors.Fixtures.Credential[:len(authorityVectors.Fixtures.Credential)-1] + "!"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := strings.Replace(valid, authorityVectors.Fixtures.Credential, test.credential, 1)
			authority := &fakeRegistrationAuthority{}
			result := mustRegistrationHandler(t, authority).HandleOTP(
				liveContext(t), []byte(body), peer, authorityVectors.Fixtures.ObservedSourceAddress,
			)
			if result.Action != RegistrationActionNoApplicationReply || result.Body != nil ||
				result.Classification != ClassificationRequestRejected || result.RequestRejection != RequestRejectionSemantic ||
				authority.callCount() != 0 {
				t.Fatalf("result=%#v calls=%d", result, authority.callCount())
			}
		})
	}
}

type fakeRegistrationAuthority struct {
	mu        sync.Mutex
	operation string
	response  []byte
	err       error
	payloads  [][]byte
	returned  []byte
	afterCall func()
}

func (f *fakeRegistrationAuthority) IssueRegistrationOTP(_ context.Context, payload []byte) ([]byte, error) {
	return f.invoke(conformance.ConnectorAuthorityOperationIssueRegistrationOTP, payload)
}

func (f *fakeRegistrationAuthority) ActivateRegistration(_ context.Context, payload []byte) ([]byte, error) {
	return f.invoke(conformance.ConnectorAuthorityOperationActivateRegistration, payload)
}

func (f *fakeRegistrationAuthority) CompleteRegistration(_ context.Context, payload []byte) ([]byte, error) {
	return f.invoke(conformance.ConnectorAuthorityOperationCompleteRegistration, payload)
}

func (f *fakeRegistrationAuthority) invoke(operation string, payload []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.operation != "" && f.operation != operation {
		panic("unexpected authority operation: " + operation)
	}
	f.payloads = append(f.payloads, payload)
	f.returned = bytes.Clone(f.response)
	if f.afterCall != nil {
		f.afterCall()
	}
	return f.returned, f.err
}

func (f *fakeRegistrationAuthority) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.payloads)
}

func (f *fakeRegistrationAuthority) buffersCleared() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, payload := range f.payloads {
		if !allZero(payload) {
			return false
		}
	}
	return allZero(f.returned)
}

func allZero(buffer []byte) bool {
	for _, value := range buffer {
		if value != 0 {
			return false
		}
	}
	return true
}

func mustRegistrationHandler(t *testing.T, authority RegistrationAuthority) *RegistrationHandler {
	t.Helper()
	handler, err := NewRegistrationHandler(authority)
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}
	return handler
}
