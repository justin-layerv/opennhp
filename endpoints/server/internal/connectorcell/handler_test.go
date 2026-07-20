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

func TestNewHandlerRejectsNilAuthority(t *testing.T) {
	t.Parallel()
	if handler, err := NewHandler(nil); handler != nil || !errors.Is(err, ErrInvalidHandlerConfiguration) {
		t.Fatalf("NewHandler(nil) = %#v, %v", handler, err)
	}
}

func TestCompletionHandlerConformanceMappings(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].RequestBodyJSON
	for _, mapping := range vectors.PrivateOperations[conformance.AgentCredentialRecoveryCompleteOperation].PublicMappings {
		t.Run(mapping.Name, func(t *testing.T) {
			t.Parallel()
			authority := &fakeAuthority{}
			requestBody := request
			wantCalls := 1
			wantClass := ClassificationAuthoritySemanticError
			switch mapping.MappingSource {
			case "authority_response":
				authority.response = []byte(mapping.PrivateResponseBodyJSON)
				if mapping.PrivateOutcome == "success" {
					wantClass = ClassificationSuccess
				}
			case "nhp_preinvoke":
				requestBody = strings.Replace(request, vectors.Fixtures.DeviceAPIKeyCandidate, "lv_live_bad", 1)
				wantCalls = 0
				wantClass = ClassificationRequestRejected
			default:
				t.Fatalf("unknown mapping source %q", mapping.MappingSource)
			}
			handler := mustHandler(t, authority)
			result := handler.HandleCompletion(liveContext(t), []byte(requestBody), decodedPeer(t, vectors))
			// Body is checked after HandleCompletion's deferred response wipe, so
			// the success body cannot alias Authority response storage.
			if result.Classification != wantClass || string(result.Body) != mapping.NHPBodyJSON || authority.callCount() != wantCalls || !authority.buffersCleared() {
				t.Fatalf("result = %#v calls=%d; want %q %s calls=%d", result, authority.callCount(), wantClass, mapping.NHPBodyJSON, wantCalls)
			}
		})
	}
}

func TestCompletionHandlerRejectsNeverReachAuthority(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	want, _ := EncodeCompletionError(CompletionErrorInvalidRequest)
	for _, test := range vectors.RequestRejects {
		if test.Phase != conformance.AgentCredentialRecoveryCellPhase {
			continue
		}
		t.Run(test.Name, func(t *testing.T) {
			authority := &fakeAuthority{}
			result := mustHandler(t, authority).HandleCompletion(liveContext(t), []byte(test.BodyJSON), decodedPeer(t, vectors))
			if result.Classification != ClassificationRequestRejected || !bytes.Equal(result.Body, want) || authority.callCount() != 0 {
				t.Fatalf("result = %#v calls=%d", result, authority.callCount())
			}
		})
	}
}

func TestCompletionHandlerFailsClosedWithoutSecretReflection(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].RequestBodyJSON
	want, _ := EncodeCompletionError(CompletionErrorUnavailable)
	tests := []struct {
		name     string
		response []byte
		err      error
		class    Classification
	}{
		{name: "invoke", err: errors.New("private-secret"), class: ClassificationAuthorityInvocationFailed},
		{name: "future error", response: []byte(`{"version":1,"error":{"code":"future"}}`), class: ClassificationAuthorityResponseRejected},
		{name: "secret echo", response: []byte(`{"version":1,"result":{"device_api_key_id":"key_RcV8mP3qTn5W","device_api_key":"secret"}}`), class: ClassificationAuthorityResponseRejected},
		{name: "empty", class: ClassificationAuthorityResponseRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := &fakeAuthority{response: test.response, err: test.err}
			result := mustHandler(t, authority).HandleCompletion(liveContext(t), []byte(request), decodedPeer(t, vectors))
			if result.Classification != test.class || !bytes.Equal(result.Body, want) || authority.callCount() != 1 ||
				strings.Contains(string(result.Body), "secret") || !authority.buffersCleared() {
				t.Fatalf("result = %#v calls=%d", result, authority.callCount())
			}
		})
	}
}

func TestCompletionHandlerRejectsResponseHiddenByCallerCancellation(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].RequestBodyJSON
	var response string
	for _, mapping := range vectors.PrivateOperations[conformance.AgentCredentialRecoveryCompleteOperation].PublicMappings {
		if mapping.PrivateOutcome == "success" {
			response = mapping.PrivateResponseBodyJSON
			break
		}
	}
	if response == "" {
		t.Fatal("completion conformance vectors have no success mapping")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	authority := &fakeAuthority{response: []byte(response), afterCall: cancel}

	result := mustHandler(t, authority).HandleCompletion(ctx, []byte(request), decodedPeer(t, vectors))
	want, _ := EncodeCompletionError(CompletionErrorUnavailable)
	if result.Classification != ClassificationAuthorityInvocationFailed || !bytes.Equal(result.Body, want) ||
		authority.callCount() != 1 || !authority.buffersCleared() {
		t.Fatalf("result = %#v calls=%d", result, authority.callCount())
	}
}

func TestCompletionHandlerRequiresLiveDeadline(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := []byte(vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].RequestBodyJSON)
	want, _ := EncodeCompletionError(CompletionErrorUnavailable)
	for _, ctx := range []context.Context{nil, context.Background()} {
		authority := &fakeAuthority{}
		result := mustHandler(t, authority).HandleCompletion(ctx, request, decodedPeer(t, vectors))
		if result.Classification != ClassificationDeadlineRejected || !bytes.Equal(result.Body, want) || authority.callCount() != 0 {
			t.Fatalf("result = %#v", result)
		}
	}
}

type fakeAuthority struct {
	mu        sync.Mutex
	response  []byte
	err       error
	afterCall func()
	payloads  [][]byte
	returned  []byte
}

func (f *fakeAuthority) CompleteCredentialRecovery(_ context.Context, payload []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.payloads = append(f.payloads, payload)
	f.returned = bytes.Clone(f.response)
	if f.afterCall != nil {
		f.afterCall()
	}
	return f.returned, f.err
}

func (f *fakeAuthority) buffersCleared() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, payload := range f.payloads {
		for _, value := range payload {
			if value != 0 {
				return false
			}
		}
	}
	for _, value := range f.returned {
		if value != 0 {
			return false
		}
	}
	return true
}

func (f *fakeAuthority) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.payloads)
}

func mustHandler(t *testing.T, authority Authority) *Handler {
	t.Helper()
	handler, err := NewHandler(authority)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return handler
}

func liveContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
