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

	"github.com/OpenNHP/opennhp/nhp/core"
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

func TestHandleDirectRoutesMalformedRecoveryIntentWithoutAuthority(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	valid := vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].RequestBodyJSON
	dataMarker := `"usrData":`
	dataStart := strings.Index(valid, dataMarker)
	if dataStart < 0 || !strings.HasSuffix(valid, "}}") {
		t.Fatal("golden request has unexpected shape")
	}
	dataJSON := valid[dataStart+len(dataMarker) : len(valid)-1]
	duplicateData := valid[:dataStart] + `"usrData":{"query":"ordinary"},"usrData":` + dataJSON + `}`
	padding := strings.Repeat("x", conformance.AgentCredentialRecoveryMaxBodyBytes)
	tests := []struct {
		name string
		body string
	}{
		{name: "duplicate asp exact and other", body: strings.Replace(valid, `"aspId":"agent"`, `"aspId":"other","aspId":"agent"`, 1)},
		{name: "duplicate query exact and other", body: strings.Replace(valid, `"query":"agent_credential_recovery"`, `"query":"ordinary","query":"agent_credential_recovery"`, 1)},
		{name: "duplicate usrData exact and other", body: duplicateData},
		{name: "unknown root field", body: strings.TrimSuffix(valid, "}") + `,"unknown":true}`},
		{name: "unknown nested field", body: strings.Replace(valid, `"query":"agent_credential_recovery"`, `"unknown":true,"query":"agent_credential_recovery"`, 1)},
		{name: "trailing object", body: valid + `{}`},
		{name: "invalid UTF-8 trailing byte", body: valid + string([]byte{0xff})},
		{name: "type invalid devId", body: strings.Replace(valid, `"devId":"`+vectors.Fixtures.AgentID+`"`, `"devId":42`, 1)},
		{name: "oversized recovery", body: strings.TrimSuffix(valid, "}") + `,"padding":"` + padding + `"}`},
	}
	want, err := EncodeCompletionError(CompletionErrorInvalidRequest)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := &fakeAuthority{}
			result, handled := mustHandler(t, authority).HandleDirect(
				liveContext(t), []byte(test.body), decodedPeer(t, vectors),
			)
			if !handled || result.Classification != ClassificationRequestRejected ||
				!bytes.Equal(result.Body, want) || authority.callCount() != 0 {
				t.Fatalf("handled=%v result=%#v calls=%d", handled, result, authority.callCount())
			}
		})
	}
}

func TestHandleDirectLeavesOrdinaryListRequestUntouched(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	ordinary := []byte(strings.Replace(
		vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].RequestBodyJSON,
		`"query":"agent_credential_recovery"`, `"query":"ordinary"`, 1,
	))
	want := bytes.Clone(ordinary)
	authority := &fakeAuthority{}
	result, handled := mustHandler(t, authority).HandleDirect(liveContext(t), ordinary, decodedPeer(t, vectors))
	if handled || result.Body != nil || result.Classification != "" || result.RequestRejection != "" ||
		authority.callCount() != 0 || !bytes.Equal(ordinary, want) {
		t.Fatalf("handled=%v result=%#v calls=%d body=%q", handled, result, authority.callCount(), ordinary)
	}
}

func TestHandleDirectHandlesNearCeilingDuplicateFlood(t *testing.T) {
	vectors := recoveryVectors(t)
	const duplicate = `"aspId":"other","usrData":{"query":"ordinary"},`
	const exact = `"aspId":"agent","usrData":{"query":"agent_credential_recovery"}`
	var body strings.Builder
	body.Grow(core.MaxDecompressedBodySize)
	body.WriteByte('{')
	for body.Len()+len(duplicate)+len(exact)+1 <= core.MaxDecompressedBodySize {
		body.WriteString(duplicate)
	}
	body.WriteString(exact)
	body.WriteByte('}')
	if body.Len() < core.MaxDecompressedBodyWarnSize {
		t.Fatalf("adversarial body is only %d bytes", body.Len())
	}

	bodyBytes := []byte(body.String())
	if allocs := testing.AllocsPerRun(10, func() {
		if !routeCompletionIntent(bodyBytes) {
			panic("near-ceiling exact-last intent was not routed")
		}
	}); allocs > 4 {
		// Regular builds measure zero; race/compiler instrumentation may account
		// for a couple. This small ceiling still catches the old ~1.2M-allocation
		// encoding/json duplicate scan without coupling the test to a toolchain.
		t.Fatalf("route probe allocations = %.0f, want at most 4", allocs)
	}

	authority := &fakeAuthority{}
	result, handled := mustHandler(t, authority).HandleDirect(
		liveContext(t), bodyBytes, decodedPeer(t, vectors),
	)
	want, err := EncodeCompletionError(CompletionErrorInvalidRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || !bytes.Equal(result.Body, want) || authority.callCount() != 0 {
		t.Fatalf("handled=%v result=%#v calls=%d", handled, result, authority.callCount())
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
