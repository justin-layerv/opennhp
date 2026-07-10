package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// newTestRegistrar wires a registrar at an httptest server URL with a fixed
// service token, mirroring qurl's newAuthorizeTestResolver. The transport is
// left default (httptest is local; pooling is irrelevant to these assertions).
func newTestRegistrar(t *testing.T, h http.HandlerFunc) (*registrar, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &registrar{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      srv.URL,
		serviceToken: "test-service-token",
	}, srv
}

// capturedRequest records what the fake qurl-service received so a test can
// assert the exact wire contract.
type capturedRequest struct {
	path         string
	method       string
	serviceToken string
	contentType  string
	rawBody      []byte
}

func captureInto(cap *capturedRequest) func(*http.Request) {
	return func(req *http.Request) {
		cap.path = req.URL.Path
		cap.method = req.Method
		cap.serviceToken = req.Header.Get(ServiceTokenHeader)
		cap.contentType = req.Header.Get("Content-Type")
		cap.rawBody, _ = io.ReadAll(req.Body)
	}
}

// ---- OTP endpoint ---------------------------------------------------------

func TestRequestOTP_202SendsExactContractAndReturnsNil(t *testing.T) {
	var cap capturedRequest
	r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
		captureInto(&cap)(req)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"success":true}`))
	})

	err := r.requestOTP(context.Background(), &otpAPIRequest{
		APIKeyID:        "ak_123",
		APIKeySecret:    "super-secret-passcode",
		DeviceID:        "dev_abc",
		DevicePubkeyB64: "cHVია==", // arbitrary, treated opaquely
		SrcIP:           "203.0.113.7",
	}, "trace-otp-1")
	if err != nil {
		t.Fatalf("requestOTP on 202 returned err=%v, want nil", err)
	}

	// Method + path + headers.
	if cap.method != http.MethodPost {
		t.Errorf("method=%q want POST", cap.method)
	}
	if cap.path != "/internal/v1/agent/otp" {
		t.Errorf("path=%q want /internal/v1/agent/otp", cap.path)
	}
	if cap.serviceToken != "test-service-token" {
		t.Errorf("X-Service-Token=%q want test-service-token", cap.serviceToken)
	}
	if cap.contentType != "application/json" {
		t.Errorf("Content-Type=%q want application/json", cap.contentType)
	}

	// Exact JSON field names + values (decode into a raw map to assert the WIRE
	// keys, not the Go field names).
	var got map[string]any
	if err := json.Unmarshal(cap.rawBody, &got); err != nil {
		t.Fatalf("request body not JSON: %v (%s)", err, cap.rawBody)
	}
	wantFields := map[string]any{
		"api_key_id":        "ak_123",
		"api_key_secret":    "super-secret-passcode",
		"device_id":         "dev_abc",
		"device_pubkey_b64": "cHVია==",
		"src_ip":            "203.0.113.7",
	}
	for k, want := range wantFields {
		if got[k] != want {
			t.Errorf("otp body[%q]=%v want %v", k, got[k], want)
		}
	}
}

// src_ip is omitempty: an empty source must be omitted from the wire, not sent
// as "".
func TestRequestOTP_OmitsEmptySrcIP(t *testing.T) {
	var cap capturedRequest
	r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
		captureInto(&cap)(req)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	if err := r.requestOTP(context.Background(), &otpAPIRequest{APIKeyID: "ak", DeviceID: "d"}, ""); err != nil {
		t.Fatalf("requestOTP err=%v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(cap.rawBody, &got)
	if _, present := got["src_ip"]; present {
		t.Errorf("src_ip present in body %s; omitempty must drop an empty source", cap.rawBody)
	}
}

// Every OTP error code maps to the correct registration *common.Error.
func TestRequestOTP_ErrorCodeMapping(t *testing.T) {
	cases := []struct {
		code   string
		status int
		want   *common.Error
	}{
		{"invalid_api_key", http.StatusUnauthorized, common.ErrRegistrationApiKeyInvalid},
		{"invalid_device_id", http.StatusBadRequest, common.ErrRegistrationInvalidInput},
		{"email_unavailable", http.StatusConflict, common.ErrRegistrationEmailUnavailable},
		{"rate_limited", http.StatusTooManyRequests, common.ErrRegistrationRateLimited},
		{"send_failed", http.StatusBadGateway, common.ErrRegistrationDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"success":false,"error":{"code":"` + tc.code + `","message":"nope"}}`))
			})
			err := r.requestOTP(context.Background(), &otpAPIRequest{APIKeyID: "ak", DeviceID: "d"}, "")
			var ce *common.Error
			if !errors.As(err, &ce) || ce != tc.want {
				t.Fatalf("requestOTP(%s) err=%v want %s (%s)", tc.code, err, tc.want.Error(), tc.want.ErrorCode())
			}
		})
	}
}

// A 2xx that carries success:false is still a failure (not silently accepted).
func TestRequestOTP_2xxSuccessFalseIsError(t *testing.T) {
	r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"rate_limited"}}`))
	})
	err := r.requestOTP(context.Background(), &otpAPIRequest{APIKeyID: "ak"}, "")
	if !errors.Is(err, common.ErrRegistrationRateLimited) {
		t.Fatalf("2xx success:false err=%v want ErrRegistrationRateLimited", err)
	}
}

// A non-2xx with no structured error body falls back to errUnexpectedStatus.
func TestRequestOTP_BodilessErrorFallsBack(t *testing.T) {
	r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err := r.requestOTP(context.Background(), &otpAPIRequest{APIKeyID: "ak"}, "")
	if !errors.Is(err, errUnexpectedStatus) {
		t.Fatalf("bodiless 500 err=%v want errUnexpectedStatus", err)
	}
}

func TestRequestOTP_EmptyServiceTokenFailsFast(t *testing.T) {
	r := &registrar{httpClient: &http.Client{}, baseURL: "http://unused", serviceToken: ""}
	if err := r.requestOTP(context.Background(), &otpAPIRequest{APIKeyID: "ak"}, ""); !errors.Is(err, errEmptyServiceToken) {
		t.Fatalf("empty-token requestOTP err=%v want errEmptyServiceToken", err)
	}
}

// The X-Request-ID header propagates when a request-id is supplied.
func TestRequestOTP_PropagatesRequestID(t *testing.T) {
	var gotReqID string
	r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
		gotReqID = req.Header.Get(requestIDHeader)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	_ = r.requestOTP(context.Background(), &otpAPIRequest{APIKeyID: "ak"}, "trace-xyz")
	if gotReqID != "trace-xyz" {
		t.Errorf("X-Request-ID=%q want trace-xyz", gotReqID)
	}
}

// ---- Register endpoint ----------------------------------------------------

func TestRegisterAgent_200ReturnsAgentIDAndSendsExactContract(t *testing.T) {
	var cap capturedRequest
	r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
		captureInto(&cap)(req)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{"agent_id":"agt_777"}}`))
	})

	agentID, err := r.registerAgent(context.Background(), &registerAPIRequest{
		APIKeyID:        "ak_9",
		DeviceID:        "dev_9",
		Credential:      "654321-secret-otp",
		DevicePubkeyB64: "cHVიaz0=",
		Hostname:        "host-1",
		Version:         "1.2.3",
		Takeover:        true,
		SrcIP:           "198.51.100.9",
	}, "trace-reg-1")
	if err != nil {
		t.Fatalf("registerAgent on 200 returned err=%v", err)
	}
	if agentID != "agt_777" {
		t.Errorf("agentID=%q want agt_777", agentID)
	}
	if cap.path != "/internal/v1/agent/register" {
		t.Errorf("path=%q want /internal/v1/agent/register", cap.path)
	}
	if cap.serviceToken != "test-service-token" {
		t.Errorf("X-Service-Token=%q want test-service-token", cap.serviceToken)
	}

	var got map[string]any
	if err := json.Unmarshal(cap.rawBody, &got); err != nil {
		t.Fatalf("register body not JSON: %v", err)
	}
	wantFields := map[string]any{
		"api_key_id":        "ak_9",
		"device_id":         "dev_9",
		"credential":        "654321-secret-otp",
		"device_pubkey_b64": "cHVიaz0=",
		"hostname":          "host-1",
		"version":           "1.2.3",
		"takeover":          true,
		"src_ip":            "198.51.100.9",
	}
	for k, want := range wantFields {
		if got[k] != want {
			t.Errorf("register body[%q]=%v want %v", k, got[k], want)
		}
	}
	// The register contract carries NO api_key_secret field — only the OTP path does.
	if _, present := got["api_key_secret"]; present {
		t.Errorf("register body leaked api_key_secret: %s", cap.rawBody)
	}
}

// hostname/version are omitempty; takeover is always present (a bool has no
// absent wire state).
func TestRegisterAgent_OmitsEmptyOptionalMetadata(t *testing.T) {
	var cap capturedRequest
	r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
		captureInto(&cap)(req)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{"agent_id":"agt_1"}}`))
	})
	if _, err := r.registerAgent(context.Background(), &registerAPIRequest{APIKeyID: "ak", DeviceID: "d", Credential: "c"}, ""); err != nil {
		t.Fatalf("registerAgent err=%v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(cap.rawBody, &got)
	for _, k := range []string{"hostname", "version", "src_ip"} {
		if _, present := got[k]; present {
			t.Errorf("optional field %q present in %s; omitempty must drop it", k, cap.rawBody)
		}
	}
	if _, present := got["takeover"]; !present {
		t.Errorf("takeover missing from %s; a bool must always be sent", cap.rawBody)
	}
}

func TestRegisterAgent_ErrorCodeMapping(t *testing.T) {
	cases := []struct {
		code   string
		status int
		want   *common.Error
	}{
		{"credential_invalid", http.StatusUnauthorized, common.ErrRegistrationCredentialInvalid},
		{"credential_expired", http.StatusUnauthorized, common.ErrRegistrationCredentialExpired},
		{"attempts_exceeded", http.StatusTooManyRequests, common.ErrRegistrationAttemptsExceeded},
		{"agent_identity_conflict", http.StatusConflict, common.ErrRegistrationIdentityConflict},
		{"rate_limited", http.StatusTooManyRequests, common.ErrRegistrationRateLimited},
		{"invalid_api_key", http.StatusUnauthorized, common.ErrRegistrationApiKeyInvalid},
		{"bootstrap_key_consumed", http.StatusConflict, common.ErrRegistrationBootstrapKeyConsumed},
		{"internal_error", http.StatusInternalServerError, common.ErrRegistrationDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"success":false,"error":{"code":"` + tc.code + `"}}`))
			})
			agentID, err := r.registerAgent(context.Background(), &registerAPIRequest{APIKeyID: "ak"}, "")
			if agentID != "" {
				t.Errorf("agentID=%q want empty on error", agentID)
			}
			var ce *common.Error
			if !errors.As(err, &ce) || ce != tc.want {
				t.Fatalf("registerAgent(%s) err=%v want %s (%s)", tc.code, err, tc.want.Error(), tc.want.ErrorCode())
			}
		})
	}
}

// A 200 success that omits agent_id violates the contract → treated as a
// malformed response (server-side fault), not a silent success.
func TestRegisterAgent_200WithoutAgentIDIsMalformed(t *testing.T) {
	r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	})
	_, err := r.registerAgent(context.Background(), &registerAPIRequest{APIKeyID: "ak"}, "")
	if !errors.Is(err, errMalformedResponse) {
		t.Fatalf("200 without agent_id err=%v want errMalformedResponse", err)
	}
}

func TestRegisterAgent_UnparseableBodyIsMalformed(t *testing.T) {
	r, _ := newTestRegistrar(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{ not json`))
	})
	_, err := r.registerAgent(context.Background(), &registerAPIRequest{APIKeyID: "ak"}, "")
	if !errors.Is(err, errMalformedResponse) {
		t.Fatalf("unparseable body err=%v want errMalformedResponse", err)
	}
}

// TestQurlErrCodeToRegErr is the direct table test for the mapping, including
// the dedicated invalid_device_id code and the unknown-code fail-closed default.
func TestQurlErrCodeToRegErr(t *testing.T) {
	cases := map[string]*common.Error{
		"credential_invalid":      common.ErrRegistrationCredentialInvalid,
		"credential_expired":      common.ErrRegistrationCredentialExpired,
		"attempts_exceeded":       common.ErrRegistrationAttemptsExceeded,
		"agent_identity_conflict": common.ErrRegistrationIdentityConflict,
		"rate_limited":            common.ErrRegistrationRateLimited,
		"email_unavailable":       common.ErrRegistrationEmailUnavailable,
		"invalid_api_key":         common.ErrRegistrationApiKeyInvalid,
		"invalid_device_id":       common.ErrRegistrationInvalidInput,
		"bootstrap_key_consumed":  common.ErrRegistrationBootstrapKeyConsumed,
		"send_failed":             common.ErrRegistrationDisabled,
		"internal_error":          common.ErrRegistrationDisabled,
		"some_future_code":        common.ErrRegistrationDisabled,
		"":                        common.ErrRegistrationDisabled,
	}
	for code, want := range cases {
		if got := qurlErrCodeToRegErr(code); got != want {
			t.Errorf("qurlErrCodeToRegErr(%q)=%s want %s", code, got.ErrorCode(), want.ErrorCode())
		}
	}
}
