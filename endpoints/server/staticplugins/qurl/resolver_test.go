package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestQurlResolver_Resolve_Success(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.URL.Path != "/internal/v1/resolve" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-Service-Token") != "test-token" {
			t.Errorf("unexpected service token: %s", r.Header.Get("X-Service-Token"))
		}
		if r.Header.Get("X-Request-ID") != "rid-test-123" {
			t.Errorf("unexpected request ID header: %s", r.Header.Get("X-Request-ID"))
		}

		// Parse request body
		var req ResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if req.AccessToken != "test-access-token" {
			t.Errorf("unexpected access token: %s", req.AccessToken)
		}

		// Return success response
		resp := internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:  "r_test123",
				TargetURL:   "https://backend.example.com",
				QurlSiteURL: "https://r_test123.qurl.site",
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId:     "ac-001",
						Hostname: "backend.example.com",
						Addr: &common.NetAddress{
							Ip:   "10.0.0.1",
							Port: 443,
						},
					},
				},
				JWTSecret:    "test-jwt-secret",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create resolver with mock server
	resolver := &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}

	// Test resolve
	req := &ResolveRequest{
		AccessToken: "test-access-token",
		SrcIP:       "192.168.1.1",
		UserAgent:   "TestAgent/1.0",
		RequestID:   "rid-test-123",
	}

	resp, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.ResourceID != "r_test123" {
		t.Errorf("unexpected resource ID: %s", resp.ResourceID)
	}
	if resp.QurlSiteURL != "https://r_test123.qurl.site" {
		t.Errorf("unexpected qurl site URL: %s", resp.QurlSiteURL)
	}
	if resp.JWTSecret != "test-jwt-secret" {
		t.Errorf("unexpected JWT secret: %s", resp.JWTSecret)
	}
}

func TestQurlResolver_Resolve_TokenNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		resp := internalResolveResponse{
			Success: false,
			Error: &resolveError{
				Code:    "token_not_found",
				Message: "Token not found",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	resolver := &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}

	req := &ResolveRequest{AccessToken: "invalid-token"}
	_, err := resolver.Resolve(context.Background(), req)

	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got: %v", err)
	}
}

func TestQurlResolver_Resolve_TokenConsumed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
		resp := internalResolveResponse{
			Success: false,
			Error: &resolveError{
				Code:    "token_consumed",
				Message: "Token already consumed",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	resolver := &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}

	req := &ResolveRequest{AccessToken: "consumed-token"}
	_, err := resolver.Resolve(context.Background(), req)

	if !errors.Is(err, ErrTokenConsumed) {
		t.Errorf("expected ErrTokenConsumed, got: %v", err)
	}
}

func TestQurlResolver_Resolve_TokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := internalResolveResponse{
			Success: false,
			Error: &resolveError{
				Code:    "token_expired",
				Message: "Token expired",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	resolver := &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}

	req := &ResolveRequest{AccessToken: "expired-token"}
	_, err := resolver.Resolve(context.Background(), req)

	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestQurlResolver_Resolve_PolicyViolation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		resp := internalResolveResponse{
			Success: false,
			Error: &resolveError{
				Code:    "policy_violation",
				Message: "Access denied by policy",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	resolver := &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}

	req := &ResolveRequest{AccessToken: "policy-denied-token"}
	_, err := resolver.Resolve(context.Background(), req)

	if !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("expected ErrPolicyViolation, got: %v", err)
	}
}

func TestQurlResolver_Resolve_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	resolver := &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}

	req := &ResolveRequest{AccessToken: "any-token"}
	_, err := resolver.Resolve(context.Background(), req)

	if !errors.Is(err, ErrServiceError) {
		t.Errorf("expected ErrServiceError, got: %v", err)
	}
}

func TestQurlResolver_Resolve_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	resolver := &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}

	req := &ResolveRequest{AccessToken: "any-token"}
	_, err := resolver.Resolve(context.Background(), req)

	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestQurlResolver_Resolve_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	resolver := &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := &ResolveRequest{AccessToken: "any-token"}
	_, err := resolver.Resolve(ctx, req)

	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestQurlResolver_Resolve_EmptyServiceToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not be made with empty service token")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	resolver := &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "", // Empty token
	}

	req := &ResolveRequest{AccessToken: "any-token"}
	_, err := resolver.Resolve(context.Background(), req)

	if err == nil {
		t.Error("expected error for empty service token")
	}
	if err.Error() != "service token is empty - cannot authenticate with QURL API" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestMapErrorCode(t *testing.T) {
	resolver := &QurlResolver{}

	tests := []struct {
		code     string
		expected error
	}{
		// Token-level errors
		{"token_not_found", ErrTokenNotFound},
		{"token_consumed", ErrTokenConsumed},
		{"token_expired", ErrTokenExpired},
		{"token_revoked", ErrTokenNotFound},
		// Resource-level errors mapped to token equivalents
		{"resource_not_found", ErrTokenNotFound},
		{"resource_revoked", ErrTokenNotFound},
		{"resource_consumed", ErrTokenConsumed},
		{"resource_expired", ErrTokenExpired},
		// Policy errors
		{"policy_violation", ErrPolicyViolation},
		{"max_sessions_reached", ErrPolicyViolation},
		// Unknown codes
		{"unknown_error", ErrServiceError},
		{"", ErrServiceError},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			err := resolver.mapErrorCode(tt.code)
			if !errors.Is(err, tt.expected) {
				t.Errorf("mapErrorCode(%q) = %v, want %v", tt.code, err, tt.expected)
			}
		})
	}
}

func TestValidateResolveResponse(t *testing.T) {
	tests := []struct {
		name    string
		resp    *ResolveResponse
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid response",
			resp: &ResolveResponse{
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId: "ac-001",
						Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty resources",
			resp: &ResolveResponse{
				Resources: map[string]*common.ResourceInfo{},
			},
			wantErr: true,
			errMsg:  "empty resources",
		},
		{
			name: "nil resources",
			resp: &ResolveResponse{
				Resources: nil,
			},
			wantErr: true,
			errMsg:  "empty resources",
		},
		{
			name: "nil resource entry",
			resp: &ResolveResponse{
				Resources: map[string]*common.ResourceInfo{
					"default": nil,
				},
			},
			wantErr: true,
			errMsg:  "is nil",
		},
		{
			name: "empty ACId",
			resp: &ResolveResponse{
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId: "",
						Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443},
					},
				},
			},
			wantErr: true,
			errMsg:  "empty ACId",
		},
		{
			name: "nil address",
			resp: &ResolveResponse{
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId: "ac-001",
						Addr: nil,
					},
				},
			},
			wantErr: true,
			errMsg:  "nil address",
		},
		{
			name: "empty IP",
			resp: &ResolveResponse{
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId: "ac-001",
						Addr: &common.NetAddress{Ip: "", Port: 443},
					},
				},
			},
			wantErr: true,
			errMsg:  "empty IP",
		},
		{
			name: "zero port",
			resp: &ResolveResponse{
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId: "ac-001",
						Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 0},
					},
				},
			},
			wantErr: true,
			errMsg:  "zero port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResolveResponse(tt.resp)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateResolveResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateResolveResponse() error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestParseErrorResponse(t *testing.T) {
	resolver := &QurlResolver{}

	tests := []struct {
		name       string
		statusCode int
		body       string
		expected   error
	}{
		{
			name:       "404 with error body",
			statusCode: http.StatusNotFound,
			body:       `{"success":false,"error":{"code":"token_not_found","message":"not found"}}`,
			expected:   ErrTokenNotFound,
		},
		{
			name:       "410 with resource_revoked body",
			statusCode: http.StatusGone,
			body:       `{"success":false,"error":{"code":"resource_revoked","message":"Resource has been revoked"}}`,
			expected:   ErrTokenNotFound,
		},
		{
			name:       "410 without body",
			statusCode: http.StatusGone,
			body:       "",
			expected:   ErrTokenConsumed,
		},
		{
			name:       "403 status fallback",
			statusCode: http.StatusForbidden,
			body:       "invalid json",
			expected:   ErrPolicyViolation,
		},
		{
			name:       "500 status fallback",
			statusCode: http.StatusInternalServerError,
			body:       "",
			expected:   ErrServiceError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := resolver.parseErrorResponse(tt.statusCode, []byte(tt.body))
			if !errors.Is(err, tt.expected) {
				t.Errorf("parseErrorResponse(%d, %q) = %v, want %v", tt.statusCode, tt.body, err, tt.expected)
			}
		})
	}
}
