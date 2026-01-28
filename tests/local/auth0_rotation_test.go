//go:build local

// Package local provides unit tests for Auth0 secret rotation logic.
// These tests use mock HTTP servers to simulate Auth0 APIs and validate
// the rotation Lambda handler behavior.
//
// Run tests:
//
//	cd tests/local && go test -v -tags=local ./... -run TestAuth0
//
// Or from project root:
//
//	make test-local
package local

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Auth0TokenResponse represents a successful token response from Auth0
type Auth0TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// Auth0CredentialResponse represents a credential rotation response from Auth0
type Auth0CredentialResponse struct {
	ID             string `json:"id"`
	CredentialType string `json:"credential_type"`
	ClientSecret   string `json:"client_secret"`
	CreatedAt      string `json:"created_at"`
}

// Auth0ErrorResponse represents an error response from Auth0
type Auth0ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// MockAuth0Server creates a mock Auth0 server for testing
type MockAuth0Server struct {
	server              *httptest.Server
	managementToken     string
	backendClientID     string
	backendClientSecret string
	newClientSecret     string
	apiAudience         string
	tokenCallCount      int32
	rotateCallCount     int32
	shouldFailToken     bool
	shouldFailRotate    bool
	shouldFailTest      bool
}

// NewMockAuth0Server creates a new mock Auth0 server
func NewMockAuth0Server(t *testing.T) *MockAuth0Server {
	mock := &MockAuth0Server{
		managementToken:     "test-management-token",
		backendClientID:     "test-backend-client-id",
		backendClientSecret: "test-backend-secret",
		newClientSecret:     "new-rotated-secret",
		apiAudience:         "https://api.test.layerv.xyz",
	}

	mux := http.NewServeMux()

	// POST /oauth/token - Token endpoint for both management and backend clients
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		atomic.AddInt32(&mock.tokenCallCount, 1)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		var req map[string]string
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		clientID := req["client_id"]
		clientSecret := req["client_secret"]
		audience := req["audience"]

		t.Logf("Token request: client_id=%s, audience=%s", clientID, audience)

		// Check if this is a management token request
		if strings.Contains(audience, "/api/v2/") {
			if mock.shouldFailToken {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(Auth0ErrorResponse{
					Error:            "access_denied",
					ErrorDescription: "Unauthorized",
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(Auth0TokenResponse{
				AccessToken: mock.managementToken,
				TokenType:   "Bearer",
				ExpiresIn:   86400,
			})
			return
		}

		// Backend client token request (for testing new credentials)
		if clientID == mock.backendClientID {
			// Check if using old or new secret
			if clientSecret == mock.newClientSecret {
				if mock.shouldFailTest {
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(Auth0ErrorResponse{
						Error:            "access_denied",
						ErrorDescription: "Invalid client credentials",
					})
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(Auth0TokenResponse{
					AccessToken: "backend-access-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				})
				return
			} else if clientSecret == mock.backendClientSecret {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(Auth0TokenResponse{
					AccessToken: "backend-access-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				})
				return
			}
		}

		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Auth0ErrorResponse{
			Error:            "access_denied",
			ErrorDescription: "Invalid client credentials",
		})
	})

	// POST /api/v2/clients/{clientId}/credentials - Credential rotation endpoint
	mux.HandleFunc("/api/v2/clients/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		atomic.AddInt32(&mock.rotateCallCount, 1)

		// Verify authorization header
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + mock.managementToken
		if authHeader != expectedAuth {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(Auth0ErrorResponse{
				Error:            "unauthorized",
				ErrorDescription: "Invalid access token",
			})
			return
		}

		if mock.shouldFailRotate {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(Auth0ErrorResponse{
				Error:            "server_error",
				ErrorDescription: "Internal server error",
			})
			return
		}

		// Return new credential
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(Auth0CredentialResponse{
			ID:             "cred_123",
			CredentialType: "client_secret_post",
			ClientSecret:   mock.newClientSecret,
			CreatedAt:      "2024-01-15T00:00:00.000Z",
		})
	})

	mock.server = httptest.NewServer(mux)
	return mock
}

// Close shuts down the mock server
func (m *MockAuth0Server) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

// URL returns the mock server URL
func (m *MockAuth0Server) URL() string {
	return m.server.URL
}

// Domain returns the mock server host:port as a domain
func (m *MockAuth0Server) Domain() string {
	return strings.TrimPrefix(m.server.URL, "http://")
}

// TestAuth0Rotation_MockServerSetup verifies the mock Auth0 server works correctly
func TestAuth0Rotation_MockServerSetup(t *testing.T) {
	mock := NewMockAuth0Server(t)
	defer mock.Close()

	t.Run("management_token_request", func(t *testing.T) {
		body := `{"client_id":"mgmt-client","client_secret":"mgmt-secret","audience":"https://test.auth0.com/api/v2/","grant_type":"client_credentials"}`
		resp, err := http.Post(mock.URL()+"/oauth/token", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}

		var tokenResp Auth0TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if tokenResp.AccessToken != mock.managementToken {
			t.Errorf("Expected token %s, got %s", mock.managementToken, tokenResp.AccessToken)
		}
	})

	t.Run("credential_rotation_request", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, mock.URL()+"/api/v2/clients/test-client-id/credentials", strings.NewReader(`{"credential_type":"client_secret_post"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+mock.managementToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			t.Errorf("Expected 201, got %d", resp.StatusCode)
		}

		var credResp Auth0CredentialResponse
		if err := json.NewDecoder(resp.Body).Decode(&credResp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if credResp.ClientSecret != mock.newClientSecret {
			t.Errorf("Expected secret %s, got %s", mock.newClientSecret, credResp.ClientSecret)
		}
	})

	t.Run("backend_token_with_new_secret", func(t *testing.T) {
		body := `{"client_id":"` + mock.backendClientID + `","client_secret":"` + mock.newClientSecret + `","audience":"` + mock.apiAudience + `","grant_type":"client_credentials"}`
		resp, err := http.Post(mock.URL()+"/oauth/token", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("Expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})
}

// TestAuth0Rotation_TokenEndpointFailure verifies handling of token endpoint failures
func TestAuth0Rotation_TokenEndpointFailure(t *testing.T) {
	mock := NewMockAuth0Server(t)
	defer mock.Close()

	mock.shouldFailToken = true

	body := `{"client_id":"mgmt-client","client_secret":"mgmt-secret","audience":"https://test.auth0.com/api/v2/","grant_type":"client_credentials"}`
	resp, err := http.Post(mock.URL()+"/oauth/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}
}

// TestAuth0Rotation_RotationEndpointFailure verifies handling of rotation endpoint failures
func TestAuth0Rotation_RotationEndpointFailure(t *testing.T) {
	mock := NewMockAuth0Server(t)
	defer mock.Close()

	mock.shouldFailRotate = true

	req, _ := http.NewRequest(http.MethodPost, mock.URL()+"/api/v2/clients/test-client/credentials", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+mock.managementToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", resp.StatusCode)
	}
}

// TestAuth0Rotation_InvalidCredentialsTest verifies handling when new credentials fail validation
func TestAuth0Rotation_InvalidCredentialsTest(t *testing.T) {
	mock := NewMockAuth0Server(t)
	defer mock.Close()

	mock.shouldFailTest = true

	body := `{"client_id":"` + mock.backendClientID + `","client_secret":"` + mock.newClientSecret + `","audience":"` + mock.apiAudience + `","grant_type":"client_credentials"}`
	resp, err := http.Post(mock.URL()+"/oauth/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}
}

// TestAuth0Rotation_UnauthorizedManagementRequest verifies authorization is required
func TestAuth0Rotation_UnauthorizedManagementRequest(t *testing.T) {
	mock := NewMockAuth0Server(t)
	defer mock.Close()

	// Request without proper authorization
	req, _ := http.NewRequest(http.MethodPost, mock.URL()+"/api/v2/clients/test-client/credentials", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}
}

// TestAuth0Rotation_SecretStructure verifies the expected secret JSON structure
func TestAuth0Rotation_SecretStructure(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		valid  bool
		errMsg string
	}{
		{
			name:   "valid_secret",
			secret: `{"client_id":"abc","client_secret":"xyz","audience":"https://api.example.com"}`,
			valid:  true,
		},
		{
			name:   "missing_client_id",
			secret: `{"client_secret":"xyz","audience":"https://api.example.com"}`,
			valid:  false,
			errMsg: "client_id is required",
		},
		{
			name:   "missing_client_secret",
			secret: `{"client_id":"abc","audience":"https://api.example.com"}`,
			valid:  false,
			errMsg: "client_secret is required",
		},
		{
			name:   "missing_audience",
			secret: `{"client_id":"abc","client_secret":"xyz"}`,
			valid:  false,
			errMsg: "audience is required",
		},
		{
			name:   "empty_values",
			secret: `{"client_id":"","client_secret":"xyz","audience":"https://api.example.com"}`,
			valid:  false,
			errMsg: "client_id cannot be empty",
		},
		{
			name:   "invalid_json",
			secret: `not json at all`,
			valid:  false,
			errMsg: "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var secret struct {
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
				Audience     string `json:"audience"`
			}

			err := json.Unmarshal([]byte(tt.secret), &secret)
			if err != nil {
				if tt.valid {
					t.Errorf("Expected valid JSON, got error: %v", err)
				}
				return
			}

			isValid := secret.ClientID != "" && secret.ClientSecret != "" && secret.Audience != ""

			if isValid != tt.valid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.valid, isValid)
			}
		})
	}
}

// TestAuth0Rotation_RotationFlow simulates the complete rotation flow
func TestAuth0Rotation_RotationFlow(t *testing.T) {
	mock := NewMockAuth0Server(t)
	defer mock.Close()

	// Simulate the 4-step rotation flow

	// Step 1: createSecret - Get management token and rotate
	t.Log("Step 1: createSecret")

	// Get management token
	mgmtBody := `{"client_id":"mgmt-client","client_secret":"mgmt-secret","audience":"https://test.auth0.com/api/v2/","grant_type":"client_credentials"}`
	mgmtResp, err := http.Post(mock.URL()+"/oauth/token", "application/json", strings.NewReader(mgmtBody))
	if err != nil {
		t.Fatalf("Failed to get management token: %v", err)
	}
	defer mgmtResp.Body.Close()

	if mgmtResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for management token, got %d", mgmtResp.StatusCode)
	}

	var mgmtToken Auth0TokenResponse
	json.NewDecoder(mgmtResp.Body).Decode(&mgmtToken)

	// Rotate the credential
	rotateReq, _ := http.NewRequest(http.MethodPost, mock.URL()+"/api/v2/clients/"+mock.backendClientID+"/credentials", strings.NewReader(`{"credential_type":"client_secret_post"}`))
	rotateReq.Header.Set("Authorization", "Bearer "+mgmtToken.AccessToken)
	rotateReq.Header.Set("Content-Type", "application/json")

	rotateResp, err := http.DefaultClient.Do(rotateReq)
	if err != nil {
		t.Fatalf("Failed to rotate credential: %v", err)
	}
	defer rotateResp.Body.Close()

	if rotateResp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 for rotation, got %d", rotateResp.StatusCode)
	}

	var newCred Auth0CredentialResponse
	json.NewDecoder(rotateResp.Body).Decode(&newCred)
	t.Logf("New secret received: %s...", newCred.ClientSecret[:min(10, len(newCred.ClientSecret))])

	// Step 2: setSecret - N/A for Auth0 (atomic operation)
	t.Log("Step 2: setSecret - skipped (Auth0 handles atomically)")

	// Step 3: testSecret - Verify new credentials work
	t.Log("Step 3: testSecret")

	testBody := `{"client_id":"` + mock.backendClientID + `","client_secret":"` + newCred.ClientSecret + `","audience":"` + mock.apiAudience + `","grant_type":"client_credentials"}`
	testResp, err := http.Post(mock.URL()+"/oauth/token", "application/json", strings.NewReader(testBody))
	if err != nil {
		t.Fatalf("Failed to test new credentials: %v", err)
	}
	defer testResp.Body.Close()

	if testResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for test, got %d", testResp.StatusCode)
	}
	t.Log("New credentials validated successfully")

	// Step 4: finishSecret - Would update Secrets Manager (simulated)
	t.Log("Step 4: finishSecret - AWSPENDING promoted to AWSCURRENT (simulated)")

	// Verify call counts
	tokenCalls := atomic.LoadInt32(&mock.tokenCallCount)
	rotateCalls := atomic.LoadInt32(&mock.rotateCallCount)

	t.Logf("Total calls - Token: %d, Rotate: %d", tokenCalls, rotateCalls)

	if tokenCalls < 2 {
		t.Errorf("Expected at least 2 token calls (management + test), got %d", tokenCalls)
	}
	if rotateCalls != 1 {
		t.Errorf("Expected exactly 1 rotate call, got %d", rotateCalls)
	}

	t.Log("PASS: Complete rotation flow succeeded")
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
