//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"
)

// Environment configuration
var (
	// Console API endpoint for createPortalSitesByURL
	consoleAPIURL = getEnv("CONSOLE_API_URL", "https://home.secure.layerv.xyz")
	// Login portal domain
	loginPortalDomain = getEnv("LOGIN_PORTAL_DOMAIN", "qurl.link.layerv.xyz")
	// Protected apps domain
	appsDomain = getEnv("APPS_DOMAIN", "qurl.site.layerv.xyz")
)

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// CreatePortalSiteResponse is the response from createPortalSitesByURL
type CreatePortalSiteResponse struct {
	Code int `json:"code"`
	Data struct {
		AppID    string `json:"appId"`
		Passcode string `json:"passcode"`
	} `json:"data"`
	Msg string `json:"msg"`
}

// TestDemoFlow_CreateAndAccessCloakedURL tests the complete website demo flow:
// 1. Create a cloaked URL via createPortalSitesByURL API
// 2. Verify the protected server blocks unauthenticated access
// 3. Authenticate with passcode and verify access is granted
// 4. Verify we reach the actual target resource
func TestDemoFlow_CreateAndAccessCloakedURL(t *testing.T) {
	// Step 1: Create a cloaked URL
	t.Log("Step 1: Creating cloaked URL...")

	targetURL := "https://httpbin.org/get"
	createReq := map[string]any{
		"url":            targetURL,
		"expirationDays": 1,
		"usageCount":     100, // Allow multiple uses for testing
	}
	reqBody, err := json.Marshal(createReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := http.Post(
		consoleAPIURL+"/api/ps/createPortalSitesByURL",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		t.Fatalf("Failed to call createPortalSitesByURL: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("createPortalSitesByURL returned status %d: %s", resp.StatusCode, string(body))
	}

	var createResp CreatePortalSiteResponse
	if err := json.Unmarshal(body, &createResp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if createResp.Code != 0 {
		t.Fatalf("createPortalSitesByURL returned error code %d: %s", createResp.Code, createResp.Msg)
	}

	appID := createResp.Data.AppID
	passcode := createResp.Data.Passcode

	if appID == "" || passcode == "" {
		t.Fatalf("createPortalSitesByURL returned empty appId or passcode")
	}

	t.Logf("Created cloaked URL - appId: %s, passcode: %s", appID, passcode)

	// Step 2: Verify protected server blocks unauthenticated access
	t.Log("Step 2: Verifying protected server blocks unauthenticated access...")

	protectedURL := fmt.Sprintf("https://%s.%s/", appID, appsDomain)
	t.Logf("Testing protected URL: %s", protectedURL)

	// Create a client that doesn't follow redirects
	noRedirectClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	unauthResp, err := noRedirectClient.Get(protectedURL)
	if err != nil {
		// Connection refused or timeout is expected for protected resources
		t.Logf("Protected URL connection failed as expected: %v", err)
	} else {
		defer unauthResp.Body.Close()
		unauthBody, _ := io.ReadAll(unauthResp.Body)

		// Should be blocked - either redirect to login, 401/403, or connection refused
		if unauthResp.StatusCode == 200 && strings.Contains(string(unauthBody), "httpbin") {
			t.Errorf("Protected URL should NOT return httpbin content without authentication")
		} else {
			t.Logf("Protected URL correctly blocked: status=%d", unauthResp.StatusCode)
		}
	}

	// Step 3: Authenticate with passcode
	t.Log("Step 3: Authenticating with passcode...")

	// Create a client with cookie jar that follows redirects
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}

	authClient := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
	}

	loginURL := fmt.Sprintf("https://%s/%s?passcode=%s&format=json", loginPortalDomain, appID, passcode)
	t.Logf("Authenticating via: %s", loginURL)

	authResp, err := authClient.Get(loginURL)
	if err != nil {
		t.Fatalf("Failed to authenticate: %v", err)
	}
	defer authResp.Body.Close()

	authBody, err := io.ReadAll(authResp.Body)
	if err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}

	t.Logf("Auth response status: %d", authResp.StatusCode)
	t.Logf("Auth response body: %s", string(authBody))

	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("Authentication failed with status %d: %s", authResp.StatusCode, string(authBody))
	}

	// Check for nhp_token cookie
	var hasNHPToken bool
	for _, cookie := range jar.Cookies(authResp.Request.URL) {
		t.Logf("Cookie: %s=%s", cookie.Name, cookie.Value[:min(20, len(cookie.Value))]+"...")
		if cookie.Name == "nhp_token" {
			hasNHPToken = true
		}
	}

	if !hasNHPToken {
		t.Log("Warning: nhp_token cookie not set (may be on different domain)")
	}

	// Step 4: Access protected resource with authenticated session
	t.Log("Step 4: Accessing protected resource with authentication...")

	// Wait a moment for iptables rules to propagate
	time.Sleep(2 * time.Second)

	accessResp, err := authClient.Get(protectedURL)
	if err != nil {
		t.Fatalf("Failed to access protected resource: %v", err)
	}
	defer accessResp.Body.Close()

	accessBody, err := io.ReadAll(accessResp.Body)
	if err != nil {
		t.Fatalf("Failed to read access response: %v", err)
	}

	t.Logf("Access response status: %d", accessResp.StatusCode)

	if accessResp.StatusCode != http.StatusOK {
		t.Errorf("Protected resource returned status %d, expected 200", accessResp.StatusCode)
		t.Logf("Response body: %s", string(accessBody))
	}

	// Verify we actually reached the target (httpbin)
	if !strings.Contains(string(accessBody), "httpbin") && !strings.Contains(string(accessBody), "origin") {
		t.Errorf("Response does not appear to be from httpbin: %s", string(accessBody)[:min(500, len(accessBody))])
	} else {
		t.Log("Successfully accessed protected resource - httpbin content received")
	}
}

// TestDemoFlow_InvalidPasscode verifies that invalid passcodes are rejected
func TestDemoFlow_InvalidPasscode(t *testing.T) {
	// Create a cloaked URL first
	createReq := map[string]any{
		"url": "https://httpbin.org/get",
	}
	reqBody, _ := json.Marshal(createReq)

	resp, err := http.Post(
		consoleAPIURL+"/api/ps/createPortalSitesByURL",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		t.Fatalf("Failed to create portal site: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var createResp CreatePortalSiteResponse
	if err := json.Unmarshal(body, &createResp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if createResp.Code != 0 {
		t.Skipf("Skipping - createPortalSitesByURL failed: %s", createResp.Msg)
	}

	appID := createResp.Data.AppID

	// Try to authenticate with wrong passcode
	loginURL := fmt.Sprintf("https://%s/%s?passcode=wrong_passcode&format=json", loginPortalDomain, appID)

	authResp, err := http.Get(loginURL)
	if err != nil {
		t.Fatalf("Failed to attempt authentication: %v", err)
	}
	defer authResp.Body.Close()

	authBody, _ := io.ReadAll(authResp.Body)

	// Should be rejected - either non-200 status or error in response
	if authResp.StatusCode == 200 {
		// Check if response indicates error
		if strings.Contains(string(authBody), "error") ||
			strings.Contains(string(authBody), "invalid") ||
			strings.Contains(string(authBody), "failed") {
			t.Logf("Invalid passcode correctly rejected: %s", string(authBody))
		} else {
			t.Errorf("Invalid passcode should be rejected, got: %s", string(authBody))
		}
	} else {
		t.Logf("Invalid passcode correctly rejected with status %d", authResp.StatusCode)
	}
}

// TestDemoFlow_APIHealth verifies the Console API is reachable
func TestDemoFlow_APIHealth(t *testing.T) {
	// Simple health check - try to reach the API
	client := &http.Client{Timeout: 10 * time.Second}

	// Try a simple POST with empty body to see if API responds
	resp, err := client.Post(
		consoleAPIURL+"/api/ps/createPortalSitesByURL",
		"application/json",
		strings.NewReader("{}"),
	)
	if err != nil {
		t.Fatalf("Console API unreachable: %v", err)
	}
	defer resp.Body.Close()

	// Even with invalid request, API should respond (not connection error)
	body, _ := io.ReadAll(resp.Body)
	t.Logf("API response status: %d, body: %s", resp.StatusCode, string(body)[:min(200, len(body))])

	if resp.StatusCode >= 500 {
		t.Errorf("Console API returned server error: %d", resp.StatusCode)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
