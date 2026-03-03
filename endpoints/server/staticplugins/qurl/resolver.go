package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// Maximum response body size to prevent memory exhaustion (1MB)
const maxResponseBodySize = 1 << 20

// Resolution errors returned by the QURL API
var (
	// ErrTokenNotFound indicates the access token does not exist
	ErrTokenNotFound = errors.New("token not found")
	// ErrTokenConsumed indicates the access token has already been used (one-time tokens)
	ErrTokenConsumed = errors.New("token already consumed")
	// ErrTokenExpired indicates the access token has expired
	ErrTokenExpired = errors.New("token expired")
	// ErrPolicyViolation indicates access was denied by policy (IP, time, etc.)
	ErrPolicyViolation = errors.New("access denied by policy")
	// ErrServiceError indicates an internal error in the QURL service
	ErrServiceError = errors.New("qurl service error")
)

// ResolveRequest represents a request to validate and consume a QURL access token.
// This is sent to the QURL API internal endpoint for token resolution.
type ResolveRequest struct {
	// AccessToken is the token extracted from the qurl.link redirect
	AccessToken string `json:"access_token"` //nolint:gosec // G117: JSON tag required — sent to QURL API for token resolution
	// SrcIP is the client's IP address for policy evaluation
	SrcIP string `json:"src_ip"`
	// UserAgent is the client's user agent for logging/analytics
	UserAgent string `json:"user_agent"`
}

// ResolveResponse represents the response from QURL API token resolution.
// It contains all data needed to perform the NHP knock and redirect the user.
type ResolveResponse struct {
	// ResourceID is the QURL resource identifier (e.g., "r_9f3a2c8e")
	ResourceID string `json:"resource_id"`
	// TargetURL is the protected backend URL.
	// Used by the QURL router Traefik plugin to proxy requests to the actual target.
	// Not used directly in this plugin but included for API completeness.
	TargetURL string `json:"target_url"`

	// QurlSiteURL is the URL to redirect the user to (e.g., "https://r_9f3a2c8e.qurl.site")
	QurlSiteURL string `json:"qurl_site_url"`

	// NHPResourceID is the mapping to NHP resource configuration
	NHPResourceID string `json:"nhp_resource_id"`
	// Resources contains NHP resource info for the knock
	Resources map[string]*common.ResourceInfo `json:"resources"`

	// JWTSecret is the secret used to sign NHP tokens for this resource
	JWTSecret string `json:"jwt_secret"` //nolint:gosec // G117: JSON tag required — received from QURL API response, never re-serialized
	// TokenExpire is the token expiration time in seconds
	TokenExpire int64 `json:"token_expire"`
	// OpenTime is the firewall open time in seconds
	OpenTime uint32 `json:"open_time"`
	// CookieDomain is the domain for setting NHP cookies
	CookieDomain string `json:"cookie_domain"`

	// AccessCount tracks how many times this token has been used
	AccessCount int `json:"access_count"`
	// Consumed indicates if this one-time token has been consumed
	Consumed bool `json:"consumed"`
}

// internalResolveResponse is the wire format from QURL API
type internalResolveResponse struct {
	Success bool             `json:"success"`
	Data    *ResolveResponse `json:"data,omitempty"`
	Error   *resolveError    `json:"error,omitempty"`
}

type resolveError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// QurlResolver handles communication with the QURL API service.
// It manages HTTP connections and provides token resolution functionality.
type QurlResolver struct {
	httpClient            *http.Client
	transport             *http.Transport
	baseURL               string
	serviceToken          string
	allowedRedirectDomain string
}

// NewQurlResolver creates a new resolver instance with configured HTTP client.
// The resolver uses connection pooling for efficient API communication.
// Returns an error if required configuration is missing.
func NewQurlResolver() (*QurlResolver, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create transport with connection pooling and HTTP/2 support
	// All values are configured via environment variables (no defaults)
	transport := &http.Transport{
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     time.Duration(cfg.IdleConnTimeout) * time.Second,
		ForceAttemptHTTP2:   true, // Enable HTTP/2 if QURL API supports it
	}

	return &QurlResolver{
		httpClient: &http.Client{
			Timeout:   time.Duration(cfg.APITimeout) * time.Second,
			Transport: transport,
			// Disable redirects for internal API calls - we expect direct responses only
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		transport:             transport,
		baseURL:               cfg.QurlAPIURL,
		serviceToken:          cfg.ServiceToken,
		allowedRedirectDomain: cfg.AllowedRedirectDomain,
	}, nil
}

// AllowedRedirectDomain returns the configured allowed redirect domain
func (r *QurlResolver) AllowedRedirectDomain() string {
	return r.allowedRedirectDomain
}

// Close releases resources held by the resolver.
func (r *QurlResolver) Close() error {
	// Close idle connections
	if r.transport != nil {
		r.transport.CloseIdleConnections()
	}
	return nil
}

// Resolve validates an access token and returns resource data
// This calls the QURL API internal endpoint: POST /internal/v1/resolve
func (r *QurlResolver) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	// Build request body
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build HTTP request
	url := fmt.Sprintf("%s/internal/v1/resolve", r.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Add service token authentication header
	// Fail fast if token is empty - this should never happen due to config validation,
	// but proceeding without auth would be a silent security issue.
	if r.serviceToken == "" {
		return nil, errors.New("service token is empty - cannot authenticate with QURL API")
	}
	httpReq.Header.Set("X-Service-Token", r.serviceToken)

	// Execute request
	log.Debug("[QURL] Calling QURL API: %s", url)
	resp, err := r.httpClient.Do(httpReq) //nolint:gosec // G704: URL from QURL_API_URL env var with schema validation
	if err != nil {
		log.Error("[QURL] HTTP request failed: %v", err)
		return nil, fmt.Errorf("failed to call QURL API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body with size limit to prevent memory exhaustion
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Handle HTTP-level errors
	if resp.StatusCode != http.StatusOK {
		log.Error("[QURL] QURL API returned status %d: %s", resp.StatusCode, string(respBody))
		return nil, r.parseErrorResponse(resp.StatusCode, respBody)
	}

	// Parse response
	var internalResp internalResolveResponse
	if err := json.Unmarshal(respBody, &internalResp); err != nil {
		log.Error("[QURL] Failed to parse response: %v", err)
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for API-level errors
	if !internalResp.Success || internalResp.Error != nil {
		if internalResp.Error != nil {
			return nil, r.mapErrorCode(internalResp.Error.Code)
		}
		return nil, ErrServiceError
	}

	if internalResp.Data == nil {
		return nil, ErrServiceError
	}

	return internalResp.Data, nil
}

// parseErrorResponse converts HTTP status codes to domain errors
func (r *QurlResolver) parseErrorResponse(statusCode int, body []byte) error {
	// Try to parse error body
	var internalResp internalResolveResponse
	if err := json.Unmarshal(body, &internalResp); err == nil && internalResp.Error != nil {
		return r.mapErrorCode(internalResp.Error.Code)
	}

	// Fall back to HTTP status code mapping
	switch statusCode {
	case http.StatusNotFound:
		return ErrTokenNotFound
	case http.StatusGone:
		return ErrTokenConsumed
	case http.StatusForbidden:
		return ErrPolicyViolation
	default:
		return ErrServiceError
	}
}

// mapErrorCode converts QURL API error codes to domain errors.
// Maps both token-level and resource-level errors from the QURL API.
// Resource-level errors are mapped to their token-level equivalents
// so handleResolveError returns a generic 403 without leaking state.
func (r *QurlResolver) mapErrorCode(code string) error {
	switch code {
	case "token_not_found", "resource_not_found", "token_revoked", "resource_revoked":
		return ErrTokenNotFound
	case "token_consumed", "resource_consumed":
		return ErrTokenConsumed
	case "token_expired", "resource_expired":
		return ErrTokenExpired
	case "policy_violation", "max_sessions_reached":
		return ErrPolicyViolation
	default:
		return ErrServiceError
	}
}
