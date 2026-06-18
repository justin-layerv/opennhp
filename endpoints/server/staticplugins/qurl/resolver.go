package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	nhpserver "github.com/OpenNHP/opennhp/endpoints/server"
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
	// ErrInvalidResolveResponse indicates the QURL API returned structurally
	// invalid data (e.g., missing nhp_resource_id). This is distinct from
	// token/policy errors and indicates a configuration issue.
	ErrInvalidResolveResponse = errors.New("invalid resolve response")

	// ErrQurlAccessDenied indicates qurl-service has no active session for the
	// (resource_id, client_ip) pair — the knock is cryptographically
	// authenticated but the client is not authorized right now (403/404/410
	// from the /authorize endpoint). The agent must re-resolve via the qURL
	// link to mint a fresh session. Distinct from a transient API failure.
	ErrQurlAccessDenied = errors.New("qurl access denied: no active session")
)

// AuthorizeResult is the decision returned by qurl-service
// GET /internal/v1/resource/:id/authorize. RemainingSeconds is the session's
// remaining lifetime (used to cap the AC pinhole). Tunnel marks a reverse-
// tunnel resource, which is authorized via a different flow and not servable
// on the browser knock path.
type AuthorizeResult struct {
	RemainingSeconds uint32 `json:"remaining_seconds"`
	Tunnel           bool   `json:"tunnel,omitempty"`
}

// ResolveRequest represents a request to validate and consume a QURL access token.
// This is sent to the QURL API internal endpoint for token resolution.
type ResolveRequest struct {
	// AccessToken is the token extracted from the qurl.link redirect
	AccessToken string `json:"access_token"` //nolint:gosec // G117: JSON tag required — sent to QURL API for token resolution
	// SrcIP is the client's IP address for policy evaluation
	SrcIP string `json:"src_ip"`
	// UserAgent is the client's user agent for logging/analytics
	UserAgent string `json:"user_agent"`
	// RequestID is propagated via HTTP header for trace correlation.
	RequestID string `json:"-"`
}

// BrowserRelayResolveRequest is the NHP-only relay bootstrap request. The
// AuthenticatedAgentPublicKey is the Noise peer public key NHP authenticated on
// the relay-forwarded knock; it is not browser-submitted JSON to qurl-service.
type BrowserRelayResolveRequest struct {
	AccessToken                 string `json:"access_token"` //nolint:gosec // G117: JSON tag required — sent to QURL API for token resolution
	SrcIP                       string `json:"src_ip"`
	UserAgent                   string `json:"user_agent"`
	AuthenticatedAgentPublicKey string `json:"authenticated_agent_public_key"`
	RequestID                   string `json:"-"`
}

// ResolveResponse represents the response from QURL API token resolution.
// It contains all data needed to perform the NHP knock and redirect the user.
// For custom domains, IsCustomDomain is true and QurlSiteURL/CookieDomain
// reflect the customer's domain instead of qurl.site.
type ResolveResponse struct {
	// ResourceID is the QURL resource identifier (e.g., "r_9f3a2c8e")
	ResourceID string `json:"resource_id"`
	// TargetURL is the protected backend URL.
	// Used by the QURL router Traefik plugin to proxy requests to the actual target.
	// Not used directly in this plugin but included for API completeness.
	TargetURL string `json:"target_url"`

	// QurlSiteURL is the URL to redirect the user to (e.g., "https://r_9f3a2c8e.qurl.site")
	QurlSiteURL string `json:"qurl_site_url"`

	// NHPResourceID is the qURL display id (q_…) qurl-service publishes as
	// the key of the per-qURL routing row in NHP's catalog at mint
	// (upsertNHPCatalogForToken). The plugin resolves AC routing from the
	// catalog by this id (#2540), so it is required (validateResolveResponse).
	NHPResourceID string `json:"nhp_resource_id"`
	// Resources is qurl-service's mint-time copy of the NHP routing map. As of
	// #2540 the plugin no longer consumes it — AC routing is resolved from the
	// server-owned catalog by NHPResourceID instead. The field is retained only
	// to deserialize current qurl-service responses; layervai/qurl-service#823
	// removes it from the wire once this change is deployed. (No omitempty: this
	// struct is only ever deserialized from qurl-service, never re-serialized,
	// so the tag option would be a no-op.)
	Resources map[string]*common.ResourceInfo `json:"resources"`

	// JWTSecret is the secret used to sign NHP tokens for this resource
	JWTSecret string `json:"jwt_secret"` //nolint:gosec // G117: JSON tag required — received from QURL API response, never re-serialized
	// TokenExpire is the token expiration time in seconds
	TokenExpire int64 `json:"token_expire"`
	// SessionDuration is the per-QURL session lifetime in seconds.
	// 0 means use the global default (TokenExpire). When set, overrides
	// TokenExpire for cookie MaxAge so the QURL creator controls access duration.
	SessionDuration int `json:"session_duration,omitempty"`
	// OpenTime is the firewall open time in seconds
	OpenTime uint32 `json:"open_time"`
	// CookieDomain is the domain for setting NHP cookies
	CookieDomain string `json:"cookie_domain"`

	// IsCustomDomain indicates the resource uses a custom domain instead of qurl.site.
	// When true, the redirect URL and cookie domain come from the custom domain
	// and should bypass the AllowedRedirectDomain check (only HTTPS is required).
	IsCustomDomain bool `json:"is_custom_domain,omitempty"`

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

// Resolve validates an access token and returns resource data.
// This calls the legacy QURL API internal endpoint: POST /internal/v1/resolve.
func (r *QurlResolver) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	return r.resolvePath(ctx, "/internal/v1/resolve", req, req.RequestID)
}

// ResolveBrowserRelay validates a qURL token and binds the authenticated JS
// agent pubkey for the relay-first browser flow. This endpoint is called only by
// nhp-server after it decrypts a relay-forwarded browser knock; the browser
// never calls qurl-service directly.
func (r *QurlResolver) ResolveBrowserRelay(ctx context.Context, req *BrowserRelayResolveRequest) (*ResolveResponse, error) {
	return r.resolvePath(ctx, "/internal/v1/browser-relay/resolve", req, req.RequestID)
}

func (r *QurlResolver) resolvePath(ctx context.Context, path string, req any, requestID string) (*ResolveResponse, error) {
	// Build request body. G117 (secret-in-json): ResolveRequest carries
	// AccessToken — marshaling into the internal resolve POST is
	// the whole point of this call. Newer gosec flags the Marshal
	// callsite via taint analysis even when the field has its own
	// nolint; suppress here with the protocol-required rationale.
	body, err := json.Marshal(req) //nolint:gosec // G117
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build HTTP request
	url := fmt.Sprintf("%s%s", r.baseURL, path)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if requestID != "" {
		httpReq.Header.Set(nhpserver.RequestIDHeader, requestID)
	}

	// Add service token authentication header
	// Fail fast if token is empty - this should never happen due to config validation,
	// but proceeding without auth would be a silent security issue.
	if r.serviceToken == "" {
		return nil, errors.New("service token is empty - cannot authenticate with QURL API")
	}
	httpReq.Header.Set(ServiceTokenHeader, r.serviceToken)

	// Execute request
	log.Debug("[QURL] [req_id=%s] Calling QURL API: %s", requestID, url)
	resp, err := r.httpClient.Do(httpReq) //nolint:gosec // G704: URL from QURL_API_URL env var with schema validation
	if err != nil {
		log.Error("[QURL] [req_id=%s] HTTP request failed: %v", requestID, err)
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
		log.Error("[QURL] [req_id=%s] QURL API returned status %d: %s", requestID, resp.StatusCode, string(respBody))
		return nil, r.parseErrorResponse(resp.StatusCode, respBody)
	}

	// Parse response
	var internalResp internalResolveResponse
	if err := json.Unmarshal(respBody, &internalResp); err != nil {
		log.Error("[QURL] [req_id=%s] Failed to parse response: %v", requestID, err)
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

	if err := validateResolveResponse(internalResp.Data); err != nil {
		log.Error("[QURL] [req_id=%s] Invalid resolve response: %v", requestID, err)
		return nil, fmt.Errorf("%w: %s", ErrInvalidResolveResponse, err.Error())
	}

	return internalResp.Data, nil
}

// Authorize asks qurl-service whether clientIP currently holds an active
// session for resourceID (an r_ resource id). This is the token-less,
// idempotent, IP-scoped session check the NHP knock path uses — the same one
// qurl-router runs per HTTP request — so a re-knock or relay-forwarded knock
// (#2208) re-consults the live session without a token.
//
// Returns the decision on HTTP 200; ErrQurlAccessDenied on 403/404/410 (no
// active session / unknown / expired); ErrInvalidResolveResponse on a
// malformed 200 body; and a wrapped transient error otherwise.
func (r *QurlResolver) Authorize(ctx context.Context, resourceID, clientIP, requestID string) (*AuthorizeResult, error) {
	if r.serviceToken == "" {
		return nil, errors.New("service token is empty - cannot authenticate with QURL API")
	}

	authURL := fmt.Sprintf("%s/internal/v1/resource/%s/authorize?client_ip=%s",
		r.baseURL, url.PathEscape(resourceID), url.QueryEscape(clientIP))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorize request: %w", err)
	}
	httpReq.Header.Set(ServiceTokenHeader, r.serviceToken)
	if requestID != "" {
		httpReq.Header.Set(nhpserver.RequestIDHeader, requestID)
	}

	resp, err := r.httpClient.Do(httpReq) //nolint:gosec // G704: baseURL from QURL_API_URL env var with schema validation
	if err != nil {
		return nil, fmt.Errorf("failed to call QURL authorize API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read authorize response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var out AuthorizeResult
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidResolveResponse, err.Error())
		}
		return &out, nil
	case http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		// 403 no active session for this client; 404 unknown resource; 410
		// expired/consumed/revoked — all map to "not authorized now".
		return nil, ErrQurlAccessDenied
	default:
		return nil, fmt.Errorf("qurl authorize returned status %d", resp.StatusCode)
	}
}

// validateResolveResponse checks that the QURL API returned the fields the
// plugin still depends on for a successful NHP knock. Missing fields here would
// cause a downstream failure with a less actionable error message.
//
// AC routing is deliberately NOT validated here: as of #2540 the plugin
// resolves routing from the server-owned catalog keyed by NHPResourceID, so the
// response's `resources` map is ignored (and removed entirely by qurl-service
// in layervai/qurl-service#823). NHPResourceID is now the load-bearing field:
// without it there is no catalog key, and it must be a dynamic qURL key (q_ +
// 11 hex) so the resolver takes the exact-row lookup the plugin's qURLs use. A
// malformed id would otherwise pass, fall through to the ASP-placement branch,
// and surface as a generic FailResolveCatalog miss — so fail fast here with an
// actionable FailValidate using the resolver's own predicate (no drift).
func validateResolveResponse(resp *ResolveResponse) error {
	if resp.NHPResourceID == "" {
		return errors.New("QURL API returned empty nhp_resource_id — required to resolve AC routing from the NHP catalog")
	}
	if !nhpserver.IsQURLDynamicResourceID(resp.NHPResourceID) {
		return fmt.Errorf("QURL API returned nhp_resource_id %q that is not a dynamic qURL catalog key (expected q_ + 11 hex)", resp.NHPResourceID)
	}

	return nil
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
