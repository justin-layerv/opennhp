package qurl

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	nhpserver "github.com/OpenNHP/opennhp/endpoints/server"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"

	nhpplugins "github.com/fengyily/nhp-plugins-sdk"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
)

const (
	name    = "qurl"
	version = "1.0.0"

	// knockMaxAttempts is the total number of knock attempts (initial + retries).
	// Multiple attempts handle transient failures: stale connections get closed
	// on timeout, so subsequent attempts use fresh connections.
	knockMaxAttempts = 3

	// knockRetryDelay is the wait time before retrying a failed NHP knock.
	// This gives time for AC connections to re-establish during blue/green
	// deployments or transient connectivity gaps.
	knockRetryDelay = 2 * time.Second

	// redirectURLField names the JSON field on the JSON branch of
	// /plugins/qurl. MIRROR: redirectURLField in
	// tests/smoke/15_resolve_accept_negotiation_test.go must rename
	// in lockstep — they live in separate Go modules so an import
	// would create a worse coupling. Same name on both sides reduces
	// #1325's CI grep guard to a literal grep. Tracked in #1325.
	redirectURLField = "redirect_url"
)

var (
	resolver *QurlResolver
	initOnce sync.Once
	initErr  error
)

// Version returns the plugin version string
func Version() string {
	return name + " v" + version
}

// Init initializes the QURL plugin with configuration.
// Returns an error if required configuration is missing (fail-fast).
// Uses sync.Once to ensure thread-safe initialization even if called multiple times.
func Init(in *plugins.PluginParamsIn) error {
	_ = in // unused but required by plugin interface

	initOnce.Do(func() {
		resolver, initErr = NewQurlResolver()
		if initErr != nil {
			initErr = fmt.Errorf("[QURL] failed to initialize: %w", initErr)
			return
		}
		log.Info("[QURL] Plugin initialized: %s", Version())
	})

	return initErr
}

// Close shuts down the plugin and releases resources.
// The nil check is defensive - Close may be called even if Init failed or was never called.
func Close() error {
	if resolver != nil {
		_ = resolver.Close()
	}
	log.Info("[QURL] Plugin closed")
	return nil
}

// AuthWithHttp handles HTTP-based QURL token resolution and NHP knock
//
// Flow:
//  1. User visits qurl.link/#<access_token>
//  2. qurl.link SPA extracts fragment and submits a form POST to /plugins/qurl
//     with token=<access_token> in the request body (not the URL)
//  3. This handler validates the token via QURL API
//  4. On success, triggers NHP knock via helper callback
//  5. Sets NHP cookies and redirects to qurl.site resource
//
// The POST body path is preferred because it keeps the access token out of
// URL query strings, which appear in CloudFront access logs, NHP access logs,
// and any intermediary that captures request URIs. The GET query parameter
// path is retained for backward compatibility but logs a deprecation warning.
//
// Response shape (only the success branch honors Accept; error paths
// keep their existing shapes for backward compatibility with form-POST
// callers). Each row maps a (status, Content-Type) pair to a body shape;
// SPAs MUST discriminate on that pair, not on the fact that they sent
// Accept: application/json — both success and inline-5xx errors are JSON,
// so a blind JSON.parse on every 200 is wrong without the Content-Type
// gate.
//
//	200 + application/json   {redirect_url: ...}        (Accept: application/json)
//	302 + Location header    no body                    (any other Accept)
//	403 + text/html          branded error page         (token validation OR handleResolveError)
//	502 + text/html          branded error page         (handleResolveError, ErrInvalidResolveResponse)
//	5xx + application/json   {error, message, detail}   (inline failures: knock_failed, configuration_error, etc.)
//
// Fenced by TestAuthWithHttp_AcceptJSON_ErrorStaysHTML (HTML 403 from
// token validation), TestHandleResolveError_InvalidResolve_Return502
// (HTML 502 from handleResolveError), and
// TestAuthWithHttp_AcceptJSON_KnockFailedStaysJSON (JSON 500 from inline knock).
//
// Security note: Rate limiting should be handled at infrastructure level (NLB, WAF)
// to protect against brute-force token guessing attacks.
func AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	if helper == nil {
		// Defensive wiring check; unreachable in production (the
		// dispatcher always passes a real helper). This branch
		// returns before any header is written, so it doesn't
		// carry Vary: Accept.
		return nil, errors.New("authWithHTTP: helper is null")
	}

	requestID := getOrCreateRequestID(ctx)
	ctx.Header(nhpserver.RequestIDHeader, requestID)

	// SameSite=None for cross-origin cookies set later in this handler
	// (nhp_token, nhp_refresh_token, nhp_session_ttl) — the qurl.link.*
	// SPA needs them on a credentialed fetch to a different host.
	//
	// CORS headers are written by the engine-level corsMiddleware in
	// httpserver.go, which runs before this handler and covers every
	// route including error paths. Do NOT call nhpplugins.CorsMiddleware
	// here: in nhp-plugins-sdk v0.1.30 it overwrites
	// Access-Control-Expose-Headers with a stale default
	// ("Content-Length, Content-Type, Authorization") that drops
	// Set-Cookie, silently breaking the SPA's credentialed-fetch cookie
	// pickup. See #1394 for the lint that prevents reintroduction.
	ctx.SetSameSite(http.SameSiteNoneMode)

	// Vary: Accept on every response so caching intermediaries key on
	// the negotiated shape, not just the URL. Add (not Set) to append
	// to the Vary: Origin written by the engine middleware. Fenced by
	// TestAuthWithHttp_AcceptJSON_VaryAddDoesNotClobberPreexisting.
	ctx.Writer.Header().Add("Vary", "Accept")

	// Extract access token: prefer POST form body, fall back to query parameter.
	// POST body keeps the token out of access logs (CloudFront, NHP, intermediaries).
	// Query parameter is deprecated regardless of HTTP method — the token appears
	// in the URL either way, and URLs are logged by every intermediary.
	// Note: PostForm requires Content-Type: application/x-www-form-urlencoded.
	// The qurl.link SPA uses a hidden <form> submit which sets this automatically.
	var accessToken string
	if ctx.Request.Method == http.MethodPost {
		accessToken = ctx.PostForm("token")
	}
	if accessToken == "" {
		accessToken = ctx.Query("token")
		if accessToken != "" {
			log.Warning("[QURL] [req_id=%s] [client=%s] DEPRECATED: token passed as query param — migrate to POST body", requestID, ctx.ClientIP())
		}
	}
	if err := ValidateAccessToken(accessToken); err != nil {
		log.Error("[QURL] [req_id=%s] Invalid access token from %s: %v", requestID, ctx.ClientIP(), err)
		ctx.Data(http.StatusForbidden, "text/html; charset=utf-8", []byte(accessDeniedHTML))
		ctx.Abort()
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	// Resolve the access token via QURL API
	resolveReq := &ResolveRequest{
		AccessToken: accessToken,
		SrcIP:       ctx.ClientIP(),
		UserAgent:   ctx.Request.UserAgent(),
		RequestID:   requestID,
	}

	resolveResp, err := resolver.Resolve(ctx.Request.Context(), resolveReq)
	if err != nil {
		log.Error("[QURL] [req_id=%s] Token resolution failed: %v", requestID, err)
		handleResolveError(ctx, err)
		return nil, err
	}

	log.Info("[QURL] [req_id=%s] Token resolved successfully: resource_id=%s, resources=%d", requestID, resolveResp.ResourceID, len(resolveResp.Resources))

	// Build ResourceData from the resolved response
	res := buildResourceData(resolveResp)

	// Trigger NHP knock via helper callback.
	// Retry on failure: timed-out connections are closed after the first failure,
	// so subsequent attempts use fresh connections. This handles transient AC
	// connectivity issues during blue/green deployments or network blips.
	// The retry loop is context-aware: if the client disconnects or the HTTP
	// write deadline passes, retries stop to avoid wasted work.
	reqCtx := ctx.Request.Context()
	for attempt := 1; attempt <= knockMaxAttempts; attempt++ {
		ackMsg, err = helper.AuthWithHttpCallbackFunc(req, res)
		if err == nil {
			break
		}
		if attempt < knockMaxAttempts {
			log.Warning("[QURL] [req_id=%s] NHP knock failed (attempt %d/%d): %v, retrying...", requestID, attempt, knockMaxAttempts, err)
			select {
			case <-time.After(knockRetryDelay):
			case <-reqCtx.Done():
				log.Warning("[QURL] [req_id=%s] NHP knock retry canceled: %v", requestID, reqCtx.Err())
				err = fmt.Errorf("knock canceled: %w", reqCtx.Err())
			}
			if reqCtx.Err() != nil {
				break
			}
		}
	}
	if err != nil {
		log.Error("[QURL] [req_id=%s] NHP knock failed after %d attempts: %v", requestID, knockMaxAttempts, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "knock_failed",
			"message": "Failed to open access to resource",
			"detail":  err.Error(),
		})
		return nil, err
	}

	if ackMsg == nil || len(ackMsg.ResourceHost) == 0 {
		log.Error("[QURL] [req_id=%s] NHP knock returned no resource hosts", requestID)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "no_resource_hosts",
			"message": "No resource hosts available",
		})
		return nil, errors.New("no resource hosts available")
	}

	log.Info("[QURL] [req_id=%s] NHP knock succeeded: hosts=%v", requestID, ackMsg.ResourceHost)

	// Generate NHP tokens and set cookies
	jwtSecret := nhpsdkutils.GetStringFromMap(res.ExInfo, ExInfoKeyJWTSecret)
	if jwtSecret == "" {
		log.Error("[QURL] [req_id=%s] JWT secret is empty - cannot generate tokens", requestID)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "configuration_error",
			"message": "JWT secret not configured",
		})
		return nil, errors.New("JWT secret is empty")
	}

	jwt := &nhpplugins.JWTToken{
		JwtKey: []byte(jwtSecret),
	}

	nhpToken, refreshToken, err := jwt.GenerateAll(res.AuthServiceId, res)
	if err != nil {
		log.Error("[QURL] [req_id=%s] Failed to generate tokens: %v", requestID, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "token_generation_failed",
			"message": "Failed to generate access tokens",
		})
		return nil, err
	}

	// Validate cookie domain and redirect URL BEFORE setting any cookies.
	// This ensures we don't set cookies if either validation fails.
	// When IsCustomDomain is true, the QURL API (authenticated via service token)
	// tells us the domain is valid, so we only need to verify HTTPS and basic structure.
	var cookieErr, redirectErr error
	if resolveResp.IsCustomDomain {
		cookieErr = ValidateCustomDomainCookieDomain(res.CookieDomain)
		redirectErr = ValidateCustomDomainRedirectURL(resolveResp.QurlSiteURL)
	} else {
		cookieErr = ValidateCookieDomain(res.CookieDomain, resolver.AllowedRedirectDomain())
		redirectErr = ValidateRedirectURL(resolveResp.QurlSiteURL, resolver.AllowedRedirectDomain())
	}
	if cookieErr != nil {
		log.Error("[QURL] [req_id=%s] Invalid cookie domain from API: %v", requestID, cookieErr)
		ctx.JSON(http.StatusBadGateway, gin.H{
			"error":   "invalid_cookie_domain",
			"message": "Invalid cookie domain from upstream service",
		})
		return nil, fmt.Errorf("invalid cookie domain: %w", cookieErr)
	}
	if redirectErr != nil {
		log.Error("[QURL] [req_id=%s] Invalid redirect URL from API: %v", requestID, redirectErr)
		ctx.JSON(http.StatusBadGateway, gin.H{
			"error":   "invalid_redirect",
			"message": "Invalid redirect URL from upstream service",
		})
		return nil, fmt.Errorf("invalid redirect URL: %w", redirectErr)
	}

	// Now safe to set cookies and redirect.
	// Per-QURL session_duration overrides the global token_expire for cookie MaxAge
	// so the QURL creator controls how long access lasts after clicking.
	tokenExpire := nhpsdkutils.GetIntFromMap(res.ExInfo, ExInfoKeyTokenExpire)
	cookieMaxAge := tokenExpire
	if sessionDuration := nhpsdkutils.GetIntFromMap(res.ExInfo, ExInfoKeySessionDuration); sessionDuration > 0 {
		cookieMaxAge = sessionDuration
	}
	ctx.SetCookie(CookieNHPToken, nhpToken, cookieMaxAge, "/", res.CookieDomain, true, true)
	ctx.SetCookie(CookieNHPRefreshToken, refreshToken, cookieMaxAge, "/", res.CookieDomain, true, true)
	// Communicate session TTL to downstream middleware (hqdatamiddleware) so it
	// can align its session_id cookie expiry with the NHP cookie.
	ctx.SetCookie(CookieNHPSessionTTL, strconv.Itoa(cookieMaxAge), cookieMaxAge, "/", res.CookieDomain, true, true)

	// Negotiate response shape from the Accept header.
	// Form-POST (legacy SPA) gets a 302; fetch() callers that want progressive
	// UI send Accept: application/json and receive {"redirect_url": "..."} so
	// they can stay on the qurl.link page until the knock is confirmed.
	//
	// Note: error paths above (token-invalid 403, knock_failed 500, etc.)
	// keep their existing shapes — branded HTML for 403 token errors, JSON
	// {error, message, detail} for 5xx — even when the caller asked for
	// JSON. Consumers that send Accept: application/json must handle both
	// the success {redirect_url} body and the existing error shapes.
	// Unified log prefix so an operator can `grep "[QURL] resolved ->"` to
	// see every successful resolve and trivially aggregate by shape during
	// the SPA rollout.
	if wantsJSON(ctx) {
		log.Info("[QURL] [req_id=%s] resolved -> %s (shape=json)", requestID, resolveResp.QurlSiteURL)
		ctx.JSON(http.StatusOK, gin.H{redirectURLField: resolveResp.QurlSiteURL})
	} else {
		log.Info("[QURL] [req_id=%s] resolved -> %s (shape=302)", requestID, resolveResp.QurlSiteURL)
		ctx.Redirect(http.StatusFound, resolveResp.QurlSiteURL)
	}

	return ackMsg, nil
}

// wantsJSON returns true when the client signaled (via Accept) that it wants
// a JSON body instead of a 302. We only return JSON when application/json is
// explicitly requested — the wildcard "*/*" still gets the 302 path so legacy
// form-POST callers (with no explicit Accept) keep their existing behavior.
//
// Parsing uses mime.ParseMediaType per comma-separated segment, which handles
// quoted-string parameters, folded whitespace, and case normalization (the
// returned media type is lowercased) without bespoke logic. Malformed
// segments are skipped silently — we only need one valid match.
//
// Multiple Accept headers are folded into one comma-separated value via
// Header.Values, matching RFC 7230's equivalence rule. Real clients
// (browsers, fetch, every SDK) emit a single header; the fold covers the
// rare case where a Go SDK uses Header.Add("Accept", ...) twice.
//
// Known RFC simplifications (consciously chosen for parser simplicity, not
// merely because browsers + fetch() don't emit them today):
//   - q=0 is treated as accept, not reject. RFC 7231 §5.3.1 says q=0 means
//     "not acceptable"; we ignore the q value entirely. The tradeoff is
//     deliberate: a strict client doing
//     `Accept: application/json;q=0, text/html` will receive JSON it
//     didn't want. The redirect_url body is the same value the 302
//     Location would have leaked, so the surprise is annoying but not
//     security-impacting. If/when a real client legitimately uses q=0
//     to deselect application/json, file an issue and we'll switch to
//     a q-aware parser.
//   - Preference order is ignored. "text/html;q=1, application/json;q=0.1"
//     returns true; we don't sort by quality.
//   - +json structured-syntax suffixes (application/vnd.api+json,
//     application/hal+json, etc.) do NOT match. Only application/json
//     itself triggers the JSON branch. If a future caller needs +json
//     types, replace the equality check below with
//     strings.HasSuffix(mt, "+json") — mt is already lowercased by
//     mime.ParseMediaType so no ToLower is needed.
//   - Commas inside quoted media-type parameters (e.g.
//     `application/json;param="a,b"`) split the segment incorrectly:
//     strings.Split is comma-naive, mime.ParseMediaType then fails
//     on each fragment, and we fall through to the legacy 302 path.
//     No real Accept header uses quoted-string parameters with
//     commas; flagged here so the next bug-tracer doesn't have to
//     re-derive it.
//
// If a future client legitimately needs strict negotiation, swap to a parser
// that honors q-values (e.g. github.com/elnormous/contenttype). Until then,
// matching by presence is faster, simpler, and correct for every real caller.
func wantsJSON(ctx *gin.Context) bool {
	values := ctx.Request.Header.Values("Accept")
	if len(values) == 0 {
		return false
	}
	accept := strings.Join(values, ",")
	for _, part := range strings.Split(accept, ",") {
		mt, _, err := mime.ParseMediaType(part)
		if err != nil {
			continue
		}
		// mime.ParseMediaType lowercases the media type, so a literal
		// equality check is sufficient — no EqualFold needed.
		if mt == "application/json" {
			return true
		}
	}
	return false
}

// getOrCreateRequestID returns the request ID from the Gin context.
// In production, the server's requestIDMiddleware has already validated and
// set the ID before this handler runs. The UUID fallback is defensive — it
// covers edge cases like direct handler invocation in tests.
func getOrCreateRequestID(ctx *gin.Context) string {
	if id := nhpserver.GetRequestID(ctx); id != "" {
		return id
	}
	id := uuid.NewString()
	ctx.Set(nhpserver.RequestIDKey, id)
	return id
}

// buildResourceData constructs a ResourceData from the QURL API response
func buildResourceData(resp *ResolveResponse) *common.ResourceData {
	return &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId:    resp.ResourceID,
			AuthServiceId: PluginID,
			OpenTime:      resp.OpenTime,
			Resources:     resp.Resources,
		},
		ExInfo: map[string]any{
			ExInfoKeyJWTSecret:       resp.JWTSecret,
			ExInfoKeyTokenExpire:     resp.TokenExpire,
			ExInfoKeySessionDuration: resp.SessionDuration,
		},
		RedirectUrl:  resp.QurlSiteURL,
		CookieDomain: resp.CookieDomain,
	}
}

// nhpDrop silently drops the connection without sending any HTTP response.
// NOTE: Currently unused — all QURL error paths return the branded HTML error
// page to avoid CloudFront 502 errors. Kept for potential future use in other
// NHP stealth scenarios.
// This implements NHP (Network Hiding Protocol) behavior: unauthorized requests
// receive no application-level response, making the server appear non-existent.
// Behind infrastructure (CloudFront/NLB), this manifests as a generic 502/504.
func nhpDrop(ctx *gin.Context) {
	// Attempt to hijack the TCP connection for a true NHP silent drop.
	// In production, Hijack() closes the raw TCP connection — the client
	// sees a connection reset with no HTTP response.
	// In tests (httptest.ResponseRecorder), gin's Hijack() panics because
	// the underlying writer doesn't support it, so we recover gracefully.
	func() {
		defer func() { recover() }() //nolint:errcheck // side-effect intentional; return value unused
		if conn, _, err := ctx.Writer.Hijack(); err == nil && conn != nil {
			_ = conn.Close()
		}
	}()
	// Prevent any further handler processing
	ctx.Abort()
}

// handleResolveError handles token resolution failures.
// accessDeniedHTML is the branded error page shown when a QURL access link is
// invalid, expired, consumed, or denied by policy. Matches the SPA error page
// design from qurl/frontend/index.html. Generic message — no token state leaked.
const accessDeniedHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Access Link Invalid</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{text-align:center;padding:2rem;max-width:480px}
.wordmark{margin-bottom:1.5rem}
.wordmark svg{width:160px;height:auto}
.icon{font-size:3rem;margin-bottom:1.5rem}
h2{font-size:1.5rem;font-weight:600;color:#fff;margin-bottom:1rem}
p{font-size:.9375rem;line-height:1.6;color:#a0a0b0;margin-bottom:2rem}
.footer{font-size:.75rem}
.footer a{color:#555;text-decoration:none}
.footer a:hover{color:#00d4ff}
</style>
</head>
<body>
<div class="container">
<div class="wordmark" aria-label="LayerV"><svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" style="fill-rule:evenodd;clip-rule:evenodd;stroke-linejoin:round;stroke-miterlimit:2" viewBox="0 0 3342 728"><path d="M370.288 117.879c13.508 1.595 13.487 3.183 26.992 1.01 8.007-1.288 9.654 1.071 38.549-12.377C652.861 5.51 651.941.991 674.702.267c13.244-.421 48.385 18.663 70.545 29.218 24.179 11.517 26.649 17.076 27.752 19.559.651 1.465 5.665 16.512-4.277 23.996-13.613 10.247-14.52 8.696-192.064 92.566-139.65 65.969-139.225 66.796-151.811 71.464-13.858 5.14-25.163 9.724-54.513 5.862-13.502-1.777-13.101-3.328-125.746-55.812-85.123-39.661-141.675-67.403-175.527-82.599-58.554-26.286-62.189-31.14-65.783-35.94-6.729-8.986-2.708-22.526 8.544-29.209 6.047-3.591 44.261-22.902 57.636-28.726C89.721 1.823 102.565-6.7 131.09 7.838c7.217 3.678 7.314 3.265 91.397 43.578 8.253 3.957 23.34 10.348 74.214 35.199 17.307 8.454 17.582 7.749 34.817 16.292 16.992 8.422 35.586 14.014 38.77 14.972" style="fill:#07dcef"/><path d="M774.581 295.425c-.221 1.223.076 2.503-.145 3.726-2.824 15.621-27.108 22.426-83.212 48.932-21.873 10.333-263.82 124.639-273.786 128.363-.236.088-19.589 10.292-54.717.789-13.714-3.71-94.021-43.537-125.235-57.268-4.441-1.954-104.797-49.104-113.906-53.384C9.219 312.852 1.798 312.351.475 295.395c-1.242-15.914 21.48-25.359 38.07-34.073 14.602-7.67 24.613-7.755 26.849-7.774 12.853-.109 13.945.956 63.265 24.551 7.444 3.561 7.609 3.193 93.344 43.912 122.703 58.278 125.052 59.148 136.329 63.324 33.738 12.494 57.899.521 73.53-5.823 8.21-3.332 156.551-74.541 187.982-88.442 40.047-17.711 66.378-37.387 90.054-37.226 7.293.05 11.878-1.702 49.836 19.809 1.348.764 11.637 6.595 13.812 13.573.197.631.077.606 1.034 8.198Z" style="fill:#4a77e2"/><path d="m385.681 363.638-8.045-.394c-7.972-1.187-26.148-7.641-41.914-14.946-46.717-21.647-46.767-21.362-50.788-23.317-42.778-20.793-101.657-48.031-105.752-50.162-5.271-2.742-153.242-71.77-168.657-80.678C2.632 189.58-.066 179.914.492 174.445c1.255-12.285 8.192-16.652 40.988-32.307 31.305-14.943 40.09-5.087 70.595 9.131 45.994 21.437 187.475 88.683 191.175 90.38 57.928 26.571 57.991 27.227 70.637 28.124 27.611 1.959 32.504-.575 43.521-3.921 6.31-1.917 6.582-1.383 203.126-94.421 81.472-38.567 83.298-41.215 105.328-33.078 6.077 2.245 24.857 11.465 31.458 15.523 6.508 4.001 16.763 8.439 17.279 20.527.72 16.861-14.736 22.745-17.246 24.336-1.95 1.236-62.884 30.141-74.238 35.41-173.537 80.52-173.053 81.457-188.233 88.252-16.473 7.374-67.414 33.508-86.106 37.775-11.498 2.625-11.376 3.269-23.096 3.46Z" style="fill:#0aa4e4"/><path d="M774.539 412.681c-1.136 8.553 1.959 13.047-22.23 26.165-7.191 3.9-110.535 51.194-148.665 69.722-5.908 2.871-6.085 2.473-74.232 35.091-12.576 6.019-51.325 23.221-93.356 43.913-14.735 7.254-20.168 10.54-46.506 11.623-29.325 1.206-47.272-11.208-62.657-18.167-7.051-3.189-82.872-39.072-90.073-42.48-60.999-28.868-168.879-79.107-183.579-85.953-32.659-15.209-60.896-25.162-50.133-47.654 4.392-9.178 13.066-12.204 31.708-22.229.833-.448 21.022-10.005 30.463-10.625 8.036-.528 12.128-.796 93.222 37.98 91.98 43.981 92.116 43.545 140.634 66.406 67.013 31.575 82.769 44.069 133.056 21.261 100.657-45.652 255.586-124.494 273.721-125.683 14.219-.932 27.511 7.139 46.97 17.147 24.397 12.549 21.58 23.165 21.659 23.481Z" style="fill:#7c45dd"/><path d="M385.741 629.181c30.526-2.243 37.191-8.055 116.648-45.703 7.832-3.711 93.183-44.151 97.957-46.255 82.159-36.203 95.991-58.243 136.354-37.49 23.037 11.844 37.154 17.214 37.821 30.213.955 18.609-9.486 21.272-16.745 25.186-27.738 14.957-62.657 29.506-91.515 43.559-81.747 39.807-82.574 37.941-164.121 78.049-27.481 13.516-27.847 12.633-45.84 21.615-48.536 24.229-58.566 21.696-70.591 21.703-31.684.018-63.147-22.104-78.764-28.378-8.328-3.346-68.705-32.098-82.294-38.96-13.89-7.014-14.357-5.93-50.67-23.565-17.935-8.71-127.641-59.099-159.461-75.753-2.17-1.136-19.699-10.311-12.543-27.929 4.724-11.631 46.38-30.132 47.824-30.705 29.018-11.533 41.911 4.304 101.656 30.867 8.418 3.743 147.146 69.48 148.542 70.071 39.744 16.823 57.887 31.645 85.742 33.477Z" style="fill:#ba1bd8"/><path d="M1266.335 529.82c0 28.048 3.035 36.122-13.409 36.548-10.894.282-287.037.154-289.203.043-15.524-.798-12.863-15.482-12.848-40.498.022-36.563.277-455.913.288-457.043.209-20.21 8.097-17.019 28.277-17.064 64.11-.14 66.604-1.142 69.191 5.839 2.176 5.873 1.048 6.157 1.179 390.143.007 21.07-1.346 28.546 15.523 28.899 20.637.431 188.144-.268 191.261.231 9.85 1.579 9.674 7.707 9.731 13.816.012 1.288.009 30.369.009 39.084Z" style="fill:#fcfcfc"/><path d="M1498.938 180.343c7.858-.042 7.762-.089 15.712-.007 16.318.169 19.934 2.392 27.137 3.128 2.255.23 13.622 1.392 27.675 6.052 47.384 15.715 68.143 35.681 75.134 42.266 19.732 18.588 21.416 23.552 27.403 31.579 17.905 24.007 27.142 58.051 28.391 67.436 1.822 13.695 3.741 13.406 4.108 27.206.407 15.302 1.557 58.463.588 191.341-.111 15.222-2.916 17.201-18.613 17.201-64.076 0-64.096-.776-66.353-1.678-11.066-4.421-1.72-34.042-7.382-35.732-6.716-2.004-8.2 4.388-16.545 11.904-41.353 37.241-106.539 43.247-164.17 25.706-37.333-11.363-67.702-36.99-77.919-48.341-19.484-21.647-28.425-36.774-35.615-54.662-31.874-79.299-7.64-145.318-3.709-156.8 5.588-16.322 19.431-41.582 30.928-55.213 20.215-23.968 34.157-32.744 40.623-37.382 18.816-13.5 49.571-24.165 57.606-25.931 17.166-3.772 17.071-4.266 23.919-4.698 15.643-.986 15.403-2.772 31.081-3.375Zm11.684 85.585c-20.302-.151-20.309.03-30.992 2.84-4.461 1.174-34.537 9.086-51.264 26.389-32.42 33.536-33.18 75.246-33.31 82.352-1.036 56.831 35.884 101.778 84.184 110.385 64.216 11.444 96.007-20.728 104.559-29.479 14.818-15.163 25.313-42.346 26.736-57.625 1.848-19.84 1.341-25 1.129-27.164-1.49-15.175-.848-32.737-18.692-62.72-3.714-6.24-21.956-27.36-42.81-35.965-15.801-6.521-36.313-8.674-39.539-9.013Z" style="fill:#fcfcfc"/><path d="M1770.641 666.535c.169-6.866-1.383-15.775 9.804-18.227 1.591-.349 1.576-.168 11.498-.184 2.237-.004 13.816-.022 27.739-3.576 47.775-12.194 64.344-61.742 60.654-79.272-1.5-7.124-119.041-289.856-140.272-343.61-7.523-19.046-10.223-24.22-8.503-28.688 2.095-5.439 8.149-4.557 52.574-4.52 35.358.029 40.092-2.112 47.583 16.866l78.195 199.19c16.406 41.634 15.301 42.019 17.798 47.722 3.46 7.901 8.092 3.717 8.64 3.222 1.452-1.311 1-1.558 2.914-8.031 1.076-3.64 1.161-3.605 72.082-202.522 16.222-45.5 17.175-53.981 30.413-56.087 6.933-1.103 72.081-.528 74.57-.294 11.921 1.119 11.162 5.627 6.902 16.797-19.509 51.142-19.505 51.064-21.192 55.508-6.568 17.301-113.975 294.836-115.95 299.771-21.806 54.494-45.313 130.026-112.309 156.252-32.495 12.72-56.857 10.848-70.156 10.206-22.794-1.101-32.353.033-32.741-21.416-.545-30.082-.348-35.98-.243-39.107" style="fill:#fbfbfb"/><path d="M2342.731 180.043c5.98.258 5.905.295 11.84.51 12.701.461 17.012 2.502 23.169 3.021 19.713 1.663 47.994 10.092 71.491 24.179 74.166 44.467 82.732 122.549 85.424 134.444 3.513 15.524 1.845 59.462.658 63.073-1.834 5.581-8.133 6.967-9.034 7.165-6.126 1.348-268.923.387-277.098 1.436-2.033.261-13.302 1.707.672 25.618.908 1.553 6.964 11.917 12.392 18.764 35.747 45.092 125.481 52.456 170.595 1.49 2.794-3.156 2.491-3.308 5.27-6.538 7.711-8.959 17.602-1.496 52.769 18.514 16.388 9.325 22.12 11.809 21.421 19.243-.58 6.173-18.282 26.067-28.564 35.38-24.6 22.28-44.655 30.512-51.632 33.707-17.257 7.902-46.169 13.335-54.083 14.037-61.781 5.483-91.445-5.499-101.822-8.753-57.732-18.104-91.409-61.975-99.674-75.672-25.783-42.728-28.05-78.878-29.726-96.515-1.435-15.093 1.094-44.649 4.193-58.71 11.435-51.887 30.837-74.047 37.668-83.302 37.934-51.4 96.874-63.006 103.33-64.928 11.422-3.402 11.704-1.528 23.43-3.846 13.508-2.671 19.655-2.015 27.312-2.317Zm-71.144 106.708c-4.628 4.491-15.444 12.464-26.644 39.892-8.1 19.836 7.587 16.823 39.187 16.889 12.199.026 148.54.311 152.483-.569 14.196-3.168-2.046-34.501-12.424-47.062-31.427-38.04-77.602-34.96-85.325-34.663-9.649.371-39.34-.449-67.277 25.513" style="fill:#fcfcfc"/><path d="M2684.343 346.24c.77 38.002-.224 166.416-.132 195.27.029 9.164 2.135 24.455-13.271 25.063-.694.027-67.874.219-70.577-.107-11.703-1.414-9.915-6.537-9.915-52.271 0-173.397-.166-173.433 1.799-183.68 2.271-11.839 9.081-95.713 97.734-129.878 17.384-6.7 17.449-6.297 35.323-11.38 7.914-2.251 8.225-.217 23.593-3.559 10.18-2.213 50.199-2.671 55.248-.747 7.529 2.869 6.34 9.587 6.133 59.706-.068 16.43 2.022 22.228-14.445 23.044-40.718 2.018-43.378 2.821-46.989 3.912-5.999 1.811-28.302 5.122-45.317 25.081-6.37 7.472-11.938 20.47-12.749 22.363-6.909 16.127-6.356 25.9-6.434 27.183Z" style="fill:#fbfbfb"/><path d="M3036.312 80.625c-.153 6.148.947 6.357-1.691 11.974-3.023 6.438-14.548 4.876-24.007 7.211-1.562.386-39.497 3.784-29.26 38.879 9.434 32.34 99.175 250.014 113.989 293.979 3.079 9.138 8.598 12.033 11.483 2.873 18.047-57.304 105.002-273.18 108.282-292.136 1.047-6.05 6.25-26.837-13.811-37.889-10.442-5.753-38.315-7.332-42.211-9.212-6.324-3.051-10.817-28.386 4.102-30.305 1.035-.133.993-.327 152.195-.312 12.154.001 22.683-1.383 24.967 6.636.532 1.867 3.251 20.993-5.192 24.366-16.365 6.538-21.224 2.46-40.691 17.253-4.065 3.089-4.671 2.568-15.178 16.789-15.274 20.674-42.348 94.058-64.969 149.297-7.499 18.313-6.669 18.615-89.379 230.65-21.702 55.636-20.96 58.879-32.405 60.523-2.221.319-43.561.568-46.369-.095-12.116-2.86-8.647-7.597-50.758-107.835-.223-.53-36.97-88.868-60.422-147.73-13.4-33.633-63.837-158.239-74.413-179.391-5.962-11.924-18.151-25.476-30.201-30.637-19.04-8.156-31.665-4.916-34.356-17.135-1.516-6.885-.422-17.992 3.26-20.082 6.062-3.442 9.642-2.585 195.795-2.806 11.133-.013 25.358-.202 31.049.626 10.663 1.553 9.54 9.411 10.192 14.508Z" style="fill:#fbfbfb"/></svg></div>
<div class="icon" role="img" aria-label="Lock icon">&#128274;</div>
<h2>Access Link Invalid</h2>
<p>This access link may have expired, been revoked, or already used. Please request a new access link from the resource owner.</p>
<div class="footer"><a href="https://layerv.ai" target="_blank">Powered by LayerV</a></div>
</div>
</body>
</html>`

// All resolve errors return the same branded HTML error page. The user sees
// "Access Link Invalid" regardless of whether the token was consumed, expired,
// not found, or denied by policy — no internal state is leaked. This also avoids
// CloudFront 502 errors that occur when connections are silently dropped.
func handleResolveError(ctx *gin.Context, err error) {
	statusCode := http.StatusForbidden
	if errors.Is(err, ErrInvalidResolveResponse) {
		statusCode = http.StatusBadGateway
	}
	ctx.Data(statusCode, "text/html; charset=utf-8", []byte(accessDeniedHTML))
	ctx.Abort()
}
