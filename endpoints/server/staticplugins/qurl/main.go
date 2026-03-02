package qurl

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"

	nhpplugins "github.com/fengyily/nhp-plugins-sdk"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
)

const (
	name    = "qurl"
	version = "1.0.0"
)

var (
	resolver *QurlResolver
	initOnce sync.Once
	initErr  error
)

// Version returns the plugin version string
func Version() string {
	return fmt.Sprintf("%s v%s", name, version)
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
		resolver.Close()
	}
	log.Info("[QURL] Plugin closed")
	return nil
}

// AuthWithHttp handles HTTP-based QURL token resolution and NHP knock
//
// Flow:
// 1. User visits qurl.link/#<access_token>
// 2. qurl.link SPA extracts fragment and redirects to /plugins/qurl?token=<access_token>
// 3. This handler validates the token via QURL API
// 4. On success, triggers NHP knock via helper callback
// 5. Sets NHP cookies and redirects to qurl.site resource
//
// Security note: Rate limiting should be handled at infrastructure level (NLB, WAF)
// to protect against brute-force token guessing attacks.
func AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	if helper == nil {
		return nil, errors.New("authWithHTTP: helper is null")
	}

	// Set CORS headers early so error responses are also CORS-enabled.
	// This is important for cross-origin error handling in the qurl.link SPA.
	ctx.SetSameSite(http.SameSiteNoneMode)
	nhpplugins.CorsMiddleware(ctx)

	// Extract and validate access token from query parameter.
	// NHP behavior: invalid tokens get silent connection drop — revealing nothing
	// about token format requirements or server existence.
	accessToken := ctx.Query("token")
	if err := ValidateAccessToken(accessToken); err != nil {
		log.Error("[QURL] Invalid access token from %s: %v", ctx.ClientIP(), err)
		nhpDrop(ctx)
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	// Resolve the access token via QURL API
	resolveReq := &ResolveRequest{
		AccessToken: accessToken,
		SrcIP:       ctx.ClientIP(),
		UserAgent:   ctx.Request.UserAgent(),
	}

	resolveResp, err := resolver.Resolve(ctx.Request.Context(), resolveReq)
	if err != nil {
		log.Error("[QURL] Token resolution failed: %v", err)
		handleResolveError(ctx, err)
		return nil, err
	}

	log.Info("[QURL] Token resolved successfully: resource_id=%s", resolveResp.ResourceID)

	// Build ResourceData from the resolved response
	res := buildResourceData(resolveResp)

	// Trigger NHP knock via helper callback
	ackMsg, err = helper.AuthWithHttpCallbackFunc(req, res)
	if err != nil {
		log.Error("[QURL] NHP knock failed: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "knock_failed",
			"message": "Failed to open access to resource",
		})
		return nil, err
	}

	if ackMsg == nil || len(ackMsg.ResourceHost) == 0 {
		log.Error("[QURL] NHP knock returned no resource hosts")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "no_resource_hosts",
			"message": "No resource hosts available",
		})
		return nil, errors.New("no resource hosts available")
	}

	log.Info("[QURL] NHP knock succeeded: hosts=%v", ackMsg.ResourceHost)

	// Generate NHP tokens and set cookies
	jwtSecret := nhpsdkutils.GetStringFromMap(res.ExInfo, "JWTSecret")
	if jwtSecret == "" {
		log.Error("[QURL] JWT secret is empty - cannot generate tokens")
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
		log.Error("[QURL] Failed to generate tokens: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "token_generation_failed",
			"message": "Failed to generate access tokens",
		})
		return nil, err
	}

	// Validate cookie domain and redirect URL BEFORE setting any cookies.
	// This ensures we don't set cookies if either validation fails.
	if err := ValidateCookieDomain(res.CookieDomain, resolver.AllowedRedirectDomain()); err != nil {
		log.Error("[QURL] Invalid cookie domain from API: %v", err)
		ctx.JSON(http.StatusBadGateway, gin.H{
			"error":   "invalid_cookie_domain",
			"message": "Invalid cookie domain from upstream service",
		})
		return nil, fmt.Errorf("invalid cookie domain: %w", err)
	}

	if err := ValidateRedirectURL(resolveResp.QurlSiteURL, resolver.AllowedRedirectDomain()); err != nil {
		log.Error("[QURL] Invalid redirect URL from API: %v", err)
		ctx.JSON(http.StatusBadGateway, gin.H{
			"error":   "invalid_redirect",
			"message": "Invalid redirect URL from upstream service",
		})
		return nil, fmt.Errorf("invalid redirect URL: %w", err)
	}

	// Now safe to set cookies and redirect
	tokenExpire := nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire")
	ctx.SetCookie("nhp_token", nhpToken, tokenExpire, "/", res.CookieDomain, true, true)
	ctx.SetCookie("nhp_refresh_token", refreshToken, tokenExpire, "/", res.CookieDomain, true, true)

	log.Info("[QURL] Tokens generated and cookies set, redirecting to: %s", resolveResp.QurlSiteURL)

	// Redirect to the qurl.site URL (e.g., https://r_9f3a2c8e.qurl.site)
	ctx.Redirect(http.StatusFound, resolveResp.QurlSiteURL)

	return ackMsg, nil
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
			"JWTSecret":   resp.JWTSecret,
			"TokenExpire": resp.TokenExpire,
		},
		RedirectUrl:  resp.QurlSiteURL,
		CookieDomain: resp.CookieDomain,
	}
}

// nhpDrop silently drops the connection without sending any HTTP response.
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
		defer func() { recover() }()
		if conn, _, err := ctx.Writer.Hijack(); err == nil && conn != nil {
			conn.Close()
		}
	}()
	// Prevent any further handler processing
	ctx.Abort()
}

// handleResolveError handles token resolution failures.
// Known token errors (consumed, expired, not found, policy violation) return
// a generic 403 with no details — the user sees "access denied" but learns
// nothing about the token's actual state. This avoids CloudFront 502 errors
// that occur when the connection is silently dropped behind CDN infrastructure.
// Unexpected errors still trigger nhpDrop for true NHP stealth behavior.
func handleResolveError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrTokenConsumed),
		errors.Is(err, ErrTokenExpired),
		errors.Is(err, ErrTokenNotFound),
		errors.Is(err, ErrPolicyViolation):
		ctx.JSON(http.StatusForbidden, gin.H{
			"error":   "access_denied",
			"message": "This link is no longer available",
		})
		ctx.Abort()
	default:
		nhpDrop(ctx)
	}
}
