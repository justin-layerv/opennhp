package qurl

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
)

// Token validation constants
const (
	// minTokenLength is the minimum allowed access token length.
	// Set to 8 to reject obviously invalid tokens early (typos, truncated tokens).
	minTokenLength = 8

	// maxTokenLength is the maximum allowed access token length.
	// Set to 512 to accommodate UUID-based tokens with potential prefixes/suffixes
	// while preventing DoS via extremely long tokens in query parameters.
	maxTokenLength = 512
)

// Token validation errors
var (
	ErrTokenEmpty        = errors.New("access token is empty")
	ErrTokenTooShort     = errors.New("access token is too short")
	ErrTokenTooLong      = errors.New("access token exceeds maximum length")
	ErrTokenInvalidChars = errors.New("access token contains invalid characters")
)

// Config holds the QURL plugin configuration.
// All fields must be explicitly configured via environment variables.
// There are no defaults - missing configuration will cause the plugin to fail at startup.
type Config struct {
	// QurlAPIURL is the base URL for the QURL API service
	// Environment variable: QURL_API_URL
	// Required
	QurlAPIURL string

	// ServiceToken is the shared secret for authenticating with the QURL internal API
	// Environment variable: QURL_SERVICE_TOKEN
	// Required
	ServiceToken string

	// AllowedRedirectDomain is the domain suffix allowed for redirects (e.g., "qurl.site")
	// Environment variable: QURL_ALLOWED_REDIRECT_DOMAIN
	// Required - used to validate redirect URLs from API responses
	AllowedRedirectDomain string

	// APITimeout is the timeout for QURL API requests in seconds
	// Environment variable: QURL_API_TIMEOUT
	// Required. Recommended: 10
	APITimeout int

	// MaxIdleConns is the maximum number of idle HTTP connections to keep pooled
	// Environment variable: QURL_MAX_IDLE_CONNS
	// Required. Recommended: 10
	MaxIdleConns int

	// MaxIdleConnsPerHost is the maximum idle connections per host
	// Environment variable: QURL_MAX_IDLE_CONNS_PER_HOST
	// Required. Recommended: 5
	MaxIdleConnsPerHost int

	// IdleConnTimeout is the timeout for idle connections in seconds
	// Environment variable: QURL_IDLE_CONN_TIMEOUT
	// Required. Recommended: 30
	IdleConnTimeout int
}

// LoadConfig loads and validates configuration from environment variables.
// Returns an error if any required configuration is missing.
// This enables fail-fast behavior where Terraform deployments fail early on misconfiguration.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		QurlAPIURL:            os.Getenv("QURL_API_URL"),
		ServiceToken:          os.Getenv("QURL_SERVICE_TOKEN"),
		AllowedRedirectDomain: os.Getenv("QURL_ALLOWED_REDIRECT_DOMAIN"),
		APITimeout:            getEnvInt("QURL_API_TIMEOUT"),
		MaxIdleConns:          getEnvInt("QURL_MAX_IDLE_CONNS"),
		MaxIdleConnsPerHost:   getEnvInt("QURL_MAX_IDLE_CONNS_PER_HOST"),
		IdleConnTimeout:       getEnvInt("QURL_IDLE_CONN_TIMEOUT"),
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// getEnvInt returns the integer value of an environment variable, or 0 if not set/invalid.
// Validation of required values happens in validateConfig.
func getEnvInt(key string) int {
	val := os.Getenv(key)
	if val == "" {
		return 0
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return 0
	}
	return i
}

// validateConfig validates all required configuration fields.
// Returns an error for any missing or invalid value.
func validateConfig(cfg *Config) error {
	if cfg.QurlAPIURL == "" {
		return errors.New("missing required config: QURL_API_URL")
	}
	if cfg.ServiceToken == "" {
		return errors.New("missing required config: QURL_SERVICE_TOKEN")
	}
	if cfg.AllowedRedirectDomain == "" {
		return errors.New("missing required config: QURL_ALLOWED_REDIRECT_DOMAIN")
	}

	// Validate URL format
	if !strings.HasPrefix(cfg.QurlAPIURL, "http://") && !strings.HasPrefix(cfg.QurlAPIURL, "https://") {
		return errors.New("invalid QURL_API_URL: must start with http:// or https://")
	}

	// Validate HTTP client settings
	if cfg.APITimeout <= 0 {
		return errors.New("missing or invalid QURL_API_TIMEOUT: must be positive (recommended: 10)")
	}
	if cfg.MaxIdleConns <= 0 {
		return errors.New("missing or invalid QURL_MAX_IDLE_CONNS: must be positive (recommended: 10)")
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		return errors.New("missing or invalid QURL_MAX_IDLE_CONNS_PER_HOST: must be positive (recommended: 5)")
	}
	if cfg.IdleConnTimeout <= 0 {
		return errors.New("missing or invalid QURL_IDLE_CONN_TIMEOUT: must be positive (recommended: 30)")
	}

	return nil
}

// ValidateRedirectURL validates that a redirect URL is safe.
// It must use HTTPS and belong to the allowed domain (exact match or subdomain).
func ValidateRedirectURL(rawURL, allowedDomain string) error {
	if rawURL == "" {
		return errors.New("redirect URL is empty")
	}

	// Use net/url.Parse for robust URL parsing (handles edge cases like userinfo, query params)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid redirect URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("redirect URL must use HTTPS: %s", rawURL)
	}

	// Extract hostname (without port)
	hostPart := parsed.Hostname()

	// Check if host is exactly the allowed domain or a proper subdomain
	// A proper subdomain must have a dot before the allowed domain (e.g., "sub.qurl.site" for "qurl.site")
	// This prevents suffix attacks like "evilqurl.site" matching "qurl.site"
	if hostPart != allowedDomain && !strings.HasSuffix(hostPart, "."+allowedDomain) {
		return fmt.Errorf("redirect URL domain %q not allowed (must be %q or a subdomain)", hostPart, allowedDomain)
	}

	return nil
}

// ValidateAccessToken validates an access token for security
// Returns nil if valid, error otherwise
func ValidateAccessToken(token string) error {
	if token == "" {
		return ErrTokenEmpty
	}

	if len(token) < minTokenLength {
		return ErrTokenTooShort
	}

	if len(token) > maxTokenLength {
		return ErrTokenTooLong
	}

	// Only allow alphanumeric, dash, underscore, and dot
	for _, c := range token {
		if !isValidTokenChar(c) {
			return ErrTokenInvalidChars
		}
	}

	return nil
}

// isValidTokenChar returns true if the character is allowed in an access token
func isValidTokenChar(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-' || c == '_' || c == '.'
}

// ValidateCookieDomain validates that a cookie domain is safe.
// It must be the allowed domain (with leading dot) or a subdomain cookie scoped to it.
// This prevents a compromised upstream from setting cookies on arbitrary domains.
func ValidateCookieDomain(cookieDomain, allowedDomain string) error {
	if cookieDomain == "" {
		return errors.New("cookie domain is empty")
	}

	// Cookie domain typically has a leading dot (e.g., ".qurl.site")
	// Strip the leading dot for comparison
	domainToCheck := strings.TrimPrefix(cookieDomain, ".")

	// Check if it's exactly the allowed domain or a proper subdomain
	if domainToCheck != allowedDomain && !strings.HasSuffix(domainToCheck, "."+allowedDomain) {
		return fmt.Errorf("cookie domain %q not allowed (must be %q or a subdomain)", cookieDomain, allowedDomain)
	}

	return nil
}
