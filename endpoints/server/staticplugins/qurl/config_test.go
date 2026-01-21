package qurl

import (
	"os"
	"strings"
	"testing"
)

func TestLoadConfig_AllRequired(t *testing.T) {
	// Set all required env vars
	os.Setenv("QURL_API_URL", "https://qurl-api.example.com")
	os.Setenv("QURL_SERVICE_TOKEN", "my-secret-token")
	os.Setenv("QURL_ALLOWED_REDIRECT_DOMAIN", "qurl.site")
	os.Setenv("QURL_API_TIMEOUT", "10")
	os.Setenv("QURL_MAX_IDLE_CONNS", "10")
	os.Setenv("QURL_MAX_IDLE_CONNS_PER_HOST", "5")
	os.Setenv("QURL_IDLE_CONN_TIMEOUT", "30")
	defer func() {
		os.Unsetenv("QURL_API_URL")
		os.Unsetenv("QURL_SERVICE_TOKEN")
		os.Unsetenv("QURL_ALLOWED_REDIRECT_DOMAIN")
		os.Unsetenv("QURL_API_TIMEOUT")
		os.Unsetenv("QURL_MAX_IDLE_CONNS")
		os.Unsetenv("QURL_MAX_IDLE_CONNS_PER_HOST")
		os.Unsetenv("QURL_IDLE_CONN_TIMEOUT")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want nil", err)
	}

	if cfg.QurlAPIURL != "https://qurl-api.example.com" {
		t.Errorf("QurlAPIURL = %q, want %q", cfg.QurlAPIURL, "https://qurl-api.example.com")
	}
	if cfg.ServiceToken != "my-secret-token" {
		t.Errorf("ServiceToken = %q, want %q", cfg.ServiceToken, "my-secret-token")
	}
	if cfg.AllowedRedirectDomain != "qurl.site" {
		t.Errorf("AllowedRedirectDomain = %q, want %q", cfg.AllowedRedirectDomain, "qurl.site")
	}
	if cfg.APITimeout != 10 {
		t.Errorf("APITimeout = %d, want %d", cfg.APITimeout, 10)
	}
	if cfg.MaxIdleConns != 10 {
		t.Errorf("MaxIdleConns = %d, want %d", cfg.MaxIdleConns, 10)
	}
	if cfg.MaxIdleConnsPerHost != 5 {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", cfg.MaxIdleConnsPerHost, 5)
	}
	if cfg.IdleConnTimeout != 30 {
		t.Errorf("IdleConnTimeout = %d, want %d", cfg.IdleConnTimeout, 30)
	}
}

// baseEnvVars returns a map with all required env vars set to valid values
func baseEnvVars() map[string]string {
	return map[string]string{
		"QURL_API_URL":                 "http://localhost:8080",
		"QURL_SERVICE_TOKEN":           "token",
		"QURL_ALLOWED_REDIRECT_DOMAIN": "qurl.site",
		"QURL_API_TIMEOUT":             "10",
		"QURL_MAX_IDLE_CONNS":          "10",
		"QURL_MAX_IDLE_CONNS_PER_HOST": "5",
		"QURL_IDLE_CONN_TIMEOUT":       "30",
	}
}

// clearAllEnvVars clears all QURL env vars
func clearAllEnvVars() {
	os.Unsetenv("QURL_API_URL")
	os.Unsetenv("QURL_SERVICE_TOKEN")
	os.Unsetenv("QURL_ALLOWED_REDIRECT_DOMAIN")
	os.Unsetenv("QURL_API_TIMEOUT")
	os.Unsetenv("QURL_MAX_IDLE_CONNS")
	os.Unsetenv("QURL_MAX_IDLE_CONNS_PER_HOST")
	os.Unsetenv("QURL_IDLE_CONN_TIMEOUT")
}

func TestLoadConfig_MissingRequired(t *testing.T) {
	tests := []struct {
		name        string
		removeKey   string // key to remove from base env vars
		expectedErr string
	}{
		{
			name:        "missing QURL_API_URL",
			removeKey:   "QURL_API_URL",
			expectedErr: "missing required config: QURL_API_URL",
		},
		{
			name:        "missing QURL_SERVICE_TOKEN",
			removeKey:   "QURL_SERVICE_TOKEN",
			expectedErr: "missing required config: QURL_SERVICE_TOKEN",
		},
		{
			name:        "missing QURL_ALLOWED_REDIRECT_DOMAIN",
			removeKey:   "QURL_ALLOWED_REDIRECT_DOMAIN",
			expectedErr: "missing required config: QURL_ALLOWED_REDIRECT_DOMAIN",
		},
		{
			name:        "missing QURL_API_TIMEOUT",
			removeKey:   "QURL_API_TIMEOUT",
			expectedErr: "missing or invalid QURL_API_TIMEOUT",
		},
		{
			name:        "missing QURL_MAX_IDLE_CONNS",
			removeKey:   "QURL_MAX_IDLE_CONNS",
			expectedErr: "missing or invalid QURL_MAX_IDLE_CONNS",
		},
		{
			name:        "missing QURL_MAX_IDLE_CONNS_PER_HOST",
			removeKey:   "QURL_MAX_IDLE_CONNS_PER_HOST",
			expectedErr: "missing or invalid QURL_MAX_IDLE_CONNS_PER_HOST",
		},
		{
			name:        "missing QURL_IDLE_CONN_TIMEOUT",
			removeKey:   "QURL_IDLE_CONN_TIMEOUT",
			expectedErr: "missing or invalid QURL_IDLE_CONN_TIMEOUT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAllEnvVars()

			// Set all env vars except the one we're testing
			envVars := baseEnvVars()
			delete(envVars, tt.removeKey)
			for k, v := range envVars {
				os.Setenv(k, v)
			}
			defer clearAllEnvVars()

			_, err := LoadConfig()
			if err == nil {
				t.Error("LoadConfig() error = nil, want error")
				return
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("LoadConfig() error = %q, want to contain %q", err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestLoadConfig_InvalidURLFormat(t *testing.T) {
	clearAllEnvVars()
	envVars := baseEnvVars()
	envVars["QURL_API_URL"] = "not-a-url" // invalid URL
	for k, v := range envVars {
		os.Setenv(k, v)
	}
	defer clearAllEnvVars()

	_, err := LoadConfig()
	if err == nil {
		t.Error("LoadConfig() error = nil, want error")
		return
	}
	if !strings.Contains(err.Error(), "invalid QURL_API_URL: must start with http:// or https://") {
		t.Errorf("LoadConfig() error = %q, want to contain URL format error", err.Error())
	}
}

// TestLoadConfig_MissingRequired_ExactErrors verifies each missing required config
// produces the exact expected error message for fail-fast diagnostics.
func TestLoadConfig_MissingRequired_ExactErrors(t *testing.T) {
	tests := []struct {
		name           string
		removeKey      string
		wantExactError string
	}{
		{
			name:           "missing QURL_API_URL produces exact error",
			removeKey:      "QURL_API_URL",
			wantExactError: "missing required config: QURL_API_URL",
		},
		{
			name:           "missing QURL_SERVICE_TOKEN produces exact error",
			removeKey:      "QURL_SERVICE_TOKEN",
			wantExactError: "missing required config: QURL_SERVICE_TOKEN",
		},
		{
			name:           "missing QURL_ALLOWED_REDIRECT_DOMAIN produces exact error",
			removeKey:      "QURL_ALLOWED_REDIRECT_DOMAIN",
			wantExactError: "missing required config: QURL_ALLOWED_REDIRECT_DOMAIN",
		},
		{
			name:           "missing QURL_API_TIMEOUT produces exact error",
			removeKey:      "QURL_API_TIMEOUT",
			wantExactError: "missing or invalid QURL_API_TIMEOUT: must be positive (recommended: 10)",
		},
		{
			name:           "missing QURL_MAX_IDLE_CONNS produces exact error",
			removeKey:      "QURL_MAX_IDLE_CONNS",
			wantExactError: "missing or invalid QURL_MAX_IDLE_CONNS: must be positive (recommended: 10)",
		},
		{
			name:           "missing QURL_MAX_IDLE_CONNS_PER_HOST produces exact error",
			removeKey:      "QURL_MAX_IDLE_CONNS_PER_HOST",
			wantExactError: "missing or invalid QURL_MAX_IDLE_CONNS_PER_HOST: must be positive (recommended: 5)",
		},
		{
			name:           "missing QURL_IDLE_CONN_TIMEOUT produces exact error",
			removeKey:      "QURL_IDLE_CONN_TIMEOUT",
			wantExactError: "missing or invalid QURL_IDLE_CONN_TIMEOUT: must be positive (recommended: 30)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAllEnvVars()

			// Set all env vars except the one we're testing
			envVars := baseEnvVars()
			delete(envVars, tt.removeKey)
			for k, v := range envVars {
				os.Setenv(k, v)
			}
			defer clearAllEnvVars()

			_, err := LoadConfig()
			if err == nil {
				t.Errorf("LoadConfig() with missing %s: error = nil, want error", tt.removeKey)
				return
			}
			if err.Error() != tt.wantExactError {
				t.Errorf("LoadConfig() with missing %s:\n  got:  %q\n  want: %q", tt.removeKey, err.Error(), tt.wantExactError)
			}
		})
	}
}

// TestLoadConfig_InvalidIntegerValues verifies that invalid integer values
// for HTTP client settings produce appropriate errors.
func TestLoadConfig_InvalidIntegerValues(t *testing.T) {
	tests := []struct {
		name        string
		envKey      string
		envValue    string
		errContains string
	}{
		{
			name:        "negative API timeout",
			envKey:      "QURL_API_TIMEOUT",
			envValue:    "-5",
			errContains: "QURL_API_TIMEOUT",
		},
		{
			name:        "zero API timeout",
			envKey:      "QURL_API_TIMEOUT",
			envValue:    "0",
			errContains: "QURL_API_TIMEOUT",
		},
		{
			name:        "non-numeric API timeout",
			envKey:      "QURL_API_TIMEOUT",
			envValue:    "abc",
			errContains: "QURL_API_TIMEOUT",
		},
		{
			name:        "negative max idle conns",
			envKey:      "QURL_MAX_IDLE_CONNS",
			envValue:    "-1",
			errContains: "QURL_MAX_IDLE_CONNS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAllEnvVars()

			// Set all valid env vars
			envVars := baseEnvVars()
			envVars[tt.envKey] = tt.envValue // Override with invalid value
			for k, v := range envVars {
				os.Setenv(k, v)
			}
			defer clearAllEnvVars()

			_, err := LoadConfig()
			if err == nil {
				t.Errorf("LoadConfig() with %s=%s: error = nil, want error", tt.envKey, tt.envValue)
				return
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("LoadConfig() with %s=%s:\n  got:  %q\n  want to contain: %q", tt.envKey, tt.envValue, err.Error(), tt.errContains)
			}
		})
	}
}

func TestValidateAccessToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{
			name:    "valid token",
			token:   "abc123-def456",
			wantErr: nil,
		},
		{
			name:    "valid token with underscores",
			token:   "token_abc_123",
			wantErr: nil,
		},
		{
			name:    "valid token with dots",
			token:   "token.abc.123",
			wantErr: nil,
		},
		{
			name:    "valid minimum length token",
			token:   "12345678", // exactly minTokenLength
			wantErr: nil,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: ErrTokenEmpty,
		},
		{
			name:    "token too short",
			token:   "abc", // less than minTokenLength (8)
			wantErr: ErrTokenTooShort,
		},
		{
			name:    "token one char below minimum",
			token:   "1234567", // minTokenLength - 1
			wantErr: ErrTokenTooShort,
		},
		{
			name:    "token too long",
			token:   strings.Repeat("a", maxTokenLength+1),
			wantErr: ErrTokenTooLong,
		},
		{
			name:    "token with invalid characters",
			token:   "token<script>alert(1)</script>",
			wantErr: ErrTokenInvalidChars,
		},
		{
			name:    "token with spaces",
			token:   "token with spaces",
			wantErr: ErrTokenInvalidChars,
		},
		{
			name:    "token with path traversal",
			token:   "../../../etc/passwd",
			wantErr: ErrTokenInvalidChars,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAccessToken(tt.token)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateAccessToken(%q) error = %v, want nil", tt.token, err)
				}
			} else {
				if err != tt.wantErr {
					t.Errorf("ValidateAccessToken(%q) error = %v, want %v", tt.token, err, tt.wantErr)
				}
			}
		})
	}
}

func TestValidateRedirectURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowedDomain string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "valid subdomain URL",
			url:           "https://r_abc123.qurl.site/path",
			allowedDomain: "qurl.site",
			wantErr:       false,
		},
		{
			name:          "valid exact domain URL",
			url:           "https://qurl.site/",
			allowedDomain: "qurl.site",
			wantErr:       false,
		},
		{
			name:          "valid URL with port",
			url:           "https://r_abc123.qurl.site:443/path",
			allowedDomain: "qurl.site",
			wantErr:       false,
		},
		{
			name:          "empty URL",
			url:           "",
			allowedDomain: "qurl.site",
			wantErr:       true,
			errContains:   "empty",
		},
		{
			name:          "HTTP instead of HTTPS",
			url:           "http://r_abc123.qurl.site/",
			allowedDomain: "qurl.site",
			wantErr:       true,
			errContains:   "must use HTTPS",
		},
		{
			name:          "wrong domain",
			url:           "https://evil.com/",
			allowedDomain: "qurl.site",
			wantErr:       true,
			errContains:   "not allowed",
		},
		{
			name:          "domain suffix attack",
			url:           "https://evilqurl.site/",
			allowedDomain: "qurl.site",
			wantErr:       true,
			errContains:   "not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURL(tt.url, tt.allowedDomain)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateRedirectURL(%q, %q) = nil, want error", tt.url, tt.allowedDomain)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateRedirectURL(%q, %q) error = %q, want to contain %q", tt.url, tt.allowedDomain, err.Error(), tt.errContains)
				}
			} else if err != nil {
				t.Errorf("ValidateRedirectURL(%q, %q) = %v, want nil", tt.url, tt.allowedDomain, err)
			}
		})
	}
}

func TestValidateCookieDomain(t *testing.T) {
	tests := []struct {
		name          string
		cookieDomain  string
		allowedDomain string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "valid cookie domain with leading dot",
			cookieDomain:  ".qurl.site",
			allowedDomain: "qurl.site",
			wantErr:       false,
		},
		{
			name:          "valid cookie domain without leading dot",
			cookieDomain:  "qurl.site",
			allowedDomain: "qurl.site",
			wantErr:       false,
		},
		{
			name:          "valid subdomain cookie",
			cookieDomain:  ".sub.qurl.site",
			allowedDomain: "qurl.site",
			wantErr:       false,
		},
		{
			name:          "empty cookie domain",
			cookieDomain:  "",
			allowedDomain: "qurl.site",
			wantErr:       true,
			errContains:   "empty",
		},
		{
			name:          "wrong domain",
			cookieDomain:  ".evil.com",
			allowedDomain: "qurl.site",
			wantErr:       true,
			errContains:   "not allowed",
		},
		{
			name:          "domain suffix attack",
			cookieDomain:  ".evilqurl.site",
			allowedDomain: "qurl.site",
			wantErr:       true,
			errContains:   "not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCookieDomain(tt.cookieDomain, tt.allowedDomain)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateCookieDomain(%q, %q) = nil, want error", tt.cookieDomain, tt.allowedDomain)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateCookieDomain(%q, %q) error = %q, want to contain %q", tt.cookieDomain, tt.allowedDomain, err.Error(), tt.errContains)
				}
			} else if err != nil {
				t.Errorf("ValidateCookieDomain(%q, %q) = %v, want nil", tt.cookieDomain, tt.allowedDomain, err)
			}
		})
	}
}
