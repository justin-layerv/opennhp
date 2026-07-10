package agent

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

// ServiceTokenHeader is the HTTP header the agent plugin uses to authenticate
// with the qurl-service internal API. It carries the same shared secret the
// qURL plugin sends (staticplugins/qurl/config.go::ServiceTokenHeader) — both
// plugins call the same qurl-service internal surface, so the header name is
// pinned to the same literal on purpose. If qurl-service ever rotates the
// header name, change both plugins in lockstep.
const ServiceTokenHeader = "X-Service-Token"

// Config holds the agent-registration plugin configuration.
//
// The HTTP-client half of this config (QurlAPIURL, ServiceToken, APITimeout,
// and the connection-pool knobs) is READ FROM THE SAME environment variables
// the qURL plugin already consumes (QURL_API_URL, QURL_SERVICE_TOKEN,
// QURL_API_TIMEOUT, QURL_MAX_IDLE_CONNS, QURL_MAX_IDLE_CONNS_PER_HOST,
// QURL_IDLE_CONN_TIMEOUT — see staticplugins/qurl/config.go). Both plugins run
// in the same nhp-server process and talk to the same qurl-service internal
// endpoints, so they share one set of connection settings rather than
// introducing a parallel AGENT_QURL_* namespace that ops would have to keep in
// sync. The registration feature adds exactly ONE new variable of its own,
// AGENT_OTP_REGISTRATION_ENABLED, so the plugin can ship dark (default OFF).
type Config struct {
	// Enabled gates the whole NHP-native registration feature. Default OFF:
	// when false, RequestOTP/RegisterAgent never touch the network — they
	// return the registration-disabled verdict — so this PR is inert until ops
	// flips the flag AND supplies QurlAPIURL + ServiceToken on nhp-server.
	// Environment variable: AGENT_OTP_REGISTRATION_ENABLED
	// (truthy: "1"/"true"/"yes"/"on", case-insensitive). Optional; defaults false.
	Enabled bool

	// QurlAPIURL is the base URL of the qurl-service internal API
	// (POST {QurlAPIURL}/internal/v1/agent/otp and .../register).
	// Environment variable: QURL_API_URL (shared with the qURL plugin).
	// Required ONLY when Enabled is true.
	QurlAPIURL string

	// ServiceToken is the shared secret sent in the X-Service-Token header to
	// authenticate with the qurl-service internal API.
	// Environment variable: QURL_SERVICE_TOKEN (shared with the qURL plugin).
	// Required ONLY when Enabled is true.
	ServiceToken string

	// APITimeout is the per-request timeout for qurl-service calls, in seconds.
	// Environment variable: QURL_API_TIMEOUT (shared with the qURL plugin).
	// Optional; falls back to defaultAPITimeout when unset/invalid so an
	// operator who enables registration without re-specifying the qURL timeout
	// still gets a bounded client rather than an unbounded (0 == no-timeout)
	// http.Client. Recommended: 10.
	APITimeout int

	// MaxIdleConns / MaxIdleConnsPerHost / IdleConnTimeout configure the pooled
	// transport, mirroring the qURL resolver's transport exactly. All three fall
	// back to defaults when unset/invalid (same rationale as APITimeout): the
	// pool tuning is an optimization, not a correctness input, so a missing
	// value must not produce a zero-sized/never-idle pool.
	// Environment variables: QURL_MAX_IDLE_CONNS, QURL_MAX_IDLE_CONNS_PER_HOST,
	// QURL_IDLE_CONN_TIMEOUT (shared with the qURL plugin).
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     int
}

// Connection-pool + timeout fallbacks. Unlike the qURL plugin — which hard-fails
// when any QURL_* knob is missing because qURL serving is always-on there — the
// agent plugin treats the shared pool/timeout knobs as OPTIONAL and defaults
// them. Rationale: the registration path is feature-flag-gated and the operator
// enabling it (setting AGENT_OTP_REGISTRATION_ENABLED + QURL_API_URL +
// QURL_SERVICE_TOKEN) may not have the qURL plugin's tuning vars present. The
// only HARD requirements when enabled are the URL and the token; everything else
// degrades to a sane bounded default so we never construct an unbounded client.
const (
	defaultAPITimeout         = 10
	defaultMaxIdleConns       = 10
	defaultMaxIdleConnsPerHos = 5
	defaultIdleConnTimeout    = 30
)

// LoadConfig reads the agent-registration configuration from the environment.
//
// Validation is deliberately asymmetric with the qURL plugin's LoadConfig: when
// the feature is DISABLED (the default) this returns a zero-value-ish config
// with no error even if QURL_API_URL / QURL_SERVICE_TOKEN are unset, so the
// plugin loads cleanly on a server that never intends to register agents. When
// the feature is ENABLED, QURL_API_URL and QURL_SERVICE_TOKEN become hard
// requirements (fail-fast at Init, so a misconfigured enablement surfaces at
// boot rather than at the first agent OTP), and the URL must be http(s).
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Enabled:    getEnvBool("AGENT_OTP_REGISTRATION_ENABLED"),
		QurlAPIURL: strings.TrimSpace(os.Getenv("QURL_API_URL")),
		// TrimSpace the token: secret-manager/echo-populated env files commonly
		// append a trailing newline, which would otherwise ride verbatim into the
		// X-Service-Token header and produce a confusing auth reject that still
		// passes the != "" check. Trimming also means a whitespace-only token
		// collapses to "" and is caught by validateConfig's fail-fast below.
		ServiceToken:        strings.TrimSpace(os.Getenv("QURL_SERVICE_TOKEN")),
		APITimeout:          getEnvIntDefault("QURL_API_TIMEOUT", defaultAPITimeout),
		MaxIdleConns:        getEnvIntDefault("QURL_MAX_IDLE_CONNS", defaultMaxIdleConns),
		MaxIdleConnsPerHost: getEnvIntDefault("QURL_MAX_IDLE_CONNS_PER_HOST", defaultMaxIdleConnsPerHos),
		IdleConnTimeout:     getEnvIntDefault("QURL_IDLE_CONN_TIMEOUT", defaultIdleConnTimeout),
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validateConfig enforces the enabled-only requirements. A disabled config is
// always valid (the feature is dark), so no field is checked in that case.
func validateConfig(cfg *Config) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.QurlAPIURL == "" {
		return errors.New("AGENT_OTP_REGISTRATION_ENABLED is set but QURL_API_URL is empty")
	}
	if cfg.ServiceToken == "" {
		return errors.New("AGENT_OTP_REGISTRATION_ENABLED is set but QURL_SERVICE_TOKEN is empty")
	}
	// SECURITY: http:// is permitted (matching the qURL plugin) ONLY for a
	// loopback / in-VPC qurl-service — e.g. the same-host dev/smoke relay or a
	// private-subnet service address. This is the FIRST code path that sends the
	// api_key_secret (Passcode) and the registration OTP credential in the
	// REQUEST BODY, and over http:// those travel in cleartext. In any
	// deployment where qurl-service is not reachable purely over loopback/in-VPC,
	// QURL_API_URL MUST be https. (The ops runbook carries the deployment-side
	// enforcement; this comment is the in-code warning at the decision site.)
	if !strings.HasPrefix(cfg.QurlAPIURL, "http://") && !strings.HasPrefix(cfg.QurlAPIURL, "https://") {
		return errors.New("invalid QURL_API_URL: must start with http:// or https://")
	}
	return nil
}

// getEnvIntDefault returns the integer value of an environment variable, or the
// supplied default when the variable is unset, empty, or unparseable. This
// mirrors the qURL plugin's getEnvInt shape but substitutes a caller-chosen
// default (rather than 0) because the agent plugin treats these knobs as
// optional; see the Config field comments.
//
// NOTE: a value of 0 (or negative) is treated as unset and falls back to the
// default — so an operator cannot express "0" to mean Go's transport semantics
// (0 == unlimited idle-conn timeout / no timeout). That is intentional for these
// pool/timeout knobs: an unbounded client is never a desirable accidental
// configuration here, so 0 is coerced to the bounded default rather than passed
// through.
func getEnvIntDefault(key string, def int) int {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil || i <= 0 {
		return def
	}
	return i
}

// getEnvBool returns true iff the environment variable is set to a truthy value
// ("1", "true", "yes", "on", case-insensitive). Any other value — including
// unset, "0", "false", or an unrecognized string — is false, so the
// registration feature stays OFF unless explicitly enabled (fail-safe default).
// Byte-for-byte identical semantics to the qURL plugin's getEnvBool so the two
// feature flags read the same across the server.
func getEnvBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
