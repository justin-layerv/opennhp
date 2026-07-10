package agent

import (
	"strings"
	"testing"
)

// clearRegEnv unsets every env var LoadConfig reads so a test starts from a
// known-empty environment regardless of the host's ambient config. t.Setenv on
// an empty value both sets it empty for the test and restores it afterward.
func clearRegEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AGENT_OTP_REGISTRATION_ENABLED",
		"QURL_API_URL",
		"QURL_SERVICE_TOKEN",
		"QURL_API_TIMEOUT",
		"QURL_MAX_IDLE_CONNS",
		"QURL_MAX_IDLE_CONNS_PER_HOST",
		"QURL_IDLE_CONN_TIMEOUT",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadConfig_DisabledByDefault(t *testing.T) {
	clearRegEnv(t)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig with everything unset returned err=%v; disabled config must load cleanly", err)
	}
	if cfg.Enabled {
		t.Fatal("cfg.Enabled = true with AGENT_OTP_REGISTRATION_ENABLED unset; must default OFF")
	}
}

// A disabled server must not require QURL_API_URL / QURL_SERVICE_TOKEN — the
// plugin loads inert on a server that never registers agents.
func TestLoadConfig_DisabledIgnoresMissingURLAndToken(t *testing.T) {
	clearRegEnv(t)
	// Explicitly disabled, no URL/token.
	t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", "false")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("disabled LoadConfig without URL/token returned err=%v; must be tolerated", err)
	}
	if cfg.Enabled {
		t.Fatal("cfg.Enabled = true; want false")
	}
}

func TestLoadConfig_EnabledRequiresURL(t *testing.T) {
	clearRegEnv(t)
	t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", "1")
	t.Setenv("QURL_SERVICE_TOKEN", "tok")
	// QURL_API_URL intentionally missing.
	_, err := LoadConfig()
	if err == nil {
		t.Fatal("enabled LoadConfig without QURL_API_URL must error (fail-fast at boot)")
	}
	if !strings.Contains(err.Error(), "QURL_API_URL") {
		t.Errorf("err=%v, want it to name the missing QURL_API_URL", err)
	}
}

func TestLoadConfig_EnabledRequiresToken(t *testing.T) {
	clearRegEnv(t)
	t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", "yes")
	t.Setenv("QURL_API_URL", "https://qurl.example.com")
	// QURL_SERVICE_TOKEN intentionally missing.
	_, err := LoadConfig()
	if err == nil {
		t.Fatal("enabled LoadConfig without QURL_SERVICE_TOKEN must error")
	}
	if !strings.Contains(err.Error(), "QURL_SERVICE_TOKEN") {
		t.Errorf("err=%v, want it to name the missing QURL_SERVICE_TOKEN", err)
	}
}

// A whitespace-only token (e.g. a secret file that is just a newline) must be
// rejected fail-fast at Init, not pass the != "" check and produce a runtime
// auth reject.
func TestLoadConfig_EnabledRejectsWhitespaceOnlyToken(t *testing.T) {
	clearRegEnv(t)
	t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", "1")
	t.Setenv("QURL_API_URL", "https://qurl.example.com")
	t.Setenv("QURL_SERVICE_TOKEN", "   \n\t ")
	_, err := LoadConfig()
	if err == nil || !strings.Contains(err.Error(), "QURL_SERVICE_TOKEN") {
		t.Fatalf("enabled LoadConfig with a whitespace-only token must error naming QURL_SERVICE_TOKEN; got %v", err)
	}
}

// A trailing newline on the token (the common secret-manager/echo shape) is
// trimmed so it does not ride into the X-Service-Token header.
func TestLoadConfig_TrimsTokenWhitespace(t *testing.T) {
	clearRegEnv(t)
	t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", "true")
	t.Setenv("QURL_API_URL", "  https://qurl.example.com\n")
	t.Setenv("QURL_SERVICE_TOKEN", "s3cr3t-token\n")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig err=%v", err)
	}
	if cfg.ServiceToken != "s3cr3t-token" {
		t.Errorf("ServiceToken=%q want trimmed \"s3cr3t-token\"", cfg.ServiceToken)
	}
	if cfg.QurlAPIURL != "https://qurl.example.com" {
		t.Errorf("QurlAPIURL=%q want trimmed", cfg.QurlAPIURL)
	}
}

func TestLoadConfig_EnabledRejectsNonHTTPURL(t *testing.T) {
	clearRegEnv(t)
	t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", "on")
	t.Setenv("QURL_API_URL", "qurl.example.com") // no scheme
	t.Setenv("QURL_SERVICE_TOKEN", "tok")
	_, err := LoadConfig()
	if err == nil || !strings.Contains(err.Error(), "http") {
		t.Fatalf("enabled LoadConfig with a schemeless URL must error about http(s); got %v", err)
	}
}

// The happy enabled path: URL+token present, pool/timeout knobs unset ⇒
// defaulted (not a hard error, unlike the qURL plugin).
func TestLoadConfig_EnabledDefaultsPoolKnobs(t *testing.T) {
	clearRegEnv(t)
	t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", "true")
	t.Setenv("QURL_API_URL", "https://qurl.example.com")
	t.Setenv("QURL_SERVICE_TOKEN", "tok")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("enabled LoadConfig with URL+token but no pool knobs returned err=%v; knobs must default", err)
	}
	if !cfg.Enabled {
		t.Fatal("cfg.Enabled = false; want true")
	}
	if cfg.APITimeout != defaultAPITimeout {
		t.Errorf("APITimeout=%d want default %d", cfg.APITimeout, defaultAPITimeout)
	}
	if cfg.MaxIdleConns != defaultMaxIdleConns {
		t.Errorf("MaxIdleConns=%d want default %d", cfg.MaxIdleConns, defaultMaxIdleConns)
	}
	if cfg.MaxIdleConnsPerHost != defaultMaxIdleConnsPerHos {
		t.Errorf("MaxIdleConnsPerHost=%d want default %d", cfg.MaxIdleConnsPerHost, defaultMaxIdleConnsPerHos)
	}
	if cfg.IdleConnTimeout != defaultIdleConnTimeout {
		t.Errorf("IdleConnTimeout=%d want default %d", cfg.IdleConnTimeout, defaultIdleConnTimeout)
	}
}

// An explicitly-supplied pool knob overrides the default; an invalid (<=0 or
// non-numeric) value falls back to the default rather than producing a
// zero-sized pool.
func TestLoadConfig_PoolKnobOverrideAndFallback(t *testing.T) {
	clearRegEnv(t)
	t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", "true")
	t.Setenv("QURL_API_URL", "https://qurl.example.com")
	t.Setenv("QURL_SERVICE_TOKEN", "tok")
	t.Setenv("QURL_API_TIMEOUT", "25")
	t.Setenv("QURL_MAX_IDLE_CONNS", "0")        // invalid ⇒ default
	t.Setenv("QURL_IDLE_CONN_TIMEOUT", "notan") // invalid ⇒ default
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig err=%v", err)
	}
	if cfg.APITimeout != 25 {
		t.Errorf("APITimeout=%d want overridden 25", cfg.APITimeout)
	}
	if cfg.MaxIdleConns != defaultMaxIdleConns {
		t.Errorf("MaxIdleConns=%d want default %d (0 is invalid)", cfg.MaxIdleConns, defaultMaxIdleConns)
	}
	if cfg.IdleConnTimeout != defaultIdleConnTimeout {
		t.Errorf("IdleConnTimeout=%d want default %d (non-numeric is invalid)", cfg.IdleConnTimeout, defaultIdleConnTimeout)
	}
}

func TestGetEnvBool(t *testing.T) {
	clearRegEnv(t)
	truthy := []string{"1", "true", "TRUE", "Yes", "on", " on "}
	for _, v := range truthy {
		t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", v)
		if !getEnvBool("AGENT_OTP_REGISTRATION_ENABLED") {
			t.Errorf("getEnvBool(%q) = false, want true", v)
		}
	}
	falsy := []string{"", "0", "false", "no", "off", "enabled?"}
	for _, v := range falsy {
		t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", v)
		if getEnvBool("AGENT_OTP_REGISTRATION_ENABLED") {
			t.Errorf("getEnvBool(%q) = true, want false", v)
		}
	}
}
