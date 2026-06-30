package qurlv2

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateRelayURL(t *testing.T) {
	allow := NewRelayAllowlist([]string{"relay.example.com", "relay2.example.com:8443"})

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https allowed host", "https://relay.example.com", false},
		{"https allowed host with path", "https://relay.example.com/relay/abc", false},
		{"https allowed host any port (host-only entry)", "https://relay.example.com:9000", false},
		{"https allowed host:port exact", "https://relay2.example.com:8443", false},
		{"http rejected", "http://relay.example.com", true},
		{"host not on allowlist", "https://evil.example.com", true},
		{"host:port not matching entry port", "https://relay2.example.com:9999", true},
		{"missing scheme", "relay.example.com", true},
		{"userinfo rejected", "https://user:pass@relay.example.com", true},
		{"empty", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRelayURL(tc.url, allow)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.url, err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, ErrRelayURL) {
				t.Fatalf("error must wrap ErrRelayURL, got: %v", err)
			}
		})
	}
}

// TestValidateRelayURL_DefaultPortSemantics pins the chosen, security-relevant
// port-matching contract so the wiring slice (P3c/P3d/P3f) that consumes relay_url
// cannot regress it: a `host:443` allowlist entry is matched literally on the
// `Host` field and therefore does NOT match a default-port URL whose `Host` is the
// bare host. Operators who want to allow a 443 relay must enumerate the bare host
// (which then matches any port via the hostname fallback). See env-vars.md.
func TestValidateRelayURL_DefaultPortSemantics(t *testing.T) {
	t.Run("host:443 entry does not match default-port url", func(t *testing.T) {
		// Allowlist carries the explicit :443 form; the URL omits the port, so its
		// url.Host is "relay.example.com" (no port). The :443 entry never matches.
		allow := NewRelayAllowlist([]string{"relay.example.com:443"})
		if err := ValidateRelayURL("https://relay.example.com", allow); !errors.Is(err, ErrRelayURL) {
			t.Fatalf("a host:443 allowlist entry must NOT match a default-port URL (host has no :443); got: %v", err)
		}
		// The same :443 entry DOES match a URL that spells the port out.
		if err := ValidateRelayURL("https://relay.example.com:443", allow); err != nil {
			t.Fatalf("host:443 entry must match an explicit :443 URL: %v", err)
		}
	})

	t.Run("bare-host entry matches both default and explicit ports", func(t *testing.T) {
		// A bare-host entry is the operator's way to allow a 443 relay; the hostname
		// fallback lets it match regardless of whether the URL spells the port.
		allow := NewRelayAllowlist([]string{"relay.example.com"})
		for _, u := range []string{
			"https://relay.example.com",
			"https://relay.example.com:443",
			"https://relay.example.com:9000",
		} {
			if err := ValidateRelayURL(u, allow); err != nil {
				t.Fatalf("bare-host entry must match %q via hostname fallback: %v", u, err)
			}
		}
	})
}

// TestValidateRelayURL_EmbeddedCredentialsBypass is the classic allowlist-bypass
// vector: a URL of the form https://allowed.example.com@evil.example.com parses to
// host=evil.example.com with allowed.example.com sitting in userinfo. A naive
// allowlist that string-matched the front of the authority would treat this as the
// allowed host. ValidateRelayURL parses the TRUE host via net/url and additionally
// rejects any URL carrying userinfo, so the real target (evil.example.com) is never
// admitted even though it is on no allowlist — and even an allowlist that DID list
// allowed.example.com must not let this through.
func TestValidateRelayURL_EmbeddedCredentialsBypass(t *testing.T) {
	// Allowlist deliberately lists the decoy host to make the bypass attractive.
	allow := NewRelayAllowlist([]string{"allowed.example.com"})

	tests := []struct {
		name string
		url  string
	}{
		{"userinfo decoy as bare host", "https://allowed.example.com@evil.example.com"},
		{"userinfo decoy with path", "https://allowed.example.com@evil.example.com/relay/abc"},
		{"userinfo decoy with explicit port", "https://allowed.example.com@evil.example.com:8443"},
		{"user:pass decoy form", "https://allowed.example.com:tok@evil.example.com"},
		// Real host EQUALS the allowlisted host: this is the case that proves the
		// rejection comes from the userinfo guard, not merely from the real target
		// being off the allowlist. The decoy and the post-`@` host are both
		// "allowed.example.com", so an allowlist-only check would PASS — the userinfo
		// guard must still reject it.
		{"userinfo bearing, real host allowlisted", "https://allowed.example.com@allowed.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRelayURL(tc.url, allow)
			if !errors.Is(err, ErrRelayURL) {
				t.Fatalf("userinfo-bearing URL %q must be rejected regardless of the real host; got: %v", tc.url, err)
			}
		})
	}
}

// TestValidateRelayURL_NilAndEmptyAllowlistFailClosed proves an unconfigured or
// empty allowlist rejects every URL (fail closed).
func TestValidateRelayURL_NilAndEmptyAllowlistFailClosed(t *testing.T) {
	if err := ValidateRelayURL("https://relay.example.com", nil); !errors.Is(err, ErrRelayURL) {
		t.Fatalf("nil allowlist must fail closed, got: %v", err)
	}
	empty := NewRelayAllowlist(nil)
	if err := ValidateRelayURL("https://relay.example.com", empty); !errors.Is(err, ErrRelayURL) {
		t.Fatalf("empty allowlist must fail closed, got: %v", err)
	}
}

// TestRelayURL_NotCheckedByParser proves relay_url is NOT validated during
// parsing — it is a post-verify step. A claims with a non-HTTPS relay_url still
// parses; only ValidateRelayURL rejects it.
func TestRelayURL_NotCheckedByParser(t *testing.T) {
	base := validClaimsJSON(t)
	withHTTP := strings.Replace(base, `"relay_url":"https://relay.example.com",`, `"relay_url":"http://relay.example.com",`, 1)
	if withHTTP == base {
		t.Fatal("relay_url substitution did not apply")
	}
	c, err := parseClaims([]byte(withHTTP))
	if err != nil {
		t.Fatalf("parser must NOT reject a non-https relay_url (that is a post-verify check): %v", err)
	}
	allow := NewRelayAllowlist([]string{"relay.example.com"})
	if err := ValidateRelayURL(c.RelayURL, allow); !errors.Is(err, ErrRelayURL) {
		t.Fatalf("ValidateRelayURL must reject http, got: %v", err)
	}
}
