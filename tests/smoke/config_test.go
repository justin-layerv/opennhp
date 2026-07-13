//go:build smoke

// Unit tests for the pure helpers in config.go. Not a tiered smoke test —
// this file pairs with config.go the same way dns_test.go pairs with dns.go
// (no 01_–29_ prefix, no live AWS or network). The smoke-suite maintenance
// rules in CLAUDE.md (one-file-per-capability, tier-prefix naming) apply to
// capability tests, not helper tests.

package smoke

import "testing"

// TestNHPIngressTLSURL locks the env-topology selection that
// TestProtocol_NLBTLSCertValid relies on. It is a method on *TestConfig
// precisely so it can be exercised here against constructed configs — the
// deployed run only ever hits the resolve-on-https and relay branches, so the
// localhost ("", false) and no-relay ("", false) arms have no other coverage.
func TestNHPIngressTLSURL(t *testing.T) {
	cases := []struct {
		name    string
		cfg     TestConfig
		wantURL string
		wantOK  bool
	}{
		{
			name:    "resolve_on_https_returns_server_url",
			cfg:     TestConfig{ResolveEndpointEnabled: true, NHPServerBaseURL: "https://resolve.qurl.link", RelayBaseURL: ""},
			wantURL: "https://resolve.qurl.link",
			wantOK:  true,
		},
		{
			name:    "resolve_on_localhost_http_skips",
			cfg:     TestConfig{ResolveEndpointEnabled: true, NHPServerBaseURL: "http://localhost:8888", RelayBaseURL: ""},
			wantURL: "",
			wantOK:  false,
		},
		{
			name:    "resolve_off_relay_set_returns_relay",
			cfg:     TestConfig{ResolveEndpointEnabled: false, NHPServerBaseURL: "https://resolve.qurl.link.layerv.xyz", RelayBaseURL: "https://relay.qurl.link.layerv.xyz"},
			wantURL: "https://relay.qurl.link.layerv.xyz",
			wantOK:  true,
		},
		{
			name:    "resolve_off_no_relay_skips",
			cfg:     TestConfig{ResolveEndpointEnabled: false, NHPServerBaseURL: "", RelayBaseURL: ""},
			wantURL: "",
			wantOK:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotURL, gotOK := tc.cfg.nhpIngressTLSURL()
			if gotURL != tc.wantURL || gotOK != tc.wantOK {
				t.Errorf("nhpIngressTLSURL() = (%q, %v), want (%q, %v)", gotURL, gotOK, tc.wantURL, tc.wantOK)
			}
		})
	}
}
