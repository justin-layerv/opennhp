package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestParseTrustedCIDRs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
	}{
		{"empty string", "", 0},
		{"valid CIDRs", "130.176.0.0/16,54.239.192.0/19", 2},
		{"single CIDR", "10.0.0.0/8", 1},
		{"trailing comma", "130.176.0.0/16,54.239.192.0/19,", 2},
		{"leading comma", ",130.176.0.0/16", 1},
		{"empty entries filtered", "130.176.0.0/16,,54.239.192.0/19", 2},
		{"whitespace trimmed", " 130.176.0.0/16 , 54.239.192.0/19 ", 2},
		{"only commas", ",,,", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseTrustedCIDRs(tt.input)
			if len(result) != tt.wantCount {
				t.Errorf("parseTrustedCIDRs(%q) returned %d CIDRs, want %d", tt.input, len(result), tt.wantCount)
			}
		})
	}
}

func TestTrustedProxyConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		envValue    string
		wantTrusted bool
		wantErr     bool
	}{
		{
			name:        "no env var trusts nobody",
			envValue:    "",
			wantTrusted: false,
		},
		{
			name:        "valid CIDRs are configured",
			envValue:    "130.176.0.0/16,54.239.192.0/19",
			wantTrusted: true,
		},
		{
			name:        "only commas trusts nobody",
			envValue:    ",,,",
			wantTrusted: false,
		},
		{
			name:        "invalid CIDR rejected by Gin",
			envValue:    "not-a-cidr",
			wantTrusted: false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := gin.New()

			if tt.envValue != "" {
				t.Setenv("NHP_TRUSTED_PROXY_CIDRS", tt.envValue)
			} else {
				_ = os.Unsetenv("NHP_TRUSTED_PROXY_CIDRS")
			}

			var trusted bool
			if validCIDRs := parseTrustedCIDRs(os.Getenv("NHP_TRUSTED_PROXY_CIDRS")); len(validCIDRs) > 0 {
				if err := engine.SetTrustedProxies(validCIDRs); err != nil {
					if !tt.wantErr {
						t.Fatalf("SetTrustedProxies failed unexpectedly: %v", err)
					}
					return
				}
				if tt.wantErr {
					t.Fatal("SetTrustedProxies should have returned an error")
				}
				trusted = true
			} else {
				_ = engine.SetTrustedProxies(nil)
			}

			if trusted != tt.wantTrusted {
				t.Errorf("trusted = %v, want %v", trusted, tt.wantTrusted)
			}
		})
	}
}

// TestClientIP_IgnoresXForwardedFor_WhenNoTrustedProxies fences the
// load-bearing security property of the SetTrustedProxies(nil) branch
// in httpserver.go: when NHP_TRUSTED_PROXY_CIDRS is unset, an HTTP
// knock with a hostile X-Forwarded-For header must NOT influence
// ctx.ClientIP(). The returned ClientIP must be the TCP RemoteAddr.
//
// Plugin and internal HTTP routes use ctx.ClientIP for source gates and audit
// attribution. If Gin's default "trust all proxies" posture re-asserts here,
// an attacker can spoof X-Forwarded-For and bypass those assumptions.
func TestClientIP_IgnoresXForwardedFor_WhenNoTrustedProxies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	if err := engine.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil) returned unexpected error: %v", err)
	}

	var observed string
	engine.GET("/probe", func(c *gin.Context) {
		observed = c.ClientIP()
		c.Status(http.StatusOK)
	})

	srv := httptest.NewServer(engine)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/probe", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Hostile XFF header — the value an attacker would inject to claim
	// an accomplice's IP on the knock.
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8") // belt-and-braces; gin also reads X-Real-IP

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	// Loopback covers both v4 (127.0.0.1) and v6 (::1) — httptest may
	// bind either depending on the host stack.
	if observed != "127.0.0.1" && observed != "::1" {
		t.Errorf("ClientIP = %q; want loopback (127.0.0.1 or ::1) — XFF or X-Real-IP leaked into ClientIP, SetTrustedProxies(nil) is not being honored", observed)
	}
	if observed == "1.2.3.4" || observed == "5.6.7.8" {
		t.Errorf("ClientIP = %q; spoofed proxy header overrode RemoteAddr (this is the bug PR-2a's #2 closes)", observed)
	}
}
