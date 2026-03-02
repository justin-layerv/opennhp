package server

import (
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
