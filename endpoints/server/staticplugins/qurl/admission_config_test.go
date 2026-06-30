package qurl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// p256TrustStoreJSON builds a valid QURL_V2_ISSUER_TRUST_STORE value with one
// P-256 issuer key under the given kid.
func p256TrustStoreJSON(t *testing.T, kid string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, _ := json.Marshal(map[string]string{kid: base64.StdEncoding.EncodeToString(der)})
	return string(b)
}

func TestLoadV2TrustStore_Valid(t *testing.T) {
	ts, err := LoadV2TrustStore(p256TrustStoreJSON(t, "kid-1"))
	if err != nil {
		t.Fatalf("LoadV2TrustStore: %v", err)
	}
	if ts == nil {
		t.Fatal("trust store is nil")
	}
}

func TestLoadV2TrustStore_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantSub string
	}{
		{name: "empty json", json: "", wantSub: "parse"},
		{name: "not an object", json: `["a"]`, wantSub: "parse"},
		{name: "no keys", json: `{}`, wantSub: "no issuer keys"},
		{name: "empty kid", json: `{"":"AAAA"}`, wantSub: "empty kid"},
		{name: "bad base64", json: `{"kid-1":"!!!not-base64!!!"}`, wantSub: "not valid base64"},
		{name: "not a p256 key", json: `{"kid-1":"AAAA"}`, wantSub: "trust store"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadV2TrustStore(tt.json)
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

// TestLoadConfig_V2Flag covers the flag default (off), enabling it, and the
// fail-closed gate that the trust store must be present when the flag is on.
func TestLoadConfig_V2Flag(t *testing.T) {
	setBaseEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("QURL_API_URL", "https://qurl-api.example.com")
		t.Setenv("QURL_SERVICE_TOKEN", "tok")
		t.Setenv("QURL_ALLOWED_REDIRECT_DOMAIN", "qurl.site")
		t.Setenv("QURL_API_TIMEOUT", "10")
		t.Setenv("QURL_MAX_IDLE_CONNS", "10")
		t.Setenv("QURL_MAX_IDLE_CONNS_PER_HOST", "5")
		t.Setenv("QURL_IDLE_CONN_TIMEOUT", "30")
	}

	t.Run("default off", func(t *testing.T) {
		setBaseEnv(t)
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.V2AdmissionEnabled {
			t.Error("V2AdmissionEnabled must default to false")
		}
	})

	t.Run("enabled with trust store", func(t *testing.T) {
		setBaseEnv(t)
		t.Setenv("QURL_V2_ADMISSION_ENABLED", "true")
		t.Setenv("QURL_V2_ISSUER_TRUST_STORE", p256TrustStoreJSON(t, "kid-1"))
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if !cfg.V2AdmissionEnabled {
			t.Error("V2AdmissionEnabled must be true")
		}
	})

	t.Run("enabled without trust store fails closed", func(t *testing.T) {
		setBaseEnv(t)
		t.Setenv("QURL_V2_ADMISSION_ENABLED", "1")
		// QURL_V2_ISSUER_TRUST_STORE intentionally unset.
		_, err := LoadConfig()
		if err == nil {
			t.Fatal("LoadConfig must fail when v2 admission is enabled without a trust store")
		}
		if !strings.Contains(err.Error(), "QURL_V2_ISSUER_TRUST_STORE") {
			t.Errorf("error %q should mention the missing trust store", err.Error())
		}
	})

	t.Run("flag truthy variants", func(t *testing.T) {
		for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
			setBaseEnv(t)
			t.Setenv("QURL_V2_ADMISSION_ENABLED", v)
			t.Setenv("QURL_V2_ISSUER_TRUST_STORE", p256TrustStoreJSON(t, "kid-1"))
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig(%q): %v", v, err)
			}
			if !cfg.V2AdmissionEnabled {
				t.Errorf("value %q should enable the flag", v)
			}
		}
	})

	t.Run("flag falsy variants stay off", func(t *testing.T) {
		for _, v := range []string{"0", "false", "no", "off", "", "maybe"} {
			setBaseEnv(t)
			t.Setenv("QURL_V2_ADMISSION_ENABLED", v)
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig(%q): %v", v, err)
			}
			if cfg.V2AdmissionEnabled {
				t.Errorf("value %q must NOT enable the flag", v)
			}
		}
	})
}
