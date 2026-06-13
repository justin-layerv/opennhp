package redirecturl

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	nhplog "github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"

	nhpplugins "github.com/fengyily/nhp-plugins-sdk"
	"github.com/fengyily/nhp-plugins-sdk/models"
	"github.com/fengyily/nhp-plugins-sdk/resource"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
	"github.com/golang-jwt/jwt/v4"
)

const (
	sdkParityModule = "github.com/fengyily/nhp-plugins-sdk"
	// Keep this tied to TestGetByResourceMatchesPinnedSDKBehavior; any SDK
	// bump should re-verify behavior against the real helper before updating.
	sdkParityVersion = "v0.1.30"
)

func TestSafeForLogDropsSecretURLParts(t *testing.T) {
	got := SafeForLog("https://user:pass@example.com:8443/webgate/path?access_token=secret&state=s#/?key=sharing")
	want := "https://example.com:8443/webgate/path"

	if got != want {
		t.Fatalf("SafeForLog() = %q, want %q", got, want)
	}
}

func TestSafeForLogEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "empty",
			raw:  "",
			want: "",
		},
		{
			name: "parse error",
			raw:  "https://[::1",
			want: "<invalid redirect URL>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SafeForLog(tt.raw); got != tt.want {
				t.Fatalf("SafeForLog(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestGetByResourceAddsAccessTokenButSafeForLogDropsIt(t *testing.T) {
	ackMsg := &common.ServerKnockAckMsg{
		ResourceHost: map[string]string{"primary": "target.example.com"},
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{ResourceId: "app-1"},
		RedirectUrl:   "https://placeholder.example/webgate?existing=1#frag",
		ExInfo: map[string]any{
			"Ip":      "10.0.0.1",
			"Port":    443,
			"Scheme":  "https",
			"MapPort": 8443,
			"ConPort": 10443,
		},
	}
	conf := resource.Config{AesKey: "0123456789abcdef"}

	_, redirectURL, err := GetByResource(ackMsg, res, conf, "access", "alice")
	if err != nil {
		t.Fatalf("GetByResource() error = %v", err)
	}

	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("generated redirect URL did not parse: %v", err)
	}
	if parsed.Host != "target.example.com" {
		t.Fatalf("redirect host = %q, want target.example.com", parsed.Host)
	}
	if got := parsed.Query().Get("access_token"); got == "" {
		t.Fatal("redirect URL missing access_token query parameter")
	}
	if got := parsed.Query().Get("existing"); got != "1" {
		t.Fatalf("existing query = %q, want 1", got)
	}

	if got, want := SafeForLog(redirectURL), "https://target.example.com/webgate"; got != want {
		t.Fatalf("SafeForLog(generated URL) = %q, want %q", got, want)
	}
}

func TestGetByResourceMatchesPinnedSDKBehavior(t *testing.T) {
	initSDKLogger(t)

	localAck := &common.ServerKnockAckMsg{
		ResourceHost: map[string]string{"primary": "target.example.com"},
	}
	sdkAck := &common.ServerKnockAckMsg{
		ResourceHost: map[string]string{"primary": "target.example.com"},
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{ResourceId: "app-1"},
		RedirectUrl:   "https://placeholder.example/webgate?existing=1#frag",
		ExInfo: map[string]any{
			"Ip":      "10.0.0.1",
			"Port":    443,
			"Scheme":  "https",
			"MapPort": 8443,
			"ConPort": 10443,
			"Sub": []models.Resource{
				{IP: "10.0.0.2", Port: 8444, Scheme: "https", MapPort: 9443, ConnectorPort: 11443},
			},
		},
	}
	conf := resource.Config{AesKey: "0123456789abcdef"}

	localReturnedAck, localURL, err := GetByResource(localAck, res, conf, "access", "alice")
	if err != nil {
		t.Fatalf("GetByResource() error = %v", err)
	}
	sdkReturnedAck, sdkURL, err := nhpplugins.GetRedirectUrlByResource(sdkAck, res, conf, "access", "alice")
	if err != nil {
		t.Fatalf("SDK GetRedirectUrlByResource() error = %v", err)
	}
	if localReturnedAck != localAck {
		t.Fatal("GetByResource() returned a different ackMsg pointer")
	}
	if sdkReturnedAck != sdkAck {
		t.Fatal("SDK GetRedirectUrlByResource() returned a different ackMsg pointer")
	}
	if !reflect.DeepEqual(localAck, sdkAck) {
		t.Fatalf("ackMsg = %#v, want SDK %#v", localAck, sdkAck)
	}

	if got, want := urlWithAccessTokenPlaceholder(t, localURL), urlWithAccessTokenPlaceholder(t, sdkURL); got != want {
		t.Fatalf("URL with redacted access_token = %q, want SDK %q", got, want)
	}

	localInfo := decryptServiceInfo(t, localURL, conf.AesKey)
	sdkInfo := decryptServiceInfo(t, sdkURL, conf.AesKey)
	if !reflect.DeepEqual(localInfo, sdkInfo) {
		t.Fatalf("ServiceInfo = %#v, want SDK %#v", localInfo, sdkInfo)
	}
}

func TestGetByResourceMatchesPinnedSDKAnonymousUserAndJSONSub(t *testing.T) {
	initSDKLogger(t)

	localAck := &common.ServerKnockAckMsg{
		ResourceHost: map[string]string{"primary": "target.example.com"},
	}
	sdkAck := &common.ServerKnockAckMsg{
		ResourceHost: map[string]string{"primary": "target.example.com"},
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{ResourceId: "app-1"},
		RedirectUrl:   "https://placeholder.example/webgate",
		ExInfo: map[string]any{
			"Ip":      "10.0.0.1",
			"Port":    443,
			"Scheme":  "https",
			"MapPort": 8443,
			"ConPort": 10443,
			"Sub": []any{
				map[string]any{
					"IP":            "10.0.0.2",
					"Port":          8444,
					"Scheme":        "https",
					"MapPort":       9443,
					"ConnectorPort": 11443,
				},
			},
		},
	}
	conf := resource.Config{AesKey: "0123456789abcdef"}

	localReturnedAck, localURL, err := GetByResource(localAck, res, conf, "oidc", "")
	if err != nil {
		t.Fatalf("GetByResource() error = %v", err)
	}
	sdkReturnedAck, sdkURL, err := nhpplugins.GetRedirectUrlByResource(sdkAck, res, conf, "oidc", "")
	if err != nil {
		t.Fatalf("SDK GetRedirectUrlByResource() error = %v", err)
	}
	if localReturnedAck != localAck {
		t.Fatal("GetByResource() returned a different ackMsg pointer")
	}
	if sdkReturnedAck != sdkAck {
		t.Fatal("SDK GetRedirectUrlByResource() returned a different ackMsg pointer")
	}
	if !reflect.DeepEqual(localAck, sdkAck) {
		t.Fatalf("ackMsg = %#v, want SDK %#v", localAck, sdkAck)
	}
	if got, want := urlWithAccessTokenPlaceholder(t, localURL), urlWithAccessTokenPlaceholder(t, sdkURL); got != want {
		t.Fatalf("URL with redacted access_token = %q, want SDK %q", got, want)
	}

	localInfo := decryptServiceInfo(t, localURL, conf.AesKey)
	sdkInfo := decryptServiceInfo(t, sdkURL, conf.AesKey)
	if !reflect.DeepEqual(localInfo, sdkInfo) {
		t.Fatalf("ServiceInfo = %#v, want SDK %#v", localInfo, sdkInfo)
	}
	if localInfo.User != "anonymous" {
		t.Fatalf("ServiceInfo.User = %q, want anonymous", localInfo.User)
	}
	if len(localInfo.Sub) != 0 {
		t.Fatalf("ServiceInfo.Sub length = %d, want 0 for JSON-shaped Sub parity", len(localInfo.Sub))
	}
}

func TestGetByResourceMatchesPinnedSDKBranches(t *testing.T) {
	initSDKLogger(t)

	tests := []struct {
		name string
		ack  *common.ServerKnockAckMsg
		res  *common.ResourceData
	}{
		{
			name: "empty redirect",
			ack: &common.ServerKnockAckMsg{
				ResourceHost: map[string]string{"primary": "target.example.com"},
			},
			res: &common.ResourceData{
				ResourceGroup: common.ResourceGroup{ResourceId: "app-1"},
				ExInfo:        map[string]any{},
			},
		},
		{
			name: "no resource host",
			ack: &common.ServerKnockAckMsg{
				ResourceHost: map[string]string{},
			},
			res: &common.ResourceData{
				ResourceGroup: common.ResourceGroup{ResourceId: "app-1"},
				RedirectUrl:   "https://placeholder.example/webgate",
				ExInfo:        map[string]any{},
			},
		},
		{
			name: "parse failure",
			ack: &common.ServerKnockAckMsg{
				ResourceHost: map[string]string{"primary": "target.example.com"},
			},
			res: &common.ResourceData{
				ResourceGroup: common.ResourceGroup{ResourceId: "app-1"},
				RedirectUrl:   "https://[::1",
				ExInfo:        map[string]any{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			localAck := cloneAck(tt.ack)
			sdkAck := cloneAck(tt.ack)

			localReturnedAck, localURL, localErr := GetByResource(localAck, tt.res, resource.Config{AesKey: "0123456789abcdef"}, "access", "alice")
			sdkReturnedAck, sdkURL, sdkErr := nhpplugins.GetRedirectUrlByResource(sdkAck, tt.res, resource.Config{AesKey: "0123456789abcdef"}, "access", "alice")

			if localReturnedAck != localAck {
				t.Fatal("GetByResource() returned a different ackMsg pointer")
			}
			if sdkReturnedAck != sdkAck {
				t.Fatal("SDK GetRedirectUrlByResource() returned a different ackMsg pointer")
			}
			if !sameErrState(localErr, sdkErr) {
				t.Fatalf("error state = %v, want SDK %v", localErr, sdkErr)
			}
			if localURL != sdkURL {
				t.Fatalf("redirectURL = %q, want SDK %q", localURL, sdkURL)
			}
			if !reflect.DeepEqual(localAck, sdkAck) {
				t.Fatalf("ackMsg = %#v, want SDK %#v", localAck, sdkAck)
			}
		})
	}
}

func TestGetByResourceEmptyRedirectURL(t *testing.T) {
	ackMsg := &common.ServerKnockAckMsg{
		ResourceHost: map[string]string{"primary": "target.example.com"},
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{ResourceId: "app-1"},
		ExInfo:        map[string]any{},
	}

	gotAck, redirectURL, err := GetByResource(ackMsg, res, resource.Config{AesKey: "0123456789abcdef"}, "access", "alice")
	if err != nil {
		t.Fatalf("GetByResource() error = %v, want nil", err)
	}
	if gotAck != ackMsg {
		t.Fatal("GetByResource() returned a different ackMsg")
	}
	if redirectURL != "" {
		t.Fatalf("redirectURL = %q, want empty", redirectURL)
	}
}

func TestGetByResourceParseErrorDoesNotReturnRawURL(t *testing.T) {
	raw := "https://placeholder.example/%zz?access_token=config-secret#frag"
	ackMsg := &common.ServerKnockAckMsg{
		ResourceHost: map[string]string{"primary": "target.example.com"},
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{ResourceId: "app-1"},
		RedirectUrl:   raw,
		ExInfo:        map[string]any{},
	}

	_, redirectURL, err := GetByResource(ackMsg, res, resource.Config{AesKey: "0123456789abcdef"}, "access", "alice")
	if !errors.Is(err, errInvalidRedirectURL) {
		t.Fatalf("GetByResource() error = %v, want errInvalidRedirectURL", err)
	}
	if redirectURL != "" {
		t.Fatalf("redirectURL = %q, want empty", redirectURL)
	}
	if strings.Contains(err.Error(), raw) || strings.Contains(err.Error(), "config-secret") {
		t.Fatalf("error leaked raw redirect URL: %q", err)
	}
}

func cloneAck(ack *common.ServerKnockAckMsg) *common.ServerKnockAckMsg {
	clone := *ack
	if ack.ResourceHost != nil {
		clone.ResourceHost = make(map[string]string, len(ack.ResourceHost))
		for k, v := range ack.ResourceHost {
			clone.ResourceHost[k] = v
		}
	}
	return &clone
}

func sameErrState(a, b error) bool {
	return (a == nil) == (b == nil)
}

func TestSDKParityVersionPinned(t *testing.T) {
	data := readModuleFile(t, "go.mod")
	want := sdkParityModule + " " + sdkParityVersion
	if !strings.Contains(string(data), want) {
		t.Fatalf("go.mod does not pin %q; re-verify redirecturl.GetByResource against SDK GetRedirectUrlByResource before updating this test", want)
	}
}

func readModuleFile(t *testing.T, name string) []byte {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err == nil {
			return data
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find %s", name)
		}
		dir = parent
	}
}

func initSDKLogger(t *testing.T) {
	t.Helper()

	logger := nhplog.NewLogger("", nhplog.LogLevelSilent, t.TempDir(), "sdk")
	t.Cleanup(logger.Close)

	pluginDir := t.TempDir()
	err := nhpplugins.Init(&plugins.PluginParamsIn{
		Log:           logger,
		PluginDirPath: &pluginDir,
	}, func(resource.ResourceHandler) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nhpplugins.Close() })
}

func urlWithAccessTokenPlaceholder(t *testing.T, raw string) string {
	t.Helper()

	prefix, queryAndFragment, ok := strings.Cut(raw, "?")
	if !ok {
		t.Fatalf("redirect URL %q is missing query string", raw)
	}
	query, fragment, hasFragment := strings.Cut(queryAndFragment, "#")
	parts := strings.Split(query, "&")
	found := false
	for i, part := range parts {
		key, _, _ := strings.Cut(part, "=")
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			t.Fatalf("query key %q did not unescape: %v", key, err)
		}
		if decodedKey == "access_token" {
			parts[i] = key + "=<redacted>"
			found = true
		}
	}
	if !found {
		t.Fatalf("redirect URL %q is missing access_token", raw)
	}
	if hasFragment {
		return prefix + "?" + strings.Join(parts, "&") + "#" + fragment
	}
	return prefix + "?" + strings.Join(parts, "&")
}

func decryptServiceInfo(t *testing.T, rawURL string, aesKey string) models.ServiceInfo {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	tokenString := u.Query().Get("access_token")
	if tokenString == "" {
		t.Fatal("missing access_token")
	}

	claims := &models.JWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (any, error) {
		return []byte(aesKey), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !token.Valid {
		t.Fatal("access_token JWT is invalid")
	}

	plaintext, err := nhpsdkutils.DecryptGCM(claims.EncryptedData, aesKey)
	if err != nil {
		t.Fatal(err)
	}

	var info models.ServiceInfo
	if err := json.Unmarshal(plaintext, &info); err != nil {
		t.Fatal(err)
	}
	return info
}
