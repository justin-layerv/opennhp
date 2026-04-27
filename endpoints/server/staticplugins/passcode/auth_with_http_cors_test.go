package passcode

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	nhpplugins "github.com/fengyily/nhp-plugins-sdk"
	"github.com/fengyily/nhp-plugins-sdk/resource"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// stubResourceHandler is a minimal ResourceHandler that returns a fixed
// resource for any id. Used by tests that need AuthWithHttp to advance
// past its FindResourceByID call without depending on the production
// File/API resource handlers.
type stubResourceHandler struct {
	res *common.ResourceData
}

func (s *stubResourceHandler) Init(plugins.PluginParamsIn, resource.Config) error { return nil }
func (s *stubResourceHandler) Update(resource.Config) error                       { return nil }
func (s *stubResourceHandler) FindResourceByID(string) (*common.ResourceData, error) {
	return s.res, nil
}
func (s *stubResourceHandler) Close() error               { return nil }
func (s *stubResourceHandler) GetConfig() resource.Config { return resource.Config{} }

// withStubResource swaps the package-global resourceHandler for the
// duration of the test and restores it on cleanup. Using a stub keeps
// this test free of API/file-fixture setup; AuthWithHttp only needs a
// non-empty Resources map to advance past the early-return paths.
// Pass a JWTSecret to seed res.ExInfo for tests that need to drive
// AuthWithHttpRefresh past jwt.Validate.
//
// Not safe under t.Parallel(): mutates the package global. Same caveat
// applies to the resolver-swap pattern in qurl/main_test.go.
func withStubResource(t *testing.T, jwtSecret string) *common.ResourceData {
	t.Helper()
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: "r1",
			Resources: map[string]*common.ResourceInfo{
				"default": {ACId: "ac-001"},
			},
			OpenTime: 300,
		},
		ExInfo: map[string]any{
			"JWTSecret":   jwtSecret,
			"TokenExpire": int64(3600),
		},
	}
	old := resourceHandler
	resourceHandler = &stubResourceHandler{res: res}
	t.Cleanup(func() { resourceHandler = old })
	return res
}

// TestAuthWithHttp_DoesNotClobberExposeHeaders fences the same regression
// the qurl-side TestAuthWithHttp_AcceptJSON_DoesNotClobberExposeHeaders
// catches: the engine-level corsMiddleware in httpserver.go writes
// Access-Control-Expose-Headers before this handler runs, and nothing
// in this handler may touch that header. A prior nhpplugins.CorsMiddleware
// call at the deletion site overwrote it with a stale default
// ("Content-Length, Content-Type, Authorization") that dropped
// Set-Cookie, silently breaking credentialed-fetch cookie pickup.
//
// Drives AuthWithHttp with an unknown action so the switch defaults
// to "action invalid" — the deletion site at line ~245 (ctx.SetSameSite)
// runs, then the switch returns without invoking deeper handlers that
// would require additional mocks. Seeds a sentinel value (not the
// production literal) so the fence is decoupled from httpserver.go's
// Expose-Headers list and any handler write at all flips the assertion.
func TestAuthWithHttp_DoesNotClobberExposeHeaders(t *testing.T) {
	withStubResource(t, "")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/passcode?resid=r1&action=unknown", nil)
	const sentinel = "X-Sentinel-DoNotTouch"
	w.Header().Set("Access-Control-Expose-Headers", sentinel)

	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, &plugins.HttpServerPluginHelper{}); err == nil {
		t.Fatal("expected 'action invalid' error from default switch case")
	}
	if got := w.Header().Get("Access-Control-Expose-Headers"); got != sentinel {
		t.Errorf("Access-Control-Expose-Headers = %q, want %q unchanged (handler must not touch this header)", got, sentinel)
	}
}

// TestAuthWithHttpRefresh_DoesNotClobberExposeHeaders fences the
// second nhpplugins.CorsMiddleware deletion site, in AuthWithHttpRefresh.
// Reaching that site requires (1) a valid nhp_token cookie carrying a
// JWT signed with the resource's JWTSecret and (2) a passing
// jwt.Validate(token, TokenTypeNHPToken) — so this test mints a real
// token via the same JWTToken machinery the production code uses,
// installs it as a cookie, and drives AuthWithHttpRefresh with an
// unknown action so the inner switch falls through after the deletion
// site without invoking refreshToken/exchangeAndKnock (which would
// require a real knock helper).
func TestAuthWithHttpRefresh_DoesNotClobberExposeHeaders(t *testing.T) {
	const jwtSecret = "test-jwt-secret-key-for-signing"
	res := withStubResource(t, jwtSecret)
	jwt := &nhpplugins.JWTToken{JwtKey: []byte(jwtSecret)}
	nhpToken, _, err := jwt.GenerateAll("asp1", res)
	if err != nil {
		t.Fatalf("jwt.GenerateAll: %v", err)
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/passcode?action=bogus", nil)
	ctx.Request.AddCookie(&http.Cookie{Name: "nhp_token", Value: nhpToken})
	const sentinel = "X-Sentinel-DoNotTouch"
	w.Header().Set("Access-Control-Expose-Headers", sentinel)

	if _, err := AuthWithHttpRefresh(ctx, "bogus", &common.HttpKnockRequest{}, &plugins.HttpServerPluginHelper{}); err == nil {
		t.Fatal("expected 'unknown action' error from else branch")
	}
	if got := w.Header().Get("Access-Control-Expose-Headers"); got != sentinel {
		t.Errorf("Access-Control-Expose-Headers = %q, want %q unchanged (handler must not touch this header)", got, sentinel)
	}
}
