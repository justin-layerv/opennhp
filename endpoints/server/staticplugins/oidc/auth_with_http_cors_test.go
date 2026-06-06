package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/fengyily/nhp-plugins-sdk/resource"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// stubResourceHandler is a minimal ResourceHandler that returns a fixed
// resource for any id. Used by tests that need AuthWithHttp to advance
// past its FindResourceByID call without depending on the production
// File/API resource handlers. Mirrors the same helper in the passcode
// plugin's auth_with_http_cors_test.go.
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
// duration of the test and restores it on cleanup. AuthWithHttp only
// needs a non-empty Resources map to advance past its early-return paths.
//
// Not safe under t.Parallel(): mutates the package global.
func withStubResource(t *testing.T) {
	t.Helper()
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: "r1",
			Resources: map[string]*common.ResourceInfo{
				"default": {ACId: "ac-001"},
			},
			OpenTime: 300,
		},
	}
	old := resourceHandler
	resourceHandler = &stubResourceHandler{res: res}
	t.Cleanup(func() { resourceHandler = old })
}

// TestAuthWithHttp_DoesNotClobberAllowOrigin fences the regression this
// PR removed: a handler-local corsMiddleware in AuthWithHttp used to echo
// the request Origin into Access-Control-Allow-Origin with no allowlist,
// overwriting the allowlisted value the engine-level corsMiddleware in
// httpserver.go writes before this handler runs. Nothing in this handler
// may touch that header — the platform middleware owns it.
//
// Drives AuthWithHttp with an unknown action so the switch defaults to
// "action invalid"; the former deletion site ran before that switch, so
// the default path exercises it. Seeds a sentinel (distinct from the
// request Origin, which the old code would have echoed) so the fence is
// decoupled from any specific allowlist value — any handler write flips
// the assertion.
func TestAuthWithHttp_DoesNotClobberAllowOrigin(t *testing.T) {
	withStubResource(t)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/oktaoidc?resid=r1&action=unknown", nil)
	ctx.Request.Header.Set("Origin", "https://attacker.example")
	const sentinel = "https://allowlisted.example"
	w.Header().Set("Access-Control-Allow-Origin", sentinel)

	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, &plugins.HttpServerPluginHelper{}); err == nil {
		t.Fatal("expected 'action invalid' error from default switch case")
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != sentinel {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q unchanged (handler must not touch this header)", got, sentinel)
	}
}
