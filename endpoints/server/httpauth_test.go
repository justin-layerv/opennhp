package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockPluginHandler implements plugins.PluginHandler for testing.
type mockPluginHandler struct {
	authWithHttpFn func(*gin.Context, *common.HttpKnockRequest, *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error)
}

func (m *mockPluginHandler) Version() string                        { return "mock v0.0.0" }
func (m *mockPluginHandler) Signature() string                      { return "" }
func (m *mockPluginHandler) ExportedData() *plugins.PluginParamsOut { return nil }
func (m *mockPluginHandler) Init(*plugins.PluginParamsIn) error     { return nil }
func (m *mockPluginHandler) Close() error                           { return nil }
func (m *mockPluginHandler) RequestOTP(*common.NhpOTPRequest, *plugins.NhpServerPluginHelper) error {
	return nil
}
func (m *mockPluginHandler) RegisterAgent(*common.NhpRegisterRequest, *plugins.NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	return nil, nil
}
func (m *mockPluginHandler) ListService(*common.NhpListRequest, *plugins.NhpServerPluginHelper) (*common.ServerListResultMsg, error) {
	return nil, nil
}
func (m *mockPluginHandler) AuthWithNHP(*common.NhpAuthRequest, *plugins.NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return nil, nil
}
func (m *mockPluginHandler) AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return m.authWithHttpFn(ctx, req, helper)
}

// newTestHttpServer creates a minimal HttpServer suitable for unit tests.
func newTestHttpServer() *HttpServer {
	hs := &HttpServer{}
	hs.signals.stop = make(chan struct{})
	return hs
}

// newTestHttpServerWithPlugins returns a test HttpServer whose
// FindPluginHandler is wired through a real UdpServer with the
// supplied plugin map. Pass an empty map to fence the
// no-handler-found path. Encapsulates the udpServer field-init so
// callers don't depend on UdpServer's internal layout.
func newTestHttpServerWithPlugins(handlers map[string]plugins.PluginHandler) *HttpServer {
	hs := newTestHttpServer()
	hs.udpServer = &UdpServer{pluginHandlerMap: handlers}
	return hs
}

func TestRunPluginAuth_AbortedContext_NoResponseWritten(t *testing.T) {
	hs := newTestHttpServer()

	handler := &mockPluginHandler{
		authWithHttpFn: func(ctx *gin.Context, _ *common.HttpKnockRequest, _ *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
			ctx.Abort()
			return nil, fmt.Errorf("token already consumed")
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	hs.runPluginAuth(ctx, &common.HttpKnockRequest{}, handler)

	if body := w.Body.String(); body != "" {
		t.Errorf("expected empty body (NHP silence), got %q", body)
	}
	if !ctx.IsAborted() {
		t.Error("expected context to be aborted")
	}
}

func TestRunPluginAuth_ErrorWithoutAbort_WritesError(t *testing.T) {
	hs := newTestHttpServer()

	handler := &mockPluginHandler{
		authWithHttpFn: func(_ *gin.Context, _ *common.HttpKnockRequest, _ *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
			return nil, fmt.Errorf("some plugin error")
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	hs.runPluginAuth(ctx, &common.HttpKnockRequest{}, handler)

	expected := `{"errMsg":"auth error: some plugin error"}`
	if body := w.Body.String(); body != expected {
		t.Errorf("expected %q, got %q", expected, body)
	}
}

// TestAuthWithAspPlugin_UnknownASPID_Returns404 fences issue #1017:
// /plugins/{unknown-aspid} previously returned 200 with a JSON
// errMsg, which let downstream callers treating status_code==200
// as "succeeded" silently treat a missing plugin as success.
func TestAuthWithAspPlugin_UnknownASPID_Returns404(t *testing.T) {
	hs := newTestHttpServerWithPlugins(map[string]plugins.PluginHandler{})

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	hs.authWithAspPlugin(ctx, &common.HttpKnockRequest{AuthServiceId: "nonexistent"})

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	expected := `{"errMsg":"no auth handler provided"}`
	if body := w.Body.String(); body != expected {
		t.Errorf("body = %q, want %q", body, expected)
	}
}

// TestRunPluginAuth_SetsKnockProcessingDeadline fences the plugin compatibility
// contract: req.Ctx remains bounded by HttpKnockProcessingBudget even though the
// direct application-admission callback now terminates as unsupported.
func TestRunPluginAuth_SetsKnockProcessingDeadline(t *testing.T) {
	hs := newTestHttpServer()

	var gotDeadline time.Time
	var hadDeadline bool
	handler := &mockPluginHandler{
		authWithHttpFn: func(_ *gin.Context, req *common.HttpKnockRequest, _ *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
			gotDeadline, hadDeadline = req.Ctx.Deadline()
			return &common.ServerKnockAckMsg{}, nil
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", nil)

	before := time.Now()
	hs.runPluginAuth(ctx, &common.HttpKnockRequest{}, handler)

	if !hadDeadline {
		t.Fatal("req.Ctx has no deadline; the plugin path must apply HttpKnockProcessingBudget")
	}
	// The deadline should be ≈ HttpKnockProcessingBudget from just before the call
	// (generous slack for scheduling jitter, tight enough to catch a wrong budget).
	if budget := gotDeadline.Sub(before); budget < HttpKnockProcessingBudget-2*time.Second || budget > HttpKnockProcessingBudget+2*time.Second {
		t.Errorf("deadline budget = %v, want ≈ HttpKnockProcessingBudget (%v)", budget, HttpKnockProcessingBudget)
	}
}

func TestRunPluginAuth_Success_NoError(t *testing.T) {
	hs := newTestHttpServer()

	handler := &mockPluginHandler{
		authWithHttpFn: func(ctx *gin.Context, _ *common.HttpKnockRequest, _ *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
			ctx.String(200, "ok")
			return &common.ServerKnockAckMsg{}, nil
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	hs.runPluginAuth(ctx, &common.HttpKnockRequest{}, handler)

	if w.Body.String() != "ok" {
		t.Errorf("expected body 'ok', got %q", w.Body.String())
	}
}
