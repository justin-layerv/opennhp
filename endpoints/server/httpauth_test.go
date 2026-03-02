package server

import (
	"fmt"
	"net/http/httptest"
	"testing"

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
