package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestContext creates a gin test context with an optional Origin header.
func newTestContext(origin string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request, _ = http.NewRequest("GET", "/test", nil)
	if origin != "" {
		ctx.Request.Header.Set("Origin", origin)
	}
	return ctx, w
}

func TestAuthWithHttp_NilHelper(t *testing.T) {
	ctx, _ := newTestContext("")
	req := &common.HttpKnockRequest{}

	_, err := AuthWithHttp(ctx, req, nil)
	if err == nil {
		t.Fatal("expected error for nil helper")
	}
	if err.Error() != "AuthWithHttp: helper is null" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAuthWithNHP_NilHelper(t *testing.T) {
	ack := &common.ServerKnockAckMsg{}
	req := &common.NhpAuthRequest{Ack: ack}

	result, err := AuthWithNHP(req, nil)
	if err == nil {
		t.Fatal("expected error for nil helper")
	}
	if err.Error() != "AuthWithNHP: helper is null" {
		t.Errorf("unexpected error: %v", err)
	}
	if result != ack {
		t.Error("expected original ack to be returned")
	}
}

func TestCorsMiddleware_WithOrigin(t *testing.T) {
	origin := "https://example.com"
	ctx, w := newTestContext(origin)

	corsMiddleware(ctx)

	got := w.Header().Get("Access-Control-Allow-Origin")
	if got != origin {
		t.Errorf("expected CORS origin %q, got %q", origin, got)
	}
}

func TestCorsMiddleware_WithoutOrigin(t *testing.T) {
	ctx, w := newTestContext("")

	corsMiddleware(ctx)

	got := w.Header().Get("Access-Control-Allow-Origin")
	if got != "" {
		t.Errorf("expected no CORS header, got %q", got)
	}
}

func TestAuthRegular_NilAuthenticator(t *testing.T) {
	ctx, w := newTestContext("")
	req := &common.HttpKnockRequest{}
	res := &common.ResourceData{}
	helper := &plugins.HttpServerPluginHelper{}

	// Ensure oktaAuth is nil
	oktaAuth = nil

	_, err := authRegular(ctx, req, res, helper)
	if err == nil {
		t.Fatal("expected error for nil authenticator")
	}
	if err.Error() != "invalid authenticator" {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify JSON error response was written
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json; charset=utf-8" {
		t.Errorf("expected JSON content-type, got %q", ct)
	}
}

func TestAuthOkta_InvalidConfig(t *testing.T) {
	ctx, _ := newTestContext("")

	// baseConf with empty domain will fail OIDC provider creation
	baseConf = &config{
		AUTH0_DOMAIN: "",
	}

	err := authOkta(ctx)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	if err.Error() != "failed to initialize authenticator" {
		t.Errorf("unexpected error: %v", err)
	}
	if oktaAuth != nil {
		t.Error("expected oktaAuth to be nil after failed initialization")
	}
}
