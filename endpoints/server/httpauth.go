package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

func (hs *HttpServer) authWithAspPlugin(c *gin.Context, req *common.HttpKnockRequest) {
	handler := hs.FindPluginHandler(req.AuthServiceId)
	if handler == nil {
		log.Error("no auth handler provided")
		c.JSON(http.StatusNotFound, gin.H{"errMsg": "no auth handler provided"})
		return
	}

	hs.runPluginAuth(c, req, handler)
}

// runPluginAuth calls the plugin's AuthWithHttp and handles the result.
// If the plugin aborted the context (e.g., NHP silent drop), no error
// response is written — preserving NHP protocol silence.
func (hs *HttpServer) runPluginAuth(c *gin.Context, req *common.HttpKnockRequest, handler plugins.PluginHandler) {
	// Stamp a bounded request context onto the deprecated Ctx compatibility
	// field used by the fengyily/nhp-plugins-sdk callback. Direct HTTP admission
	// is retired, but plugins may still inspect this request-scoped context before
	// the callback returns ErrHTTPAccessOperationUnsupported.
	if c.Request != nil {
		knockCtx, cancel := withKnockProcessingBudget(c.Request.Context())
		defer cancel()
		req.Ctx = knockCtx
	}
	helper := hs.NewHttpServerHelper()
	_, err := handler.AuthWithHttp(c, req, helper)
	if err != nil {
		log.Info("auth error: %v", err)
		if !c.Writer.Written() && !c.IsAborted() {
			c.JSON(http.StatusOK, gin.H{"errMsg": fmt.Sprintf("auth error: %v", err)})
		}
	} else {
		log.Info("auth completed successfully")
	}
}

// withKnockProcessingBudget bounds an HTTP knock's request context with
// HttpKnockProcessingBudget. Both HTTP knock entry points wrap their request
// context with it — runPluginAuth (the ASP-plugin /plugins/:aspid path) and
// handleInternalKnock (qurl-service's /nhp/internal/knock) — so the AC-open reknock
// retry's deadline short-circuit (broadcastACOpenWithReknock) has a deadline to
// read against the caller's budget; c.Request.Context() carries none of its own
// (Go's http.Server ReadTimeout/WriteTimeout do not surface as a context deadline).
// The clock starts here, BEFORE any admission on this path, so a slow admission
// cannot let the doubled AC-open overrun the caller's budget. It does NOT cancel
// admission (which runs on its own context.Background()-derived contexts) or the
// AOP broadcasts (processACOperationBroadcast WithoutCancels the parent) — only the
// reknock retry decision + backoff observe it. The budget is stamped on req.Ctx
// only; a plugin's own admission/resolve HTTP calls that run on the raw
// c.Request.Context() or the lifecycle context are deliberately NOT bounded by it
// (a future refactor that unifies those contexts must preserve that, or it would
// pull admission under the 5s knock-budget axe).
//
// SCOPE — this is stamped for EVERY ASP-plugin knock (runPluginAuth, /plugins/:aspid),
// but it bounds only code that reads req.Ctx. Confirmed no in-tree plugin does: agent,
// oidc, passcode, and qurl all run their auth on the gin.Context or their own contexts
// (oidc bounds its IdP discovery with its own oidcDiscoveryTimeout, not req.Ctx), so
// the 5s cap changes none of their behavior. The only readers are the AC-open reknock
// deadline short-circuit and out-of-tree fengyily/nhp-plugins-sdk plugins that use the
// deprecated req.Ctx field — such a plugin needing >5s of req.Ctx must derive its own
// context rather than lean on the deprecated field.
//
// Callers MUST defer the returned cancel; safe
// because both entry points run the whole knock synchronously before returning. The
// UDP knock path (handleNhpOpenResource) deliberately gets NO such deadline: there
// the agent paces its own re-knock cadence via OpenTime, so the single-retry
// ceiling is the only bound.
func withKnockProcessingBudget(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, HttpKnockProcessingBudget)
}
