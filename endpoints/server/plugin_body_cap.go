package server

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// pluginBodySizeMiddleware caps the request body for /plugins/:aspid
// routes. Defense-in-depth on top of Go's defaultMaxMemory for
// ParseForm (10 MiB), which would otherwise let an attacker force a
// downstream parser (e.g. qurl's recordBrowserTimings calling
// strconv.ParseFloat on form values) to chew through arbitrary bytes
// before any per-field length check fires.
//
// Behavior:
//   - GET: body is empty, so wrapping is a no-op.
//   - POST oversized: surfaced as 413 explicitly with a Warning log.
//     Without this pre-check, MaxBytesReader still bounds the read but
//     the failure surfaces as a silent ParseForm error → empty token
//     → branded 403, indistinguishable in logs/metrics from a real
//     missing-token request. The 413 path makes DoS attempts visible.
//   - POST other ParseForm errors (e.g. malformed encoding) fall
//     through — the downstream plugin handles them via the
//     empty-token branded 403 response.
//
// Content-Type scope: ParseForm reads the body only for
// application/x-www-form-urlencoded; on other content types it
// returns nil without triggering MaxBytesReader, so the explicit 413
// path here doesn't fire. The read-side cap still applies — a
// non-form handler that reads ctx.Request.Body past `limit` gets a
// *http.MaxBytesError. Fenced by
// TestPluginBodySizeMiddleware_NonFormPostStillCappedAtRead.
//
// Mirrors the cap pattern used on /nhp/internal/knock (see
// http_forward.go::maxInternalKnockRequestSize); the literal sizes are
// declared separately so a future tuning PR diverging them produces a
// diff in both places.
//
// See http_forward.go::maxPluginRequestSize for the edge-WAF
// layering rationale behind the cap value callers pass in.
func pluginBodySizeMiddleware(limit int64) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, limit)

		if ctx.Request.Method == http.MethodPost {
			if perr := ctx.Request.ParseForm(); perr != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(perr, &maxBytesErr) {
					log.Warning("plugin request rejected: body over limit src=%s aspid=%s limit=%d",
						ctx.ClientIP(), ctx.Param("aspid"), limit)
					ctx.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
					return
				}
				// Non-cap ParseForm errors fall through to the handler.
			}
		}

		ctx.Next()
	}
}
