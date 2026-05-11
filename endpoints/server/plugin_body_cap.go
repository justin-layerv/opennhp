package server

import (
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// pluginBodyDrainCeiling bounds how many additional bytes the
// middleware reads from an oversized request body after the cap is
// tripped, before sending the 413 response. Sized at 1 MiB —
// ~64x the maxPluginRequestSize cap (http_forward.go), enough to
// absorb any reasonable client upload that races past the cap, while
// keeping per-request read cost bounded. The drift fence in
// TestPluginBodyDrainCeilingExceedsCap keeps the ratio honest as the
// cap evolves.
//
// Sizing rationale: chosen as a thoughtful default, not from
// production telemetry on oversized-POST payload sizes (we don't
// collect CloudFront-side request-size histograms for this endpoint
// today). 1 MiB comfortably covers a typical browser/CDN HTTP body
// buffer envelope and exceeds the smoke test payload (64 KiB) by an
// order of magnitude. If a future operator-side observation surfaces
// a different payload shape — e.g., legitimate uploads spiking at
// 256 KiB through a slow link, or a new plugin posting larger
// objects — revise here and revisit TestPluginBodyDrainCeilingExceedsCap.
//
// Why we drain at all: /plugins/:aspid sits behind CloudFront. When we
// respond with 413 while the client is still streaming the rest of its
// upload to the CloudFront origin connection, the kernel sends RST on
// the unconsumed bytes when the connection eventually closes — and
// CloudFront sees the RST as a broken origin and serves its own 403
// "Error from cloudfront" page instead of forwarding our 413. The
// drain consumes the client's in-flight bytes so the eventual close
// is a clean FIN after the upload completes. See issue #1859.
//
// Note: net/http's MaxBytesReader does *try* to set Connection: close
// on the 413 (via requestTooLarge() on the underlying *response), but
// gin's ResponseWriter wrapper doesn't satisfy that type assertion,
// so the header isn't emitted via that path. The middleware sets the
// header explicitly. Two effects: (a) signals CloudFront's connection-
// reuse layer that the socket is done, and (b) inside Go itself,
// http.Server's chunkWriter.writeHeader parses the response's
// Connection header on its way out and sets closeAfterReply=true,
// which makes finishRequest call discardBody (256 KiB cap). So even
// if a future code path skips our 1 MiB drain, the explicit header
// still recovers a 256 KiB partial defense. The drain remains the
// primary RST-avoidance mechanism; the header is the safety net.
// If gin ever exposes requestTooLarge, the explicit ctx.Header call
// becomes redundant.
//
// Attacker cost: bounded at limit + pluginBodyDrainCeiling (~1.016
// MiB) per request, vs. the unbounded ParseForm path this whole
// middleware exists to fence. The drain inherits whatever is left of
// the request-wide ReadTimeout (httpserver.go: 30s by default — the
// budget starts at request begin, not at drain begin), so a slow
// uploader can hold a goroutine for at most ~30s total on this path
// vs. near-zero before this PR. Per-IP request rate is fenced
// operationally by the CloudFront WAF on the resolve domain
// (terraform/main.tf::aws_wafv2_web_acl.qurl_resolve): 2000 req/
// 5 min/IP in sandbox, 5000 req/5 min/IP in prod, plus the
// AWSManagedRulesCommonRuleSet (which filters known slow-body
// patterns). Worst-case per-IP concurrent goroutines: prod 5000/300s
// × 30s = ~500, sandbox 2000/300s × 30s = ~200 — bounded, well within
// a single nhp-server's envelope, and a small fraction of the
// MaxConcurrentConnection cap (constants.go: 20480).
//
// Above-ceiling truncation: a body larger than limit+drain ceiling
// still has unread bytes when AbortWithStatusJSON fires. Go's
// (*response).finishRequest then caps its own drain at
// net/http.maxPostHandlerReadBytes (256 << 10 = 256 KiB) and sets
// closeAfterReply=true, so the kernel-RST symptom from #1859
// returns for legitimate-but-bloated uploads above ~1 MiB. The 4×
// drift fence (TestPluginBodyDrainCeilingExceedsCap) keeps the
// margin honest as the cap evolves; if a future plugin legitimately
// posts beyond the ceiling, the ceiling must grow with it.
//
// This asymmetry (drain on plugins, not on /nhp/internal/knock —
// http_forward.go::maxInternalKnockRequestSize) is intentional: the
// internal knock endpoint is server-to-server (qurl-service →
// nhp-server) and has no intermediate proxy that would replace the
// 413 with its own error page.
const pluginBodyDrainCeiling int64 = 1 << 20 // 1 MiB

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
//     Before responding, the middleware drains up to
//     pluginBodyDrainCeiling bytes from the original body so the
//     client (and any intermediate proxy — CloudFront) can finish its
//     upload cleanly. Without this drain, CloudFront replaces our 413
//     with its own 403 (issue #1859).
//     Without the pre-check, MaxBytesReader still bounds the read but
//     the failure surfaces as a silent ParseForm error → empty token
//     → branded 403, indistinguishable in logs/metrics from a real
//     missing-token request. The 413 path makes DoS attempts visible.
//   - POST other ParseForm errors (e.g. malformed encoding) fall
//     through — the downstream plugin handles them via the
//     empty-token branded 403 response.
//
// Content-Type scope: ParseForm reads the body only for
// application/x-www-form-urlencoded; for multipart/form-data it just
// sets r.Form from URL query and defers body parsing to
// ParseMultipartForm. So this 413+drain path fires only for
// x-www-form-urlencoded POSTs that exceed the cap. All current static
// plugins (qurl, oidc, passcode) post x-www-form-urlencoded, so this
// is sufficient today. A future plugin posting JSON or multipart
// would (a) bypass this 413 path, (b) trip MaxBytesReader inside the
// plugin handler instead, with no drain, and (c) re-expose the
// CloudFront-substitution failure mode from issue #1859 — without
// 13_plugins_test.go catching it (the smoke test POSTs
// x-www-form-urlencoded). At that point the drain must move into
// the handler, or this middleware must learn to peek at Content-Type
// and drain on a wider branch.
//
// Mirrors the cap pattern used on /nhp/internal/knock (see
// http_forward.go::maxInternalKnockRequestSize); the literal sizes are
// declared separately so a future tuning PR diverging them produces a
// diff in both places.
func pluginBodySizeMiddleware(limit int64) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origBody := ctx.Request.Body
		// MaxBytesReader wraps unconditionally — read-side cap applies
		// to any method that ever grows a body. The 413 + drain path
		// below is the only POST-gated part.
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, origBody, limit)

		// POST is the only body-bearing method registered on
		// /plugins/:aspid today (httpserver.go GET + POST registration).
		// If a future plugin route admits PUT/PATCH with a body, the
		// CloudFront-substitution symptom returns silently — widen this
		// guard (e.g., `ctx.Request.Body != http.NoBody`) and add a
		// smoke variant.
		if ctx.Request.Method == http.MethodPost {
			if perr := ctx.Request.ParseForm(); perr != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(perr, &maxBytesErr) {
					// Log the rejection up front so operators see DoS
					// attempts even when the drain takes the full
					// ReadTimeout window on a slow uploader.
					log.Warning("plugin request rejected: body over limit src=%s aspid=%s limit=%d",
						ctx.ClientIP(), ctx.Param("aspid"), limit)
					// Drain bypassing the tripped MaxBytesReader so the
					// client finishes its upload before we close (see
					// pluginBodyDrainCeiling docs). drainErr is io.EOF
					// on the common case (smaller than ceiling); a
					// non-EOF error is rare but useful at Debug for
					// distinguishing torn-connection drains from
					// clean attacker probes during incidents.
					drained, drainErr := io.CopyN(io.Discard, origBody, pluginBodyDrainCeiling)
					if drainErr != nil && !errors.Is(drainErr, io.EOF) {
						log.Debug("plugin body drain ended early: src=%s aspid=%s drained=%d err=%v",
							ctx.ClientIP(), ctx.Param("aspid"), drained, drainErr)
					}
					// Signal connection-not-reusable to CloudFront's
					// connection-reuse layer. MaxBytesReader tries to
					// do this via requestTooLarge() on the *response,
					// but gin's writer wrapper doesn't satisfy that
					// type assertion (see pluginBodyDrainCeiling docs)
					// — set it explicitly to match the stdlib intent.
					ctx.Header("Connection", "close")
					ctx.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
					return
				}
				// Non-cap ParseForm errors fall through to the handler.
			}
		}

		ctx.Next()
	}
}
