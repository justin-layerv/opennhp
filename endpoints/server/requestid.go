package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	// RequestIDKey is the Gin context key for the request ID.
	RequestIDKey = "request_id"

	// RequestIDHeader is the HTTP header used to propagate request IDs.
	RequestIDHeader = "X-Request-ID"

	// maxRequestIDLength is the maximum accepted length for client-provided request IDs.
	maxRequestIDLength = 128
)

// traceContextPropagator is reused across requests to avoid per-request allocation.
var traceContextPropagator = propagation.TraceContext{}

// requestIDMiddleware extracts or generates a request ID for every HTTP request.
//
// When OTEL tracing is active, the trace ID is used as the request ID so that
// logs and traces share a single correlation key. The resolution order is:
//  1. OTEL span context already in the Go context (set by OTEL middleware)
//  2. W3C traceparent header (set by upstream proxy / load balancer)
//  3. Client-provided X-Request-ID header
//  4. Random 16-character hex ID
//
// The request ID is:
// - Stored in the Gin context (accessible via GetRequestID)
// - Added to the response X-Request-ID header
func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := traceIDFromContext(c)

		if requestID == "" {
			requestID = c.GetHeader(RequestIDHeader)
			if requestID != "" && (len(requestID) > maxRequestIDLength || !isValidRequestID(requestID)) {
				slog.Warn("rejected invalid X-Request-ID header", //nolint:gosec // G706: requestID is not logged; only safe rejection reason
					"reason", requestIDRejectReason(requestID),
					"client_ip", c.ClientIP(),
					"path", c.Request.URL.Path,
				)
				requestID = ""
			}
		}

		if requestID == "" {
			requestID = generateRequestID()
		}

		c.Set(RequestIDKey, requestID)
		c.Header(RequestIDHeader, requestID)

		c.Next()
	}
}

// traceIDFromContext extracts the OTEL trace ID from the request context.
// It first checks for an active span context (set by OTEL middleware), then
// falls back to parsing the W3C traceparent header via the OTEL propagator.
//
// NOTE: Span context extraction (step 1) requires OTEL middleware (e.g.,
// otelgin) to run before this middleware in the chain. If no OTEL middleware
// is configured, step 2 still extracts trace IDs from the traceparent header.
func traceIDFromContext(c *gin.Context) string {
	ctx := c.Request.Context()

	// Check existing span context (injected by OTEL middleware)
	if spanCtx := trace.SpanFromContext(ctx).SpanContext(); spanCtx.HasTraceID() {
		return spanCtx.TraceID().String()
	}

	// Fall back to W3C traceparent header parsing via OTEL propagator
	extracted := traceContextPropagator.Extract(ctx, propagation.HeaderCarrier(c.Request.Header))
	if spanCtx := trace.SpanContextFromContext(extracted); spanCtx.HasTraceID() {
		return spanCtx.TraceID().String()
	}

	return ""
}

// GetRequestID retrieves the request ID from a Gin context.
func GetRequestID(c *gin.Context) string {
	if id, exists := c.Get(RequestIDKey); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}

// isValidRequestID checks that a client-provided request ID contains only safe
// characters. Rejects newlines, control chars, and other characters that could
// be used for log injection attacks.
//
// Allowed: a-zA-Z0-9 - _ . : , =
// The : , = characters support W3C Trace Context trace-state format
// (e.g., "key1=value1,key2=value2") and OpenTelemetry propagation headers.
func isValidRequestID(id string) bool {
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' ||
			r == ':' || r == ',' || r == '=') {
			return false
		}
	}
	return true
}

// requestIDRejectReason returns a safe description of why a request ID was rejected.
// The original value is intentionally NOT logged to prevent log injection.
func requestIDRejectReason(id string) string {
	if len(id) > maxRequestIDLength {
		return "exceeds max length"
	}
	return "contains invalid characters"
}

// generateRequestID generates a random 16-character hex request ID.
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
