package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"

	"github.com/gin-gonic/gin"
)

const (
	// RequestIDKey is the Gin context key for the request ID.
	RequestIDKey = "request_id"

	// RequestIDHeader is the HTTP header used to propagate request IDs.
	RequestIDHeader = "X-Request-ID"

	// maxRequestIDLength is the maximum accepted length for client-provided request IDs.
	maxRequestIDLength = 128
)

// requestIDMiddleware extracts or generates a request ID for every HTTP request.
// If the incoming request has an X-Request-ID header, it is reused for distributed
// tracing. Otherwise, a random 16-character hex ID is generated.
// Client-provided IDs exceeding maxRequestIDLength are rejected and replaced.
//
// The request ID is:
// - Stored in the Gin context (accessible via GetRequestID)
// - Added to the response X-Request-ID header
func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader(RequestIDHeader)
		if requestID != "" && (len(requestID) > maxRequestIDLength || !isValidRequestID(requestID)) {
			slog.Warn("rejected invalid X-Request-ID header",
				"reason", requestIDRejectReason(requestID),
				"client_ip", c.ClientIP(),
				"path", c.Request.URL.Path,
			)
			requestID = ""
		}
		if requestID == "" {
			requestID = generateRequestID()
		}

		c.Set(RequestIDKey, requestID)
		c.Header(RequestIDHeader, requestID)

		c.Next()
	}
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
