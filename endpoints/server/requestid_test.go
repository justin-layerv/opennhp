package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

func TestRequestIDMiddleware_GeneratesID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		id := GetRequestID(c)
		if id == "" {
			t.Error("expected non-empty request ID")
		}
		c.String(http.StatusOK, id)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Response header should have the generated ID
	respID := w.Header().Get(RequestIDHeader)
	if respID == "" {
		t.Error("expected X-Request-ID response header")
	}
	if len(respID) != 16 {
		t.Errorf("expected 16-char hex ID, got %q (len %d)", respID, len(respID))
	}

	// Body should match header
	if w.Body.String() != respID {
		t.Errorf("body %q != header %q", w.Body.String(), respID)
	}
}

func TestRequestIDMiddleware_ReusesHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(RequestIDHeader, "my-custom-id-123")
	r.ServeHTTP(w, req)

	if w.Body.String() != "my-custom-id-123" {
		t.Errorf("expected reused ID, got %q", w.Body.String())
	}
	if w.Header().Get(RequestIDHeader) != "my-custom-id-123" {
		t.Errorf("expected header to echo back custom ID")
	}
}

func TestRequestIDMiddleware_UniqueIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, req)
		id := w.Body.String()
		if ids[id] {
			t.Fatalf("duplicate request ID: %s", id)
		}
		ids[id] = true
	}
}

func TestRequestIDMiddleware_RejectsOversizedHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	oversized := strings.Repeat("a", maxRequestIDLength+1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(RequestIDHeader, oversized)
	r.ServeHTTP(w, req)

	respID := w.Body.String()
	if respID == oversized {
		t.Error("expected oversized request ID to be replaced")
	}
	if len(respID) != 16 {
		t.Errorf("expected generated 16-char hex ID, got %q (len %d)", respID, len(respID))
	}
}

func TestRequestIDMiddleware_AcceptsMaxLengthHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	maxLen := strings.Repeat("b", maxRequestIDLength)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(RequestIDHeader, maxLen)
	r.ServeHTTP(w, req)

	if w.Body.String() != maxLen {
		t.Errorf("expected max-length ID to be accepted, got %q", w.Body.String())
	}
}

func TestRequestIDMiddleware_RejectsLogInjection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	injections := []string{
		"valid-prefix\nInjected-Log-Line", // newline injection
		"id\r\nHTTP/1.1 200 OK",           // CRLF injection
		"id\twith\ttabs",                  // tab characters
		"id with spaces",                  // spaces
		"<script>alert(1)</script>",       // HTML/XSS
		"id;DROP TABLE users",             // SQL-like
		"id\x00null",                      // null byte
		"id$(whoami)",                     // command injection
		"id`whoami`",                      // backtick injection
	}

	for _, injection := range injections {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(RequestIDHeader, injection)
		r.ServeHTTP(w, req)

		respID := w.Body.String()
		if respID == injection {
			t.Errorf("expected injection to be rejected, but %q was accepted", injection)
		}
		if len(respID) != 16 {
			t.Errorf("expected generated 16-char hex ID for injection %q, got %q (len %d)", injection, respID, len(respID))
		}
	}
}

func TestRequestIDMiddleware_AcceptsValidCharacters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	valid := []string{
		"abc123",           // alphanumeric
		"trace-id-abc-123", // hyphens
		"span_id_456",      // underscores
		"req.abc.def.123",  // dots
		"W3C-trace-00-abcdef1234567890abcdef1234567890-abcdef1234567890-01", // W3C traceparent
		"key1=value1,key2=value2",                 // W3C trace-state
		"vendor:value",                            // trace-state with colon
		"rojo=00f067aa0ba902b7,congo=t61rcWkgMzE", // multi-vendor trace-state
	}

	for _, id := range valid {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(RequestIDHeader, id)
		r.ServeHTTP(w, req)

		if w.Body.String() != id {
			t.Errorf("expected valid ID %q to be accepted, got %q", id, w.Body.String())
		}
	}
}

// ============================================================================
// OTEL Trace ID Integration Tests
// ============================================================================

func TestRequestIDMiddleware_UsesTraceparentHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	const traceID = "4bf92f3577b6a27e8e681df2e0f0a3aa"
	tp := "00-" + traceID + "-00f067aa0ba902b7-01"

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Traceparent", tp)
	r.ServeHTTP(w, req)

	if w.Body.String() != traceID {
		t.Errorf("expected trace ID %q, got %q", traceID, w.Body.String())
	}
	if w.Header().Get(RequestIDHeader) != traceID {
		t.Errorf("expected X-Request-ID header to be trace ID")
	}
}

func TestRequestIDMiddleware_UsesLowercaseTraceparentHeaderName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	const traceID = "4bf92f3577b6a27e8e681df2e0f0a3aa"
	tp := "00-" + traceID + "-00f067aa0ba902b7-01"

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("traceparent", tp)
	r.ServeHTTP(w, req)

	if w.Body.String() != traceID {
		t.Errorf("expected trace ID %q from lowercase traceparent header, got %q", traceID, w.Body.String())
	}
}

func TestRequestIDMiddleware_TraceparentOverridesXRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	const traceID = "abcdef1234567890abcdef1234567890"
	tp := "00-" + traceID + "-1234567890abcdef-01"

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Traceparent", tp)
	req.Header.Set(RequestIDHeader, "my-custom-id")
	r.ServeHTTP(w, req)

	if w.Body.String() != traceID {
		t.Errorf("traceparent should take priority over X-Request-ID; got %q", w.Body.String())
	}
}

func TestRequestIDMiddleware_SpanContextOverridesTraceparent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	spanTraceID := trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    spanTraceID,
		SpanID:     trace.SpanID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		TraceFlags: trace.FlagsSampled,
	})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		ctx := trace.ContextWithSpanContext(c.Request.Context(), spanCtx)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Traceparent", "00-ffffffffffffffffffffffffffffffff-aaaaaaaaaaaaaaaa-01")
	r.ServeHTTP(w, req)

	expected := spanTraceID.String()
	if w.Body.String() != expected {
		t.Errorf("span context should take priority; expected %q, got %q", expected, w.Body.String())
	}
}

func TestRequestIDMiddleware_IgnoresInvalidTraceparent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	invalid := []string{
		"",
		"too-short",
		"00-0000000000000000000000000000000g-00f067aa0ba902b7-01", // non-hex in trace-id
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // all-zero trace-id
	}

	for _, tp := range invalid {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		if tp != "" {
			req.Header.Set("Traceparent", tp)
		}
		req.Header.Set(RequestIDHeader, "fallback-id")
		r.ServeHTTP(w, req)

		if w.Body.String() != "fallback-id" {
			t.Errorf("expected fallback to X-Request-ID for invalid traceparent %q, got %q", tp, w.Body.String())
		}
	}
}

func TestRequestIDMiddleware_FutureTraceparentVersionStillUsesTraceID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})

	// W3C spec: future versions (>00, !=ff) should still be parsed for
	// trace-id and parent-id at the standard positions.
	const traceID = "4bf92f3577b6a27e8e681df2e0f0a3aa"
	tp := "01-" + traceID + "-00f067aa0ba902b7-01"

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Traceparent", tp)
	req.Header.Set(RequestIDHeader, "fallback-id")
	r.ServeHTTP(w, req)

	if w.Body.String() != traceID {
		t.Errorf("expected trace ID %q for future traceparent version, got %q", traceID, w.Body.String())
	}
}

// ============================================================================
// traceIDFromContext Unit Tests
// ============================================================================

func TestTraceIDFromContext_NoTraceID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	if id := traceIDFromContext(c); id != "" {
		t.Errorf("expected empty string without span or traceparent, got %q", id)
	}
}

func TestTraceIDFromContext_WithSpanContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	traceID := trace.TraceID{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     trace.SpanID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)
	c.Request = httptest.NewRequest("GET", "/", nil).WithContext(ctx)

	got := traceIDFromContext(c)
	if got != traceID.String() {
		t.Errorf("expected %q, got %q", traceID.String(), got)
	}
}

func TestTraceIDFromContext_WithTraceparentHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.Header.Set("Traceparent", "00-4bf92f3577b6a27e8e681df2e0f0a3aa-00f067aa0ba902b7-01")

	got := traceIDFromContext(c)
	if got != "4bf92f3577b6a27e8e681df2e0f0a3aa" {
		t.Errorf("expected trace ID from traceparent, got %q", got)
	}
}

// ============================================================================
// GetRequestID Tests
// ============================================================================

func TestGetRequestID_EmptyContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	if id := GetRequestID(c); id != "" {
		t.Errorf("expected empty string for context without middleware, got %q", id)
	}
}
