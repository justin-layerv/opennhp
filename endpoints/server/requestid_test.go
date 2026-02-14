package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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

func TestGetRequestID_EmptyContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	if id := GetRequestID(c); id != "" {
		t.Errorf("expected empty string for context without middleware, got %q", id)
	}
}
