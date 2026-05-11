package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// newPluginCapTestRouter wires a minimal gin engine with the body-size
// middleware on a /plugins/:aspid route and a sentinel handler that
// records what made it through. The handler records:
//   - the parsed token form value (if any), so the test can assert
//     the body actually reached the handler intact below the cap.
//   - a "reached" sentinel for assertions on whether the middleware
//     short-circuited.
func newPluginCapTestRouter(t *testing.T, limit int64) (*gin.Engine, *bool, *string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()

	reached := false
	gotToken := ""

	pluginGrp := r.Group("plugins")
	pluginGrp.Use(pluginBodySizeMiddleware(limit))
	pluginGrp.POST("/:aspid", func(ctx *gin.Context) {
		reached = true
		gotToken = ctx.PostForm("token")
		ctx.Status(http.StatusOK)
	})
	pluginGrp.GET("/:aspid", func(ctx *gin.Context) {
		reached = true
		ctx.Status(http.StatusOK)
	})

	return r, &reached, &gotToken
}

// TestPluginBodySizeMiddleware_BoundaryAtLimit fences the inclusive/
// exclusive choice at the cap. The check is `>` (a body of exactly
// `limit` bytes must reach the handler); a future refactor flipping
// to `>=` would silently tighten the contract by one byte.
func TestPluginBodySizeMiddleware_BoundaryAtLimit(t *testing.T) {
	const limit = int64(64) // tiny limit so we can build payloads cheaply

	cases := []struct {
		name        string
		bodySize    int
		wantStatus  int
		wantReached bool
	}{
		// At limit: handler runs. The 64-byte body is "token=" + 58 chars
		// of "a" — valid form data, parses cleanly.
		{"at_limit", 64, http.StatusOK, true},
		// One byte over: 413, handler must NOT run.
		{"one_over_limit", 65, http.StatusRequestEntityTooLarge, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, reached, _ := newPluginCapTestRouter(t, limit)

			// Build a body of exactly tc.bodySize bytes that's valid
			// form-encoded: "token=" + filler.
			prefix := "token="
			if tc.bodySize < len(prefix) {
				t.Fatalf("test setup: bodySize %d < prefix len %d", tc.bodySize, len(prefix))
			}
			body := prefix + strings.Repeat("a", tc.bodySize-len(prefix))

			req := httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body size %d, limit %d)\n  body: %q",
					rec.Code, tc.wantStatus, tc.bodySize, limit, rec.Body.String())
			}
			if *reached != tc.wantReached {
				t.Errorf("handler reached = %v, want %v", *reached, tc.wantReached)
			}
		})
	}
}

// TestPluginBodySizeMiddleware_PostFormPreservedBelowLimit fences the
// load-bearing assumption that calling ParseForm in the middleware
// doesn't break downstream ctx.PostForm() calls. ParseForm is
// idempotent (caches r.PostForm), so the handler still observes the
// populated map. A regression here would silently break every plugin
// that reads form data.
func TestPluginBodySizeMiddleware_PostFormPreservedBelowLimit(t *testing.T) {
	r, reached, gotToken := newPluginCapTestRouter(t, 16<<10)

	body := "token=at_test_token_value_here_x"
	req := httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if !*reached {
		t.Fatal("handler must run on under-cap body")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if want := "at_test_token_value_here_x"; *gotToken != want {
		t.Errorf("downstream PostForm token = %q, want %q (middleware ParseForm broke the form cache)",
			*gotToken, want)
	}
}

// TestPluginBodySizeMiddleware_GetUnaffected fences that GET requests
// (no body) flow through the middleware untouched. MaxBytesReader on
// an empty body is a no-op and the ParseForm short-circuit only fires
// for POST.
func TestPluginBodySizeMiddleware_GetUnaffected(t *testing.T) {
	r, reached, _ := newPluginCapTestRouter(t, 16) // tiny limit, irrelevant for GET

	req := httptest.NewRequest(http.MethodGet, "/plugins/qurl", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if !*reached {
		t.Fatal("GET handler must run regardless of body cap")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestPluginBodySizeMiddleware_NonFormPostStillCappedAtRead fences
// the cap-without-413 path for non-form-encoded POSTs. ParseForm
// short-circuits when Content-Type isn't form-urlencoded /
// multipart, so the explicit 413 in the middleware doesn't fire,
// but MaxBytesReader is still wrapping the body — any handler that
// reads it sees io.EOF / *http.MaxBytesError after the cap. The
// security goal (no unbounded read) is met regardless of the
// surfaced response code.
//
// This test asserts the read-side cap by having the handler attempt
// to consume the full body and surface the error. A regression where
// MaxBytesReader stopped wrapping non-form bodies would let the
// handler read all 200 bytes successfully.
func TestPluginBodySizeMiddleware_NonFormPostStillCappedAtRead(t *testing.T) {
	const limit = int64(32)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	pluginGrp := r.Group("plugins")
	pluginGrp.Use(pluginBodySizeMiddleware(limit))

	var readErr error
	pluginGrp.POST("/:aspid", func(ctx *gin.Context) {
		buf := make([]byte, 1024)
		_, readErr = ctx.Request.Body.Read(buf[:cap(buf)])
		// Drain remaining; the cap should produce *http.MaxBytesError.
		for readErr == nil {
			_, readErr = ctx.Request.Body.Read(buf[:cap(buf)])
		}
		ctx.Status(http.StatusOK)
	})

	body := bytes.Repeat([]byte("x"), 200)
	req := httptest.NewRequest(http.MethodPost, "/plugins/qurl", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if readErr == nil {
		t.Fatal("expected read error from MaxBytesReader, got nil (body fully readable past cap)")
	}
	var maxBytesErr *http.MaxBytesError
	if !errors.As(readErr, &maxBytesErr) {
		t.Errorf("read error = %v (%T), want *http.MaxBytesError", readErr, readErr)
	}
}
