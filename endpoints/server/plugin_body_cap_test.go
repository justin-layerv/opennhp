package server

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// countingReader wraps an io.Reader and counts every byte read from
// it. Used to fence the drain-past-cap path in
// pluginBodySizeMiddleware: a regression that removes the drain
// would only read ~limit+1 bytes (enough to trip MaxBytesReader),
// not the full request body. Single-goroutine: gin's ServeHTTP runs
// synchronously on the test goroutine, so no atomic needed.
type countingReader struct {
	inner io.Reader
	n     int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	r.n += int64(n)
	return n, err
}

// runOversizedDrainRequest builds a /plugins/qurl POST with a body of
// totalBytes form-encoded bytes, runs it through a router with a
// pluginBodySizeMiddleware capped at limit, and returns the recorder
// + the count of bytes the middleware consumed from the body. The
// handler under the middleware is fatal-on-reach: oversized requests
// must short-circuit before the handler runs.
//
// Unit-scope: this fences the Go-level drain (bytes read past the cap,
// drain-ceiling enforcement). httptest.NewRequest sends a
// Content-Length body; the CloudFront → origin path uses
// Transfer-Encoding: chunked, which goes through Go's chunked decoder
// transparently. The chunked path is fenced empirically by
// tests/smoke/13_plugins_test.go::TestPlugins_OversizedPOSTReturns413
// after deploy.
func runOversizedDrainRequest(t *testing.T, limit, totalBytes int64) (*httptest.ResponseRecorder, int64) {
	t.Helper()
	// 32-bit guard: strings.Repeat takes int, and int(int64) silently
	// truncates on 32-bit GOARCH. CI runs only on 64-bit today, but a
	// future test passing a body >= 2 GiB on a 32-bit platform would
	// build a bogus payload and the failure mode would be subtle.
	if totalBytes > math.MaxInt32 {
		t.Fatalf("totalBytes=%d exceeds MaxInt32; tighten the test or build a streaming body", totalBytes)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	pluginGrp := r.Group("plugins")
	pluginGrp.Use(pluginBodySizeMiddleware(limit))
	pluginGrp.POST("/:aspid", func(ctx *gin.Context) {
		t.Fatal("handler must not run on oversized body")
	})

	body := []byte("token=" + strings.Repeat("a", int(totalBytes)-len("token=")))
	tr := &countingReader{inner: bytes.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, "/plugins/qurl", tr)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec, tr.n
}

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

// TestPluginBodySizeMiddleware_DrainsBeyondCapOnOversized fences the
// drain-past-cap path added for issue #1859. When the body exceeds
// the cap, the middleware must keep reading from the underlying body
// (up to pluginBodyDrainCeiling) before responding with 413.
//
// Without this drain, the origin closes the TCP connection while the
// client is still streaming, and intermediate proxies (CloudFront)
// see a broken-origin close and serve their own error page instead
// of forwarding our 413. The visible symptom was the smoke test in
// 13_plugins_test.go observing a CloudFront 403 instead of the
// server's 413.
//
// Asserts on the read count, not just status — a regression that
// removes the io.CopyN drain would produce status=413 with only
// ~limit+1 bytes consumed.
func TestPluginBodySizeMiddleware_DrainsBeyondCapOnOversized(t *testing.T) {
	const limit = int64(32)
	const totalBytes = int64(4096) // well over limit, well under pluginBodyDrainCeiling

	rec, gotN := runOversizedDrainRequest(t, limit, totalBytes)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	// Tight equality: for a body smaller than the drain ceiling,
	// gotN must equal totalBytes exactly. `<` would catch an
	// under-drain regression; `==` also catches a future over-read
	// drift (e.g., a MaxBytesReader change that doubles the
	// initial read).
	if gotN != totalBytes {
		t.Errorf("body bytes read = %d, want exactly %d (drain past cap is not running, or over-read drift)",
			gotN, totalBytes)
	}
	// Connection: close is set explicitly because gin's writer
	// wrapper hides the *response from MaxBytesReader's
	// requestTooLarge() type assertion. Locking it in here so a
	// future change that drops the ctx.Header call fails loudly.
	if got := rec.Header().Get("Connection"); got != "close" {
		t.Errorf("Connection header = %q, want %q", got, "close")
	}
}

// TestPluginBodySizeMiddleware_DrainCappedAtCeiling fences the upper
// bound on the courtesy drain. An attacker uploading orders of
// magnitude more than the cap must not be able to force the
// middleware to consume the entire body — the drain stops at
// pluginBodyDrainCeiling bytes regardless of how much more the
// client wants to send.
//
// Asserts read count is bounded at roughly (limit + drain ceiling).
// The slack accounts for MaxBytesReader's internal read-ahead by the
// time ParseForm trips and is well under one MiB.
func TestPluginBodySizeMiddleware_DrainCappedAtCeiling(t *testing.T) {
	const limit = int64(32)
	// Total body exceeds limit + drain ceiling, so the middleware
	// must stop reading before consuming all of it.
	totalBytes := limit + pluginBodyDrainCeiling + (4 << 10)

	rec, gotN := runOversizedDrainRequest(t, limit, totalBytes)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	// Tight equality: MaxBytesReader caps incoming Read at l.n+1
	// and io.CopyN reads exactly N or until EOF, so for a body
	// bigger than the ceiling, gotN must equal limit+1+ceiling
	// exactly. No slack — if a future Go release loosens
	// MaxBytesReader's read-ahead, this assert surfaces it. The
	// equality form also catches under-drain regressions that the
	// previous `>= ceiling` lower-bound missed.
	if wantExact := limit + 1 + pluginBodyDrainCeiling; gotN != wantExact {
		t.Errorf("body bytes read = %d, want exactly %d (drain ceiling not enforced, or under-/over-drain drift)",
			gotN, wantExact)
	}
}

// failingReader returns up to byteBudget bytes from inner and then
// returns the configured non-EOF error on the next Read. Used to
// fence the Debug-log path that fires when io.CopyN drains end
// early on a torn TCP connection (vs. clean EOF on a smaller-than-
// ceiling body).
type failingReader struct {
	inner      io.Reader
	byteBudget int64
	read       int64
	err        error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.read >= r.byteBudget {
		return 0, r.err
	}
	remain := r.byteBudget - r.read
	if int64(len(p)) > remain {
		p = p[:remain]
	}
	n, err := r.inner.Read(p)
	r.read += int64(n)
	if err != nil {
		return n, err
	}
	if r.read >= r.byteBudget {
		return n, r.err
	}
	return n, nil
}

// TestPluginBodySizeMiddleware_DrainErrorStillResponds413 fences that
// a non-EOF read error mid-drain still produces a 413 + Connection:
// close response. Mirrors a torn TCP connection where the client
// hangs up while the server is mid-drain.
//
// The Debug-log path inside the middleware fires on non-EOF errors;
// this test exercises the same branch from the response side. A
// regression that returns early on drainErr (e.g., a future change
// that bubbles the error to the caller) would skip the
// AbortWithStatusJSON and the response code would not be 413.
func TestPluginBodySizeMiddleware_DrainErrorStillResponds413(t *testing.T) {
	const limit = int64(32)
	const goodBytes = int64(1024) // drain reads this many before erroring

	gin.SetMode(gin.TestMode)
	r := gin.New()
	pluginGrp := r.Group("plugins")
	pluginGrp.Use(pluginBodySizeMiddleware(limit))
	pluginGrp.POST("/:aspid", func(ctx *gin.Context) {
		t.Fatal("handler must not run on oversized body")
	})

	body := []byte("token=" + strings.Repeat("a", int(goodBytes)*2))
	fr := &failingReader{
		inner:      bytes.NewReader(body),
		byteBudget: goodBytes,
		err:        errors.New("connection torn"),
	}
	req := httptest.NewRequest(http.MethodPost, "/plugins/qurl", fr)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 (mid-drain error should still produce 413)",
			rec.Code)
	}
	if got := rec.Header().Get("Connection"); got != "close" {
		t.Errorf("Connection header = %q, want %q", got, "close")
	}
}

// TestPluginBodyDrainCeilingExceedsCap fences the absorption-margin
// invariant between the request cap and the drain ceiling. Same shape
// as the maxInternalKnockRequestSize == maxForwardResponseSize drift
// test in http_forward_test.go. A future PR that raises
// maxPluginRequestSize past pluginBodyDrainCeiling silently
// invalidates the comment block on pluginBodyDrainCeiling and
// shrinks the absorption margin below 1x, putting the CloudFront
// substitution back on the table for legitimate-but-bloated uploads.
//
// Floor ratio: 4×. Sized so the absorption margin always covers at
// least one TLS record (16 KiB max) plus a typical kernel socket-
// buffer page of in-flight overshoot, even if the cap is bumped to
// the largest plausible plugin payload short of structural redesign
// (~256 KiB). The current live ratio is 64× (16 KiB cap, 1 MiB drain);
// the 16× margin between the floor and the live value is intentional
// headroom so modest cap bumps don't force a drain-ceiling bump in
// lockstep.
func TestPluginBodyDrainCeilingExceedsCap(t *testing.T) {
	const minRatio = int64(4) // see comment above
	if pluginBodyDrainCeiling < maxPluginRequestSize*minRatio {
		t.Errorf("pluginBodyDrainCeiling (%d) < %dx maxPluginRequestSize (%d). "+
			"If the cap is being intentionally raised, also raise the drain "+
			"ceiling and update the comment block on pluginBodyDrainCeiling "+
			"(plugin_body_cap.go) — the absorption margin is load-bearing for "+
			"the CloudFront-fronted path (issue #1859).",
			pluginBodyDrainCeiling, minRatio, maxPluginRequestSize)
	}
}
