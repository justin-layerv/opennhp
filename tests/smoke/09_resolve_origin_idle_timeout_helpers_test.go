//go:build smoke

package smoke

// Pure unit tests for helpers in 09_resolve_origin_idle_timeout_test.go.
//
// File-split rationale (CLAUDE.md `tests/smoke/` rule #1, "one file per
// NHP capability"): this file does NOT introduce a second capability —
// it covers the same capability as `09_resolve_origin_idle_timeout_test.go`
// (resolve-origin HTTP IdleTimeout fence). The split is purely a
// segregation between the network-dependent integration probe and the
// pure-logic unit tests for two non-trivial helpers it relies on:
//   - `parseOriginURL` defaults `path` and `port` and rejects
//     empty-host URLs (a real foot-gun: `net.JoinHostPort("", "443")`
//     yields `:443` which silently dials the wildcard).
//   - `isConnectionClosedErr` classifies an error type across syscall
//     errnos, EOF, errors.Join, and a (likely-dead, see #1802)
//     substring fallback.
// Inlining these unit tests into the integration file would force every
// developer iterating on them to either run the network probe or
// hand-pick test names. Splitting keeps unit-level regressions cheap to
// surface while the integration probe stays the single capability fence.
// Both files share the `smoke` build tag so `go test -tags=smoke ./...`
// runs them together; this file alone is identical local-vs-CI (no
// network, no AWS).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"syscall"
	"testing"
)

// TestIdleProbeInvalidTokenSatisfiesQurlServiceRegex fences the fixture
// against the qurl-service spec it relies on. The integration test
// docstring claims the fixture matches `^at_[a-z0-9_-]{22}$` (the
// service-side regex) AND the qurl-plugin's runtime validator
// (isValidTokenChar). Plugin-runtime coverage is implicit (a real
// regression there fails the integration test loud), but the
// service-side regex is plain string data — a typo that drops below
// 25 chars or accidentally introduces an uppercase letter would
// silently invalidate the probe (the plugin runtime is more permissive
// and would still 403, masking the fixture drift). One assertion here
// keeps the contract honest. See followup #1801 for distinguishing
// smoke-test 403s from real-invalid-token 403s in plugin metrics.
func TestIdleProbeInvalidTokenSatisfiesQurlServiceRegex(t *testing.T) {
	const qurlServiceTokenRegex = `^at_[a-z0-9_-]{22}$`
	re := regexp.MustCompile(qurlServiceTokenRegex)
	if !re.MatchString(idleProbeInvalidToken) {
		t.Fatalf("idleProbeInvalidToken=%q does not match qurl-service spec regex %s — fixture drifted; the integration probe will hit a non-403 path and the regression fence will fail for a non-regression reason", idleProbeInvalidToken, qurlServiceTokenRegex)
	}
}

func TestParseOriginURL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantHost  string
		wantPort  string
		wantPath  string
		wantError bool
	}{
		{
			name:     "bare host defaults port and path",
			input:    "https://resolve-origin.qurl.link",
			wantHost: "resolve-origin.qurl.link",
			wantPort: "443",
			wantPath: "/plugins/qurl",
		},
		{
			name:     "trailing slash also defaults path",
			input:    "https://resolve-origin.qurl.link/",
			wantHost: "resolve-origin.qurl.link",
			wantPort: "443",
			wantPath: "/plugins/qurl",
		},
		{
			name:     "explicit path is honored (env-var override use case)",
			input:    "https://resolve-origin.qurl.link/some/other/path",
			wantHost: "resolve-origin.qurl.link",
			wantPort: "443",
			wantPath: "/some/other/path",
		},
		{
			name:     "explicit non-default port carries through",
			input:    "https://resolve-origin.qurl.link:8443/plugins/qurl",
			wantHost: "resolve-origin.qurl.link",
			wantPort: "8443",
			wantPath: "/plugins/qurl",
		},
		{
			name:     "sandbox-style FQDN",
			input:    "https://resolve-origin.qurl.link.layerv.xyz",
			wantHost: "resolve-origin.qurl.link.layerv.xyz",
			wantPort: "443",
			wantPath: "/plugins/qurl",
		},
		{
			name:      "http scheme rejected",
			input:     "http://resolve-origin.qurl.link",
			wantError: true,
		},
		{
			// Documents that the rejection is "must be https", not
			// "must not be http". A future caller passing a non-http
			// non-https scheme should also fail loud rather than dial.
			name:      "non-https/non-http scheme also rejected",
			input:     "ftp://resolve-origin.qurl.link",
			wantError: true,
		},
		{
			name:      "garbage URL surfaces parse error",
			input:     "://not-a-url",
			wantError: true,
		},
		{
			// "https://" is parseable per Go's url.Parse but yields an
			// empty Host. parseOriginURL rejects this so a future code
			// path that strips the host doesn't silently dial the
			// wildcard via net.JoinHostPort("", "443") → ":443".
			name:      "empty-host URL is rejected loudly",
			input:     "https://",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, path, err := parseOriginURL(tc.input)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error, got host=%q port=%q path=%q", host, port, path)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tc.wantHost {
				t.Errorf("host: got %q, want %q", host, tc.wantHost)
			}
			if port != tc.wantPort {
				t.Errorf("port: got %q, want %q", port, tc.wantPort)
			}
			if path != tc.wantPath {
				t.Errorf("path: got %q, want %q", path, tc.wantPath)
			}
		})
	}
}

func TestIsConnectionClosedErr(t *testing.T) {
	// Sentinel errors the helper must recognize.
	wrappedECONNRESET := &net.OpError{Op: "read", Err: syscall.ECONNRESET}
	wrappedEPIPE := &net.OpError{Op: "write", Err: syscall.EPIPE}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "io.EOF", err: io.EOF, want: true},
		{name: "io.ErrUnexpectedEOF", err: io.ErrUnexpectedEOF, want: true},
		{name: "wrapped EOF via fmt.Errorf %w", err: fmt.Errorf("read response: %w", io.EOF), want: true},
		{name: "ECONNRESET via net.OpError", err: wrappedECONNRESET, want: true},
		{name: "EPIPE via net.OpError", err: wrappedEPIPE, want: true},
		{name: "ECONNRESET wrapped twice", err: fmt.Errorf("send: %w", fmt.Errorf("inner: %w", wrappedECONNRESET)), want: true},
		{name: "use of closed network connection (no sentinel)", err: errors.New("write: use of closed network connection"), want: true},
		{name: "wrapped use of closed network connection", err: fmt.Errorf("conn write: %w", errors.New("use of closed network connection")), want: true},
		{name: "unrelated error returns false", err: errors.New("connection refused"), want: false},
		{name: "freeform error containing 'context canceled' string returns false", err: errors.New("context canceled"), want: false},
		{name: "real context.Canceled sentinel returns false", err: context.Canceled, want: false},
		{name: "TLS handshake error returns false", err: errors.New("remote error: tls: bad record MAC"), want: false},
		{name: "errors.Join with EOF inside", err: errors.Join(io.EOF, errors.New("other")), want: true},
		{name: "errors.Join without close-related err", err: errors.Join(errors.New("a"), errors.New("b")), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isConnectionClosedErr(tc.err)
			if got != tc.want {
				t.Errorf("isConnectionClosedErr(%T:%v) = %v, want %v", tc.err, tc.err, got, tc.want)
			}
		})
	}

	// Spot-check the substring match isn't overly broad — strings that
	// merely *contain* network terminology should NOT trigger the
	// fallback. Neither of these contains the exact substring
	// "use of closed network connection", so isConnectionClosedErr must
	// return false for both. (Round-7 CR caught this: the previous
	// `if got && !strings.Contains(...)` form was a no-op; the assertion
	// now fails loudly if the substring fallback ever broadens.)
	for _, msg := range []string{
		"used a closed connection (intentional)",
		"this network connection is closed",
	} {
		if got := isConnectionClosedErr(errors.New(msg)); got {
			t.Errorf("substring fallback over-matched on %q: got true, want false", msg)
		}
	}
}
