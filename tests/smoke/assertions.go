//go:build smoke

package smoke

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// assertEventually polls check until it returns nil or maxWait elapses.
// Polls at pollInterval. Logs elapsed-on-success at INFO level; fails
// only on timeout. This is the standard shape for "the system needs a
// few seconds to converge after a blue/green flip" tests.
//
// Never assert `elapsed < X` on the happy path. This helper only fails
// when the deadline is reached with a non-nil error.
func assertEventually(t *testing.T, maxWait, pollInterval time.Duration, check func() error) {
	t.Helper()
	start := time.Now()
	deadline := start.Add(maxWait)

	var lastErr error
	for {
		err := check()
		if err == nil {
			t.Logf("assertEventually: success after %s", time.Since(start).Round(time.Millisecond))
			return
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("assertEventually: timed out after %s: %v", maxWait, lastErr)
		}
		time.Sleep(pollInterval)
	}
}

// assertStatusCode fails the test if resp.StatusCode does not match want.
// Closes the response body as a side effect. Safe to call on a nil
// response: it fails cleanly.
func assertStatusCode(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp == nil {
		t.Fatalf("assertStatusCode: response is nil (wanted %d)", want)
	}
	if resp.StatusCode != want {
		t.Fatalf("assertStatusCode: got %d, want %d", resp.StatusCode, want)
	}
}

// doGet performs a GET against the NHP server base URL with the package
// HTTPClient. Returns the response and body, both already drained and
// safe to read.
func doGet(t *testing.T, baseURL, path string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	return doRequest(t, testConfig.HTTPClient, http.MethodGet, baseURL+path, nil, headers)
}

// doGetNoRedirect is like doGet but uses the no-redirect client, so 3xx
// responses are surfaced to the caller instead of being followed.
func doGetNoRedirect(t *testing.T, baseURL, path string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	return doRequest(t, testConfig.NoRedirectClient, http.MethodGet, baseURL+path, nil, headers)
}

// doRequest performs an HTTP request with the given client and returns
// the response + a fully-read body. Fails the test on transport errors.
func doRequest(t *testing.T, client *http.Client, method, url string, body io.Reader, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, url, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Note on http.ErrUseLastResponse: when CheckRedirect returns
	// that sentinel, Go's http.Client returns (resp, nil) — error is
	// explicitly nil, not wrapped — so the no-redirect client flows
	// through this path normally. We do NOT need to special-case it
	// here. Verified against net/http source (stable since Go 1.7).
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", url, err)
	}
	return resp, respBody
}

// unmarshalJSON parses body into dst, failing the test with a truncated
// body on parse error. Used in place of bare json.Unmarshal so failures
// include context.
func unmarshalJSON(t *testing.T, body []byte, dst interface{}) {
	t.Helper()
	if err := json.Unmarshal(body, dst); err != nil {
		t.Fatalf("unmarshal JSON: %v\nbody: %s", err, truncate(body, 512))
	}
}

// truncate returns up to n bytes of body, with an "...[truncated]"
// marker if it had to cut. Useful for putting bodies in failure
// messages without spamming multi-KB JSON into test output.
func truncate(body []byte, n int) string {
	if len(body) <= n {
		return string(body)
	}
	return string(body[:n]) + "...[truncated]"
}
