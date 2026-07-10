package agent

import (
	"net/http"
	"testing"
	"time"
)

// InstallRegistrarForTest wires the package-level registrar directly at baseURL
// with serviceToken, BYPASSING Init's process-wide sync.Once, and restores the
// prior registrar when the test ends. It exists so a test in ANOTHER package
// (notably endpoints/server's relay-dispatch e2e) can drive the real agent
// plugin against a fake qurl-service WITHOUT depending on the global Init Once —
// which any other test that loads the "agent" plugin may have already consumed
// with a disabled config, leaving reg nil.
//
// This is the same cross-package test-seam pattern the metrics package uses
// (endpoints/metrics/publisher_testhelpers.go's *ForTest exports): a normal
// exported symbol, guarded only by the ForTest name + a *testing.T parameter so
// it cannot be called from production code. It does NOT touch initOnce, so a
// later real Init still behaves normally in a fresh process.
func InstallRegistrarForTest(t *testing.T, baseURL, serviceToken string) {
	t.Helper()
	prev := reg
	reg = &registrar{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      baseURL,
		serviceToken: serviceToken,
	}
	t.Cleanup(func() { reg = prev })
}
