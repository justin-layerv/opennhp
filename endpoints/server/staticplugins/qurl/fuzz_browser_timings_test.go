package qurl

import (
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

// FuzzRecordBrowserTimings drives recordBrowserTimings with arbitrary
// 6-tuple form-field values and asserts the cap-then-drop + NaN-guard
// + range-gate guarantees for every sample that escapes to the
// histogram. The contract being fenced:
//
//   - Every sample passed to recordLatencyMsRaw is finite.
//   - Every sample is >= 0 and <= browserTimingMaxMs.
//
// Any input that violates these post-conditions would mean an attacker
// can land a NaN / negative / over-cap value in the dashboard — which
// is exactly the histogram-contamination class recordBrowserTimings
// exists to prevent.
//
// The fuzz mutator emits arbitrary byte sequences. The body builder
// below sets ctx.Request.PostForm directly so each fuzz value reaches
// recordBrowserTimings byte-for-byte: an earlier raw-strings.Join
// implementation lost coverage when the mutator produced '&' / '=' /
// '%' / '+', because those characters split the form body during
// parsing and the fuzzer was effectively fuzzing "strings that survive
// application/x-www-form-urlencoded parsing" rather than the function
// under test.
func FuzzRecordBrowserTimings(f *testing.F) {
	// Seed corpus exercises the known-tricky shapes: NaN, infinities,
	// boundary values, sign-flips, exponent overflow. The fuzzer's
	// mutator can produce arbitrary bit-flips from these bases.
	seeds := []struct{ dns, tcp, tls, ttfb, dom, sub string }{
		{"10", "20", "30", "100", "200", "500"},        // happy path
		{"NaN", "0", "0", "0", "0", "0"},               // NaN guard
		{"-1", "-1", "-1", "-1", "-1", "-1"},           // negative wall
		{"60000", "60000", "60000", "60000", "0", "0"}, // exactly at cap
		{"60000.001", "0", "0", "0", "0", "0"},         // one µs over cap
		{"Infinity", "-Infinity", "0", "0", "0", "0"},  // ±Inf
		{"1e400", "1e400", "0", "0", "0", "0"},         // exponent overflow → ±Inf
		{"0", "0", "0", "0", "500", "100"},             // structurally allowed
		{"abc", "1.2.3", "", "0", "0", "0"},            // unparseable variants
		{"0.5", "0.5", "0.5", "0.5", "0.5", "0.5"},     // sub-ms valid
		{"&=%+", "=&=", "%%%", "+++", "&", "="},        // form-encoding metachars (must reach the parser intact)
	}
	for _, s := range seeds {
		f.Add(s.dns, s.tcp, s.tls, s.ttfb, s.dom, s.sub)
	}

	f.Fuzz(func(t *testing.T, dns, tcp, tls, ttfb, dom, sub string) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		// Bypass http.Request.ParseForm: set PostForm directly so each
		// fuzz value reaches recordBrowserTimings byte-for-byte regardless
		// of x-www-form-urlencoded escape semantics.
		ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", nil)
		ctx.Request.PostForm = url.Values{
			"token":                {"valid_test_token_123"},
			"t_dns_ms":             {dns},
			"t_tcp_ms":             {tcp},
			"t_tls_ms":             {tls},
			"t_ttfb_ms":            {ttfb},
			"t_dom_interactive_ms": {dom},
			"t_to_submit_ms":       {sub},
		}

		recordLatencyMsRaw := func(name string, ms float64) {
			if math.IsNaN(ms) {
				t.Errorf("NaN sample escaped to histogram: %q", name)
			}
			if math.IsInf(ms, 0) {
				t.Errorf("Inf sample escaped to histogram: %q", name)
			}
			if ms < 0 {
				t.Errorf("negative sample escaped: %q = %g", name, ms)
			}
			if ms > browserTimingMaxMs {
				t.Errorf("over-cap sample escaped: %q = %g (cap=%g)", name, ms, browserTimingMaxMs)
			}
		}
		incrCounter := func(name string) {} // counters are not part of the post-condition we fence here

		recordBrowserTimings(ctx, recordLatencyMsRaw, incrCounter)
	})
}
