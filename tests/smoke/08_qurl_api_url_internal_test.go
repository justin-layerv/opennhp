//go:build smoke

package smoke

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestQurlConfig_APIURLPointsAtInternalALB asserts that every
// nhp-server in the active ASG has QURL_API_URL set to the expected
// internal-ALB hostname. Regression class: a tfvars revert silently
// flips api_url back to the public hostname — the plugin still works
// (auth gate is identical) but the network-isolation guarantee from
// qurl-service #335 is quietly defeated. Until PR4 lands the
// public-ALB 404 lockdown, this fence is the only signal that catches
// it.
//
// Regression fence for PR #1596 (qurl-service #335 PR2 — point NHP
// server at internal-ALB hostname).
//
// What this fence catches: tfvars revert to public URL; user_data
// template regression that omits/mistypes the QURL_API_URL line.
// What it does not catch: an instance that's *running* with stale
// env. ASG instance refresh on user_data change makes that
// non-class today — fencing /proc/<pid>/environ would add SSM
// complexity for an unrealistic regression.
//
// Lifecycle (Tier 1 → delete, not Tier 2 → keep): this test fences a
// *configuration-drift* bug class, not a consumer contract. Once
// (a) PR4 lands the public-ALB 404 for `/internal/*` (revert to the
// public URL produces a hard handler failure, not silent drift), and
// (b) #1605 tightens the TF coupling so `qurl_config.api_url` is
// derived from `var.qurl_internal_service_domain` rather than free-
// form tfvars, the underlying regression class is structurally
// eliminated. Per CLAUDE.md "Smoke Test Suite" rule 5 ("Deletion is
// a valid PR"), this file should be deleted at that point — not
// retargeted at a different bug class.
func TestQurlConfig_APIURLPointsAtInternalALB(t *testing.T) {
	skipIfQurlInternalALBDisabled(t)
	skipIfNoSSMProbes(t)

	asgName := requireActiveServerASG(t)
	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s — cannot probe QURL_API_URL", asgName)
	}

	wantURL := "https://" + testConfig.QURLInternalAPIHostname

	for _, instance := range instances {
		t.Run(instance, func(t *testing.T) {
			t.Parallel()

			// 120s matches 07_qurl_internal_alb_test.go's per-instance
			// budget. sendShellScript's polling deadline is 45s, so
			// the extra slack hardens against transient SSM agent
			// slowness without meaningful cost on the happy path.
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()

			gotURL, err := probeQurlAPIURL(ctx, instance)
			if err != nil {
				t.Errorf("instance %s: read QURL_API_URL from %s: %v", instance, nhpServerEnvFilePath, err)
				return
			}
			if msg := classifyAPIURLDrift(gotURL, wantURL); msg != "" {
				t.Errorf("instance %s: %s", instance, msg)
			}
		})
	}
}

// classifyAPIURLDrift returns "" if gotURL matches wantURL exactly, or
// a triage-hint string identifying the drift class. The cases are
// ordered simple-first so the compound shell-quoted-AND-trailing-slash
// case is only matched as a residual:
//
//   - "" — exact match.
//   - "value is empty ..." — gotURL is the empty string (line exists
//     in env file but with no RHS).
//   - "Trailing-slash drift in tfvars." — gotURL is wantURL with a
//     trailing slash, no quotes.
//   - "Value is shell-quoted ..." — gotURL is wantURL wrapped in
//     single or double quotes, no trailing slash.
//   - "Value is shell-quoted AND trailing-slashed ..." — both
//     classes at once.
//   - "Value has surrounding whitespace ..." — gotURL is wantURL
//     with leading/trailing whitespace (no quotes, no slash).
//   - "Mismatch ... regressed to the public URL ..." — anything else.
//
// Compound shapes that mix whitespace with quotes or slashes (e.g.
// `" https://...."` or `https://...../  `) deliberately fall through
// to the catch-all "templating broke" hint. The user_data template
// has no path that produces those shapes today, so a dedicated branch
// per compound is not worth its diagnostic precision.
//
// Most branches below fence shapes the user_data template cannot
// produce today (it emits `QURL_API_URL=${qurl_api_url}` unquoted, and
// var.qurl_config.api_url is operator-controlled tfvars). Branches
// exist to lock in the dispatch contract under unit test, not because
// the template can emit them — a future template edit that DOES emit
// quoted or whitespace-padded values would be caught with a precise
// diagnostic instead of a confused operator chasing a "regressed to
// the public URL" hint.
//
// Pulled out as a pure function so the dispatch is unit-testable in
// TestClassifyAPIURLDrift without an SSM round-trip.
//
// Production-reachability asymmetry: the whitespace branch is locked
// in unit tests but is unreachable from the live probe — both
// sendShellScript and parseQurlAPIURLValue TrimSpace before the
// classifier ever sees the value. Branch exists for the dispatch
// contract; a future probe path that bypasses TrimSpace would
// re-activate it.
func classifyAPIURLDrift(gotURL, wantURL string) string {
	if gotURL == wantURL {
		return ""
	}
	prefix := fmt.Sprintf("QURL_API_URL = %q; want %q", gotURL, wantURL)
	if gotURL == "" {
		// Line exists in env file but the RHS is empty. Distinct from
		// "line missing entirely" (caught by classifyQurlAPIURLError
		// at the probe layer): here the env was rendered but the
		// variable interpolation produced nothing — most likely a
		// tfvars value of "" or a templating regression that left
		// var.qurl_api_url unset.
		return prefix + ". Value is empty — tfvars set api_url to an empty string, or the user_data template's variable interpolation produced nothing."
	}
	// Paired-delimiter strip: only treat the value as quoted if both
	// ends are the same quote char. strings.Trim with a cutset would
	// happily accept mismatched pairs like `"foo'`, which is not a
	// shape any real shell would produce — those should fall to the
	// catch-all "regressed to the public URL" hint, not the misleading
	// "shell-quoted" hint.
	unquoted := stripPairedQuotes(gotURL)
	switch {
	case strings.TrimRight(gotURL, "/") == wantURL:
		// Trailing slash, not quoted (TrimRight on the unmodified
		// gotURL removes only the slash).
		return prefix + ". Trailing-slash drift in tfvars."
	case unquoted == wantURL:
		// Quoted, no trailing slash (Trim removed quotes; what
		// remains is exactly wantURL).
		return prefix + ". Value is shell-quoted — user_data template likely added quotes around the variable expansion."
	case strings.TrimRight(unquoted, "/") == wantURL && unquoted != gotURL:
		// Both: quotes were stripped (unquoted != gotURL) and the
		// inner value still has a trailing slash.
		return prefix + ". Value is shell-quoted AND trailing-slashed — both drift classes at once, likely a user_data template regression that wrapped the variable expansion AND tfvars typo."
	case strings.TrimSpace(gotURL) == wantURL:
		// Surrounding whitespace, no quotes, no slash. systemd's
		// EnvironmentFile parser strips leading/trailing whitespace
		// from unquoted values so runtime behavior is unaffected, but
		// the diagnostic class is distinct: a stray space points at
		// either a tfvars typo or a user_data template that emitted
		// the variable expansion with a leading/trailing space rather
		// than at "tfvars regressed to the public URL".
		return prefix + ". Value has surrounding whitespace — likely a tfvars typo or a user_data template regression that emitted whitespace around the variable expansion."
	default:
		return prefix + " (internal-ALB hostname). A mismatch usually means tfvars regressed to the public URL or the user_data templating broke."
	}
}

// stripPairedQuotes returns s without its outer quote chars iff s
// starts and ends with the same quote (`"` or `'`) and is at least
// two chars long. Otherwise returns s unchanged. Mismatched pairs
// like `"x'` or single-char strings fall through unchanged so the
// catch-all classifier branch fires instead of the misleading
// "shell-quoted" hint.
func stripPairedQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	first, last := s[0], s[len(s)-1]
	if (first == '"' || first == '\'') && first == last {
		return s[1 : len(s)-1]
	}
	return s
}

// TestClassifyAPIURLDrift pins the dispatch contract for the
// triage-hint generator above. The switch must distinguish:
//
//   - exact match: empty hint (caller skips the t.Errorf).
//   - empty value (line present, RHS empty).
//   - trailing slash only.
//   - shell-quoted only.
//   - shell-quoted AND trailing-slashed (compound).
//   - everything else (catch-all: tfvars revert to public URL or
//     templating broke).
//
// The compound branch must NOT fire on the pure-quoted case (the
// regression cr identified that this test exists to lock in).
func TestClassifyAPIURLDrift(t *testing.T) {
	const wantURL = "https://internal-api.qurl.layerv.xyz"

	tests := []struct {
		name     string
		got      string
		wantHint string // substring that must appear ("" means no hint)
	}{
		{
			name:     "exact_match_no_hint",
			got:      wantURL,
			wantHint: "",
		},
		{
			name:     "empty_value",
			got:      "",
			wantHint: "Value is empty",
		},
		{
			name:     "trailing_slash_only",
			got:      wantURL + "/",
			wantHint: "Trailing-slash drift in tfvars.",
		},
		{
			name:     "double_quoted_only",
			got:      `"` + wantURL + `"`,
			wantHint: "user_data template likely added quotes",
		},
		{
			name:     "single_quoted_only",
			got:      "'" + wantURL + "'",
			wantHint: "user_data template likely added quotes",
		},
		{
			name:     "double_quoted_and_trailing_slash",
			got:      `"` + wantURL + `/"`,
			wantHint: "shell-quoted AND trailing-slashed",
		},
		{
			name:     "single_quoted_and_trailing_slash",
			got:      "'" + wantURL + "/'",
			wantHint: "shell-quoted AND trailing-slashed",
		},
		{
			name:     "public_url_revert",
			got:      "https://api.layerv.xyz",
			wantHint: "regressed to the public URL",
		},
		{
			name:     "completely_garbled",
			got:      "not-even-a-url",
			wantHint: "regressed to the public URL",
		},
		{
			name:     "mismatched_quote_pair_falls_to_catchall",
			got:      `"` + wantURL + `'`,
			wantHint: "regressed to the public URL",
		},
		// Whitespace asymmetry note: probeQurlAPIURL TrimSpaces the
		// raw grep line BEFORE prefix-strip, so trailing whitespace in
		// a real env-file value is silently normalized away — the
		// classifier never sees the trailing_whitespace shape from a
		// live probe. Leading whitespace is preserved (it sits between
		// the `=` and the value, after prefix-strip). Both branches
		// are still pinned here because (a) the pure function is the
		// dispatch contract under test, and (b) a future probe path
		// that bypasses TrimSpace must continue to classify both
		// shapes correctly.
		{
			name:     "leading_whitespace",
			got:      " " + wantURL,
			wantHint: "Value has surrounding whitespace",
		},
		{
			name:     "trailing_whitespace",
			got:      wantURL + " ",
			wantHint: "Value has surrounding whitespace",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAPIURLDrift(tc.got, wantURL)
			switch {
			case tc.wantHint == "":
				if got != "" {
					t.Errorf("expected empty hint for exact match, got %q", got)
				}
			case got == "":
				t.Errorf("expected hint containing %q, got empty (no drift detected)", tc.wantHint)
			case !strings.Contains(got, tc.wantHint):
				t.Errorf("hint %q missing expected substring %q", got, tc.wantHint)
			}
		})
	}

	// Specifically pin the regression cr identified: a pure quoted
	// value (no slash) must NOT trip the compound branch.
	t.Run("pure_quoted_does_not_trip_compound_branch", func(t *testing.T) {
		got := classifyAPIURLDrift(`"`+wantURL+`"`, wantURL)
		if strings.Contains(got, "AND trailing-slashed") {
			t.Errorf("pure-quoted value misclassified as compound: %q", got)
		}
		if !strings.Contains(got, "user_data template likely added quotes") {
			t.Errorf("pure-quoted value should fire shell-quoted hint, got: %q", got)
		}
	})
}
