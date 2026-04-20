package qurl

import (
	"regexp"
	"testing"
)

// qurlServiceTokenPattern mirrors the strict regex in qurl-service:
// see `qurlTokenPattern` in `internal/domain/qurl.go`
// (https://github.com/layervai/qurl-service/blob/main/internal/domain/qurl.go).
// The two repos are separate Go modules, so this is a hand copy that
// drifts unless someone notices — keep identical to the service-side
// pattern, and bump the cross-repo reference comment when the service
// changes shape.
//
// Today the plugin's ValidateAccessToken accepts a superset of inputs
// (Unicode letters, dots, 8-512 chars). nhp#1152 tracks tightening it.
// Once that lands, this fuzz becomes a true equality fence — the
// follow-up PR should also add the reverse assertion (plugin accepts ⇒
// service accepts) so both directions are pinned.
var qurlServiceTokenPattern = regexp.MustCompile(`^at_[a-z0-9_-]{22}$`)

// FuzzAccessTokenValidationDifferential feeds the same input to the plugin's
// ValidateAccessToken and the qurl-service token regex. Asserts only the
// "impossible" direction — plugin rejecting what the service accepts —
// because the other direction (plugin-accepts-extra) is the documented
// known gap and tracked separately at nhp#1152.
func FuzzAccessTokenValidationDifferential(f *testing.F) {
	// Seeds at exactly 25 bytes drive both validators; the shorter seeds
	// are kept as mutation hints only — the guard below skips them. The
	// fuzzer's mutator can still bit-flip the short seeds into 25-byte
	// shapes the assertion runs on.
	f.Add("at_abcdefghij_-klmnopqrst")     // 25 bytes — both accept
	f.Add("at_abc---def---ghi---jkl-")     // 25 bytes — hyphens-only body, both accept
	f.Add("at_abcdefghij.klmnopqrstu")     // 25 bytes — plugin accepts dot, service rejects on charset
	f.Add("at_abcdefghij\u00e1klmnopqrst") // 25 bytes — multi-byte non-ASCII letter (á is 2 bytes); plugin's IsLetter accepts, svc charset rejects
	f.Add("at_abcdefghij\u0660klmnopqrst") // 25 bytes — Arabic-Indic digit zero (U+0660, 2 bytes); plugin's IsDigit accepts, svc charset rejects
	f.Add("at_ABCDEFGHIJKLMNOPQRSTUV")     // 25 bytes — uppercase ASCII letters; plugin's IsLetter accepts, svc charset rejects
	f.Add("at_abc")                        // skipped by guard, mutation hint only
	f.Add("at_abcdefghij_-klmnopqrs")      // 24 bytes (skipped); mutation hint
	f.Add("")                              // skipped
	f.Add("at_")                           // skipped

	f.Fuzz(func(t *testing.T, token string) {
		// Service regex is anchored at exactly 25 bytes, so anything else
		// can never satisfy svcAccepts and the divergence assertion can't
		// fire. Bound on bytes (not runes) since that's what the regex sees.
		if len(token) != 25 {
			return
		}
		pluginErr := ValidateAccessToken(token)
		svcAccepts := qurlServiceTokenPattern.MatchString(token)
		if pluginErr != nil && svcAccepts {
			t.Fatalf("layer divergence: plugin rejects %q but svc regex accepts", token)
		}
	})
}
