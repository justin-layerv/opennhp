package server

import (
	"strings"
	"testing"
)

// TestRedactSensitiveQuery pins the request-side redaction contract: the
// helper must strip a `token=` query param (the legacy GET plugin path and
// internal-endpoint rejection logs route RawQuery through it — see
// docs/SECURITY_TOKEN_TOUCH_INVENTORY.md), while leaving token-free queries
// untouched so operator-facing query logs stay useful.
func TestRedactSensitiveQuery(t *testing.T) {
	const secret = "Zm9vYmFyYmF6cXV4c2VjcmV0dG9rZW4"

	t.Run("empty stays empty", func(t *testing.T) {
		if got := redactSensitiveQuery(""); got != "" {
			t.Fatalf("redactSensitiveQuery(%q) = %q, want empty", "", got)
		}
	})

	t.Run("no token param is unchanged", func(t *testing.T) {
		in := "srcip=1.2.3.4"
		if got := redactSensitiveQuery(in); got != in {
			t.Fatalf("redactSensitiveQuery(%q) = %q, want unchanged", in, got)
		}
	})

	t.Run("token value is redacted", func(t *testing.T) {
		got := redactSensitiveQuery("token=" + secret)
		if strings.Contains(got, secret) {
			t.Fatalf("redactSensitiveQuery leaked the token: %q", got)
		}
		if !strings.Contains(got, "REDACTED") {
			t.Fatalf("redactSensitiveQuery(%q) = %q, want a REDACTED marker", "token=...", got)
		}
	})

	t.Run("token redacted, other params preserved", func(t *testing.T) {
		got := redactSensitiveQuery("token=" + secret + "&srcip=1.2.3.4")
		if strings.Contains(got, secret) {
			t.Fatalf("redactSensitiveQuery leaked the token: %q", got)
		}
		if !strings.Contains(got, "srcip=1.2.3.4") {
			t.Fatalf("redactSensitiveQuery(%q) dropped the srcip param: %q", "token=...&srcip=...", got)
		}
	})

	// url.ParseQuery errors on a malformed percent-escape in any param; the
	// helper must still strip the token instead of falling back to the raw
	// string (the bypass cr round 6 flagged).
	t.Run("token redacted even when another param is malformed", func(t *testing.T) {
		got := redactSensitiveQuery("token=" + secret + "&x=%ZZ")
		if strings.Contains(got, secret) {
			t.Fatalf("redactSensitiveQuery leaked the token on malformed input: %q", got)
		}
		if !strings.Contains(got, "x=%ZZ") {
			t.Fatalf("redactSensitiveQuery(%q) dropped the malformed param: %q", "token=...&x=%ZZ", got)
		}
	})

	// A param whose name merely ends in "token" must not be redacted.
	t.Run("lookalike param is not redacted", func(t *testing.T) {
		in := "mytoken=keepme"
		if got := redactSensitiveQuery(in); got != in {
			t.Fatalf("redactSensitiveQuery(%q) = %q, want unchanged", in, got)
		}
	})

	// When there's no token to redact, the original query form is preserved
	// (not re-encoded/key-sorted) so operator-facing logs stay faithful. The
	// input here passes the `token=` substring gate via the lookalike but has
	// no real token param; the old v.Encode() path would have sorted it.
	t.Run("no-op query keeps original order", func(t *testing.T) {
		in := "b=2&mytoken=x&a=1"
		if got := redactSensitiveQuery(in); got != in {
			t.Fatalf("redactSensitiveQuery(%q) = %q, want unchanged order", in, got)
		}
	})

	// An empty token value carries no secret and is left untouched on BOTH the
	// parse-ok and the malformed-fallback branch (consistency).
	t.Run("empty token value is not redacted on either branch", func(t *testing.T) {
		if got := redactSensitiveQuery("token=&srcip=1.2.3.4"); strings.Contains(got, "REDACTED") {
			t.Fatalf("parse-ok branch redacted an empty token: %q", got)
		}
		if got := redactSensitiveQuery("token=&x=%ZZ"); strings.Contains(got, "REDACTED") {
			t.Fatalf("malformed branch redacted an empty token: %q", got)
		}
	})
}
