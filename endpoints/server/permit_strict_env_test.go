package server

import "testing"

// TestParsePermitStrictEnv_Tokens pins the shared token grammar
// directly against parsePermitStrictEnv, not via either caller's
// wrapper. The function is now load-bearing for two gates
// (NHP_INTERNAL_AUTH_REQUIRE, NHP_KNOCK_HEADERTYPE_VERIFY) and
// advertised as the authoritative grammar definition for any
// future fail-closed gate. Testing it transitively through one
// caller's wrapper tests would let a future refactor that only
// touches one wrapper silently drift the grammar — this test
// keeps the parser's contract pinned to the parser itself.
func TestParsePermitStrictEnv_Tokens(t *testing.T) {
	tests := []struct {
		in       string
		want     bool
		wantErr  bool
		wantWhat string
	}{
		// Falsy → permit (default).
		{"", false, false, "unset → permit"},
		{"false", false, false, "false → permit"},
		{"0", false, false, "0 → permit"},
		{"no", false, false, "no → permit"},
		{"off", false, false, "off → permit"},
		{"FALSE", false, false, "case-insensitive falsy"},
		{"  false  ", false, false, "whitespace-trimmed falsy"},
		// Truthy → strict.
		{"true", true, false, "true → strict"},
		{"1", true, false, "1 → strict"},
		{"yes", true, false, "yes → strict"},
		{"on", true, false, "on → strict"},
		{"TRUE", true, false, "case-insensitive truthy"},
		{"  true  ", true, false, "whitespace-trimmed truthy"},
		// Unrecognized → fail-loud (fail-closed against operator typo).
		{"enable", false, true, "typo 'enable' fails loud"},
		{"2", false, true, "non-boolean integer fails loud"},
		{"yep", false, true, "non-canonical truthy fails loud"},
		{"truthy", false, true, "substring of truthy fails loud"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parsePermitStrictEnv(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("%s: err=%v wantErr=%v", tt.wantWhat, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("%s: got=%v want=%v", tt.wantWhat, got, tt.want)
			}
		})
	}
}
