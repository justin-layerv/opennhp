package qurlv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

// validClaimsJSON is a canonical, schema-valid claims object used as the baseline
// the strict-parser tests perturb. Keys, key lengths, and time fields are all
// valid so that any test failure isolates the single field under test.
func validClaimsJSON(t *testing.T) string {
	t.Helper()
	return `{` +
		`"v":2,` +
		`"iss":"qurl-service",` +
		`"kid":"qurl-issuer-key-2026-06",` +
		`"iat":1781910000,` +
		`"nbf":1781910000,` +
		`"exp":1781910300,` +
		`"jti":"qurl_01JABCDEF",` +
		`"cell_public_key_b64":"` + testX25519B64(t, 1) + `",` +
		`"cell_id":"cell-a",` +
		`"relay_url":"https://relay.example.com",` +
		`"resource_public_key_b64":"` + testResourceKeyB64(t) + `",` +
		`"qurl_user_public_key_b64":"` + testX25519B64(t, 2) + `"` +
		`}`
}

// testX25519B64 returns a deterministic 32-byte (X25519-shaped) base64url key.
func testX25519B64(t *testing.T, seed byte) string {
	t.Helper()
	raw := make([]byte, x25519PublicKeyBytes)
	for i := range raw {
		raw[i] = seed
	}
	return encodeB64(raw)
}

// testResourceKeyB64 returns a real DER SPKI P-256 public key as base64url, so
// the resource-key length window is exercised against realistic bytes.
func testResourceKeyB64(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return encodeB64(der)
}

func TestParseClaims_Valid(t *testing.T) {
	c, err := parseClaims([]byte(validClaimsJSON(t)))
	if err != nil {
		t.Fatalf("expected valid claims, got error: %v", err)
	}
	if c.V != 2 || c.Iss != "qurl-service" || c.Kid == "" {
		t.Fatalf("unexpected parsed claims: %+v", c)
	}
}

// TestParseClaims_CellIDOptional locks the one optional claim's contract: the
// strict parser accepts claims with cell_id absent entirely AND with cell_id
// present, since cell_id is allowlisted but not required. (SignClaims uses
// omitempty so newly-minted claims omit an unset cell_id rather than emitting
// "cell_id":""; see TestSignClaims_OmitsEmptyCellID.)
func TestParseClaims_CellIDOptional(t *testing.T) {
	base := validClaimsJSON(t)

	// Present (non-empty) — the baseline already carries "cell_id":"cell-a".
	if _, err := parseClaims([]byte(base)); err != nil {
		t.Fatalf("claims with cell_id present must parse: %v", err)
	}

	// Absent entirely — drop the cell_id member.
	absent := strings.Replace(base, `"cell_id":"cell-a",`, ``, 1)
	if absent == base {
		t.Fatal("test setup: cell_id not removed from baseline")
	}
	c, err := parseClaims([]byte(absent))
	if err != nil {
		t.Fatalf("claims with cell_id absent must parse (it is optional): %v", err)
	}
	if c.CellID != "" {
		t.Fatalf("absent cell_id should decode to empty string, got %q", c.CellID)
	}
}

func TestParseClaims_StrictRejections(t *testing.T) {
	base := validClaimsJSON(t)
	tests := []struct {
		name string
		json string
	}{
		{"duplicate key", strings.Replace(base, `"v":2,`, `"v":2,"v":2,`, 1)},
		{"unknown field", strings.Replace(base, `"cell_id":"cell-a",`, `"cell_id":"cell-a","extra":"x",`, 1)},
		{"null required value", strings.Replace(base, `"jti":"qurl_01JABCDEF",`, `"jti":null,`, 1)},
		{"missing required", strings.Replace(base, `"jti":"qurl_01JABCDEF",`, ``, 1)},
		{"float time", strings.Replace(base, `"exp":1781910300,`, `"exp":1781910300.0,`, 1)},
		{"exponent time", strings.Replace(base, `"exp":1781910300,`, `"exp":1.7e9,`, 1)},
		{"string time", strings.Replace(base, `"exp":1781910300,`, `"exp":"1781910300",`, 1)},
		{"negative time", strings.Replace(base, `"nbf":1781910000,`, `"nbf":-1,`, 1)},
		{"array for scalar", strings.Replace(base, `"jti":"qurl_01JABCDEF",`, `"jti":["x"],`, 1)},
		{"wrong version", strings.Replace(base, `"v":2,`, `"v":1,`, 1)},
		{"nbf after exp", strings.Replace(base, `"nbf":1781910000,`, `"nbf":1781920000,`, 1)},
		// iat after exp: structurally incoherent (issued after it expires). Pushing
		// iat past exp while leaving nbf<=exp isolates the iat<=exp bound (it would
		// otherwise pass the nbf<=exp check). Baseline exp is 1781910300.
		{"iat after exp", strings.Replace(base, `"iat":1781910000,`, `"iat":1781920000,`, 1)},
		// Empty-string required scalars: present (so not caught by requireKeys) but
		// empty (caught by validateClaimValues). Isolated here per review so the
		// empty-string rejection paths are pinned, not only covered transitively.
		{"empty kid", strings.Replace(base, `"kid":"qurl-issuer-key-2026-06",`, `"kid":"",`, 1)},
		{"empty jti", strings.Replace(base, `"jti":"qurl_01JABCDEF",`, `"jti":"",`, 1)},
		{"empty relay_url", strings.Replace(base, `"relay_url":"https://relay.example.com",`, `"relay_url":"",`, 1)},
		{"short cell key", strings.Replace(base, `"cell_public_key_b64":"`+testX25519B64(t, 1)+`"`, `"cell_public_key_b64":"AAAA"`, 1)},
		{"top-level array", `[` + base + `]`},
		{"trailing data", base + `{}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseClaims([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected rejection for %q, got nil", tc.name)
			}
			if !errors.Is(err, ErrStrictParse) && !errors.Is(err, ErrKeyLength) && !errors.Is(err, ErrEncoding) {
				t.Fatalf("expected a strict-parse/key-length/encoding error, got: %v", err)
			}
		})
	}
}

func TestParseSecret_Valid(t *testing.T) {
	s, err := parseSecret([]byte(`{"qurl_user_private_key_b64":"` + testX25519B64(t, 9) + `"}`))
	if err != nil {
		t.Fatalf("expected valid secret, got: %v", err)
	}
	if s.QurlUserPrivateKeyB64 == "" {
		t.Fatal("empty private key after parse")
	}
}

func TestParseSecret_StrictRejections(t *testing.T) {
	// secretJSON wraps a base64url private key in a valid secret object so the
	// length cases below exercise ONLY the decoded-length check (valid base64url,
	// right schema, wrong key size).
	secretJSON := func(privB64 string) string {
		return `{"qurl_user_private_key_b64":"` + privB64 + `"}`
	}
	tests := []struct {
		name string
		json string
		// wantKeyLen asserts the rejection is specifically ErrKeyLength (the
		// decode-then-length-check contract for the PoP secret). Other cases only
		// assert a non-nil error.
		wantKeyLen bool
	}{
		{name: "unknown field", json: `{"qurl_user_private_key_b64":"AAAA","x":1}`},
		{name: "missing required", json: `{}`},
		{name: "duplicate key", json: `{"qurl_user_private_key_b64":"AAAA","qurl_user_private_key_b64":"BBBB"}`},
		{name: "null value", json: `{"qurl_user_private_key_b64":null}`},
		{name: "bad base64url", json: `{"qurl_user_private_key_b64":"not base64!!"}`},
		// Wrong decoded length: valid unpadded base64url, but not a 32-byte X25519
		// scalar. The PoP secret must be rejected at parse time, not deferred.
		{name: "short private key (3 bytes)", json: secretJSON(encodeB64([]byte{1, 2, 3})), wantKeyLen: true},
		{name: "short private key (31 bytes)", json: secretJSON(encodeB64(make([]byte, 31))), wantKeyLen: true},
		{name: "long private key (33 bytes)", json: secretJSON(encodeB64(make([]byte, 33))), wantKeyLen: true},
		{name: "long private key (64 bytes)", json: secretJSON(encodeB64(make([]byte, 64))), wantKeyLen: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSecret([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected rejection for %q, got nil", tc.name)
			}
			if tc.wantKeyLen && !errors.Is(err, ErrKeyLength) {
				t.Fatalf("%q: expected ErrKeyLength, got %v", tc.name, err)
			}
		})
	}
}
