package qurlv2

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// These tests pin the strict-base64url contract: the parser must reject
// NON-CANONICAL base64url encodings (a trailing-bit variant that the lenient
// RawURLEncoding decoder would silently accept and decode to the SAME bytes).
// This is both a signature-bypass guard (one string per byte slice) and the
// agreement point with the WebCrypto/JS port on which STRINGS are well-formed.
//
// Coverage is at BOTH layers per the design's "length-check / decode each field"
// rule: the three outer fragment parts (claims, secret, sig) via ParseFragment,
// and the four decoded key fields (the three claim keys + the secret key) via
// parseClaims / parseSecret. The sig part is the outer part with no inner-field
// equivalent, so it is exercised directly through ParseFragment.

// nonCanonicalB64 returns a non-canonical base64url encoding of the SAME bytes as
// canon, produced by setting the lowest bit of the final base64 character. That
// bit is a "don't care" trailing bit only when len(decoded)%3 != 0, so this helper
// is valid solely for inputs with such slack (every fixed-width key field and the
// 64-byte signature qualify). It SELF-VERIFIES the construction: the returned
// string must (a) differ from canon and (b) still decode under the lenient
// RawURLEncoding to the identical bytes — otherwise the test would be asserting
// rejection of a string that is merely different bytes (which strict legitimately
// accepts), giving a false pass. A failure here is a test-setup bug, surfaced loudly.
func nonCanonicalB64(t *testing.T, canon string) string {
	t.Helper()
	if canon == "" {
		t.Fatal("nonCanonicalB64: empty canonical input")
	}

	want, err := base64.RawURLEncoding.Strict().DecodeString(canon)
	if err != nil {
		t.Fatalf("nonCanonicalB64: %q is not canonical base64url to begin with: %v", canon, err)
	}
	if len(want)%3 == 0 {
		t.Fatalf("nonCanonicalB64: decoded length %d is a multiple of 3 (no trailing-bit slack); "+
			"this helper cannot build a same-bytes variant for %q", len(want), canon)
	}

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := canon[len(canon)-1]
	idx := strings.IndexByte(alphabet, last)
	if idx < 0 {
		t.Fatalf("nonCanonicalB64: final char %q not in base64url alphabet", string(last))
	}
	variant := canon[:len(canon)-1] + string(alphabet[idx^1]) // flip the lowest sextet bit (always changes the char)

	got, err := base64.RawURLEncoding.DecodeString(variant)
	if err != nil {
		t.Fatalf("nonCanonicalB64: lenient decode of variant %q failed: %v", variant, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("nonCanonicalB64: variant %q decodes to different bytes (%x != %x); "+
			"the flipped bit was significant, not a trailing don't-care bit", variant, got, want)
	}
	// And it MUST be rejected by the strict decoder — the property under test.
	if _, err := base64.RawURLEncoding.Strict().DecodeString(variant); err == nil {
		t.Fatalf("nonCanonicalB64: strict decoder unexpectedly accepted non-canonical %q", variant)
	}
	return variant
}

// TestDecodeB64_RejectsNonCanonical is a direct unit test of the chokepoint:
// decodeB64 must reject a non-canonical trailing-bit variant with ErrEncoding,
// even though the lenient decoder maps it to the same bytes.
func TestDecodeB64_RejectsNonCanonical(t *testing.T) {
	canon := testX25519B64(t, 0) // 32 bytes -> 43 chars, last char has 4 slack bits
	variant := nonCanonicalB64(t, canon)
	if _, err := decodeB64(variant); !errors.Is(err, ErrEncoding) {
		t.Fatalf("decodeB64(non-canonical) must return ErrEncoding, got: %v", err)
	}
	// Canonical still decodes cleanly (no over-rejection regression).
	if _, err := decodeB64(canon); err != nil {
		t.Fatalf("decodeB64(canonical) must succeed, got: %v", err)
	}
}

// TestParseClaims_RejectsNonCanonicalKeyFields feeds a non-canonical base64url
// variant into each decoded claim key field and asserts the strict parser rejects
// it. These are the inner-field cases for the three signed public keys.
func TestParseClaims_RejectsNonCanonicalKeyFields(t *testing.T) {
	base := validClaimsJSON(t)

	cases := []struct {
		name  string
		canon string // the exact canonical substring present in `base`
	}{
		{fieldCellPublicKeyB64, testX25519B64(t, 1)},
		{fieldQurlUserPublicKeyB64, testX25519B64(t, 2)},
		{fieldResourcePublicKeyB64, testResourceKeyB64ForBase(t, base)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			variant := nonCanonicalB64(t, tc.canon)
			perturbed := strings.Replace(base, tc.canon, variant, 1)
			if perturbed == base {
				t.Fatalf("test setup: canonical value for %s not found in baseline", tc.name)
			}
			_, err := parseClaims([]byte(perturbed))
			if !errors.Is(err, ErrEncoding) {
				t.Fatalf("%s: non-canonical encoding must be rejected with ErrEncoding, got: %v", tc.name, err)
			}
		})
	}
}

// TestParseSecret_RejectsNonCanonicalKey is the inner-field case for the secret's
// per-qURL private key.
func TestParseSecret_RejectsNonCanonicalKey(t *testing.T) {
	canon := testX25519B64(t, 9)
	variant := nonCanonicalB64(t, canon)
	secretJSON := `{"qurl_user_private_key_b64":"` + variant + `"}`
	if _, err := parseSecret([]byte(secretJSON)); !errors.Is(err, ErrEncoding) {
		t.Fatalf("non-canonical secret key must be rejected with ErrEncoding, got: %v", err)
	}
}

// TestParseFragment_RejectsNonCanonicalParts exercises the three OUTER fragment
// parts. The signature part is the part with no inner-field equivalent, so it can
// only be covered here. claims and secret outer parts are base64 of variable-length
// JSON (which may have no trailing-bit slack), so their non-canonical rejection is
// proven at the field layer above; here we cover the sig part end-to-end and assert
// rejection through the public ParseFragment entry point.
func TestParseFragment_RejectsNonCanonicalParts(t *testing.T) {
	sf := signedFragment(t)
	parts := strings.Split(sf.body, ".")
	// parts: [prefix, claimsB64, secretB64, sigB64]; sig is 64 bytes -> 86 chars,
	// len%3 == 1, so the final char carries trailing don't-care bits.
	sigVariant := nonCanonicalB64(t, parts[3])
	bad := strings.Join([]string{parts[0], parts[1], parts[2], sigVariant}, ".")
	if _, err := ParseFragment(bad); !errors.Is(err, ErrEncoding) {
		t.Fatalf("non-canonical sig part must be rejected with ErrEncoding, got: %v", err)
	}
	// Sanity: the unmodified fragment still parses (no over-rejection).
	if _, err := ParseFragment(sf.body); err != nil {
		t.Fatalf("canonical fragment must still parse: %v", err)
	}
}

// TestSignedClaims_ProduceCanonicalParts is a belt-and-suspenders parity check:
// a conformant signer emits canonical base64url for the claims part (so freshly
// minted artifacts are never self-rejected by the strict parser). nhp carries the
// verify side only, so this exercises the local test signer (which reuses the
// package's own encodeB64), proving the canonical-emission property the issuer
// relies on holds for the same encoding nhp verifies against.
func TestSignedClaims_ProduceCanonicalParts(t *testing.T) {
	fake := newFakeKMS(t)
	signer := newTestSigner(t, fake)
	claimsB64, _, err := signer.SignClaims(context.Background(), baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(claimsB64); err != nil {
		t.Fatalf("signer-emitted claims part is not canonical base64url: %v", err)
	}
}

// testResourceKeyB64ForBase extracts the exact resource_public_key_b64 value that
// validClaimsJSON embedded, so the non-canonical perturbation operates on the real
// substring (testResourceKeyB64 is randomized per call and would not match).
func testResourceKeyB64ForBase(t *testing.T, base string) string {
	t.Helper()
	const marker = `"resource_public_key_b64":"`
	i := strings.Index(base, marker)
	if i < 0 {
		t.Fatal("resource_public_key_b64 not present in baseline claims JSON")
	}
	rest := base[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		t.Fatal("malformed baseline: unterminated resource_public_key_b64 value")
	}
	return rest[:j]
}
