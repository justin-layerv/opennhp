package qurlv2

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// signed bundles a valid signed fragment plus everything a test needs to verify
// or tamper with it.
type signed struct {
	body      string
	ts        *TrustStore
	claimsB64 string
	secretB64 string
	rawSig    []byte
}

// signedFragment builds a fully valid, signed fragment plus the trust store that
// verifies it, for use by the fragment-level and tamper tests.
func signedFragment(t *testing.T) signed {
	t.Helper()
	fake := newFakeKMS(t)
	signer := newTestSigner(t, fake)
	ts := trustStoreFor(t, fake)
	claimsB64, rawSig, err := signer.SignClaims(context.Background(), baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	secretB64 := encodeB64([]byte(`{"qurl_user_private_key_b64":"` + testX25519B64(t, 9) + `"}`))
	body, err := BuildFragment(claimsB64, secretB64, rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}
	return signed{body: body, ts: ts, claimsB64: claimsB64, secretB64: secretB64, rawSig: rawSig}
}

func TestParseFragment_ShapeRejections(t *testing.T) {
	sf := signedFragment(t)
	good := sf.body
	parts := strings.Split(good, ".")

	tests := []struct {
		name string
		frag string
	}{
		{"wrong prefix", "qv1." + strings.Join(parts[1:], ".")},
		{"too few parts", strings.Join(parts[:3], ".")},
		{"too many parts", good + ".extra"},
		{"empty claims part", strings.Join([]string{parts[0], "", parts[2], parts[3]}, ".")},
		{"empty secret part", strings.Join([]string{parts[0], parts[1], "", parts[3]}, ".")},
		{"empty sig part", strings.Join([]string{parts[0], parts[1], parts[2], ""}, ".")},
		{"padded base64 claims", strings.Join([]string{parts[0], parts[1] + "==", parts[2], parts[3]}, ".")},
		{"non-base64url char", strings.Join([]string{parts[0], parts[1] + "*", parts[2], parts[3]}, ".")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseFragment(tc.frag); err == nil {
				t.Fatalf("expected rejection for %q, got nil", tc.name)
			}
		})
	}
}

func TestParseFragment_StripsLeadingHash(t *testing.T) {
	sf := signedFragment(t)
	good, ts := sf.body, sf.ts
	if _, err := ParseAndVerify("#"+good, ts); err != nil {
		t.Fatalf("leading-# fragment should parse+verify: %v", err)
	}
	if _, err := ParseAndVerify(good, ts); err != nil {
		t.Fatalf("no-# fragment should parse+verify: %v", err)
	}
}

// TestVerify_TamperFailsSignature covers the design Test Plan item: tampering
// with any signed binding (cell key, resource key, qURL key, exp, nbf, jti) fails
// signature verification. It mutates each field, re-encodes the claims, keeps the
// ORIGINAL signature, and asserts verification fails.
func TestVerify_TamperFailsSignature(t *testing.T) {
	sf := signedFragment(t)
	ts, claimsB64, rawSig := sf.ts, sf.claimsB64, sf.rawSig

	raw, err := decodeB64(claimsB64)
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var base Claims
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	mutate := map[string]func(*Claims){
		"cell key":     func(c *Claims) { c.CellPublicKeyB64 = testX25519B64(t, 0x77) },
		"resource key": func(c *Claims) { c.ResourcePublicKeyB64 = testResourceKeyB64(t) },
		"qurl key":     func(c *Claims) { c.QurlUserPublicKeyB64 = testX25519B64(t, 0x66) },
		"exp":          func(c *Claims) { c.Exp = base.Exp + 1 },
		"nbf":          func(c *Claims) { c.Nbf = base.Nbf - 1 },
		"jti":          func(c *Claims) { c.Jti = base.Jti + "-tampered" },
	}
	for name, fn := range mutate {
		t.Run(name, func(t *testing.T) {
			tampered := base
			fn(&tampered)
			encoded, err := json.Marshal(tampered)
			if err != nil {
				t.Fatalf("marshal tampered: %v", err)
			}
			tamperedB64 := encodeB64(encoded)
			pub, _ := ts.publicKeyForKID(base.Kid)
			err = verifyRawSignature(pub, tamperedB64, rawSig)
			if !errors.Is(err, ErrSignature) {
				t.Fatalf("tampered %s must fail signature, got: %v", name, err)
			}
		})
	}
}

// TestVerify_ReserializedClaimsRejected covers the design Test Plan item:
// "a re-serialized claims object (reordered or re-encoded fields) is rejected
// even when semantically equal." We re-encode the SAME claims (Go map ordering
// differs from the signed byte order) and assert the original signature no longer
// verifies — proving verification is over the received bytes, not a canonical form.
func TestVerify_ReserializedClaimsRejected(t *testing.T) {
	sf := signedFragment(t)
	ts, claimsB64, rawSig := sf.ts, sf.claimsB64, sf.rawSig

	raw, err := decodeB64(claimsB64)
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	// Round-trip through a map: this reorders keys and drops the optional empty
	// fields' original ordering, producing semantically-equal but byte-different
	// JSON.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal generic: %v", err)
	}
	reserialized, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if bytes.Equal(reserialized, raw) {
		t.Skip("re-serialization happened to be byte-identical; cannot exercise this case")
	}
	reB64 := encodeB64(reserialized)

	// Resolve the kid from the (valid) parsed claims and verify over the
	// re-serialized bytes; it must fail.
	parsed, err := parseClaims(reserialized)
	if err != nil {
		t.Fatalf("re-serialized claims should still strict-parse: %v", err)
	}
	pub, err := ts.publicKeyForKID(parsed.Kid)
	if err != nil {
		t.Fatalf("kid resolve: %v", err)
	}
	if err := verifyRawSignature(pub, reB64, rawSig); !errors.Is(err, ErrSignature) {
		t.Fatalf("re-serialized claims must fail signature, got: %v", err)
	}
	// Sanity: the ORIGINAL bytes still verify.
	if err := verifyRawSignature(pub, claimsB64, rawSig); err != nil {
		t.Fatalf("original claims bytes must still verify: %v", err)
	}
}

func TestVerify_UnknownKIDRejected(t *testing.T) {
	sf := signedFragment(t)
	body := sf.body
	// A trust store that does NOT contain the signing kid.
	otherTS := trustStoreForKID(t, newFakeKMS(t), "some-other-kid")
	if _, err := ParseAndVerify(body, otherTS); !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("expected ErrUnknownKID, got: %v", err)
	}
}

func TestBuildFragment_RejectsMalformedSignature(t *testing.T) {
	claimsB64 := encodeB64([]byte("{}"))
	secretB64 := encodeB64([]byte("{}"))
	// 63 bytes (not 64) must be rejected.
	if _, err := BuildFragment(claimsB64, secretB64, make([]byte, 63)); !errors.Is(err, ErrSignatureLength) {
		t.Fatalf("expected ErrSignatureLength, got: %v", err)
	}
	// 64 zero bytes -> r=0,s=0 out of range, must be rejected.
	if _, err := BuildFragment(claimsB64, secretB64, make([]byte, 64)); !errors.Is(err, ErrSignatureScalarRange) {
		t.Fatalf("expected ErrSignatureScalarRange, got: %v", err)
	}
}

// TestBuildFragment_RejectsMalformedParts pins the parts guard: claimsB64 and
// secretB64 must be well-formed base64url (encodeB64 output). The motivating bug
// is a stray "." — the field separator — which would silently split the body into
// the wrong number of parts and yield an unparseable fragment; the guard rejects
// it (and padding / non-canonical / empty-alphabet noise) up front with
// ErrFragment so BuildFragment can never emit something ParseFragment rejects. A
// VALID signature is used throughout so the failure isolates the part guard.
func TestBuildFragment_RejectsMalformedParts(t *testing.T) {
	sf := signedFragment(t)
	goodClaims := encodeB64([]byte(`{"ok":true}`))
	goodSecret := encodeB64([]byte(`{"ok":true}`))

	tests := []struct {
		name, claims, secret string
	}{
		{"dotted claims part", goodClaims[:4] + "." + goodClaims[4:], goodSecret},
		{"dotted secret part", goodClaims, goodSecret[:4] + "." + goodSecret[4:]},
		{"padded claims part", base64.URLEncoding.EncodeToString([]byte(`{"ok":true}`)), goodSecret},
		{"non-base64url claims part", goodClaims + "*", goodSecret},
		{"non-base64url secret part", goodClaims, goodSecret + "*"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildFragment(tc.claims, tc.secret, sf.rawSig)
			if !errors.Is(err, ErrFragment) {
				t.Fatalf("%s: expected ErrFragment, got: %v", tc.name, err)
			}
		})
	}
}

// TestBuildFragment_RoundTrip is the round-trip safety property the guard exists
// to guarantee: a body built from canonical parts + a valid signature parses back
// successfully (and verifies), so BuildFragment output is always a valid fragment.
func TestBuildFragment_RoundTrip(t *testing.T) {
	sf := signedFragment(t)
	body, err := BuildFragment(sf.claimsB64, sf.secretB64, sf.rawSig)
	if err != nil {
		t.Fatalf("BuildFragment(valid parts) must succeed: %v", err)
	}
	if _, err := ParseAndVerify(body, sf.ts); err != nil {
		t.Fatalf("BuildFragment output must parse+verify: %v", err)
	}
}

// trustStoreForKID builds a single-entry trust store under an arbitrary kid.
func trustStoreForKID(t *testing.T, fake *fakeKMS, kid string) *TrustStore {
	t.Helper()
	der, err := derFromFake(fake)
	if err != nil {
		t.Fatalf("der: %v", err)
	}
	ts, err := NewTrustStoreFromDER(map[string][]byte{kid: der})
	if err != nil {
		t.Fatalf("trust store: %v", err)
	}
	return ts
}
