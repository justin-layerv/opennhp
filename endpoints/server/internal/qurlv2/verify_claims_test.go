package qurlv2

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// TestVerifyClaims_RoundTrip proves the happy path: claims signed by the issuer
// verify and parse, and the returned Claims match what was signed.
func TestVerifyClaims_RoundTrip(t *testing.T) {
	fake := newFakeKMS(t)
	signer := newTestSigner(t, fake)
	ts := trustStoreFor(t, fake)

	claimsB64, rawSig, err := signer.SignClaims(context.Background(), baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	sigB64 := encodeB64(rawSig)

	claims, err := VerifyClaims(claimsB64, sigB64, ts)
	if err != nil {
		t.Fatalf("VerifyClaims: %v", err)
	}
	if claims.Jti != "qurl_01JABCDEF" {
		t.Fatalf("jti = %q, want qurl_01JABCDEF", claims.Jti)
	}
	if claims.Kid != testIssuerKID {
		t.Fatalf("kid = %q, want %q", claims.Kid, testIssuerKID)
	}
	if claims.QurlUserPublicKeyB64 != testX25519B64(t, 2) {
		t.Fatal("qurl_user_public_key_b64 did not round-trip")
	}
}

// TestVerifyClaims_RejectsReserializedClaims is the load-bearing test: a claims
// object that is parsed and RE-SERIALIZED (semantically identical, but different
// bytes) must be rejected, because the signature is over the EXACT signed bytes,
// not over a canonicalization. This is the classic signature-bypass vector the
// design forbids.
func TestVerifyClaims_RejectsReserializedClaims(t *testing.T) {
	fake := newFakeKMS(t)
	signer := newTestSigner(t, fake)
	ts := trustStoreFor(t, fake)

	claimsB64, rawSig, err := signer.SignClaims(context.Background(), baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	sigB64 := encodeB64(rawSig)

	// Sanity: the genuine bytes verify.
	if _, err := VerifyClaims(claimsB64, sigB64, ts); err != nil {
		t.Fatalf("control VerifyClaims should pass: %v", err)
	}

	// Build a SEMANTICALLY IDENTICAL but BYTE-DIFFERENT claims encoding: same
	// field values, different key order + added insignificant whitespace. A
	// canonicalizing verifier would accept this (it parses to the same Claims);
	// a wire-byte verifier MUST reject it because the signature is over the
	// original bytes. We construct it as raw JSON text (not via the struct
	// encoder, which is deterministic and would reproduce the signed bytes) so
	// the difference is guaranteed observable.
	c := baselineClaims(t)
	c.Kid = testIssuerKID // SignClaims stamps the kid; mirror it here.
	reordered := "{\n" +
		jsonStrField("qurl_user_public_key_b64", c.QurlUserPublicKeyB64) + "," +
		jsonStrField("resource_public_key_b64", c.ResourcePublicKeyB64) + "," +
		jsonStrField("relay_url", c.RelayURL) + "," +
		jsonStrField("cell_id", c.CellID) + "," +
		jsonStrField("cell_public_key_b64", c.CellPublicKeyB64) + "," +
		jsonStrField("jti", c.Jti) + "," +
		jsonIntField("exp", c.Exp) + "," +
		jsonIntField("nbf", c.Nbf) + "," +
		jsonIntField("iat", c.Iat) + "," +
		jsonStrField("kid", c.Kid) + "," +
		jsonStrField("iss", c.Iss) + "," +
		jsonIntField("v", int64(c.V)) +
		"\n}"

	// Sanity: it parses to identical claims (semantic equality) ...
	parsedReordered, err := parseClaims([]byte(reordered))
	if err != nil {
		t.Fatalf("reordered claims should still strict-parse: %v", err)
	}
	if parsedReordered.Jti != c.Jti || parsedReordered.QurlUserPublicKeyB64 != c.QurlUserPublicKeyB64 {
		t.Fatal("reordered claims are not semantically equal to the signed claims")
	}
	reencoded := encodeB64([]byte(reordered))
	// ... but its BYTES differ from the signed claims.
	if reencoded == claimsB64 {
		t.Fatal("reordered claims unexpectedly produced identical bytes — test would be vacuous")
	}

	// The original signature must NOT verify against the re-serialized bytes.
	if _, err := VerifyClaims(reencoded, sigB64, ts); !errors.Is(err, ErrSignature) {
		t.Fatalf("re-serialized claims must fail signature verification, got %v", err)
	}
}

func jsonStrField(k, v string) string {
	b, _ := json.Marshal(v)
	return "  " + strconv.Quote(k) + ": " + string(b)
}

func jsonIntField(k string, v int64) string {
	return "  " + strconv.Quote(k) + ": " + strconv.FormatInt(v, 10)
}

// TestVerifyClaims_TamperedClaimsByteRejected proves a single-byte tamper in the
// claims string breaks verification.
func TestVerifyClaims_TamperedClaimsByteRejected(t *testing.T) {
	fake := newFakeKMS(t)
	signer := newTestSigner(t, fake)
	ts := trustStoreFor(t, fake)

	claimsB64, rawSig, err := signer.SignClaims(context.Background(), baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	sigB64 := encodeB64(rawSig)

	// Flip the last base64url char to a different valid one so the string stays
	// decodable but the bytes (and therefore the signature preimage) change.
	tampered := flipLastB64Char(claimsB64)
	if tampered == claimsB64 {
		t.Fatal("failed to mutate claims string")
	}

	_, err = VerifyClaims(tampered, sigB64, ts)
	if err == nil {
		t.Fatal("tampered claims must be rejected")
	}
	// Either the strict parse fails (bytes no longer valid JSON/schema) or the
	// signature fails; both are acceptable rejections of a tamper.
	if !errors.Is(err, ErrSignature) && !errors.Is(err, ErrStrictParse) && !errors.Is(err, ErrEncoding) && !errors.Is(err, ErrKeyLength) {
		t.Fatalf("unexpected error class for tamper: %v", err)
	}
}

// TestVerifyClaims_TamperedSignatureRejected proves a mutated signature fails.
func TestVerifyClaims_TamperedSignatureRejected(t *testing.T) {
	fake := newFakeKMS(t)
	signer := newTestSigner(t, fake)
	ts := trustStoreFor(t, fake)

	claimsB64, rawSig, err := signer.SignClaims(context.Background(), baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	// Flip a byte in the raw signature (keep length 64 so it passes the length
	// gate and exercises the ECDSA verify failure path).
	bad := make([]byte, len(rawSig))
	copy(bad, rawSig)
	bad[0] ^= 0x01
	sigB64 := encodeB64(bad)

	if _, err := VerifyClaims(claimsB64, sigB64, ts); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered signature must fail with ErrSignature, got %v", err)
	}
}

// TestVerifyClaims_UnknownKIDRejected proves a claim signed by a key the trust
// store does not know is rejected as an unknown kid.
func TestVerifyClaims_UnknownKIDRejected(t *testing.T) {
	signerFake := newFakeKMS(t)
	signer := newTestSigner(t, signerFake)

	// Trust store built from a DIFFERENT key/kid than the signer used.
	otherFake := newFakeKMS(t)
	otherDER, err := derFromFake(otherFake)
	if err != nil {
		t.Fatalf("marshal other pub: %v", err)
	}
	ts, err := NewTrustStoreFromDER(map[string][]byte{"some-other-kid": otherDER})
	if err != nil {
		t.Fatalf("trust store: %v", err)
	}

	claimsB64, rawSig, err := signer.SignClaims(context.Background(), baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	if _, err := VerifyClaims(claimsB64, encodeB64(rawSig), ts); !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("unknown kid must be rejected, got %v", err)
	}
}

// TestVerifyClaims_WrongLengthSignatureRejected proves a non-64-byte signature is
// rejected before any curve math.
func TestVerifyClaims_WrongLengthSignatureRejected(t *testing.T) {
	fake := newFakeKMS(t)
	signer := newTestSigner(t, fake)
	ts := trustStoreFor(t, fake)

	claimsB64, _, err := signer.SignClaims(context.Background(), baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	shortSig := encodeB64(make([]byte, 63))
	if _, err := VerifyClaims(claimsB64, shortSig, ts); !errors.Is(err, ErrSignatureLength) {
		t.Fatalf("63-byte signature must fail length check, got %v", err)
	}
}

// TestVerifyClaims_StrictParseViolationRejected proves a structurally invalid
// claims blob is rejected by the strict parser even when its kid resolves.
func TestVerifyClaims_StrictParseViolationRejected(t *testing.T) {
	fake := newFakeKMS(t)
	ts := trustStoreFor(t, fake)

	// Hand-craft claims bytes with an unknown field, encode, and sign them
	// directly via the signer's Sign (which signs whatever bytes we give it).
	signer := newTestSigner(t, fake)
	badJSON := []byte(`{"v":2,"iss":"qurl-service","kid":"` + testIssuerKID + `","extra":"x"}`)
	badB64 := encodeB64(badJSON)
	rawSig, err := signer.Sign(context.Background(), badB64)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Signature is valid over these exact bytes, so rejection must come from the
	// strict parser, not the crypto check.
	if _, err := VerifyClaims(badB64, encodeB64(rawSig), ts); !errors.Is(err, ErrStrictParse) {
		t.Fatalf("strict-parse violation must be rejected, got %v", err)
	}
}

// TestVerifyClaims_EmptyAndNilGuards covers the cheap input guards.
func TestVerifyClaims_EmptyAndNilGuards(t *testing.T) {
	fake := newFakeKMS(t)
	ts := trustStoreFor(t, fake)

	if _, err := VerifyClaims("", "sig", ts); !errors.Is(err, ErrFragment) {
		t.Fatalf("empty claims must be ErrFragment, got %v", err)
	}
	if _, err := VerifyClaims("claims", "", ts); !errors.Is(err, ErrFragment) {
		t.Fatalf("empty sig must be ErrFragment, got %v", err)
	}
	if _, err := VerifyClaims("claims", "sig", nil); !errors.Is(err, ErrSignature) {
		t.Fatalf("nil trust store must be ErrSignature, got %v", err)
	}
}

// flipLastB64Char returns s with its final base64url character changed to a
// different valid base64url character, keeping the string decodable.
func flipLastB64Char(s string) string {
	if s == "" {
		return s
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := s[len(s)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	// Ensure repl is in the alphabet and != last (it is, by construction).
	_ = strings.IndexByte(alphabet, repl)
	return s[:len(s)-1] + string(repl)
}
