package qurlv2

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// TestClaimKeyMatchesStdB64_CrossEncoding is the load-bearing case: the SAME 32
// raw bytes encoded as base64url (claim side) and standard base64 (nhp side) must
// MATCH, even though the two strings differ. A naive string compare would
// wrongly reject this — the exact bug this helper exists to prevent.
func TestClaimKeyMatchesStdB64_CrossEncoding(t *testing.T) {
	raw := make([]byte, x25519PublicKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Pick bytes that actually differ between the two alphabets so the test is
	// not vacuous: keep regenerating until the encodings differ as strings.
	for base64.RawURLEncoding.EncodeToString(raw) == base64.StdEncoding.EncodeToString(raw) {
		if _, err := rand.Read(raw); err != nil {
			t.Fatalf("rand: %v", err)
		}
	}

	claimB64 := base64.RawURLEncoding.EncodeToString(raw) // claim side: base64url
	stdB64 := base64.StdEncoding.EncodeToString(raw)      // nhp side: std base64 (padded)

	if claimB64 == stdB64 {
		t.Fatal("test setup failed: encodings did not diverge")
	}
	if err := ClaimKeyMatchesStdB64(claimB64, stdB64); err != nil {
		t.Fatalf("same bytes in different encodings must match, got %v", err)
	}
}

// TestClaimKeyMatchesStdB64_Mismatch proves different bytes do not match.
func TestClaimKeyMatchesStdB64_Mismatch(t *testing.T) {
	a := make([]byte, x25519PublicKeyBytes)
	b := make([]byte, x25519PublicKeyBytes)
	if _, err := rand.Read(a); err != nil {
		t.Fatalf("rand: %v", err)
	}
	copy(b, a)
	b[0] ^= 0xFF // guarantee difference

	if err := ClaimKeyMatchesStdB64(base64.RawURLEncoding.EncodeToString(a), base64.StdEncoding.EncodeToString(b)); !errors.Is(err, ErrKeyMatch) {
		t.Fatalf("different keys must mismatch with ErrKeyMatch, got %v", err)
	}
}

// TestClaimKeyMatchesStdB64_UnpaddedStdAccepted proves an unpadded std-base64
// comparand also decodes and matches (defense against a caller holding RawStd).
func TestClaimKeyMatchesStdB64_UnpaddedStdAccepted(t *testing.T) {
	raw := make([]byte, x25519PublicKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := ClaimKeyMatchesStdB64(base64.RawURLEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw)); err != nil {
		t.Fatalf("unpadded std comparand must match, got %v", err)
	}
}

// TestClaimKeyMatchesStdB64_BadEncodingIsMismatch proves a non-decodable side is
// a mismatch (ErrKeyMatch), never a silent pass.
func TestClaimKeyMatchesStdB64_BadEncodingIsMismatch(t *testing.T) {
	raw := make([]byte, x25519PublicKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// claim side has a padding char, which is invalid for base64url(unpadded).
	if err := ClaimKeyMatchesStdB64("not=valid=url", base64.StdEncoding.EncodeToString(raw)); !errors.Is(err, ErrKeyMatch) {
		t.Fatalf("bad claim encoding must be ErrKeyMatch, got %v", err)
	}
	// comparand side has a base64url-only char ('-'), invalid for std base64.
	if err := ClaimKeyMatchesStdB64(base64.RawURLEncoding.EncodeToString(raw), "AAAA-AAA"); !errors.Is(err, ErrKeyMatch) {
		t.Fatalf("bad comparand encoding must be ErrKeyMatch, got %v", err)
	}
}

// TestClaimResourceKeyMatches proves the resource-identity binding compares bytes
// (base64url both sides) and rejects a non-decodable resource id.
func TestClaimResourceKeyMatches(t *testing.T) {
	raw := make([]byte, 91) // resource keys are DER SPKI, larger than X25519
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	claimB64 := base64.RawURLEncoding.EncodeToString(raw)

	if err := ClaimResourceKeyMatches(claimB64, claimB64); err != nil {
		t.Fatalf("identical resource keys must match, got %v", err)
	}

	other := make([]byte, 91)
	copy(other, raw)
	other[5] ^= 0xFF
	if err := ClaimResourceKeyMatches(claimB64, base64.RawURLEncoding.EncodeToString(other)); !errors.Is(err, ErrKeyMatch) {
		t.Fatalf("different resource keys must mismatch, got %v", err)
	}

	if err := ClaimResourceKeyMatches(claimB64, "padded=="); !errors.Is(err, ErrKeyMatch) {
		t.Fatalf("non-base64url resource id must be ErrKeyMatch, got %v", err)
	}
}
