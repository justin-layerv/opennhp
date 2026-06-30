package qurlv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

// TestDerToRawLowS_NormalizesAndFixedWidth converts many DER signatures and
// asserts the output is always exactly 64 bytes and always low-S, regardless of
// the input S parity.
func TestDerToRawLowS_NormalizesAndFixedWidth(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		digest := sha256.Sum256([]byte{byte(i)})
		der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := derToRawLowS(der)
		if err != nil {
			t.Fatalf("derToRawLowS: %v", err)
		}
		if len(raw) != p256SignatureBytes {
			t.Fatalf("raw sig is %d bytes, want %d", len(raw), p256SignatureBytes)
		}
		s := new(big.Int).SetBytes(raw[p256ScalarBytes:])
		if s.Cmp(halfOrder) > 0 {
			t.Fatal("derToRawLowS produced a high-S signature")
		}
		// The normalized signature must still verify against the original digest.
		r := new(big.Int).SetBytes(raw[:p256ScalarBytes])
		if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
			t.Fatal("normalized raw signature failed to verify against the digest")
		}
	}
}

// TestDerToRawLowS_FlipsHighS feeds a guaranteed-high-S DER and asserts the
// output is low-S and verifies.
func TestDerToRawLowS_FlipsHighS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("flip-me"))
	highDER, err := signHighSDER(priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := derToRawLowS(highDER)
	if err != nil {
		t.Fatalf("derToRawLowS(highS): %v", err)
	}
	s := new(big.Int).SetBytes(raw[p256ScalarBytes:])
	if s.Cmp(halfOrder) > 0 {
		t.Fatal("expected low-S after normalization")
	}
	r := new(big.Int).SetBytes(raw[:p256ScalarBytes])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Fatal("normalized (from high-S) signature failed to verify")
	}
}

func TestDerToRawLowS_RejectsMalformed(t *testing.T) {
	cases := [][]byte{
		[]byte("not-der"),
		{0x30, 0x00}, // empty SEQUENCE
	}
	for i, c := range cases {
		if _, err := derToRawLowS(c); err == nil {
			t.Fatalf("case %d: expected malformed-DER error", i)
		}
	}
	// Trailing bytes after a valid SEQUENCE must be rejected.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d := sha256.Sum256([]byte("x"))
	der, _ := ecdsa.SignASN1(rand.Reader, priv, d[:])
	if _, err := derToRawLowS(append(der, 0x00)); !errors.Is(err, ErrSignatureMalformedDER) {
		t.Fatalf("expected ErrSignatureMalformedDER for trailing byte, got: %v", err)
	}
}

func TestDerToRawLowS_RejectsZeroScalar(t *testing.T) {
	// r=0 is an invalid scalar and must be rejected at conversion.
	der, err := asn1.Marshal(struct{ R, S *big.Int }{R: big.NewInt(0), S: big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := derToRawLowS(der); !errors.Is(err, ErrSignatureScalarRange) {
		t.Fatalf("expected ErrSignatureScalarRange for r=0, got: %v", err)
	}
}

func TestRawToScalars_Rejections(t *testing.T) {
	n := curve.Params().N
	mkRaw := func(r, s *big.Int) []byte {
		out := make([]byte, p256SignatureBytes)
		r.FillBytes(out[:p256ScalarBytes])
		s.FillBytes(out[p256ScalarBytes:])
		return out
	}

	// Wrong length.
	if _, _, err := rawToScalars(make([]byte, 63)); !errors.Is(err, ErrSignatureLength) {
		t.Fatalf("expected ErrSignatureLength, got: %v", err)
	}
	// r = 0.
	if _, _, err := rawToScalars(mkRaw(big.NewInt(0), big.NewInt(1))); !errors.Is(err, ErrSignatureScalarRange) {
		t.Fatalf("expected ErrSignatureScalarRange (r=0), got: %v", err)
	}
	// s = N (out of range).
	if _, _, err := rawToScalars(mkRaw(big.NewInt(1), n)); !errors.Is(err, ErrSignatureScalarRange) {
		t.Fatalf("expected ErrSignatureScalarRange (s=N), got: %v", err)
	}
	// High-S (s = N-1 > N/2).
	highS := new(big.Int).Sub(n, big.NewInt(1))
	if _, _, err := rawToScalars(mkRaw(big.NewInt(1), highS)); !errors.Is(err, ErrSignatureHighS) {
		t.Fatalf("expected ErrSignatureHighS, got: %v", err)
	}
	// Valid low-S.
	if _, _, err := rawToScalars(mkRaw(big.NewInt(1), big.NewInt(1))); err != nil {
		t.Fatalf("valid low-S signature rejected: %v", err)
	}
}

func TestTrustStore_Validation(t *testing.T) {
	if _, err := NewTrustStore(nil); err == nil {
		t.Fatal("empty trust store must be rejected")
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := NewTrustStore(map[string]*ecdsa.PublicKey{"": &priv.PublicKey}); err == nil {
		t.Fatal("empty kid must be rejected")
	}
	// Non-P-256 curve rejected.
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewTrustStore(map[string]*ecdsa.PublicKey{"k": &p384.PublicKey}); err == nil {
		t.Fatal("non-P-256 key must be rejected")
	}
}
