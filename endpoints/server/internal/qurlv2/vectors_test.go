package qurlv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"testing"
)

// TestGoldenVectors_Consume is the always-run contract test. It loads the pinned
// fixture and asserts each vector accepts or rejects exactly as the fixture
// declares, with the precise sentinel for each rejection class. It FAILS (never
// skips) if the fixture is unparseable, so the contract can never silently drop
// out of CI.
func TestGoldenVectors_Consume(t *testing.T) {
	vf, err := loadVectorFile()
	if err != nil {
		// FAIL, never skip: this fixture is the cross-language signature contract.
		// The bytes come from the version-pinned public module
		// github.com/layervai/qurl-conformance (go:embed); a parse failure means the
		// pinned artifact is malformed, not that a vendored copy is missing.
		t.Fatalf("golden-vector fixture must parse: %v", err)
	}

	// Build the trust store from the fixture's published SPKI-DER key.
	der, err := decodeB64(vf.Issuer.SPKIDERB64)
	if err != nil {
		t.Fatalf("decode issuer spki: %v", err)
	}
	ts, err := NewTrustStoreFromDER(map[string][]byte{vf.Issuer.KID: der})
	if err != nil {
		t.Fatalf("trust store from fixture: %v", err)
	}
	pub, err := ParseP256PublicKeyDER(der)
	if err != nil {
		t.Fatalf("parse issuer spki: %v", err)
	}

	// Sanity-check the fixture's structural pins so a later JS port can rely on
	// them.
	if vf.DomainSeparationPrefix != domainSeparationPrefix {
		t.Fatalf("fixture prefix %q != %q", vf.DomainSeparationPrefix, domainSeparationPrefix)
	}

	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			// Cross-check: the signing input the fixture pins MUST equal the input
			// reconstructed from prefix + 0x00 + claims_b64. This is the check a
			// JS port performs on its own reconstruction.
			wantInput := encodeB64(signingInput(v.ClaimsB64))
			if v.SigningInputB64 != wantInput {
				t.Fatalf("signing_input_b64 mismatch:\n got %q\nwant %q", v.SigningInputB64, wantInput)
			}

			rawSig, err := decodeB64(v.SigB64Raw)
			if err != nil {
				t.Fatalf("decode sig: %v", err)
			}

			switch v.Expect {
			case ExpectAccept:
				// Verify the committed bytes against the fixture's OWN key.
				if err := verifyRawSignature(pub, v.ClaimsB64, rawSig); err != nil {
					t.Fatalf("accept vector failed to verify: %v", err)
				}
				// And through the full trust-store path (build a fragment).
				assertFragmentVerifies(t, ts, v.ClaimsB64, rawSig)
			case ExpectReject:
				err := verifyRawSignature(pub, v.ClaimsB64, rawSig)
				if err == nil {
					t.Fatal("reject vector unexpectedly verified")
				}
				assertRejectClass(t, &v, err)
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
	}
}

// assertRejectClass maps a vector's documented rejection class to the exact
// sentinel the verifier must return.
func assertRejectClass(t *testing.T, v *SignatureVector, err error) {
	t.Helper()
	switch v.Reason {
	case RejectClassHighS:
		if !errors.Is(err, ErrSignatureHighS) {
			t.Fatalf("high-S vector: expected ErrSignatureHighS, got %v", err)
		}
	case RejectClassWrongLength:
		if !errors.Is(err, ErrSignatureLength) {
			t.Fatalf("wrong-length vector: expected ErrSignatureLength, got %v", err)
		}
	default:
		// Any other reject reason must still be a signature error.
		if !errors.Is(err, ErrSignature) {
			t.Fatalf("reject vector %q: expected ErrSignature, got %v", v.Name, err)
		}
	}
}

// assertFragmentVerifies builds a full fragment around a claims/sig pair and runs
// it through ParseAndVerify, proving the accept vector passes the public API too.
func assertFragmentVerifies(t *testing.T, ts *TrustStore, claimsB64 string, rawSig []byte) {
	t.Helper()
	secretB64 := encodeB64([]byte(`{"qurl_user_private_key_b64":"` + testX25519B64(t, 9) + `"}`))
	body, err := BuildFragment(claimsB64, secretB64, rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}
	if _, err := ParseAndVerify("#"+body, ts); err != nil {
		t.Fatalf("ParseAndVerify accept vector: %v", err)
	}
}

// TestGoldenVectors_JWKMatchesSPKI guards the one fixture field nothing else in
// this slice consumes: the JWK x/y coordinates. It rebuilds an ecdsa.PublicKey
// from the JWK and asserts it verifies the accept vector — catching the classic
// bug where a coordinate was emitted without leading-zero padding (which would
// make a strict WebCrypto importKey reject it).
func TestGoldenVectors_JWKMatchesSPKI(t *testing.T) {
	vf, err := loadVectorFile()
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	jwk := vf.Issuer.JWK
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		t.Fatalf("unexpected JWK header: kty=%q crv=%q", jwk.Kty, jwk.Crv)
	}
	xb, err := decodeB64(jwk.X)
	if err != nil {
		t.Fatalf("decode jwk x: %v", err)
	}
	yb, err := decodeB64(jwk.Y)
	if err != nil {
		t.Fatalf("decode jwk y: %v", err)
	}
	// Coordinates MUST be fixed-width 32 bytes (leading zeros preserved). A short
	// coordinate is exactly the bug WebCrypto would reject.
	if len(xb) != p256ScalarBytes || len(yb) != p256ScalarBytes {
		t.Fatalf("jwk coordinates must be %d bytes each, got x=%d y=%d", p256ScalarBytes, len(xb), len(yb))
	}
	pubFromJWK := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
	if err := validateP256PublicKey(pubFromJWK); err != nil {
		t.Fatalf("JWK does not reconstruct a valid P-256 point: %v", err)
	}

	// Find the accept vector and verify it with the JWK-derived key.
	var accept *SignatureVector
	for i := range vf.Vectors {
		if vf.Vectors[i].Expect == ExpectAccept {
			accept = &vf.Vectors[i]
			break
		}
	}
	if accept == nil {
		t.Fatal("fixture has no accept vector")
	}
	rawSig, err := decodeB64(accept.SigB64Raw)
	if err != nil {
		t.Fatalf("decode accept sig: %v", err)
	}
	if err := verifyRawSignature(pubFromJWK, accept.ClaimsB64, rawSig); err != nil {
		t.Fatalf("JWK-derived key failed to verify the accept vector: %v", err)
	}
}
