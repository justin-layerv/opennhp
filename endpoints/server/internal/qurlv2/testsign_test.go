package qurlv2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"testing"
)

// Local (KMS-free) test signer for the verify-side port.
//
// qurl-service's qurlv2 package signs through a KMS client (issuer.go), but the
// nhp port carries only the VERIFY side — nhp never mints qURLs. The pinned
// golden vectors (issuer_signature_vectors.json, from the public
// github.com/layervai/qurl-conformance module) are the cross-language CONTRACT
// proving nhp verification agrees byte-for-byte with the KMS sign output;
// see vectors_test.go (TestGoldenVectors_Consume) for that always-run proof.
//
// These helpers exist only so the ported fragment/parse/strict-b64 tests can mint
// fresh signed fragments to exercise the verify path against arbitrary claims
// (tamper, unknown-kid, round-trip). They reuse the package's OWN signing input
// (signingDigest) and DER->raw-low-S conversion (derToRawLowS), so a test signature
// is produced exactly as a conformant signer would — the only difference from
// production is that the private key is a local ecdsa key rather than a KMS key
// handle. They are TEST-ONLY (constructed in _test.go) and never compiled into the
// server binary.

// testIssuerKID is the kid every locally-signed test fragment is signed under.
const testIssuerKID = "qurl-issuer-key-2026-06"

// fakeKMS holds a local P-256 private key standing in for a KMS-custodied issuer
// key. The name mirrors qurl-service's fixture helper so the ported tests read
// the same; here it is a plain in-memory key with no AWS dependency.
type fakeKMS struct {
	priv *ecdsa.PrivateKey
}

// newFakeKMS generates a fresh local P-256 issuer key.
func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &fakeKMS{priv: priv}
}

// testSigner mints qURL v2 issuer signatures with a local ecdsa key, using the
// package's own signing input and the pinned DER->raw-low-S conversion.
type testSigner struct {
	priv *ecdsa.PrivateKey
	kid  string
}

// newTestSigner builds a local signer over the fake KMS key under testIssuerKID.
func newTestSigner(t *testing.T, fake *fakeKMS) *testSigner {
	t.Helper()
	return &testSigner{priv: fake.priv, kid: testIssuerKID}
}

// SignClaims marshals claims to canonical base64url (encodeB64 of the marshaled
// JSON), signs the package's signing digest, and converts the DER signature to
// the pinned 64-byte raw r||s low-S wire form. It returns the exact claims bytes
// that were signed (Part 1) and the raw signature, matching the production
// signer's (claimsB64, rawSig) contract. ctx is accepted for signature parity
// with the KMS signer and is unused locally.
func (s *testSigner) SignClaims(_ context.Context, c *Claims) (string, []byte, error) {
	// Stamp the issuer kid before marshaling, exactly as the production KMS signer
	// does (the kid identifies which trust-store key verifies the claim). baseline
	// claims deliberately leave Kid unset so the signer is the single writer.
	signed := *c
	signed.Kid = s.kid
	claimsB64, err := marshalClaimsB64(&signed)
	if err != nil {
		return "", nil, err
	}
	digest := signingDigest(claimsB64)
	der, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		return "", nil, err
	}
	rawSig, err := derToRawLowS(der)
	if err != nil {
		return "", nil, err
	}
	return claimsB64, rawSig, nil
}

// Sign signs the EXACT base64url claims string passed in (no re-serialization,
// no kid stamping), returning the pinned 64-byte raw r||s low-S signature. It
// mirrors the production signer's signing-input contract (signingDigest over the
// wire bytes) and lets tests sign hand-crafted claims bytes — e.g. a structurally
// invalid claims blob — so they can assert the strict parser, not the crypto
// check, is what rejects them.
func (s *testSigner) Sign(_ context.Context, claimsB64 string) ([]byte, error) {
	digest := signingDigest(claimsB64)
	der, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		return nil, err
	}
	return derToRawLowS(der)
}

// marshalClaimsB64 renders claims as the unpadded-base64url JSON that Part 1
// carries. The signer serializes the claims exactly once here; the produced bytes
// become the canonical wire bytes the signature is computed over and the verifier
// later checks against verbatim (the verifier never re-serializes).
func marshalClaimsB64(c *Claims) (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return encodeB64(raw), nil
}

// baselineClaims builds a valid claims value used by the fragment and strict-b64
// tests as the starting point for tamper/round-trip cases. testX25519B64 and
// testResourceKeyB64 are defined in parse_test.go (same package).
func baselineClaims(t *testing.T) *Claims {
	t.Helper()
	return &Claims{
		V:                    Version,
		Iss:                  Issuer,
		Iat:                  1781910000,
		Nbf:                  1781910000,
		Exp:                  1781910300,
		Jti:                  "qurl_01JABCDEF",
		CellPublicKeyB64:     testX25519B64(t, 1),
		CellID:               "cell-a",
		RelayURL:             "https://relay.example.com",
		ResourcePublicKeyB64: testResourceKeyB64(t),
		QurlUserPublicKeyB64: testX25519B64(t, 2),
	}
}

// derFromFake returns the issuer public key in DER SPKI form (the trust-store
// load form).
func derFromFake(fake *fakeKMS) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&fake.priv.PublicKey)
}

// signHighSDER signs digest and returns a guaranteed HIGH-S DER signature (S
// flipped to N - S when low), modeling the KMS case where the returned signature
// is high-S. Used by signature_test.go to prove derToRawLowS normalizes it.
func signHighSDER(priv *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, err
	}
	n := elliptic.P256().Params().N
	half := new(big.Int).Rsh(n, 1)
	if sig.S.Cmp(half) <= 0 {
		sig.S = new(big.Int).Sub(n, sig.S) // flip low -> high
	}
	return asn1.Marshal(sig)
}

// trustStoreFor builds a single-entry trust store under testIssuerKID for the
// fake's key.
func trustStoreFor(t *testing.T, fake *fakeKMS) *TrustStore {
	t.Helper()
	return trustStoreForKID(t, fake, testIssuerKID)
}
