package qurlv2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Golden-vector fixture schema for qURL v2 issuer signatures.
//
// These vectors are the cross-language CONTRACT proving that KMS-sign output, Go
// verification, and (in a later slice) WebCrypto verification agree byte-for-byte
// on the pinned P-256 raw r||s low-S wire encoding — plus a high-S rejection and
// a wrong-length rejection vector.
//
// They are VERIFY fixtures, not sign-determinism fixtures: ECDSA's nonce is
// random, so a signature cannot be reproduced. The fixture is generated once and
// committed; consumers (Go here, JS later) re-verify the committed bytes.
//
// Field roles (read carefully — this drives the JS port):
//   - ClaimsB64 is the PRIMARY verify input: the exact base64url claims string.
//   - SigB64Raw is the 64-byte raw r||s signature, base64url. WebCrypto's ECDSA
//     verify consumes exactly this (P1363), no DER.
//   - SigningInputB64 is a CROSS-CHECK, not the verify data. A JS verifier MUST
//     reconstruct the signing input itself (prefix + 0x00 + ClaimsB64) and assert
//     its reconstruction's base64url equals SigningInputB64. It is the most
//     likely place a JS impl diverges (the 0x00 separator), so it is pinned. The
//     value verified by WebCrypto is the pre-hash signing input bytes; WebCrypto
//     hashes them with SHA-256 internally — there is deliberately NO digest field
//     to grab by mistake.
//   - Issuer public key is published two ways so either crypto API can import it:
//     SPKIDERB64 (WebCrypto importKey "spki"; Go x509.ParsePKIXPublicKey) and a
//     JWK {x,y} (WebCrypto importKey "jwk"). The JWK coordinates are fixed-width
//     32-byte base64url (leading zeros preserved).

// VectorFile is the top-level committed fixture document.
type VectorFile struct {
	// Description documents the contract for a human reader of the JSON.
	Description string `json:"description"`
	// Algorithm pins the signing profile (informational; verifiers do not
	// negotiate).
	Algorithm string `json:"algorithm"`
	// DomainSeparationPrefix is the ASCII prefix; the 0x00 separator follows it.
	DomainSeparationPrefix string `json:"domain_separation_prefix"`
	// Issuer is the shared issuer key all vectors are signed/verified under.
	Issuer IssuerKeyMaterial `json:"issuer"`
	// Vectors is the ordered list of accept/reject cases.
	Vectors []SignatureVector `json:"vectors"`
}

// IssuerKeyMaterial is the issuer public key in both import forms.
type IssuerKeyMaterial struct {
	KID string `json:"kid"`
	// SPKIDERB64 is the DER SPKI public key, base64url (KMS GetPublicKey form).
	SPKIDERB64 string `json:"spki_der_b64"`
	// JWK is the same public key as a P-256 JWK (crv/x/y), for WebCrypto "jwk".
	JWK ECPublicJWK `json:"jwk"`
}

// ECPublicJWK is a minimal P-256 public-key JWK. x and y are fixed-width 32-byte
// base64url (leading zeros preserved) so a strict importer accepts them.
type ECPublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// SignatureVector is one accept-or-reject case.
type SignatureVector struct {
	Name string `json:"name"`
	// Expect is "accept" or "reject".
	Expect string `json:"expect"`
	// Reason documents why (and, for rejects, names the failure class).
	Reason string `json:"reason"`
	// ClaimsB64 is the exact base64url claims string (primary verify input).
	ClaimsB64 string `json:"claims_b64"`
	// SigB64Raw is the signature as base64url. For accept/high-S it is 64-byte
	// raw r||s; for the wrong-length case it is the DER form (the realistic
	// "passed KMS output straight through" mistake).
	SigB64Raw string `json:"sig_b64"`
	// SigEncoding documents the signature's byte form ("raw_r_s" or "der").
	SigEncoding string `json:"sig_encoding"`
	// SigningInputB64 is the cross-check value (see VectorFile docs).
	SigningInputB64 string `json:"signing_input_b64"`
}

// Expectation constants for SignatureVector.Expect.
const (
	ExpectAccept = "accept"
	ExpectReject = "reject"
)

// VectorRejectClass enumerates the named rejection classes a vector can assert,
// so consumers can map a vector to the exact sentinel error it must trigger.
const (
	RejectClassHighS       = "high_s"
	RejectClassWrongLength = "wrong_length"
)

// LoadVectorFile reads and parses a committed vector file. It returns an error
// (never an empty/zero document) if the file is missing or malformed, so a
// consumer test FAILS rather than silently skipping the contract.
func LoadVectorFile(path string) (*VectorFile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // fixed test fixture path, not user input
	if err != nil {
		return nil, fmt.Errorf("qurlv2: read vector file: %w", err)
	}
	var vf VectorFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vf); err != nil {
		return nil, fmt.Errorf("qurlv2: parse vector file: %w", err)
	}
	if len(vf.Vectors) == 0 {
		return nil, fmt.Errorf("qurlv2: vector file %s has no vectors", path)
	}
	return &vf, nil
}
