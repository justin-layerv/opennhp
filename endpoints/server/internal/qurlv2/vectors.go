package qurlv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	// RejectClass is the machine-readable rejection class. It is present on reject
	// vectors and absent on accept vectors. The pointer carries valid string values;
	// rejectClassNull keeps explicit JSON null distinct from absence during
	// validation.
	// The tag keeps any future marshal path aligned with the wire name;
	// UnmarshalJSON handles reads so it can fail closed on null.
	// This absent/null distinction only matters while parsing raw JSON signature
	// fixtures.
	RejectClass     *string `json:"reject_class,omitempty"`
	rejectClassNull bool    // Parser-only; validation rejects null before any marshal path.
	// Reason documents why in human-readable prose. It is mandatory contract
	// metadata even though reject_class drives machine-readable control flow.
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

// Signature encoding constants for SignatureVector.SigEncoding.
const (
	SignatureEncodingRawRS = "raw_r_s"
	SignatureEncodingDER   = "der"
)

// RejectClassHighS and RejectClassWrongLength enumerate the named rejection
// classes a vector can assert, so consumers can map a vector to the exact
// sentinel error it must trigger. Keep this closed taxonomy in lockstep with
// qurl-conformance's issuer-signature reject_class values and
// assertConformanceSignatureReject.
const (
	RejectClassHighS       = "high_s"
	RejectClassWrongLength = "wrong_length"
)

type signatureRejectClassSpec struct {
	err         error
	sigEncoding string
}

// signatureRejectClasses maps each valid signature reject_class to the sentinel
// verifier error it must produce and the concrete fixture encoding that exercises
// it. The loader uses the keys as the closed taxonomy, so assertion, encoding
// shape, and schema validation move together. A qurl-conformance reject-class or
// encoding change is a coordinated Go+JS code change, not just a dependency bump.
var (
	signatureRejectClasses = map[string]signatureRejectClassSpec{
		RejectClassHighS: {
			err:         ErrSignatureHighS,
			sigEncoding: SignatureEncodingRawRS,
		},
		RejectClassWrongLength: {
			err:         ErrSignatureLength,
			sigEncoding: SignatureEncodingDER,
		},
	}
	signatureRejectClassNames = sortedSignatureRejectClassNames()
)

// UnmarshalJSON records reject_class null so validation can reject it as a
// non-canonical fixture shape instead of silently treating it as absence.
func (v *SignatureVector) UnmarshalJSON(data []byte) error {
	type signatureVectorAlias SignatureVector
	var decoded signatureVectorAlias
	// The alias carries the normal field set; the shallower raw reject_class field
	// wins over the alias's promoted field and preserves explicit null through the
	// normal validation path.
	raw := struct {
		*signatureVectorAlias
		RejectClass json.RawMessage `json:"reject_class"`
	}{
		signatureVectorAlias: &decoded,
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	*v = SignatureVector(decoded)
	// Name is the display/dedupe key, so normalize it at the decode boundary;
	// payload fields stay byte-faithful and are validated separately.
	v.Name = strings.TrimSpace(v.Name)
	// The RawMessage shadow should prevent alias RejectClass population; reset
	// defensively so a future refactor cannot carry a stale pointer into validation.
	v.RejectClass = nil
	v.rejectClassNull = bytes.Equal(raw.RejectClass, []byte("null"))
	if raw.RejectClass == nil || v.rejectClassNull {
		return nil
	}
	var rejectClass string
	if err := json.Unmarshal(raw.RejectClass, &rejectClass); err != nil {
		return fmt.Errorf("reject_class: %w", err)
	}
	v.RejectClass = &rejectClass
	return nil
}

func sortedSignatureRejectClassNames() string {
	names := make([]string, 0, len(signatureRejectClasses))
	for name := range signatureRejectClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func signatureRejectClassSpecFor(rejectClass string) (signatureRejectClassSpec, bool) {
	spec, ok := signatureRejectClasses[rejectClass]
	return spec, ok
}

// parseVectorFile strictly parses issuer-signature vector bytes into a VectorFile.
// It returns an error (never an empty/zero document) if the bytes are malformed, so
// a consumer test FAILS rather than silently skipping the contract. New upstream
// schema fields intentionally require code changes because unknown fields fail
// closed instead of being dropped. The pinned module's embedded bytes
// (conformance.IssuerSignatureVectors) are fed in by the test-only loader in
// conformance_loaders_test.go, keeping qurl-conformance out of the production
// import graph.
func parseVectorFile(data []byte) (*VectorFile, error) {
	var vf VectorFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vf); err != nil {
		return nil, fmt.Errorf("qurlv2: parse vector file: %w", err)
	}
	if len(vf.Vectors) == 0 {
		return nil, errors.New("qurlv2: vector file has no vectors")
	}
	seenNames := make(map[string]struct{}, len(vf.Vectors))
	for i := range vf.Vectors {
		if err := validateSignatureVector(i, &vf.Vectors[i], seenNames); err != nil {
			return nil, err
		}
	}
	return &vf, nil
}

func validateSignatureVector(i int, v *SignatureVector, seenNames map[string]struct{}) error {
	// Re-trim here because package tests/generators can construct SignatureVector
	// directly and bypass UnmarshalJSON's decode-boundary normalization.
	name := strings.TrimSpace(v.Name)
	if name == "" {
		return fmt.Errorf("qurlv2: signature vector at index %d has empty name", i)
	}
	v.Name = name
	if _, ok := seenNames[name]; ok {
		return fmt.Errorf("qurlv2: duplicate signature vector name %q", name)
	}
	seenNames[name] = struct{}{}
	// Reason is prose-only, but every vector must carry it so fixture diffs stay
	// reviewable and self-explanatory.
	if strings.TrimSpace(v.Reason) == "" {
		return fmt.Errorf("qurlv2: signature vector %q has empty reason", name)
	}
	if err := validateSignaturePayloadFields(name, v); err != nil {
		return err
	}
	// Keep the empty-field diagnostic distinct from the closed enum diagnostic.
	if v.SigEncoding != SignatureEncodingRawRS && v.SigEncoding != SignatureEncodingDER {
		return fmt.Errorf("qurlv2: signature vector %q has sig_encoding %q, want %s|%s", name, v.SigEncoding, SignatureEncodingRawRS, SignatureEncodingDER)
	}
	switch v.Expect {
	case ExpectAccept:
		return validateAcceptSignatureVector(name, v)
	case ExpectReject:
		return validateRejectSignatureVector(name, v)
	default:
		return fmt.Errorf("qurlv2: signature vector %q has expect %q, want accept|reject", name, v.Expect)
	}
}

func validateSignaturePayloadFields(name string, v *SignatureVector) error {
	if strings.TrimSpace(v.ClaimsB64) == "" {
		return fmt.Errorf("qurlv2: signature vector %q has empty claims_b64", name)
	}
	if strings.TrimSpace(v.SigB64Raw) == "" {
		return fmt.Errorf("qurlv2: signature vector %q has empty sig_b64", name)
	}
	if strings.TrimSpace(v.SigEncoding) == "" {
		return fmt.Errorf("qurlv2: signature vector %q has empty sig_encoding", name)
	}
	if strings.TrimSpace(v.SigningInputB64) == "" {
		return fmt.Errorf("qurlv2: signature vector %q has empty signing_input_b64", name)
	}
	return nil
}

func validateAcceptSignatureVector(name string, v *SignatureVector) error {
	if v.SigEncoding != SignatureEncodingRawRS {
		return fmt.Errorf("qurlv2: accept signature vector %q has sig_encoding %q, want %s", name, v.SigEncoding, SignatureEncodingRawRS)
	}
	present, isNull, value := rejectClassState(v)
	if present {
		if isNull {
			return fmt.Errorf("qurlv2: accept signature vector %q has reject_class null", name)
		}
		return fmt.Errorf("qurlv2: accept signature vector %q has reject_class %q", name, value)
	}
	return nil
}

func validateRejectSignatureVector(name string, v *SignatureVector) error {
	present, isNull, value := rejectClassState(v)
	if !present {
		return fmt.Errorf("qurlv2: reject signature vector %q is missing reject_class", name)
	}
	if isNull {
		return fmt.Errorf("qurlv2: reject signature vector %q has reject_class null", name)
	}
	if value == "" {
		return fmt.Errorf("qurlv2: reject signature vector %q has reject_class \"\"", name)
	}
	spec, ok := signatureRejectClassSpecFor(value)
	if !ok {
		return fmt.Errorf("qurlv2: reject signature vector %q has reject_class %q, want one of %s", name, value, signatureRejectClassNames)
	}
	if v.SigEncoding != spec.sigEncoding {
		return fmt.Errorf("qurlv2: reject signature vector %q with reject_class %q has sig_encoding %q, want %s", name, value, v.SigEncoding, spec.sigEncoding)
	}
	return nil
}

func rejectClassState(v *SignatureVector) (present, isNull bool, value string) {
	if v.RejectClass != nil {
		return true, false, *v.RejectClass
	}
	return v.rejectClassNull, v.rejectClassNull, ""
}
