package qurlv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"strings"
	"testing"
)

const (
	validSignaturePayloadJSON    = `"claims_b64":"claims","sig_b64":"sig","sig_encoding":"raw_r_s","signing_input_b64":"input"`
	validDERSignaturePayloadJSON = `"claims_b64":"claims","sig_b64":"sig","sig_encoding":"der","signing_input_b64":"input"`
)

func vectorJSON(fields string) string {
	return `{"vectors":[{` + fields + `,` + validSignaturePayloadJSON + `}]}`
}

func derVectorJSON(fields string) string {
	return `{"vectors":[{` + fields + `,` + validDERSignaturePayloadJSON + `}]}`
}

func vectorFileJSON(fields string) string {
	return `{"vectors":[{` + fields + `}]}`
}

func TestParseVectorFileValidatesSignatureRejectClass(t *testing.T) {
	tests := []struct {
		name            string
		json            string
		wantExpect      string
		wantRejectClass string
		wantErrSubstr   string
	}{
		{
			name:          "malformed_json",
			json:          `{"vectors":[`,
			wantErrSubstr: "parse vector file",
		},
		{
			name:          "empty_vectors",
			json:          `{"vectors":[]}`,
			wantErrSubstr: "vector file has no vectors",
		},
		{
			name:          "vector_with_unknown_field",
			json:          vectorJSON(`"name":"unknown_field","expect":"accept","reason":"valid signature","unexpected":true`),
			wantErrSubstr: `unknown field "unexpected"`,
		},
		{
			name:       "accept_without_reject_class",
			json:       vectorJSON(`"name":"accept_valid_low_s","expect":"accept","reason":"valid signature"`),
			wantExpect: ExpectAccept,
		},
		{
			name:            "reject_with_high_s",
			json:            vectorJSON(`"name":"reject_high_s","expect":"reject","reason":"signature is not low-S normalized","reject_class":"high_s"`),
			wantExpect:      ExpectReject,
			wantRejectClass: RejectClassHighS,
		},
		{
			name:            "reject_with_wrong_length",
			json:            derVectorJSON(`"name":"reject_wrong_length_der","expect":"reject","reason":"signature is not exactly 64 bytes","reject_class":"wrong_length"`),
			wantExpect:      ExpectReject,
			wantRejectClass: RejectClassWrongLength,
		},
		{
			name:          "accept_with_reject_class",
			json:          vectorJSON(`"name":"bad_accept","expect":"accept","reason":"valid signature","reject_class":"high_s"`),
			wantErrSubstr: `accept signature vector "bad_accept" has reject_class "high_s"`,
		},
		{
			name:          "duplicate_name",
			json:          `{"vectors":[{` + `"name":"dupe","expect":"accept","reason":"valid signature",` + validSignaturePayloadJSON + `},{` + `"name":"dupe","expect":"accept","reason":"another valid signature",` + validSignaturePayloadJSON + `}]}`,
			wantErrSubstr: `duplicate signature vector name "dupe"`,
		},
		{
			name:          "reject_without_reject_class",
			json:          vectorJSON(`"name":"stale_reject","expect":"reject","reason":"high_s"`),
			wantErrSubstr: `reject signature vector "stale_reject" is missing reject_class`,
		},
		{
			name:          "accept_with_empty_reject_class",
			json:          vectorJSON(`"name":"bad_accept_empty","expect":"accept","reason":"valid signature","reject_class":""`),
			wantErrSubstr: `accept signature vector "bad_accept_empty" has reject_class ""`,
		},
		{
			name:          "accept_with_null_reject_class",
			json:          vectorJSON(`"name":"bad_accept_null","expect":"accept","reason":"valid signature","reject_class":null`),
			wantErrSubstr: `accept signature vector "bad_accept_null" has reject_class null`,
		},
		{
			name:          "accept_with_non_string_reject_class",
			json:          vectorJSON(`"name":"bad_accept_non_string","expect":"accept","reason":"valid signature","reject_class":123`),
			wantErrSubstr: `reject_class: json: cannot unmarshal number`,
		},
		{
			name:          "reject_with_empty_reject_class",
			json:          vectorJSON(`"name":"bad_reject_empty","expect":"reject","reason":"unknown class","reject_class":""`),
			wantErrSubstr: `reject signature vector "bad_reject_empty" has reject_class ""`,
		},
		{
			name:          "reject_with_null_reject_class",
			json:          vectorJSON(`"name":"bad_reject_null","expect":"reject","reason":"unknown class","reject_class":null`),
			wantErrSubstr: `reject signature vector "bad_reject_null" has reject_class null`,
		},
		{
			name:          "reject_with_non_string_reject_class",
			json:          vectorJSON(`"name":"bad_reject_non_string","expect":"reject","reason":"unknown class","reject_class":123`),
			wantErrSubstr: `reject_class: json: cannot unmarshal number`,
		},
		{
			name:          "reject_with_unknown_reject_class",
			json:          vectorJSON(`"name":"bad_reject","expect":"reject","reason":"unknown class","reject_class":"bogus"`),
			wantErrSubstr: `reject signature vector "bad_reject" has reject_class "bogus"`,
		},
		{
			name:          "unknown_expect",
			json:          vectorJSON(`"name":"bad_expect","expect":"maybe","reason":"unknown expectation"`),
			wantErrSubstr: `signature vector "bad_expect" has expect "maybe"`,
		},
		{
			name:          "empty_name",
			json:          vectorJSON(`"expect":"accept","reason":"valid signature"`),
			wantErrSubstr: `signature vector at index 0 has empty name`,
		},
		{
			name:          "blank_name",
			json:          vectorJSON(`"name":"   ","expect":"accept","reason":"valid signature"`),
			wantErrSubstr: `signature vector at index 0 has empty name`,
		},
		{
			name:          "empty_reason",
			json:          vectorJSON(`"name":"missing_reason","expect":"accept"`),
			wantErrSubstr: `signature vector "missing_reason" has empty reason`,
		},
		{
			name:          "blank_reason",
			json:          vectorJSON(`"name":"blank_reason","expect":"accept","reason":"   "`),
			wantErrSubstr: `signature vector "blank_reason" has empty reason`,
		},
		{
			name:          "missing_claims_b64",
			json:          vectorFileJSON(`"name":"missing_claims","expect":"accept","reason":"valid signature","sig_b64":"sig","sig_encoding":"raw_r_s","signing_input_b64":"input"`),
			wantErrSubstr: `signature vector "missing_claims" has empty claims_b64`,
		},
		{
			name:          "missing_sig_b64",
			json:          vectorFileJSON(`"name":"missing_sig","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_encoding":"raw_r_s","signing_input_b64":"input"`),
			wantErrSubstr: `signature vector "missing_sig" has empty sig_b64`,
		},
		{
			name:          "missing_sig_encoding",
			json:          vectorFileJSON(`"name":"missing_encoding","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_b64":"sig","signing_input_b64":"input"`),
			wantErrSubstr: `signature vector "missing_encoding" has empty sig_encoding`,
		},
		{
			name:          "unknown_sig_encoding",
			json:          vectorFileJSON(`"name":"unknown_encoding","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_b64":"sig","sig_encoding":"pem","signing_input_b64":"input"`),
			wantErrSubstr: `signature vector "unknown_encoding" has sig_encoding "pem", want raw_r_s|der`,
		},
		{
			name:          "accept_with_der_sig_encoding",
			json:          vectorFileJSON(`"name":"bad_accept_der","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_b64":"sig","sig_encoding":"der","signing_input_b64":"input"`),
			wantErrSubstr: `accept signature vector "bad_accept_der" has sig_encoding "der", want raw_r_s`,
		},
		{
			name:          "high_s_with_der_sig_encoding",
			json:          vectorFileJSON(`"name":"bad_high_s_der","expect":"reject","reason":"high-S signature","reject_class":"high_s","claims_b64":"claims","sig_b64":"sig","sig_encoding":"der","signing_input_b64":"input"`),
			wantErrSubstr: `reject signature vector "bad_high_s_der" with reject_class "high_s" has sig_encoding "der", want raw_r_s`,
		},
		{
			name:          "wrong_length_with_raw_sig_encoding",
			json:          vectorJSON(`"name":"bad_wrong_length_raw","expect":"reject","reason":"wrong-length signature","reject_class":"wrong_length"`),
			wantErrSubstr: `reject signature vector "bad_wrong_length_raw" with reject_class "wrong_length" has sig_encoding "raw_r_s", want der`,
		},
		{
			name:          "missing_signing_input_b64",
			json:          vectorFileJSON(`"name":"missing_signing_input","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_b64":"sig","sig_encoding":"raw_r_s"`),
			wantErrSubstr: `signature vector "missing_signing_input" has empty signing_input_b64`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vf, err := parseVectorFile([]byte(tt.json))
			if tt.wantErrSubstr != "" && err == nil {
				t.Fatal("parseVectorFile() error = nil, want error")
			}
			if tt.wantErrSubstr != "" && !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Fatalf("parseVectorFile() error = %q, want substring %q", err.Error(), tt.wantErrSubstr)
			}
			if tt.wantErrSubstr == "" && err != nil {
				t.Fatalf("parseVectorFile(): %v", err)
			}
			if tt.wantErrSubstr != "" {
				return
			}
			got := vf.Vectors[0]
			if got.Expect != tt.wantExpect {
				t.Fatalf("parsed expect = %q, want %q", got.Expect, tt.wantExpect)
			}
			gotRejectClass := ""
			if got.RejectClass != nil {
				gotRejectClass = *got.RejectClass
			}
			if gotRejectClass != tt.wantRejectClass {
				t.Fatalf("parsed reject_class = %q, want %q", gotRejectClass, tt.wantRejectClass)
			}
		})
	}
}

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
	rejectClass := signatureRejectClass(t, v)
	spec, ok := signatureRejectClassSpecFor(rejectClass)
	if !ok {
		t.Fatalf("unexpected reject_class %q for vector %q; parseVectorFile should reject unknown classes before verification", rejectClass, v.Name)
	}
	if !errors.Is(err, spec.err) {
		t.Fatalf("%s vector: expected %v, got %v", rejectClass, spec.err, err)
	}
}

func signatureRejectClass(t *testing.T, v *SignatureVector) string {
	t.Helper()
	if v.RejectClass == nil {
		t.Fatalf("reject vector %q must carry reject_class after parseVectorFile", v.Name)
	}
	return *v.RejectClass
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
