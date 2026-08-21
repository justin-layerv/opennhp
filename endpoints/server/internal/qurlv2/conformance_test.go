package qurlv2

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/utils"
)

// TestConformanceVectors is the always-run, every-class contract test. It loads
// the pinned conformance artifact and drives EVERY class -- including every negative --
// through the package's REAL entry points, asserting the declared accept/reject
// outcome and (where the class pins it) the reject_class. It FAILS (never skips)
// if the artifact is missing/unparseable, so the contract can never silently drop
// out of the suite.
//
// A flipped negative (an "expect":"reject" vector edited to "accept", or vice
// versa) makes this test RED, because every accept/reject class switches on the
// expect field and asserts the real outcome -- the boolean is never trusted, it is
// re-derived. (The README documents the manual flip-one-vector demonstration that
// proves this end to end.) The server_id class is the one exception: it is a
// recompute-equality derivation with no reject branch, so its runner fails loudly
// on any non-accept expect rather than honoring a flip -- see runServerIDClass.
//
// CI coverage: this test RUNS in CI. PR #2834 widened `make test`'s endpoints
// -run allowlist to include TestConformanceVectors; `make test` runs on every PR
// (ubuntu-build.yml) and the full `go test ./...` runs on push/PR to main
// (build-and-push.yml). So a drifted vector or a verifier regression fails this
// test in CI, not just locally -- the "a drifting verifier fails its own run"
// guarantee holds. The local -race run
// (`go test -race ./server/internal/qurlv2/...`) remains the fullest behavioral proof.
func TestConformanceVectors(t *testing.T) {
	cf, err := loadConformanceFile()
	if err != nil {
		t.Fatalf("conformance artifact must load: %v", err)
	}
	// The artifact-id identity check now lives in parseConformanceFile (so every
	// consumer, not just this test, fails closed on a wrong-artifact document);
	// re-assert it here against the exported constant as a belt-and-suspenders pin.
	if cf.Artifact != ConformanceArtifactID {
		t.Fatalf("unexpected artifact id %q", cf.Artifact)
	}
	if cf.SchemaVersion != conformanceSchemaVersion {
		t.Fatalf("this test understands schema_version %d, artifact declares %d", conformanceSchemaVersion, cf.SchemaVersion)
	}

	// Every class named in the task must be present; a renamed/dropped class is a
	// silent coverage loss, so assert the taxonomy up front.
	for _, want := range []string{
		"claims_parse", "secret_parse", "strict_base64",
		"fragment", "transport", "relay_allowlist", "server_id",
	} {
		if _, ok := cf.Classes[want]; !ok {
			t.Fatalf("conformance artifact missing required class %q", want)
		}
	}

	// The reject_class field is the fixed cross-language vocabulary qurl-go and the
	// js-agent share. Assert every reject vector declares a class from its own
	// class's allowed set BEFORE running behavior, so a typo'd or out-of-vocabulary
	// reject_class is caught here rather than silently ignored by a consumer.
	t.Run("reject_class_vocabulary", func(t *testing.T) { assertRejectClassVocabulary(t, cf) })

	t.Run("signature", func(t *testing.T) { runSignatureClass(t, cf) })
	t.Run("claims_parse", func(t *testing.T) { runClaimsParseClass(t, cf.Classes["claims_parse"]) })
	t.Run("secret_parse", func(t *testing.T) { runSecretParseClass(t, cf.Classes["secret_parse"]) })
	t.Run("strict_base64", func(t *testing.T) { runStrictBase64Class(t, cf.Classes["strict_base64"]) })
	t.Run("fragment", func(t *testing.T) { runFragmentClass(t, cf.Classes["fragment"]) })
	t.Run("transport", func(t *testing.T) { runTransportClass(t, cf.Classes["transport"]) })
	t.Run("relay_allowlist", func(t *testing.T) { runRelayAllowlistClass(t, cf.Classes["relay_allowlist"]) })
	t.Run("server_id", func(t *testing.T) { runServerIDClass(t, cf.Classes["server_id"]) })
}

// runTransportClass drives the share-safe outer framing vectors through NHP's
// real decoder. Accepts must reconstruct the canonical qv2 fragment byte for
// byte; rejects must return the dedicated transport sentinel before any inner
// parse or signature semantics are considered.
func runTransportClass(t *testing.T, class ConformanceClass) {
	requireNonEmpty(t, "transport", class)
	for _, v := range class.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, err := DecodeTransport(v.TransportFragment)
			switch v.Expect {
			case conformanceAccept:
				if err != nil {
					t.Fatalf("accept transport vector failed: %v", err)
				}
				if got != v.CanonicalFragment {
					t.Fatalf("canonical fragment mismatch\n got: %q\nwant: %q", got, v.CanonicalFragment)
				}
			case conformanceReject:
				if !errors.Is(err, ErrTransport) {
					t.Fatalf("reject transport vector must return ErrTransport, got %v", err)
				}
				if got != "" {
					t.Fatalf("reject transport vector returned partial output %q", got)
				}
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
	}
}

// runSignatureClass proves the signature class is COMPOSED, not duplicated: it
// loads the separate issuer_signature_vectors.json the artifact names and runs
// it through the real verifier. (TestGoldenVectors_Consume already exercises that
// file in depth; here we assert the composition pointer is honored and the file
// is reachable + non-empty, so the conformance run covers the signature class via
// the single shared source.)
func runSignatureClass(t *testing.T, cf *ConformanceFile) {
	if cf.SignatureClass.Composes != "issuer_signature_vectors.json" {
		t.Fatalf("signature class must compose issuer_signature_vectors.json, got %q", cf.SignatureClass.Composes)
	}
	// The composed file is the same pinned-module artifact: the conformance bytes
	// name it (assertion above) and the module embeds it under that name, so loading
	// it via loadVectorFile() honors the composition pointer.
	vf, err := loadVectorFile()
	if err != nil {
		t.Fatalf("composed signature fixture must load: %v", err)
	}
	der, err := decodeB64(vf.Issuer.SPKIDERB64)
	if err != nil {
		t.Fatalf("decode issuer spki: %v", err)
	}
	pub, err := ParseP256PublicKeyDER(der)
	if err != nil {
		t.Fatalf("parse issuer spki: %v", err)
	}
	// Count accept vectors and capture the FIRST one's claims/sig for the tamper
	// derivation. The tamper_derivation says "the accept vector" (singular); if the
	// composed fixture ever carries more than one accept vector the baseline is
	// ambiguous, so we fail rather than silently deriving from whichever happened to
	// be last in iteration order.
	acceptCount, sawReject := 0, false
	var acceptClaimsB64 string
	var acceptRawSig []byte
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			rawSig, err := decodeB64(v.SigB64Raw)
			if err != nil {
				t.Fatalf("decode sig: %v", err)
			}
			verr := verifyRawSignature(pub, v.ClaimsB64, rawSig)
			switch v.Expect {
			case ExpectAccept:
				acceptCount++
				if acceptCount == 1 {
					acceptClaimsB64, acceptRawSig = v.ClaimsB64, rawSig
				}
				if verr != nil {
					t.Fatalf("accept signature vector failed to verify: %v", verr)
				}
			case ExpectReject:
				sawReject = true
				if verr == nil {
					t.Fatal("reject signature vector unexpectedly verified")
				}
				assertConformanceSignatureReject(t, signatureRejectClass(t, &v), verr)
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
	}
	if acceptCount == 0 || !sawReject {
		t.Fatalf("signature class must exercise both accept and reject (accept=%d reject=%v)", acceptCount, sawReject)
	}
	if acceptCount > 1 {
		t.Fatalf("tamper_derivation assumes a single accept vector; composed fixture has %d -- update the derivation if this is intentional", acceptCount)
	}

	// Payload-tamper reject, driven by the artifact's tamper_derivation. The
	// composed fixture's reject vectors cover signature MALLEABILITY/ENCODING
	// (high_s, wrong_length_der); the task also calls for issuer-signature
	// reject(TAMPER): a structurally well-formed signature that is simply not valid
	// over the presented claims. Rather than hardcode the recipe (which a vendoring
	// consumer in another language could not see), the artifact SPECIFIES it as a
	// derivation -- start from the accept vector and apply a named claims transform
	// -- so Go, the js-agent, and qurl-go all synthesize the SAME negative without a
	// third copy of signature bytes. This runner reads that spec and applies it.
	runSignatureTamper(t, cf.SignatureClass.TamperDerivation, pub, acceptClaimsB64, acceptRawSig)
}

// runSignatureTamper executes the artifact-specified payload-tamper derivation.
// It validates the derivation is present and uses identifiers this verifier
// supports, applies the named claims transform to the accept vector's claims, and
// asserts the accept vector's UNCHANGED signature now fails at the curve check
// with the bare ErrSignature sentinel (not the length/high-S encoding gate).
func runSignatureTamper(t *testing.T, d *ConformanceTamperDerivation, pub *ecdsa.PublicKey, acceptClaimsB64 string, acceptRawSig []byte) {
	t.Run("payload_tamper", func(t *testing.T) {
		if d == nil {
			t.Fatal("signature_class.tamper_derivation missing: the artifact must specify the language-agnostic tamper derivation")
		}
		if d.RejectClass != rejectClassTamper {
			t.Fatalf("tamper_derivation.reject_class = %q, want %q", d.RejectClass, rejectClassTamper)
		}
		if d.DeriveFrom != tamperDeriveFromAccept {
			t.Fatalf("tamper_derivation.derive_from = %q, this verifier only supports %q", d.DeriveFrom, tamperDeriveFromAccept)
		}
		if acceptRawSig == nil {
			t.Fatal("no accept vector captured to derive the tamper case from")
		}
		tampered, err := applyClaimsTransform(d.ClaimsTransform, acceptClaimsB64)
		if err != nil {
			t.Fatalf("apply tamper transform: %v", err)
		}
		if tampered == acceptClaimsB64 {
			t.Fatal("tamper transform produced identical claims; cannot prove tamper rejection")
		}
		// Cross-language portability invariant. qURL v2's Go verifier hashes the
		// claims_b64 STRING, so a string-only change is enough HERE -- but a
		// vendoring consumer may decode-then-hash or strict-decode before verifying.
		// For the derived tamper to be the SAME negative everywhere, the transformed
		// claims must (a) still be canonical base64url (so a strict-decode-first
		// consumer does not reject for ENCODING instead of tamper) and (b) decode to
		// DIFFERENT bytes than the original (so a decoded-bytes-hash consumer's
		// signature actually fails). Assert both, so a transform that only flips a
		// don't-care tail bit can never masquerade as a portable tamper.
		origDecoded, err := decodeB64(acceptClaimsB64)
		if err != nil {
			t.Fatalf("accept claims_b64 must strict-decode: %v", err)
		}
		tamperedDecoded, err := decodeB64(tampered)
		if err != nil {
			t.Fatalf("tampered claims_b64 must stay canonical base64url (else a strict-decode-first consumer rejects for encoding, not tamper): %v", err)
		}
		if bytes.Equal(origDecoded, tamperedDecoded) {
			t.Fatal("tampered claims decode to the SAME bytes as the original: a decode-then-hash consumer would still verify the signature -- the transform must change decoded bytes, not just don't-care base64 tail bits")
		}
		// Sanity: the unmodified pair verifies (so the rejection below is
		// attributable to the tamper, not a broken fixture).
		if err := verifyRawSignature(pub, acceptClaimsB64, acceptRawSig); err != nil {
			t.Fatalf("precondition: accept pair must verify before tamper: %v", err)
		}
		verr := verifyRawSignature(pub, tampered, acceptRawSig)
		if verr == nil {
			t.Fatal("tampered claims unexpectedly verified under the accept vector's signature")
		}
		// Must be the bare signature-invalid sentinel: a well-formed sig over the
		// wrong message, not a length/high-S encoding reject.
		if !errors.Is(verr, ErrSignature) {
			t.Fatalf("payload-tamper must return ErrSignature, got %v", verr)
		}
		if errors.Is(verr, ErrSignatureHighS) || errors.Is(verr, ErrSignatureLength) {
			t.Fatalf("payload-tamper must fail at the curve check, not the encoding gate, got %v", verr)
		}
	})
}

// applyClaimsTransform applies a named, artifact-specified claims transform and
// returns the transformed claims_b64. It errors on an unknown transform so a
// vendoring drift (a transform a consumer does not implement) fails loudly rather
// than silently skipping the tamper case.
func applyClaimsTransform(name, claimsB64 string) (string, error) {
	switch name {
	case tamperTransformFlipFirstB64:
		return flipFirstBase64urlChar(claimsB64), nil
	default:
		return "", fmt.Errorf("unsupported claims_transform %q", name)
	}
}

// flipFirstBase64urlChar returns claimsB64 with its FIRST character flipped
// between base64url 'A' and 'B' ('A'->'B', any other char->'A'). The first symbol
// is the top 6 bits of decoded byte 0 (always fully significant, never a don't-care
// tail bit), so the transformed value stays canonical base64url AND decodes to
// different bytes. That is what makes the derived tamper portable across consumers
// that hash the base64 string, decode-then-hash, or strict-decode first.
func flipFirstBase64urlChar(in string) string {
	if in == "" {
		return in
	}
	repl := byte('A')
	if in[0] == 'A' {
		repl = 'B'
	}
	return string(repl) + in[1:]
}

// assertConformanceSignatureReject maps a composed signature vector's reject_class
// to the precise sentinel, mirroring the signature class vocabulary.
// It reuses the exported RejectClassHighS / RejectClassWrongLength constants (the
// same vocabulary the composed fixture and its own consumer assert against) rather
// than a second copy of those literals.
func assertConformanceSignatureReject(t *testing.T, rejectClass string, err error) {
	t.Helper()
	spec, ok := signatureRejectClassSpecFor(rejectClass)
	if !ok {
		t.Fatalf("unexpected signature reject_class %q; parseVectorFile should reject unknown classes before verification", rejectClass)
	}
	if !errors.Is(err, spec.err) {
		t.Fatalf("%s vector: expected %v, got %v", rejectClass, spec.err, err)
	}
}

// runClaimsParseClass feeds each vector's RAW JSON TEXT straight to parseClaims
// (the entry point's real input is JSON bytes, not base64) and asserts the
// outcome. Reject vectors use the coarse "parse" reject_class, satisfied by any of
// the parser's strict sentinels.
func runClaimsParseClass(t *testing.T, class ConformanceClass) {
	requireNonEmpty(t, "claims_parse", class)
	for _, v := range class.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			_, err := parseClaims([]byte(v.ClaimsJSON))
			assertParseOutcome(t, v, err)
		})
	}
}

// runSecretParseClass mirrors runClaimsParseClass for parseSecret. The short-key
// vector pins the precise ErrKeyLength sentinel (the secret length-check
// contract); other rejects use the coarse "parse" class.
func runSecretParseClass(t *testing.T, class ConformanceClass) {
	requireNonEmpty(t, "secret_parse", class)
	for _, v := range class.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			_, err := parseSecret([]byte(v.SecretJSON))
			switch v.Expect {
			case conformanceAccept:
				if err != nil {
					t.Fatalf("accept secret vector failed to parse: %v", err)
				}
			case conformanceReject:
				if err == nil {
					t.Fatal("reject secret vector unexpectedly parsed")
				}
				// key_length pins the precise sentinel; the coarse "parse" class
				// must still surface a strict parse-family sentinel (it is NOT enough
				// that *some* error came back -- a wrong-family error would mean the
				// parser rejected for the wrong reason). parseSecret always wraps in
				// ErrStrictParse (any underlying ErrKeyLength/ErrEncoding is nested
				// under it), so the documented secret_parse set is ErrStrictParse |
				// ErrKeyLength -- matching the README class-to-entry-point table.
				if v.RejectClass == rejectClassKeyLength {
					if !errors.Is(err, ErrKeyLength) {
						t.Fatalf("key_length vector: expected ErrKeyLength, got %v", err)
					}
				} else if !errors.Is(err, ErrStrictParse) && !errors.Is(err, ErrKeyLength) {
					t.Fatalf("reject secret vector %q: expected a strict-parse/key-length error, got %v", v.Name, err)
				}
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
	}
}

// runStrictBase64Class feeds each vector's base64url string VERBATIM to decodeB64
// (the fault is in the encoding layer). Rejects must surface ErrEncoding.
func runStrictBase64Class(t *testing.T, class ConformanceClass) {
	requireNonEmpty(t, "strict_base64", class)
	for _, v := range class.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			_, err := decodeB64(v.ValueB64)
			switch v.Expect {
			case conformanceAccept:
				if err != nil {
					t.Fatalf("accept base64 vector failed to decode: %v", err)
				}
			case conformanceReject:
				if !errors.Is(err, ErrEncoding) {
					t.Fatalf("reject base64 vector must return ErrEncoding, got %v", err)
				}
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
	}
}

// runFragmentClass feeds each vector's full fragment body to ParseFragment, which
// pins wire SHAPE (and strict-parses the parts) but does NOT verify the signature.
// Rejects must surface ErrFragment (or a part-decode/parse error for a malformed
// part); accept must parse cleanly.
func runFragmentClass(t *testing.T, class ConformanceClass) {
	requireNonEmpty(t, "fragment", class)
	for _, v := range class.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			_, err := ParseFragment(v.Fragment)
			switch v.Expect {
			case conformanceAccept:
				if err != nil {
					t.Fatalf("accept fragment vector failed to parse: %v", err)
				}
			case conformanceReject:
				if err == nil {
					t.Fatal("reject fragment vector unexpectedly parsed")
				}
				// Shape rejects wrap ErrFragment; a fragment whose parts are
				// individually malformed may instead wrap ErrStrictParse/ErrEncoding.
				if v.RejectClass == rejectClassFragment && !errors.Is(err, ErrFragment) {
					t.Fatalf("fragment-shape vector must return ErrFragment, got %v", err)
				}
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
	}
}

// runRelayAllowlistClass builds the allowlist from each vector's entries and runs
// ValidateRelayURL. Rejects must wrap ErrRelayURL.
func runRelayAllowlistClass(t *testing.T, class ConformanceClass) {
	requireNonEmpty(t, "relay_allowlist", class)
	for _, v := range class.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			allow := NewRelayAllowlist(v.Entries)
			err := ValidateRelayURL(v.URL, allow)
			switch v.Expect {
			case conformanceAccept:
				if err != nil {
					t.Fatalf("accept relay vector failed: %v", err)
				}
			case conformanceReject:
				if !errors.Is(err, ErrRelayURL) {
					t.Fatalf("reject relay vector must return ErrRelayURL, got %v", err)
				}
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
	}
}

// runServerIDClass RECOMPUTES the relay routing id from cell_public_key_b64 using
// the canonical utils.PubKeyFingerprint (the single source the Go relay/server
// and the js-agent both implement) and asserts it equals the vector's stored
// server_id. This is a recompute-vs-canonical check, not a trusted stored value:
// it cannot fork the POST /relay/{serverId} contract because it calls the same
// function production routing uses.
//
// This class is a RECOMPUTE-EQUALITY derivation, not an accept/reject gate: a
// fingerprint either equals the pinned server_id or it does not, so every vector
// is expect=accept and there is no reject branch. The guard below makes that
// explicit (a stray expect=reject server_id vector fails loudly rather than being
// silently treated as accept) so the expect field stays load-bearing for THIS
// class too. The accept<->reject "flip goes red" demonstration therefore belongs
// to the parse/encoding/fragment/relay/signature classes, which DO switch on
// expect; flipping a server_id vector to reject is a fixture error, not a
// behavioral negative.
func runServerIDClass(t *testing.T, class ConformanceClass) {
	requireNonEmpty(t, "server_id", class)
	for _, v := range class.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Expect != conformanceAccept {
				t.Fatalf("server_id is a recompute-equality class; only expect=accept is defined, got %q", v.Expect)
			}
			// The cell key is a pinned-encoding base64url X25519 public key; decode
			// it through the same strict decoder the parser uses so the preimage is
			// exactly the on-wire bytes.
			raw, err := decodeB64(v.CellPublicKeyB64)
			if err != nil {
				t.Fatalf("decode cell_public_key_b64: %v", err)
			}
			if len(raw) != x25519PublicKeyBytes {
				t.Fatalf("cell key decoded to %d bytes, want %d", len(raw), x25519PublicKeyBytes)
			}
			got := utils.PubKeyFingerprint(raw)
			if got != v.ServerID {
				t.Fatalf("server_id mismatch for %s: recomputed %q, vector pins %q", v.Name, got, v.ServerID)
			}
			if len(got) != utils.PubKeyFingerprintLen {
				t.Fatalf("server_id length = %d, want %d", len(got), utils.PubKeyFingerprintLen)
			}
		})
	}
}

// assertParseOutcome asserts a claims_parse vector's outcome. Accept must parse;
// reject must error with one of the parser's strict sentinels (the coarse "parse"
// class -- a conformant verifier may surface any of these for a schema fault).
func assertParseOutcome(t *testing.T, v ConformanceVector, err error) {
	t.Helper()
	switch v.Expect {
	case conformanceAccept:
		if err != nil {
			t.Fatalf("accept claims vector failed to parse: %v", err)
		}
	case conformanceReject:
		if err == nil {
			t.Fatal("reject claims vector unexpectedly parsed")
		}
		if !errors.Is(err, ErrStrictParse) && !errors.Is(err, ErrKeyLength) && !errors.Is(err, ErrEncoding) {
			t.Fatalf("reject claims vector %q: expected a strict-parse/key-length/encoding error, got %v", v.Name, err)
		}
	default:
		t.Fatalf("unknown expect %q", v.Expect)
	}
}

// allowedRejectClasses maps each class name to the reject_class values its reject
// vectors may declare. It is the single in-test statement of the cross-language
// vocabulary the README documents; a reject vector outside its class's set fails
// assertRejectClassVocabulary. The signature class is composed and stored in the
// separate signature fixture, so it is not listed here.
var allowedRejectClasses = map[string]map[string]struct{}{
	"claims_parse":    {rejectClassParse: {}},
	"secret_parse":    {rejectClassParse: {}, rejectClassKeyLength: {}},
	"strict_base64":   {rejectClassEncoding: {}},
	"fragment":        {rejectClassFragment: {}},
	"transport":       {rejectClassTransport: {}},
	"relay_allowlist": {rejectClassRelayURL: {}},
}

// assertRejectClassVocabulary checks that every reject vector in every class
// declares a reject_class drawn from that class's allowed set, and that accept
// vectors do not carry one. This pins the cross-language vocabulary as a contract
// rather than prose, so a consumer in another language can switch on reject_class
// with a closed, known set.
func assertRejectClassVocabulary(t *testing.T, cf *ConformanceFile) {
	for name, allowed := range allowedRejectClasses {
		class, ok := cf.Classes[name]
		if !ok {
			t.Fatalf("class %q missing", name)
		}
		for _, v := range class.Vectors {
			switch v.Expect {
			case conformanceAccept:
				if v.RejectClass != "" {
					t.Fatalf("%s/%s: accept vector must not carry a reject_class (got %q)", name, v.Name, v.RejectClass)
				}
			case conformanceReject:
				if _, in := allowed[v.RejectClass]; !in {
					t.Fatalf("%s/%s: reject_class %q is not in this class's vocabulary", name, v.Name, v.RejectClass)
				}
			default:
				t.Fatalf("%s/%s: unknown expect %q", name, v.Name, v.Expect)
			}
		}
	}
}

// requireNonEmpty fails if a class carries no vectors -- an empty class is a
// silent coverage hole the always-run contract must not tolerate.
func requireNonEmpty(t *testing.T, name string, class ConformanceClass) {
	t.Helper()
	if len(class.Vectors) == 0 {
		t.Fatalf("conformance class %q has no vectors", name)
	}
}
