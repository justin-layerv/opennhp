package qurlv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// qURL v2 conformance-vector artifact loader.
//
// qv2_conformance_vectors.json is the LayerV-owned, language-agnostic wire-truth for
// the qURL v2 verify path. Every qURL v2 verifier (the Go package here, the
// TypeScript js-agent, and the future qurl-go) re-runs the SAME bytes against its
// OWN implementation: a consumer feeds each class's input through its real
// parser/validator and asserts the declared accept/reject outcome (and, where the
// class is about the distinction, the reject_class). The vectors are BEHAVIORAL --
// a consumer recomputes/re-verifies rather than trusting a stored boolean -- so a
// verifier that drifts from the contract fails its own run.
//
// The bytes are no longer vendored under testdata/: they come from the
// version-pinned public module github.com/layervai/qurl-conformance (go:embed
// accessors conformance.QV2Vectors / conformance.IssuerSignatureVectors), so every
// language binding consumes one source of truth. See that module's
// vectors/README_qv2_conformance_vectors.md for the schema, the reject_class
// vocabulary, the class-to-entry-point map, and the ownership story.
//
// This file is the schema + loader. conformance_test.go is the always-run test
// that drives every class (including negatives) through the package's real entry
// points.
//
// Input-shape-per-class (NOT one uniform shape): each class carries the exact
// input form its target entry point consumes, so a stored fault survives to the
// code under test:
//   - claims_parse / secret_parse: RAW JSON TEXT, fed straight to
//     parseClaims/parseSecret. Duplicate keys and other JSON-layer faults survive
//     because they live inside a JSON string value, not as object members a
//     re-serializer would normalize away. NOT base64 -- parseClaims consumes JSON
//     bytes, so base64-encoding first would reject for the wrong reason.
//   - strict_base64: the base64url string VERBATIM (the fault is in the encoding
//     layer), fed to decodeB64.
//   - fragment: a full fragment body fed to ParseFragment (which pins wire SHAPE
//     and strict-parses the parts but does NOT verify the signature).
//   - transport: a qv2t1 outer fragment body fed to DecodeTransport, which
//     reconstructs the exact canonical qv2 fragment without interpreting it.
//   - relay_allowlist: entries + url, fed to ValidateRelayURL(NewRelayAllowlist).
//   - server_id: cell_public_key_b64 the consumer DECODES and re-fingerprints.
//   - signature: composed from issuer_signature_vectors.json (not duplicated).

// Expect / reject_class vocabulary. These constants are the fixed cross-language
// vocabulary; the README pins the same set so qurl-go and the js-agent share it.
//
// The accept/reject expect values and the signature-class distinctions
// (high_s / wrong_length) are NOT redefined here -- they are the SAME wire
// vocabulary the sibling golden-vector code already exports (ExpectAccept /
// ExpectReject / RejectClassHighS / RejectClassWrongLength in vectors.go), so this
// file reuses those single-source constants rather than minting a second copy of
// the literals. Only the reject_class values that have no existing constant are
// defined below. reject_class is pinned precisely ONLY where the class is about
// the distinction (signature high_s vs wrong_length; encoding; key_length);
// JSON-schema faults use the coarse "parse" because a conformant verifier may
// surface any of several internal sentinels for them (mirroring the Go
// parse-rejection tests, which accept any of ErrStrictParse / ErrKeyLength /
// ErrEncoding).
const (
	// conformanceAccept / conformanceReject alias the exported expect vocabulary
	// so the per-class runners read naturally while the literal lives in one place.
	conformanceAccept = ExpectAccept
	conformanceReject = ExpectReject

	// rejectClassParse is the coarse class for a JSON-schema violation (duplicate
	// key, unknown field, null, wrong type, missing required, out-of-range/ordering).
	rejectClassParse = "parse"
	// rejectClassEncoding is a base64url encoding-layer rejection.
	rejectClassEncoding = "encoding"
	// rejectClassKeyLength is a decoded-key wrong-length rejection.
	rejectClassKeyLength = "key_length"
	// rejectClassFragment is a fragment wire-shape rejection.
	rejectClassFragment = "fragment"
	// rejectClassTransport is a qv2t1 outer transport framing rejection.
	rejectClassTransport = "transport"
	// rejectClassRelayURL is a relay_url HTTPS/allowlist rejection.
	rejectClassRelayURL = "relay_url"
	// rejectClassTamper is the signature-class payload-tamper rejection: a valid
	// signature verified against a flipped claims input (derived, not stored).
	rejectClassTamper = "tamper"
)

// Signature-class tamper derivation identifiers. These pin the artifact's
// language-agnostic derivation so the Go test applies exactly what the JSON
// specifies (rather than a hardcoded rule a vendoring consumer could not see).
const (
	// tamperDeriveFromAccept is the only supported derive_from: start from the
	// composed file's accept vector.
	tamperDeriveFromAccept = "accept_vector"
	// tamperTransformFlipFirstB64 flips the FIRST base64url character of the accept
	// vector's claims_b64 between 'A' and 'B' ('A'->'B', any other char->'A'). The
	// first symbol encodes the top 6 bits of decoded byte 0, so this changes the
	// DECODED claims (not just don't-care tail bits) AND keeps the string canonical
	// base64url. That makes the derived tamper identical for every consumer
	// regardless of whether it hashes the base64 string, decodes-then-hashes, or
	// strict-decodes before verifying -- unlike a last-char flip, whose low bit is a
	// don't-care padding bit when len(claims_b64) mod 4 != 0.
	tamperTransformFlipFirstB64 = "flip_first_base64url_char_A_B"
)

// ConformanceFile is the top-level conformance artifact document.
type ConformanceFile struct {
	Artifact          string                       `json:"artifact"`
	SchemaVersion     int                          `json:"schema_version"`
	Description       string                       `json:"description"`
	SourceOfTruth     string                       `json:"source_of_truth"`
	Notes             []string                     `json:"notes"`
	TransportContract ConformanceTransportContract `json:"transport_contract"`
	SignatureClass    ConformanceSignatureClass    `json:"signature_class"`
	Classes           map[string]ConformanceClass  `json:"classes"`
}

type ConformanceTransportContract struct {
	Prefix             string                     `json:"prefix"`
	CanonicalPrefix    string                     `json:"canonical_prefix"`
	ComponentMax       int                        `json:"component_max"`
	MaxTransportLength int                        `json:"max_transport_length"`
	Fields             ConformanceTransportFields `json:"fields"`
}

type ConformanceTransportFields struct {
	Claims    ConformanceTransportField `json:"claims"`
	Secret    ConformanceTransportField `json:"secret"`
	Signature ConformanceTransportField `json:"signature"`
}

type ConformanceTransportField struct {
	MaxEncodedLength int `json:"max_encoded_length"`
	MaxChunks        int `json:"max_chunks"`
}

// ConformanceSignatureClass records that the signature class is composed from a
// separate file rather than carrying its own bytes, plus the language-agnostic
// payload-tamper derivation every consumer synthesizes from the composed file's
// accept vector (so the tamper negative is vendorable without a third copy of
// signature bytes).
type ConformanceSignatureClass struct {
	EntryPoint string `json:"entry_point"`
	Composes   string `json:"composes"`
	Comment    string `json:"comment"`
	// TamperDerivation specifies the derived payload-tamper reject. It is optional
	// in the schema's struct but the test asserts it is present and well-formed.
	TamperDerivation *ConformanceTamperDerivation `json:"tamper_derivation,omitempty"`
}

// ConformanceTamperDerivation specifies how a consumer derives the payload-tamper
// reject from the composed signature file's accept vector. It is a derivation, not
// stored bytes, so Go / js-agent / qurl-go all synthesize the SAME negative.
//
//   - RejectClass: the reject_class label for the derived case ("tamper").
//   - DeriveFrom: which composed vector to start from ("accept_vector").
//   - ClaimsTransform: the transform applied to that vector's claims_b64 to make
//     the signature no longer valid over it ("flip_first_base64url_char_A_B": flip
//     the FIRST base64url character between 'A' and 'B'). The first symbol is fully
//     significant, so the result stays canonical and decodes to different bytes
//     (portable across consumer hash strategies). The signature bytes are reused
//     UNCHANGED, so the case fails only at the curve check.
type ConformanceTamperDerivation struct {
	RejectClass     string `json:"reject_class"`
	Comment         string `json:"comment"`
	DeriveFrom      string `json:"derive_from"`
	ClaimsTransform string `json:"claims_transform"`
}

// ConformanceClass is one named class: an entry-point label, the input field
// name, an optional human comment, and the ordered vectors.
type ConformanceClass struct {
	EntryPoint string              `json:"entry_point"`
	Input      string              `json:"input"`
	Comment    string              `json:"comment"`
	Vectors    []ConformanceVector `json:"vectors"`
}

// ConformanceVector is one case. Only the fields relevant to a vector's class are
// populated; the loader does not interpret them -- the test routes each class to
// the matching entry point and reads the fields that class uses.
type ConformanceVector struct {
	Name   string `json:"name"`
	Expect string `json:"expect"`
	// Composed conformance classes keep reject_class as a string because their
	// accept vectors do not need the absent-vs-empty distinction SignatureVector
	// enforces for issuer-signature JSON.
	RejectClass string `json:"reject_class"`
	Reason      string `json:"reason"`

	// claims_parse / secret_parse: raw JSON text fed directly to the parser.
	ClaimsJSON string `json:"claims_json"`
	SecretJSON string `json:"secret_json"`

	// strict_base64: the base64url string verbatim.
	ValueB64 string `json:"value_b64"`

	// fragment: a full fragment body.
	Fragment string `json:"fragment"`

	// transport: a qv2t1 outer fragment and its exact canonical qv2 output.
	TransportFragment string `json:"transport_fragment"`
	CanonicalFragment string `json:"canonical_fragment"`

	// relay_allowlist: the allowlist entries and the URL to validate.
	Entries []string `json:"entries"`
	URL     string   `json:"url"`

	// server_id: the cell public key (base64url) and its expected routing id.
	CellPublicKeyB64 string `json:"cell_public_key_b64"`
	ServerID         string `json:"server_id"`
}

// ConformanceArtifactID is the fixed identity string the top-level "artifact"
// field must carry. The loader enforces it so a consumer that relies on "the
// loader rejects malformed files" cannot silently load a DIFFERENT document
// (e.g. the golden-vector file, or a renamed artifact) into these structs. A
// vendoring consumer in another language should assert the same id (the README
// tells vendors to assert artifact + version).
const ConformanceArtifactID = "qurl-v2-conformance-vectors"

const conformanceSchemaVersion = 2

// parseConformanceFile strictly parses conformance-artifact bytes into a
// ConformanceFile. It returns an error (never an empty/zero document) when the
// bytes are malformed or are not the qURL v2 conformance artifact, so a consumer
// test FAILS rather than silently skipping or misreading the contract.
// DisallowUnknownFields keeps a typo'd or stale schema field from being ignored.
//
// The pinned module's embedded bytes (conformance.QV2Vectors) are fed in by the
// test-only loader in conformance_loaders_test.go; keeping the byte-parser here
// (and the module import out) leaves qurl-conformance out of the production import
// graph.
func parseConformanceFile(data []byte) (*ConformanceFile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cf ConformanceFile
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("qurlv2: parse conformance file: %w", err)
	}
	if cf.Artifact != ConformanceArtifactID {
		return nil, fmt.Errorf("qurlv2: conformance file has artifact %q, want %q", cf.Artifact, ConformanceArtifactID)
	}
	if cf.SchemaVersion != conformanceSchemaVersion {
		return nil, fmt.Errorf("qurlv2: conformance file has schema_version %d, want %d", cf.SchemaVersion, conformanceSchemaVersion)
	}
	if len(cf.Classes) == 0 {
		return nil, errors.New("qurlv2: conformance file has no classes")
	}
	if err := validateConformanceTransportContract(cf.TransportContract); err != nil {
		return nil, err
	}
	transportClass, ok := cf.Classes["transport"]
	if !ok {
		return nil, errors.New("qurlv2: conformance file is missing transport class")
	}
	if err := validateConformanceTransportClass(transportClass); err != nil {
		return nil, err
	}
	return &cf, nil
}

func validateConformanceTransportContract(tc ConformanceTransportContract) error {
	want := ConformanceTransportContract{
		Prefix:             TransportPrefix,
		CanonicalPrefix:    FragmentPrefix,
		ComponentMax:       TransportComponentMax,
		MaxTransportLength: TransportMaxLength,
		Fields: ConformanceTransportFields{
			Claims:    ConformanceTransportField{MaxEncodedLength: transportClaimsMaxLength, MaxChunks: transportClaimsMaxChunks},
			Secret:    ConformanceTransportField{MaxEncodedLength: transportSecretMaxLength, MaxChunks: transportSecretMaxChunks},
			Signature: ConformanceTransportField{MaxEncodedLength: transportSigMaxLength, MaxChunks: transportSigMaxChunks},
		},
	}
	if tc != want {
		return fmt.Errorf("qurlv2: conformance transport contract drifted: got %+v want %+v", tc, want)
	}
	return nil
}

func validateConformanceTransportClass(class ConformanceClass) error {
	if class.EntryPoint == "" || class.Input != "transport_fragment" || len(class.Vectors) == 0 {
		return errors.New("qurlv2: malformed conformance transport class header")
	}
	seen := make(map[string]struct{}, len(class.Vectors))
	for _, v := range class.Vectors {
		if v.Name == "" || v.Reason == "" || v.TransportFragment == "" {
			return fmt.Errorf("qurlv2: malformed conformance transport vector %q", v.Name)
		}
		if _, ok := seen[v.Name]; ok {
			return fmt.Errorf("qurlv2: duplicate conformance transport vector %q", v.Name)
		}
		seen[v.Name] = struct{}{}
		switch v.Expect {
		case conformanceAccept:
			if v.RejectClass != "" || v.CanonicalFragment == "" {
				return fmt.Errorf("qurlv2: malformed accept conformance transport vector %q", v.Name)
			}
		case conformanceReject:
			if v.RejectClass != rejectClassTransport || v.CanonicalFragment != "" {
				return fmt.Errorf("qurlv2: malformed reject conformance transport vector %q", v.Name)
			}
		default:
			return fmt.Errorf("qurlv2: conformance transport vector %q has expect %q", v.Name, v.Expect)
		}
	}
	return nil
}
