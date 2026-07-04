package qurl

// TestAdmissionWireContract pins the CLIENT (nhp-server) side of the INTERNAL
// nhp-server <-> qurl-service qURL-v2 admission HTTP wire against local golden
// fixtures under testdata/qurlv2_admission_contract/. Those fixtures are
// byte-identical with the qurl-service repo's own contract fixtures
// (tests/contract/testdata/qurlv2_admission/); the source of truth for both is
// docs/design/QURL_V2_KEYED_IDENTITY.md ("NHP Server Contract"). Any field-name,
// encoding, or body-shape change to this internal admission API MUST be mirrored
// in both repos' fixtures AND the design doc in the same change.
//
// This is an INTERNAL, per-repo contract fixture set. It is deliberately NOT the
// public cross-language crypto conformance corpus
// (endpoints/server/internal/qurlv2/vectors.go / the qurl-conformance repo): the
// internal admission API is a private service-to-service contract and must never
// be published there.
//
// Scope of the pin: this test pins SPECIFIC LOAD-BEARING FIELDS, not the entire
// body shape. The request side is enforced by a SENDER-SUBSET marshal check
// (every key the client DTO EMITS must be present in the fixture with the same
// value) — so a client-side tag rename or dropped field FAILS. But a fixture key
// the DTO does not model (session_duration, remaining_seconds,
// resource_public_key_b64, revocation_epoch, and the optional user_agent /
// visitor_session_id / authorize ac_id the client may legitimately omit) is not
// asserted: dropping such a field will NOT fail CI. Do not over-trust this as a
// full-schema guard.
//
// Why this test exists: three real bugs shipped because the client DTOs and the
// qurl-service wire drifted with nothing to catch it at PR time (pre-deploy):
//   - #3028: the authenticated qURL public key was std-base64 encoded, not the
//     base64url the hash preimage requires (see the base64url cross-check below).
//   - #1096: the prepare response field was read as open_time_seconds, not the
//     contract's open_time (see the field-name pin below).
//   - #3029: commit omitted the REQUIRED qurl_user_public_key_hash body field
//     (caught by the commit sender-subset check: the DTO emits that key, so it
//     must appear in the fixture).
//
// Each of those is now a compile-and-run failure here if the DTO regresses.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const admissionContractDir = "testdata/qurlv2_admission_contract"

// canonicalFixtureSetSHA256 pins the admission-wire fixture SET: sha256 over
// every *.json in THIS repo's testdata dir (README.md excluded), filenames
// byte-sorted, raw bytes concatenated in that order with NO separators. It is
// also recorded in docs/design/QURL_V2_KEYED_IDENTITY.md ("NHP Server Contract" /
// admission-wire section), and qurl-service runs the same computation over its own
// tests/contract/testdata/qurlv2_admission/ copy against the same constant.
//
// What this DOES catch: any LOCAL fixture edit in this repo — it forces the editor
// to also bump this constant and the design-doc note (a fixture change with a stale
// hash fails CI here). What it does NOT catch: the OTHER repo silently diverging.
// Each repo only hashes its OWN directory against its OWN copy of this constant, so
// nothing here mechanically observes qurl-service's bytes; keeping the two sides
// byte-identical is a human lockstep discipline (update this constant + the
// design-doc note + BOTH repos' fixtures in the same change), not something this
// test proves. "Green" means "the committed fixtures still hash to this value" —
// NOT "these bytes match the live qurl-service".
const canonicalFixtureSetSHA256 = "0967eb6f4107a43028848867b6353db4f6cb2ef14bcdcc74d366009c8aea5678"

// contractMeta mirrors _contract_meta.json: an agent (qURL user) public key in
// the on-wire unpadded base64url form and its canonical revocation-index hash.
// Pins the #3028 encoding invariant end to end.
type contractMeta struct {
	AgentKeyB64URL  string `json:"agent_key_b64url"`
	AgentKeyHashHex string `json:"agent_key_hash_hex"`
}

func readContractFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(admissionContractDir, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func toMap(t *testing.T, label string, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal %s into map: %v", label, err)
	}
	return m
}

// assertSenderSubset is the core request-side wire enforcement. It hydrates the
// client request DTO FROM the canonical fixture (so the emitted values are the
// fixture's, not test-local constants), re-marshals the DTO, and asserts every
// key the DTO EMITS is present in the fixture with a deep-equal value.
//
// SUBSET semantics on purpose: the client legitimately sends a SUBSET of the
// fixture (e.g. admissionLifecycleRequest omits the optional visitor_session_id
// that commit_request.json carries; cancel omits src_ip). So this asserts
// "every emitted key is in the fixture with the same value", NOT "every fixture
// key is emitted".
//
// What this mechanism catches precisely: a tag RENAME or a VALUE drift — the
// renamed key is emitted but absent from the fixture (fail), or an emitted key's
// value no longer matches (fail). It does NOT by itself catch a field being
// REMOVED from the DTO struct: fewer emitted keys is legal under subset. That
// removal class (e.g. #3029, dropping qurl_user_public_key_hash) is caught by the
// belt-and-braces non-empty spot-check at each call site — a compile-time
// struct-field reference that fails to build if the field is gone and fails the
// assertion if it stops populating — together with the rename->absent-key path
// above. The two together, not the subset semantics alone, close the drift class.
//
// dst must be a pointer to the request DTO to unmarshal into.
func assertSenderSubset(t *testing.T, fixtureName string, dst any) {
	t.Helper()
	fixtureRaw := readContractFixture(t, fixtureName)

	// Values come from the canonical fixture, not hand-written constants.
	if err := json.Unmarshal(fixtureRaw, dst); err != nil {
		t.Fatalf("unmarshal %s into %T: %v", fixtureName, dst, err)
	}
	emittedRaw, err := json.Marshal(dst)
	if err != nil {
		t.Fatalf("marshal %T: %v", dst, err)
	}

	fixtureMap := toMap(t, fixtureName, fixtureRaw)
	emittedMap := toMap(t, "emitted "+fixtureName, emittedRaw)

	if len(emittedMap) == 0 {
		t.Fatalf("%T emitted no JSON keys; a request DTO must send at least one field", dst)
	}
	for key, emittedVal := range emittedMap {
		fixtureVal, ok := fixtureMap[key]
		if !ok {
			t.Errorf("%s: DTO emits key %q that is ABSENT from the fixture (client-side rename/drift?)", fixtureName, key)
			continue
		}
		if !reflect.DeepEqual(emittedVal, fixtureVal) {
			t.Errorf("%s: DTO emits key %q = %#v, fixture has %#v", fixtureName, key, emittedVal, fixtureVal)
		}
	}
}

func TestAdmissionWireContract(t *testing.T) {
	// Request side: SENDER-SUBSET marshal enforcement per DTO. Each hydrates the
	// DTO from its fixture, re-marshals, and asserts every emitted key matches the
	// fixture (subset). This is the primary body-shape/rename guard and subsumes
	// the earlier narrow single-key marshal pins.
	t.Run("AuthorizeRequestSenderSubset", func(t *testing.T) {
		var req AdmissionAuthorizeRequest
		assertSenderSubset(t, "authorize_request.json", &req)
		// Spot-check the load-bearing fields also populated (a belt-and-braces
		// non-empty check on top of the subset equality).
		if req.AuthenticatedQurlPublicKeyB64 == "" || req.ClientIP == "" {
			t.Errorf("authorize required fields not populated: %#v", req)
		}
	})

	t.Run("PrepareRequestSenderSubset", func(t *testing.T) {
		var req AdmissionPrepareRequest
		assertSenderSubset(t, "prepare_request.json", &req)
		if req.QurlClaimsB64 == "" || req.QurlIssuerSigB64 == "" ||
			req.AuthenticatedQurlPublicKeyB64 == "" || req.SrcIP == "" {
			t.Errorf("prepare required fields not populated: %#v", req)
		}
	})

	t.Run("CommitRequestSenderSubset", func(t *testing.T) {
		// #3029: the DTO emits qurl_user_public_key_hash, so the subset check
		// requires it to be present in commit_request.json with the same value.
		var req admissionLifecycleRequest
		assertSenderSubset(t, "commit_request.json", &req)
		if req.QurlUserPublicKeyHash == "" {
			t.Errorf("commit qurl_user_public_key_hash not populated: %#v", req)
		}
	})

	t.Run("CancelRequestSenderSubset", func(t *testing.T) {
		var req admissionLifecycleRequest
		assertSenderSubset(t, "cancel_request.json", &req)
		if req.QurlUserPublicKeyHash == "" {
			t.Errorf("cancel qurl_user_public_key_hash not populated: %#v", req)
		}
	})

	t.Run("AuthorizeResponse", func(t *testing.T) {
		raw := readContractFixture(t, "authorize_response.json")
		var env internalAdmissionAuthorizeResponse
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("unmarshal authorize_response.json into internalAdmissionAuthorizeResponse: %v", err)
		}
		if !env.Success {
			t.Error("authorize response success != true")
		}
		if env.Data == nil {
			t.Fatal("authorize response data is nil")
		}
		if env.Data.SessionID == "" {
			t.Error("authorize response session_id did not populate")
		}
		if env.Data.ACRouting == nil {
			t.Fatal("authorize response ac_routing is nil")
		}
		if env.Data.ACRouting.ACId == "" {
			t.Error("authorize response ac_routing.ac_id did not populate")
		}
	})

	t.Run("PrepareResponse", func(t *testing.T) {
		raw := readContractFixture(t, "prepare_response.json")
		var env internalAdmissionPrepareResponse
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("unmarshal prepare_response.json into internalAdmissionPrepareResponse: %v", err)
		}
		if !env.Success {
			t.Error("prepare response success != true")
		}
		if env.Data == nil {
			t.Fatal("prepare response data is nil")
		}
		// #1096: open_time must decode to the fixture value via the open_time tag.
		if env.Data.OpenTime != 30 {
			t.Errorf("prepare response OpenTime = %d, want 30 (open_time)", env.Data.OpenTime)
		}
		if env.Data.QurlUserPublicKeyHash == "" {
			t.Error("prepare response qurl_user_public_key_hash did not populate")
		}
		if env.Data.QurlID != "qurl_abc123" {
			t.Errorf("prepare response QurlID = %q, want qurl_abc123", env.Data.QurlID)
		}
		if env.Data.ACRouting == nil {
			t.Fatal("prepare response ac_routing is nil")
		}
		if env.Data.ACRouting.ACId != "ac_use2_01" {
			t.Errorf("prepare response ac_routing.ac_id = %q, want ac_use2_01", env.Data.ACRouting.ACId)
		}
	})

	// The commit response shares the {success,data:{session_id,remaining_seconds,
	// ac_routing}} envelope with authorize (the extra revocation_epoch field is
	// ignored by the decoder). The client currently checks only the HTTP status on
	// commit, so there is no commit-specific envelope DTO; unmarshaling into the
	// authorize envelope pins the success-envelope wire shape and the shared
	// response fields without inventing a type.
	t.Run("CommitResponseEnvelope", func(t *testing.T) {
		raw := readContractFixture(t, "commit_response.json")
		var env internalAdmissionAuthorizeResponse
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("unmarshal commit_response.json success envelope: %v", err)
		}
		if !env.Success {
			t.Error("commit response success != true")
		}
		if env.Data == nil {
			t.Fatal("commit response data is nil")
		}
		if env.Data.SessionID == "" {
			t.Error("commit response session_id did not populate")
		}
		if env.Data.ACRouting == nil || env.Data.ACRouting.ACId != "ac_use2_01" {
			t.Errorf("commit response ac_routing.ac_id != ac_use2_01: %#v", env.Data.ACRouting)
		}
	})

	// #1096 field-name pin (response side): the prepare response field MUST
	// serialize as open_time and MUST NOT serialize as open_time_seconds (the name
	// the bug read). Kept as an explicit response-side pin because the response
	// fixtures are not exercised by the sender-subset check.
	t.Run("PrepareResponseFieldNamePin", func(t *testing.T) {
		out, err := json.Marshal(AdmissionPrepareResponse{
			AdmissionID:           "adm_2f8c1b",
			QurlID:                "qurl_abc123",
			QurlUserPublicKeyHash: "fc714cf45d81731af38f58dcd6c7a39f1a37dd699c67281a2f5c99814029b574",
			OpenTime:              30,
			QurlSiteURL:           "https://app.example.qurl.site/",
			ACRouting:             &ACRouting{ACId: "ac_use2_01", DestHost: "app.internal", DestPort: 443},
		})
		if err != nil {
			t.Fatalf("marshal AdmissionPrepareResponse: %v", err)
		}
		s := string(out)
		if !strings.Contains(s, `"open_time"`) {
			t.Errorf("prepare response JSON missing open_time: %s", s)
		}
		if strings.Contains(s, `"open_time_seconds"`) {
			t.Errorf("prepare response JSON must not use open_time_seconds (#1096): %s", s)
		}
	})

	// #3028 hash + base64url cross-check: the agent key in the fixtures is the
	// unpadded base64url form, and PublicKeyHashFromB64 (hex(sha256(base64url_decode
	// (key)))) must reproduce the pinned hash. If the client ever std-base64 encoded
	// the key, the decode would differ (or fail) and the hash would not match.
	t.Run("AgentKeyBase64URLAndHash", func(t *testing.T) {
		raw := readContractFixture(t, "_contract_meta.json")
		var meta contractMeta
		if err := json.Unmarshal(raw, &meta); err != nil {
			t.Fatalf("unmarshal _contract_meta.json: %v", err)
		}

		got := mustPubKeyHashB64(t, meta.AgentKeyB64URL)
		if got != meta.AgentKeyHashHex {
			t.Errorf("hash = %q, want %q (hex(sha256(base64url_decode(key))))", got, meta.AgentKeyHashHex)
		}

		// The key must be valid unpadded base64url decoding to a 32-byte X25519 key.
		decoded, err := base64.RawURLEncoding.DecodeString(meta.AgentKeyB64URL)
		if err != nil {
			t.Fatalf("agent key %q is not valid unpadded base64url: %v", meta.AgentKeyB64URL, err)
		}
		if len(decoded) != 32 {
			t.Errorf("agent key decoded to %d bytes, want 32", len(decoded))
		}
		// A base64url-distinct key: it must contain a '-' or '_' so a std-base64
		// decoder (which uses '+'/'/') would not round-trip it — the exact #3028
		// encoding confusion. (The fixture key was chosen to exercise this.)
		if !strings.ContainsAny(meta.AgentKeyB64URL, "-_") {
			t.Errorf("agent key %q has no base64url-distinct char (- or _); cannot guard #3028", meta.AgentKeyB64URL)
		}
	})

	// FixtureSetChecksum hashes the whole fixture SET and pins it to
	// canonicalFixtureSetSHA256. The per-field pins catch a DTO regressing against
	// the fixtures; this catches a LOCAL fixture edit in THIS repo — a single edited
	// byte in any *.json flips the hash, forcing the editor to also bump the constant
	// and the design-doc note in the same change.
	//
	// It does NOT mechanically detect qurl-service silently diverging: that repo
	// hashes only its own directory against its own copy of this constant, so nothing
	// here observes its bytes. Two-repo byte-identity is a human lockstep discipline,
	// not something this test proves. A pass means "the committed fixtures still hash
	// to this value", NOT "these bytes match the live service".
	//
	// Canonical computation (MUST match qurl-service + the design-doc note exactly):
	// every *.json in the dir (README.md excluded), filenames byte-sorted, raw
	// bytes concatenated in that order with NO separators, sha256, lowercase hex.
	t.Run("FixtureSetChecksum", func(t *testing.T) {
		entries, err := os.ReadDir(admissionContractDir)
		if err != nil {
			t.Fatalf("read fixture dir %s: %v", admissionContractDir, err)
		}
		var names []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			// Only the JSON fixtures are canonical; README.md (and any future
			// non-.json doc) is explicitly excluded from the set hash.
			if filepath.Ext(e.Name()) == ".json" {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names) // byte-order sort (matches LC_ALL=C sort / qurl-service).
		if len(names) == 0 {
			t.Fatalf("no *.json fixtures found in %s", admissionContractDir)
		}

		h := sha256.New()
		for _, name := range names {
			h.Write(readContractFixture(t, name)) // raw bytes, in sorted order, no separators.
		}
		got := hex.EncodeToString(h.Sum(nil))
		if got != canonicalFixtureSetSHA256 {
			t.Errorf("fixture-set sha256 = %s, want %s\n"+
				"the admission-wire fixtures changed: update canonicalFixtureSetSHA256, "+
				"the docs/design/QURL_V2_KEYED_IDENTITY.md note, and BOTH repos' fixtures in lockstep.\n"+
				"hashed files (sorted): %v", got, canonicalFixtureSetSHA256, names)
		}
	})
}
