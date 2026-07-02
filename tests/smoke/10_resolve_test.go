//go:build smoke

package smoke

// Tier 2: QURL resolve REJECTION path — the NHP server's static qurl
// plugin (registered at /plugins/qurl) maps a missing / unknown /
// malformed access token to a branded 403 "Access Link Invalid" page.
//
// The happy-path resolve tests (mint a real QURL via qurl-service +
// Auth0, assert the 302 → r_{id}.qurl.site redirect, cookies, and
// Accept-negotiation) were removed from nhp and re-homed in
// qurl-service#1018 because qURL minting is a qurl-service concern, not
// nhp's (see tests/smoke/CLAUDE.md). qURL v2 live resolve coverage now
// continues in qurl-service#1047.
// What remains here is the rejection contract, which is pure NHP-handler
// behavior and needs no minted QURL — a bogus token is enough to reach
// the 403 path.
//
// These run remote-only (the deployed qurl plugin must be wired for the
// host) and skip on the local target via requireRemote.
//
// Source of truth: endpoints/server/staticplugins/qurl/main.go
// (the AuthWithHttp handler).
//
// v1 vs v2 — TWO rejection contracts live here:
//
//   - The legacy v1 contract above is a SERVER-side branded 403 on
//     /plugins/qurl. It only exists where the resolve endpoint is deployed,
//     so each test gates on skipIfResolveEndpointDisabled and runs in prod
//     (and any legacy env), not in the JS-agent + relay topology where the
//     server resolve surface is gone.
//   - Under qURL v2 keyed-identity, token validation moved CLIENT-side: the
//     browser JS-agent (and the github.com/layervai/qurl-go SDK in Go)
//     parses the signed qURL fragment and verifies the issuer signature
//     before it ever knocks. There is no server endpoint to POST a bad token
//     at. TestResolveV2_SDKRejectsBadLinks fences that the pinned qurl-go SDK
//     version we ship against still fails closed on malformed, tampered, and
//     untrusted-issuer links. It is offline (no deployed infra, no minted
//     qURL) and runs in every env, so it is the resolve-rejection signal that
//     survives the sandbox cutover. Deployed v2 admission (a real signed link
//     → relay knock → ServerDenyError) needs a minted link and stays a
//     qurl-service concern, per tests/smoke/CLAUDE.md.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

// accessLinkInvalidMarker is the branded HTML page title returned by the
// qurl plugin when an access token is missing, invalid, or expired. Used
// by both the resolve rejection tests here and the plugin dispatcher test
// (13_plugins_test.go) as the single source of truth for the marker.
const accessLinkInvalidMarker = "Access Link Invalid"

// TestResolve_UnknownTokenReturns403_POST fences the access-denied
// path via POST (preferred path) for a syntactically well-formed but
// nonexistent access token. Real access tokens are at_ + 22 chars of
// base62 (25 chars total). The bogus token below matches that
// length/shape so if the server has a length-precheck it still
// reaches the store-lookup path, where the lookup fails and the
// handler returns the branded 403.
func TestResolve_UnknownTokenReturns403_POST(t *testing.T) {
	requireRemote(t)                     // remote-only: qURL bad-token 403 needs a provisioned qURL resource (qurl-service).
	skipIfResolveEndpointDisabled(t)     // v1 server-side 403 path; gone under the JS-agent topology (see TestResolveV2_SDKRejectsBadLinks)
	bogus := "at_nonexistentyyyyyyyyyyy" // at_ + 22 chars

	resp, body := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl", "token="+bogus, nil)
	assertStatusCode(t, resp, http.StatusForbidden)

	marker := accessLinkInvalidMarker
	if !strings.Contains(string(body), marker) {
		t.Fatalf("403 body does not contain %q (body: %s)", marker, truncate(body, 400))
	}
}

// TestResolve_UnknownTokenReturns403_GET_BackwardCompat verifies the
// deprecated GET query parameter path still returns a proper 403 for
// unknown tokens (backward compatibility).
func TestResolve_UnknownTokenReturns403_GET_BackwardCompat(t *testing.T) {
	requireRemote(t)                     // remote-only: qURL bad-token 403 needs a provisioned qURL resource (qurl-service).
	skipIfResolveEndpointDisabled(t)     // v1 server-side 403 path; gone under the JS-agent topology
	bogus := "at_nonexistentyyyyyyyyyyy" // at_ + 22 chars

	resp, body := doGetNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl?token="+bogus, nil)
	assertStatusCode(t, resp, http.StatusForbidden)

	marker := accessLinkInvalidMarker
	if !strings.Contains(string(body), marker) {
		t.Fatalf("403 body does not contain %q (body: %s)", marker, truncate(body, 400))
	}
}

// TestResolve_MalformedTokenReturns403 fences the error path for
// tokens that don't even parse as access tokens (no at_ prefix).
// The response must be 403 — not 500, not 400, not a panic.
func TestResolve_MalformedTokenReturns403(t *testing.T) {
	requireRemote(t)                 // remote-only: qURL bad-token 403 needs a provisioned qURL resource (qurl-service).
	skipIfResolveEndpointDisabled(t) // v1 server-side 403 path; gone under the JS-agent topology
	garbage := "definitely-not-a-token"

	resp, _ := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl", "token="+garbage, nil)
	assertStatusCode(t, resp, http.StatusForbidden)
}

// TestResolveV2_SDKRejectsBadLinks fences the qURL v2 keyed-identity
// rejection contract, which moved CLIENT-side: under the JS-agent + relay
// topology there is no server endpoint to POST a bad token at — the opener
// (the browser JS-agent, or the github.com/layervai/qurl-go SDK in Go) parses
// the signed qURL fragment and verifies the issuer signature BEFORE it knocks.
// This is the resolve-rejection signal that survives the sandbox cutover, so
// unlike the v1 tests above it carries no skipIfResolveEndpointDisabled and
// runs in every env.
//
// It is offline by construction: qurl.VerifyLink does parse + issuer-signature
// verification only (no network, no minted-by-LayerV qURL, no deployed infra).
// We mint a link with a throwaway local issuer key via the SDK's offline
// CreatePortalWithParams seam — whose documented symmetry guarantee is that the
// link it returns verifies under VerifyLink against that key — then assert the
// SDK fails CLOSED on malformed, untrusted-issuer, and claims/sig-mismatched
// links. The value is a tripwire on the pinned SDK version: a bad qurl-go bump
// that loosened the parser or signature check reddens here.
//
// Deployed v2 admission (a real signed link → relay knock → ServerDenyError)
// needs a LayerV-minted link and stays a qurl-service concern; see
// tests/smoke/CLAUDE.md and qurl-service#1047.
func TestResolveV2_SDKRejectsBadLinks(t *testing.T) {
	ctx := context.Background()

	// Throwaway issuer + a trust store that trusts it. Not a production key —
	// generated per-run, used only to mint the well-formed links we then
	// tamper with.
	signer, err := qurl.GenerateLocalSigner("smoke-resolve-v2-issuer")
	if err != nil {
		t.Fatalf("GenerateLocalSigner (qurl-go SDK API drift?): %v", err)
	}
	issuerDER, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatalf("signer.PublicKeyDER: %v", err)
	}
	trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{signer.KID(): issuerDER})
	if err != nil {
		t.Fatalf("NewTrustStoreFromDER: %v", err)
	}
	// A trust store that holds a DIFFERENT issuer (the SDK rejects an empty
	// one) — our link's kid is absent from it, so it stands in for "untrusted
	// issuer".
	otherSigner, err := qurl.GenerateLocalSigner("smoke-resolve-v2-other-issuer")
	if err != nil {
		t.Fatalf("GenerateLocalSigner(other): %v", err)
	}
	otherDER, err := otherSigner.PublicKeyDER()
	if err != nil {
		t.Fatalf("otherSigner.PublicKeyDER: %v", err)
	}
	untrusted, err := qurl.NewTrustStoreFromDER(map[string][]byte{otherSigner.KID(): otherDER})
	if err != nil {
		t.Fatalf("NewTrustStoreFromDER(other): %v", err)
	}

	link := mintSmokeQurlLink(ctx, t, signer, "smoke-resolve-v2-0001")

	// Positive control: the SDK's symmetry guarantee must hold, otherwise the
	// negative assertions below are meaningless (a parser that rejects
	// everything trivially "fails closed").
	if _, err := qurl.VerifyLink(link, trust); err != nil {
		t.Fatalf("VerifyLink on a freshly-minted, trusted link failed — qurl-go symmetry guarantee broken: %v", err)
	}

	base, parts := splitSmokeQurlLink(t, link) // base = "...#", parts = [qv2, claims, secret, sig]

	// Structural / parse-level rejections. Each must fail closed; we assert
	// err != nil rather than a specific sentinel because the strict parser
	// fans these across several distinct errors and the contract that matters
	// is "rejected", not "rejected with this exact error".
	//
	// These shapes are coupled to the pinned qurl-go wire format (a "qv2."
	// prefix + 4 dot-parts, each unpadded base64url). That coupling is the
	// point of a version-pinned tripwire — but note non_canonical_base64_claims
	// specifically relies on the parser using RawURLEncoding: appending "="
	// proves non-canonical-encoding rejection only while padding is illegal. If
	// a future qurl-go accepted padded base64, that subcase would still be
	// rejected (the padded claims no longer match the signed bytes → signature
	// failure), just for a different reason — revisit it on a wire-format bump.
	malformed := []struct{ name, link string }{
		{"not_a_qurl_link", "https://qurl.link/"},
		{"empty_fragment", "https://qurl.link/#"},
		{"wrong_version_prefix", base + "qv1." + parts[1] + "." + parts[2] + "." + parts[3]},
		{"too_few_parts", base + parts[0] + "." + parts[1] + "." + parts[2]},
		{"empty_claims_part", base + parts[0] + ".." + parts[2] + "." + parts[3]},
		{"non_canonical_base64_claims", base + parts[0] + "." + parts[1] + "=." + parts[2] + "." + parts[3]},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := qurl.VerifyLink(tc.link, trust); err == nil {
				t.Fatalf("VerifyLink(%q) accepted a malformed link, want rejection", tc.link)
			}
		})
	}

	// Untrusted issuer: a well-formed, validly-signed link whose kid is not in
	// the trust store must fail closed.
	t.Run("untrusted_issuer", func(t *testing.T) {
		if _, err := qurl.VerifyLink(link, untrusted); err == nil {
			t.Fatal("VerifyLink accepted a link signed by an untrusted issuer, want rejection")
		}
	})

	// Tamper: graft a second link's (structurally valid, low-S, correct-length)
	// issuer signature onto the first link's claims. The signature is sound but
	// signed over different claims, so it must fail ECDSA verification with
	// ErrSignature specifically — the crypto-heart assertion that the parser
	// isn't merely shape-checking.
	link2 := mintSmokeQurlLink(ctx, t, signer, "smoke-resolve-v2-0002")
	_, parts2 := splitSmokeQurlLink(t, link2)
	spliced := base + strings.Join([]string{parts[0], parts[1], parts[2], parts2[3]}, ".")
	t.Run("claims_signature_mismatch", func(t *testing.T) {
		_, err := qurl.VerifyLink(spliced, trust)
		if !errors.Is(err, qurl.ErrSignature) {
			t.Fatalf("VerifyLink on a claims/signature-mismatched link: got err=%v, want errors.Is(..., qurl.ErrSignature)", err)
		}
	})
}

// mintSmokeQurlLink mints a well-formed qURL v2 link with the given throwaway
// issuer and jti via the SDK's offline CreatePortalWithParams seam. The cell /
// resource / per-link key material is synthetic — the link is never knocked,
// only parsed and signature-verified — but it is shaped exactly as the strict
// parser requires so the only thing under test is the rejection behavior the
// caller induces.
func mintSmokeQurlLink(ctx context.Context, t *testing.T, signer qurl.Signer, jti string) string {
	t.Helper()
	resourceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate resource key: %v", err)
	}
	resourceDER, err := x509.MarshalPKIXPublicKey(&resourceKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal resource key DER: %v", err)
	}
	// x25519 public key is 32 bytes; any 32 bytes is a well-formed WIRE value
	// (not necessarily a valid curve point — fine here because the link is only
	// parsed + signature-verified, never knocked, so no ECDH runs). Don't
	// repurpose mintSmokeQurlLink for a real-knock path without a real key.
	cellKey := make([]byte, 32)
	if _, err := rand.Read(cellKey); err != nil {
		t.Fatalf("read cell key bytes: %v", err)
	}
	now := time.Now().Unix()
	link, err := qurl.CreatePortalWithParams(ctx, signer, qurl.CreateParams{
		CellPublicKey:     cellKey,
		RelayURL:          "https://relay.qurl.link.layerv.xyz",
		ResourcePublicKey: resourceDER,
		JTI:               jti,
		IssuedAt:          now - 60,
		NotBefore:         now - 60,
		Expiry:            now + 3600,
	})
	if err != nil {
		t.Fatalf("CreatePortalWithParams (qurl-go SDK API drift?): %v", err)
	}
	return link
}

// splitSmokeQurlLink splits a minted qURL link into its base ("scheme://host/#")
// and its four dot-separated fragment parts [version, claims, secret, sig].
func splitSmokeQurlLink(t *testing.T, link string) (base string, parts []string) {
	t.Helper()
	i := strings.IndexByte(link, '#')
	if i < 0 {
		t.Fatalf("minted qURL link has no '#' fragment: %q", link)
	}
	base = link[:i+1]
	parts = strings.Split(link[i+1:], ".")
	if len(parts) != 4 {
		t.Fatalf("minted qURL fragment has %d dot-parts, want 4 (qv2.claims.secret.sig): %q", len(parts), link)
	}
	return base, parts
}
