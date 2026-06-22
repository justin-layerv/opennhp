package qurlv2

// Claims-only verification entrypoint for the qURL v2 admission path.
//
// The NHP Server Contract's prepare request carries `qurl_claims_b64` and
// `qurl_issuer_sig_b64` as two SEPARATE blobs and NO secret part — the per-qURL
// private key never leaves the browser/headless client. The full-fragment
// helpers (ParseFragment / ParseAndVerify) require all four wire parts
// (`qv2.<claims>.<secret>.<sig>`) and parseSecret rejects anything that is not a
// real 32-byte private key, so admission cannot reuse them: it has no secret to
// supply and must not synthesize one.
//
// VerifyClaims is the additive entrypoint for that path. It does exactly two
// things, in the security-critical order:
//
//  1. resolve the claim's kid in the trust store and verify the issuer signature
//     over the EXACT base64url claims bytes received on the wire (never over a
//     re-serialization of the parsed struct), enforcing the pinned 64-byte /
//     low-S / in-range wire-signature contract; then
//  2. strict-parse the claims with the same allowlist profile the fragment path
//     uses (duplicate keys, unknown fields, null, wrong types, out-of-range or
//     non-integer times, wrong key lengths all rejected).
//
// It is the NHP server admission layer's INDEPENDENT verifier: even though
// qurl-service ALSO verifies the same claims in its prepare endpoint, NHP
// verifies here FIRST (before it ever calls prepare) and does not trust
// qurl-service's parse result (design: "Issuer verification is deliberately
// duplicated"). This is the Go-nhp leg of the same cross-impl contract
// qurl-service implements with the identical function name on its side.
//
// VerifyClaims is the ONLY entrypoint the nhp admission path uses from this
// package. The rest of the package (the full-fragment ParseFragment/
// ParseAndVerify/parseSecret path, ValidateRelayURL/RelayAllowlist, the vector
// helpers) is the deliberately-retained conformant copy of qurl-service's
// internal/qurlv2 verify side, kept for byte-for-byte cross-impl parity and
// exercised by the shared golden vectors — not dead code to wire in. Hardening
// the cross-repo drift story (and deciding whether to trim the unused subset) is
// tracked in layervai/nhp#2771.
//
// IMPORTANT — this is NOT a full admission gate, mirroring ParseAndVerify's
// contract. It establishes only that the issuer signed these exact claim bytes
// and that they are structurally well-formed. It does NOT enforce LIVENESS: a
// returned Claims can have an exp already in the past or an nbf still in the
// future, because this package has no trusted clock (the parser only checks the
// clock-free iat<=exp / nbf<=exp ordering bounds). The admission caller MUST
// itself reject expired/not-yet-valid claims against the current time with the
// agreed clock-skew allowance. See layervai/qurl-service#1002 and
// validateClaimValues in parse.go.

import "fmt"

// VerifyClaims strict-parses the wire claims bytes (claimsB64), verifies the
// issuer signature over those EXACT bytes, and returns the parsed Claims on
// success.
//
// Inputs are the two blobs from the prepare request:
//   - claimsB64: the unpadded-base64url claims string EXACTLY as received (Part 1
//     of a qURL v2 fragment). The signature is verified over this string
//     verbatim; it is never re-encoded.
//   - sigB64: the unpadded-base64url raw r||s issuer signature (Part 3).
//   - ts: the issuer trust store (kid -> P-256 public key).
//
// This mirrors the fragment path (ParseFragment + Fragment.Verify) exactly,
// minus the secret part: strict-parse to recover the structure (including kid),
// then resolve the key for that kid and verify the signature over the received
// bytes. Parsing first is safe and is what fragment.Verify already does — the
// signature is checked over the wire string, NOT over a re-serialization of the
// parsed struct, so a tampered or re-encoded claims blob fails the byte-exact
// signature check even though its JSON parsed. A re-serialized-but-semantically-
// equal claims object is rejected for the same reason: its bytes differ from the
// signed bytes.
func VerifyClaims(claimsB64, sigB64 string, ts *TrustStore) (*Claims, error) {
	if ts == nil {
		return nil, fmt.Errorf("%w: nil trust store", ErrSignature)
	}
	if claimsB64 == "" {
		return nil, fmt.Errorf("%w: claims part is empty", ErrFragment)
	}
	if sigB64 == "" {
		return nil, fmt.Errorf("%w: signature part is empty", ErrFragment)
	}

	// Decode the claims and signature bytes. decodeB64 is strict (unpadded,
	// canonical base64url), so the wire string and decoded bytes are in 1:1
	// correspondence — there is no canonicalization gap between "what was signed"
	// (the string) and "what we parse" (the bytes).
	claimsRaw, err := decodeB64(claimsB64)
	if err != nil {
		return nil, fmt.Errorf("claims part: %w", err)
	}
	rawSig, err := decodeB64(sigB64)
	if err != nil {
		return nil, fmt.Errorf("sig part: %w", err)
	}

	// Strict-parse to recover the claim set (and its kid). The signature is still
	// checked below over the exact wire bytes, never over a re-serialization of
	// this struct.
	claims, err := parseClaims(claimsRaw)
	if err != nil {
		return nil, err
	}

	pub, err := ts.publicKeyForKID(claims.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifyRawSignature(pub, claimsB64, rawSig); err != nil {
		return nil, err
	}
	return claims, nil
}
