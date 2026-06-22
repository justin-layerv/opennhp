package qurlv2

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// Key-binding comparison helpers for the admission path.
//
// qURL v2 claim key fields are unpadded base64url (the single pinned wire
// encoding for the whole artifact — see claims.go). But two of the values the
// NHP server must bind them against arrive in a DIFFERENT encoding:
//
//   - the Noise-authenticated agent public key (req.PublicKey) and the server's
//     own static/cell public key (device.PublicKeyBase64) are STANDARD base64
//     (padded) in nhp;
//   - the knock resource identity is whatever the js-agent puts in ResourceId.
//
// Comparing the two as STRINGS would silently mis-fire across the
// base64url-vs-std-base64 and padded-vs-unpadded gap (the same 32 bytes encode to
// different strings). So every binding check decodes BOTH sides to raw bytes and
// compares the bytes. These helpers centralize that so no call site re-derives a
// string compare. (Design "Encoding notes": pin one encoding; "base64 or
// base64url" is itself a canonicalization hazard.)

// ErrKeyMatch is returned when a claim key does not bind the value it must equal
// (cell key, proof-of-possession agent key, or resource identity). It is distinct
// from the parse/signature sentinels so admission can attribute a binding failure
// separately from a malformed or unsigned claim.
var ErrKeyMatch = fmt.Errorf("qurlv2: key binding mismatch")

// decodeStdOrRawStd decodes a standard-base64 value, accepting both the padded
// and unpadded forms. nhp emits padded std-base64 for static keys, but accepting
// the unpadded std variant too costs nothing and avoids a brittle dependency on
// which std flavor a caller happens to hold.
func decodeStdOrRawStd(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// ClaimKeyMatchesStdB64 reports whether a claim's base64url key field (claimB64)
// and a standard-base64 key string (stdB64) decode to the SAME raw bytes. It is
// the cross-encoding binding check for the cell-key and proof-of-possession
// checks: claimB64 is from the signed claims (base64url), stdB64 is from nhp
// (device.PublicKeyBase64 / req.PublicKey, std-base64).
//
// It returns ErrKeyMatch (not just false) so a caller can wrap it with binding
// context, and an encoding error if either input is not decodable under its
// expected encoding — a non-decodable side is a mismatch, never a silent pass.
// The final byte compare is constant-time; these are public-key values (not
// secrets), but a constant-time compare here costs nothing and keeps the binding
// check uniform with the rest of the crypto core.
func ClaimKeyMatchesStdB64(claimB64, stdB64 string) error {
	claimRaw, err := decodeB64(claimB64)
	if err != nil {
		return fmt.Errorf("%w: claim key not valid base64url: %w", ErrKeyMatch, err)
	}
	stdRaw, err := decodeStdOrRawStd(stdB64)
	if err != nil {
		return fmt.Errorf("%w: comparand key not valid base64: %w", ErrKeyMatch, err)
	}
	if subtle.ConstantTimeCompare(claimRaw, stdRaw) != 1 {
		return ErrKeyMatch
	}
	return nil
}

// ClaimResourceKeyMatches reports whether a claim's resource_public_key_b64
// (base64url) and the knock's resource-identity string (resID) bind the same
// resource. Per the design, the qURL v2 knock resource identity IS the protected
// resource public key, carried in the SAME pinned encoding as the claim:
// canonical unpadded base64url. So this is a base64url-vs-base64url comparison,
// and the effective client-side contract is "canonical unpadded base64url on both
// sides."
//
// Unlike ClaimKeyMatchesStdB64 (which bridges base64url and std-base64), the
// byte-compare here does NOT add robustness over a string compare: both sides go
// through the strict decoder, which rejects padding and non-canonical trailing
// bits outright, so a non-canonical or std-base64 resID errors to a mismatch
// rather than decoding to equal bytes. The decode is retained so a non-decodable
// resID is a mismatch (never a silent pass) and so the two binding helpers read
// uniformly — not because it normalizes encodings. (TestAuthWithNHPClaims_
// ResourceIDEncodingContract pins this: a std-base64 resID fails closed.)
func ClaimResourceKeyMatches(claimB64, resID string) error {
	claimRaw, err := decodeB64(claimB64)
	if err != nil {
		return fmt.Errorf("%w: claim resource key not valid base64url: %w", ErrKeyMatch, err)
	}
	resRaw, err := decodeB64(resID)
	if err != nil {
		return fmt.Errorf("%w: knock resource identity not valid base64url: %w", ErrKeyMatch, err)
	}
	if subtle.ConstantTimeCompare(claimRaw, resRaw) != 1 {
		return ErrKeyMatch
	}
	return nil
}
