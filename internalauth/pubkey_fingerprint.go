package internalauth

import (
	"crypto/sha256"
	"encoding/base64"
)

// Public-key fingerprinting for NHP-native agent registration.
//
// Why this lives here AND in nhp/utils (crypto.go PubKeyFingerprint): the
// external consumers of this module (qurl-service, qurl-reverse-tunnel-server)
// must derive the exact same short id for an agent/server static key that the
// nhp repo derives, and neither import direction is available — this module is
// deliberately pure stdlib (see the package doc) so it must not import nhp
// packages, and the nhp module does not depend on internalauth. Two copies of
// eleven characters' worth of derivation is the same trade this module already
// makes for HMAC canonicalization: keep the construction in the shared module
// and fence drift with a test. The lockstep test lives in the endpoints module
// (endpoints/relay/pubkey_fingerprint_lockstep_test.go), the only module that
// imports both implementations; the vector test in this module additionally
// pins the exact output bytes.

// PubKeyFingerprintLen is the length in characters of the short id produced
// by PubKeyFingerprint: base64url of the first 8 bytes of SHA-256
// (8 bytes → 11 base64url chars, unpadded).
const PubKeyFingerprintLen = 11

// PubKeyFingerprint returns a short, URL-safe identifier derived from a raw
// public key: base64url(SHA-256(rawPubKey)[:8]), 11 characters with no
// padding. The same public key always produces the same fingerprint, so every
// implementation (this module, nhp/utils, the TypeScript js-agent) can compute
// it independently.
//
// This is a stable routing/lookup identifier, not a security primitive. The
// 64-bit truncation gives a ~2^-64 collision probability for any given pair of
// distinct keys; a collision within a *set* of keys becomes likely only near
// ~2^32 keys (the birthday bound). Callers MUST NOT use it as an
// authentication token.
func PubKeyFingerprint(rawPubKey []byte) string {
	sum := sha256.Sum256(rawPubKey)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// PubKeyFingerprintFromBase64 is a convenience wrapper that decodes a
// standard-base64-encoded public key (the encoding NHP carries pubkeys in —
// TOML configs, NhpRegisterRequest.PublicKey, qurl-agent-keys rows) before
// hashing. Returns the fingerprint and any decode error. The decode error is
// returned unwrapped, matching the nhp/utils twin — fingerprinting is identity
// derivation, not an auth verdict, so the ErrInternalAuth sentinel does not
// apply.
func PubKeyFingerprintFromBase64(pubKeyBase64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return "", err
	}
	return PubKeyFingerprint(raw), nil
}
