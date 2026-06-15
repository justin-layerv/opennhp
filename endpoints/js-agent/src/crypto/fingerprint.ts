// `sha2` is the stable entry point (the per-algorithm `sha256` subpath was
// removed in @noble/hashes 2.0). v2 requires the explicit `.js` extension on
// subpath imports — its `exports` map no longer exposes the extensionless form.
import { sha256 } from "@noble/hashes/sha2.js";

/**
 * Length of a pubkey fingerprint string: base64url (no padding) of the first 8
 * bytes of SHA-256 = 11 characters. Mirrors Go `utils.PubKeyFingerprintLen`.
 */
export const PUBKEY_FINGERPRINT_LEN = 11;

/**
 * Derives the relay routing id for a cell server's NHP static public key:
 * `base64url(SHA-256(rawPubKey)[0:8])` with no padding.
 *
 * This is the `{serverId}` in `POST /relay/{serverId}` — the browser agent and
 * the Go relay/server MUST produce the SAME string, so this is byte-for-byte
 * compatible with Go `utils.PubKeyFingerprint` (`nhp/utils/crypto.go`). The
 * golden vectors in `test/fingerprint.test.ts` are kept identical, by hand, to
 * the Go test's (`nhp/utils/crypto_fingerprint_test.go`); each suite pins its
 * own implementation to the same constants (CI runs them independently and does
 * not cross-check the two), so an algorithm change must update both files.
 *
 * NOT an authentication token — it is collision-resistant addressing only (a
 * full SHA-256 is truncated to 8 bytes). Authentication is the outer Noise IK
 * handshake. Same contract and caveat as the Go side.
 */
export function pubKeyFingerprint(rawPubKey: Uint8Array): string {
  const digest = sha256(rawPubKey);
  return base64UrlNoPad(digest.subarray(0, 8));
}

/**
 * base64url without padding (RFC 4648 §5), matching Go's
 * `base64.RawURLEncoding`. Uses the standard alphabet via btoa, then maps
 * `+`→`-`, `/`→`_`, and strips `=` padding.
 */
function base64UrlNoPad(bytes: Uint8Array): string {
  let bin = "";
  for (const byte of bytes) {
    bin += String.fromCharCode(byte);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
