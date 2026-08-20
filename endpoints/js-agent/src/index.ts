// Public API surface of the NHP browser agent (#2208). Grows as the crypto
// core, transport, and agent loop land (see README "PR sequence").
export {
  pubKeyFingerprint,
  PUBKEY_FINGERPRINT_LEN,
} from "./crypto/fingerprint.js";

// The agent loop (#2208 PR-5b): perform one qURL knock through the relay and get
// back a discriminated result to branch on. This is the entry the qurl.link page
// (PR-6) drives.
export { knock } from "./agent/loop.js";
// KnockSuccess is part of the public surface via RenewalHandlers.onRenewed below,
// so a PR-6 consumer writing that callback can name it from the package root.
export type { KnockRequest, KnockResult, KnockSuccess } from "./agent/loop.js";
export { RelayError } from "./agent/relay.js";
export {
  generateDeviceKeyPair,
  x25519KeyFromBase64,
  x25519KeyToBase64,
} from "./agent/keys.js";
export type { DeviceKeyPair, KeyPairEntropy } from "./agent/keys.js";

// The renewal scheduler (#2208 PR-5d): keep an open grant alive by re-knocking
// before the access duration expires, with foreground recovery for backgrounded
// tabs.
export { startRenewal } from "./agent/scheduler.js";
export type {
  RenewalHandlers,
  RenewalController,
  RenewalOptions,
} from "./agent/scheduler.js";

// qURL v2 client (keyed-identity bootstrap): decode the bounded `#qv2t1.…`
// share transport to the exact inner qv2 artifact, verify the issuer signature
// locally (mandatory — before acting on relay_url/cell key), validate relay_url,
// and knock through the relay using the per-qURL private key.
//
// The public surface is deliberately construct/call/catch only: the qurl.link page
// CALLS `knockQurlV2`, CONSTRUCTS a `TrustStore` + `RelayAllowlist`, and CATCHES
// the error bases it branches on. The strict parser, signature, and fragment
// internals stay package-private (tests import them by direct path) so the
// size-budgeted browser bundle exposes only what a consumer needs. Type exports
// are erased from the bundle, so they are free.
export { knockQurlV2 } from "./qurl/knock.js";
export type {
  QurlV2KnockOptions,
  QurlV2KnockBodyParams,
} from "./qurl/knock.js";
export type { Fragment } from "./qurl/fragment.js";
export { FragmentError } from "./qurl/fragment.js";
export { QurlV2TransportError } from "./qurl/transport.js";
export type { Claims, Secret } from "./qurl/claims.js";
// Parse/encoding/key-length failures can surface from knockQurlV2 (a malformed
// claims JSON, a wrong-length key, or non-canonical base64 in a part), so a
// consumer branching on error class can catch them too — not just FragmentError.
export { StrictParseError, KeyLengthError } from "./qurl/claims.js";
export { Base64UrlError } from "./qurl/base64url.js";
export { TrustStore, UnknownKidError } from "./qurl/truststore.js";
export type { EcPublicJwk } from "./qurl/truststore.js";
// The base SignatureError catches every signature failure (length/high-S/range
// subclasses extend it); a consumer branching on the class needs only the base.
export { SignatureError } from "./qurl/signature.js";
export { RelayAllowlist, RelayUrlError } from "./qurl/relay-url.js";
