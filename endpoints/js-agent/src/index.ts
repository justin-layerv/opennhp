// Public API surface of the NHP browser agent (#2208). Grows as the crypto
// core, transport, and agent loop land (see README "PR sequence").
export {
  pubKeyFingerprint,
  PUBKEY_FINGERPRINT_LEN,
} from "./crypto/fingerprint";

// The agent loop (#2208 PR-5b): perform one qURL knock through the relay and get
// back a discriminated result to branch on. This is the entry the qurl.link page
// (PR-6) drives.
export { knock } from "./agent/loop";
export type { KnockRequest, KnockResult } from "./agent/loop";
export { RelayError } from "./agent/relay";
