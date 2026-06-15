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

// The renewal scheduler (#2208 PR-5d): keep an open grant alive by re-knocking
// before the access duration expires, with foreground recovery for backgrounded
// tabs.
export { startRenewal } from "./agent/scheduler.js";
export type {
  RenewalHandlers,
  RenewalController,
  RenewalOptions,
} from "./agent/scheduler.js";
