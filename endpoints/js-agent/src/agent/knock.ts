import { buildKnock } from "../crypto/handshake.js";
import { NHP_KNK } from "../crypto/packet.js";

/**
 * Sources of per-knock randomness and time, injectable so tests can pin them.
 * Production uses the browser CSPRNG (`crypto.getRandomValues`) and wall clock.
 */
export interface KnockEntropy {
  /** Fill `out` with cryptographically-strong random bytes, in place. */
  randomBytes(out: Uint8Array): void;
  /** Now, in nanoseconds since the Unix epoch — Go's `time.Now().UnixNano()`. */
  nowNanos(): bigint;
}

/**
 * Production entropy: the browser CSPRNG and the wall clock.
 *
 * `nowNanos` has *millisecond* resolution (`Date.now()` scaled to ns), so two
 * knocks in the same millisecond carry identical timestamps. That is safe for the
 * server's replay/dedupe caches only because the per-knock random `counter` — not
 * the timestamp — disambiguates them there (they key on pubkey + counter +
 * timestamp). It does NOT cover the server's flood gate (`responder.go`
 * `MinimalRecvIntervalMs` = 20 ms), which keys on the timestamp alone: two knocks
 * < 20 ms apart on one connection are dropped as flood regardless of counter. The
 * renewal scheduler (PR-5d) is the first caller to fire closely-spaced knocks on a
 * stable identity, so it must space them well beyond 20 ms (legitimate renewals
 * are minutes apart) — millisecond time + a unique counter make same-ms knocks
 * *safe to dedupe*, not *safe to send back-to-back*.
 */
export const browserEntropy: KnockEntropy = {
  randomBytes: (out) => {
    crypto.getRandomValues(out);
  },
  nowNanos: () => BigInt(Date.now()) * 1_000_000n,
};

/** A built initial knock, plus the counter the loop correlates the reply against. */
export interface CreatedKnock {
  /** The wire packet to POST to the relay. */
  packet: Uint8Array;
  /**
   * The per-knock counter (transaction id). The server echoes it in the reply's
   * header counter, so the agent loop matches the ACK/COK back to this knock by
   * it — the basis for the anti-replay correlation tracked in #2603.
   */
  counter: bigint;
}

/** Go's `time.Now().UnixNano()` is a signed int64; a timestamp at or past 2^63
 * would wrap negative when the server reads it, so the field caps there. */
const MAX_UNIX_NANO = 2n ** 63n;

function randomU64(entropy: KnockEntropy): bigint {
  const b = new Uint8Array(8);
  entropy.randomBytes(b);
  return new DataView(b.buffer).getBigUint64(0, false);
}

function randomU32(entropy: KnockEntropy): number {
  const b = new Uint8Array(4);
  entropy.randomBytes(b);
  return new DataView(b.buffer).getUint32(0, false);
}

/**
 * Builds a production initial knock (`NHP_KNK`): the deterministic,
 * fixture-fenced `buildKnock` (crypto/handshake.ts) wrapped with the per-knock
 * values the agent loop randomises/stamps at runtime — a fresh CSPRNG ephemeral
 * key, transaction counter, and header preamble, plus the send timestamp. Each
 * knock therefore gets a distinct ephemeral and counter, so no GCM nonce repeats
 * across knocks (the counter drives the nonce; the ephemeral re-keys every seal).
 *
 * `body` is the already-serialized, uncompressed knock message (an
 * `AgentKnockMsg`); the caller owns serialization and must set its `headerType`
 * to `NHP_KNK` per the #1154 wire-vs-body invariant. The re-knock (`NHP_RKN`) and
 * the overload cookie-challenge are separate paths (later PRs); this builds only
 * the initial knock.
 *
 * `entropy` is injectable so tests can pin the random/clock inputs; production
 * defaults to {@link browserEntropy}.
 */
export function createKnock(
  deviceStaticPriv: Uint8Array,
  serverStaticPub: Uint8Array,
  body: Uint8Array,
  entropy: KnockEntropy = browserEntropy,
): CreatedKnock {
  const ephemeralPriv = new Uint8Array(32);
  entropy.randomBytes(ephemeralPriv);
  // A fresh CSPRNG counter per knock — a deliberate divergence from Go's
  // monotonic atomic (device.go). Any unique counter serves the #2603 reply
  // correlation (and the AEAD-sealed reply, not counter unpredictability, is what
  // authenticates it); random is chosen for privacy and statelessness — it avoids
  // leaking the device's lifetime transaction count / uptime that a monotonic
  // counter exposes, and needs no durable counter state across page loads. u64
  // collision is negligible; the server only echoes the counter, requiring no
  // monotonicity.
  const counter = randomU64(entropy);
  const preamble = randomU32(entropy);
  const timestampNanos = entropy.nowNanos();
  if (timestampNanos < 0n || timestampNanos >= MAX_UNIX_NANO) {
    // Fail loud rather than emit a timestamp the server reads as a negative
    // (wrapped) int64 and rejects as wildly stale.
    throw new Error(
      `knock timestamp ${timestampNanos} outside Go's int64 UnixNano range`,
    );
  }

  const packet = buildKnock({
    deviceStaticPriv,
    serverStaticPub,
    ephemeralPriv,
    timestampNanos,
    counter,
    preamble,
    headerType: NHP_KNK,
    body,
  });
  return { packet, counter };
}

/**
 * The two fields the qURL knock body must carry. The server's qURL path reads
 * only these: `authServiceId` routes the knock to the qURL plugin
 * (`FindAuthSvcProvider` rejects an empty one) and `resourceId` is the `r_` id the
 * plugin resolves and authorizes. The client IP comes from the relay-forwarded
 * source address, not the body, and the other `AgentKnockMsg` fields
 * (`usrId`/`devId`/…) are inert on this path, so the browser omits them.
 */
export interface KnockBodyParams {
  authServiceId: string;
  resourceId: string;
}

/**
 * Serializes the qURL knock body — Go `common.AgentKnockMsg` (`nhp/common/nhpmsg.go`).
 *
 * `headerType` is set to `NHP_KNK` here, *not* by the caller: per the #1154
 * invariant it must equal the wire header type, and the server's
 * `knock_headertype_gate` rejects a mismatch (and a legacy zero). Owning it here
 * means a caller cannot miswire the body-vs-wire type. The JSON field names
 * (`headerType`/`aspId`/`resId`) are pinned to Go's struct tags; a drift fails
 * the cross-language body fence.
 */
export function buildKnockBody(params: KnockBodyParams): Uint8Array {
  const msg = {
    headerType: NHP_KNK,
    aspId: params.authServiceId,
    resId: params.resourceId,
  };
  return new TextEncoder().encode(JSON.stringify(msg));
}
