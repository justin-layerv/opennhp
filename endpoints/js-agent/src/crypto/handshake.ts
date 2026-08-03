import { HashType, createChainHash } from "./hash.js";
import { mixKey, keyGen2 } from "./kdf.js";
import { x25519PublicKey, x25519SharedSecret } from "./dh.js";
import { aeadSeal } from "./aead.js";
import {
  HEADER_SIZE,
  HEADER_COMMON_SIZE,
  NHP_KNK,
  NHP_RKN,
  OFF_EPHEMERAL,
  OFF_STATIC,
  OFF_TIMESTAMP,
  OFF_DIGEST,
  TIMESTAMP_SIZE,
  GCM_TAG_SIZE,
  MAX_SEALED_BODY_SIZE,
  PROTOCOL_VERSION_MAJOR,
  PROTOCOL_VERSION_MINOR,
  INITIAL_HASH,
  INITIAL_CHAIN_KEY,
  nonceForCounter,
  setVersion,
  setCounter,
  setFlag,
  setTypeAndPayloadSize,
  headerDigest,
} from "./packet.js";

/**
 * Inputs to a single NHP knock. The caller owns every value the agent loop
 * would randomise/stamp at runtime — the ephemeral key, timestamp, counter, and
 * preamble — so the same inputs always produce the same bytes. That determinism
 * is what lets the cross-language fixture pin TS output and have Go decrypt it.
 */
export interface KnockInputs {
  /** Initiator (agent) static private key, 32 bytes. */
  deviceStaticPriv: Uint8Array;
  /** Responder (server) static public key, 32 bytes — the Noise `rs`. */
  serverStaticPub: Uint8Array;
  /** Per-knock ephemeral private key, 32 bytes. Random in production. */
  ephemeralPriv: Uint8Array;
  /** Send time in nanoseconds (Go `time.Now().UnixNano()`), as a uint64. */
  timestampNanos: bigint;
  /** Transaction id / counter, a uint64. */
  counter: bigint;
  /** HeaderCommon obfuscation preamble, a uint32. Random in production. */
  preamble: number;
  /** Header type — `NHP_KNK` for a first knock, `NHP_RKN` for a re-knock. */
  headerType: number;
  /** Body payload, already serialized and **uncompressed** (the browser never
   * sets `NHP_FLAG_COMPRESS`, so the server reads the body as-is). */
  body: Uint8Array;
  /** Server-issued cookie, for the `NHP_RKN` re-knock digest only. */
  cookie?: Uint8Array;
}

/**
 * Builds a complete NHP knock packet (240-byte header ‖ sealed body) that the Go
 * `nhp/core` responder decrypts. This mirrors the initiator transcript in
 * `nhp/core/initiator.go` (`createMsgAssemblerData` → `setPeerPublicKey` →
 * `encryptBody`) step-for-step: the responder folds the same material into its
 * chain hash/key in the same order, so every AEAD opens.
 *
 * The Identity field (offset 56–135) is left as 80 zero bytes — the knock path
 * never seals it, and the responder ignores it (it's only covered by the header
 * digest, which is computed over those same zeros here).
 */
export function buildKnock(inp: KnockInputs): Uint8Array {
  // Only the two knock header types are valid here — fail loud on a miswire.
  if (inp.headerType !== NHP_KNK && inp.headerType !== NHP_RKN) {
    throw new Error(
      `unsupported header type ${inp.headerType}: expected NHP_KNK or NHP_RKN`,
    );
  }
  // The server folds a cookie into the digest iff NHP_RKN (addHeaderDigest), so a
  // type/cookie mismatch here produces a digest it silently rejects. Catch it at
  // the source rather than as an opaque server-side rejection.
  if (inp.headerType === NHP_RKN && inp.cookie === undefined) {
    throw new Error("NHP_RKN re-knock requires a cookie");
  }
  if (inp.headerType === NHP_KNK && inp.cookie !== undefined) {
    throw new Error("NHP_KNK takes no cookie");
  }
  // Fixed cipher suite — the server's default CIPHER_SCHEME_CURVE: X25519 (DH),
  // AES-256-GCM (aeadSeal), BLAKE2s (T below). The knock carries no suite
  // selector, so this must match the server's default; a server configured for
  // the alternate ChaCha20-Poly1305 GcmType would fail to open these seals.
  const T = HashType.BLAKE2S;
  // One nonce per packet: 4 zero bytes ‖ counter. Each seal below uses it under
  // a *distinct* derived key, so there is no AES-GCM nonce reuse.
  const nonce = nonceForCounter(inp.counter);

  const ephemeralPub = x25519PublicKey(inp.ephemeralPriv);
  const deviceStaticPub = x25519PublicKey(inp.deviceStaticPriv);

  const header = new Uint8Array(HEADER_SIZE);
  header.set(ephemeralPub, OFF_EPHEMERAL); // -> e

  // ChainHash0 / ChainKey0 from the two NHP init constants.
  const chainHash = createChainHash(T);
  chainHash.update(INITIAL_HASH);
  let chainKey = mixKey(T, chainHash.sum(), INITIAL_CHAIN_KEY);

  // Fold in rs and e: ChainHash0 -> ChainHash1, ChainKey0 -> ChainKey1.
  chainHash.update(inp.serverStaticPub);
  chainHash.update(ephemeralPub);
  chainKey = mixKey(T, chainKey, ephemeralPub);

  // es = DH(e, rs): derive the static-encryption key and seal the device pubkey.
  // AAD is ChainHash1; the ciphertext then evolves ChainHash1 -> ChainHash2.
  const ess = x25519SharedSecret(inp.ephemeralPriv, inp.serverStaticPub);
  let aeadKey: Uint8Array;
  [chainKey, aeadKey] = keyGen2(T, chainKey, ess);
  const sealedStatic = aeadSeal(
    aeadKey,
    nonce,
    deviceStaticPub,
    chainHash.sum(),
  );
  header.set(sealedStatic, OFF_STATIC);
  chainHash.update(sealedStatic);

  // ss = DH(s, rs): derive the timestamp key and seal the send time.
  // AAD is ChainHash2; the ciphertext then evolves ChainHash2 -> ChainHash3.
  const ss = x25519SharedSecret(inp.deviceStaticPriv, inp.serverStaticPub);
  [chainKey, aeadKey] = keyGen2(T, chainKey, ss);
  const tsBytes = new Uint8Array(TIMESTAMP_SIZE);
  new DataView(tsBytes.buffer).setBigUint64(0, inp.timestampNanos, false);
  const sealedTs = aeadSeal(aeadKey, nonce, tsBytes, chainHash.sum());
  header.set(sealedTs, OFF_TIMESTAMP);
  chainHash.update(sealedTs);

  // Derive the body key from the ts ciphertext; this is the terminal derivation,
  // so the evolved chain key is discarded (unlike the es/ss steps above, whose
  // chain key feeds the next KeyGen2). The body AAD is deliberately NOT taken
  // yet — the chain hash still has to absorb the finalized HeaderCommon.
  [, aeadKey] = keyGen2(T, chainKey, sealedTs);
  // Empty body: skip the seal entirely (payload size 0), matching Go encryptBody.
  const payloadSize =
    inp.body.length === 0 ? 0 : inp.body.length + GCM_TAG_SIZE;
  if (payloadSize > MAX_SEALED_BODY_SIZE) {
    // Fail loud rather than emit a packet the server's fixed buffer rejects.
    throw new Error(
      `knock body too large: sealed ${payloadSize} bytes exceeds the ${MAX_SEALED_BODY_SIZE}-byte limit`,
    );
  }

  // HeaderCommon — all of it must be set before both the fold below and the
  // digest, which covers header[0:208]. Flag is 0: uncompressed, no extended
  // length. The payload size is only known here, which is why the header cannot
  // be finalized before the body is prepared.
  setVersion(header, PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR);
  setCounter(header, inp.counter);
  setFlag(header, 0);
  setTypeAndPayloadSize(header, inp.headerType, payloadSize, inp.preamble);

  // ChainHash3 -> ChainHash4: fold the serialized HeaderCommon so the body tag
  // authenticates preamble, type, payload size, version, flags and counter. The
  // body seal is the first AEAD that can carry them, and the responder folds the
  // same 24 bytes as received, so any in-flight edit breaks the open. Under 1.0
  // these fields were forgeable by anyone holding the server's static public key.
  chainHash.update(header.subarray(0, HEADER_COMMON_SIZE));
  const bodyAad = chainHash.sum();

  const sealedBody =
    payloadSize === 0
      ? new Uint8Array(0)
      : aeadSeal(aeadKey, nonce, inp.body, bodyAad);

  // Unkeyed header digest over header[0:208] (+ cookie for NHP_RKN).
  header.set(headerDigest(inp.serverStaticPub, header, inp.cookie), OFF_DIGEST);

  const packet = new Uint8Array(HEADER_SIZE + sealedBody.length);
  packet.set(header, 0);
  packet.set(sealedBody, HEADER_SIZE);
  return packet;
}
