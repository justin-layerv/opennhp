import { HashType, createChainHash, HASH_SIZE } from "./hash.js";
import { mixKey, keyGen2 } from "./kdf.js";
import { x25519PublicKey, x25519SharedSecret } from "./dh.js";
import { aeadOpen } from "./aead.js";
import { equalBytes } from "@noble/ciphers/utils.js";
import {
  HEADER_SIZE,
  HEADER_COMMON_SIZE,
  PACKET_BUFFER_SIZE,
  OFF_EPHEMERAL,
  OFF_STATIC,
  OFF_TIMESTAMP,
  OFF_DIGEST,
  PUBLIC_KEY_SIZE,
  GCM_TAG_SIZE,
  TIMESTAMP_SIZE,
  INITIAL_HASH,
  INITIAL_CHAIN_KEY,
  NHP_FLAG_COMPRESS,
  PROTOCOL_VERSION_MAJOR,
  MIN_PROTOCOL_VERSION_MINOR,
  getTypeAndPayloadSize,
  getCounter,
  getFlag,
  getVersion,
  nonceForCounter,
  headerDigest,
} from "./packet.js";

const STATIC_FIELD_SIZE = PUBLIC_KEY_SIZE + GCM_TAG_SIZE; // sealed device pubkey + tag
const TIMESTAMP_FIELD_SIZE = TIMESTAMP_SIZE + GCM_TAG_SIZE; // sealed timestamp + tag

/** The decrypted result of a server reply to a knock (NHP_ACK / NHP_COK). */
export interface DecryptedReply {
  /** Header type — NHP_ACK (knock result) or NHP_COK (re-knock cookie). The
   * caller must reject any other (authenticated) type: `decryptReply` decrypts
   * and authenticates but does not dispatch, leaving that to the PR-5 loop. */
  headerType: number;
  /** Header counter / transaction id. Server replies echo the outstanding
   * knock's counter here, so consumers can correlate without re-parsing the
   * packet header. */
  counter: bigint;
  /** The server static public key recovered from the packet — verified to equal
   * the expected one. This pins the server identity; the `ss`-keyed opens (below)
   * complete the authentication. */
  serverStaticPub: Uint8Array;
  /** The server's send time, nanoseconds. */
  timestampNanos: bigint;
  /** The decrypted (and, if flagged, inflated) body — a JSON message such as
   * `ServerKnockAckMsg` or `ServerCookieMsg`, for the caller to parse by type. */
  body: Uint8Array;
}

/**
 * Inflate a Go `compress/zlib` (RFC 1950) stream via the native
 * DecompressionStream — `"deflate"` is the zlib-wrapped format, matching Go's
 * `zlib.Writer`. No zlib dependency; async because the Web API streams.
 *
 * No explicit *output* cap (Go uses `MaxDecompressedBodySize`), but the input is
 * doubly contained: `decryptReply`'s `PACKET_BUFFER_SIZE` guard bounds these bytes
 * (mirroring Go's `PacketBufferSize` transport cap), and the body is inflated only
 * *after* its AEAD tag verifies under a key derived from the sender's proven static
 * key — so the input is both size-bounded and in-TCB (the exact server this agent
 * knocked), not attacker-chosen. A bomb would require that server to attack its own
 * client, from ≤ one buffer of input.
 */
async function inflateZlib(compressed: Uint8Array): Promise<Uint8Array> {
  // Copy into a fresh ArrayBuffer-backed view: the AEAD output may alias a
  // larger/shared buffer, which BlobPart's type rejects. The body is tiny.
  const stream = new Blob([new Uint8Array(compressed)])
    .stream()
    .pipeThrough(new DecompressionStream("deflate"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Decrypts a server reply to a knock (the NHP_ACK / NHP_COK the relay returns).
 * This is the responder side of the Noise handshake, mirroring Go `responder.go`
 * (`createPacketParserData → validatePeer → decryptBody`) from the agent's
 * perspective — the server is the initiator of this fresh handshake (its
 * ChainHash/ChainKey and ephemeral are re-derived per packet).
 *
 * `expectedServerStaticPub` is the static key of the server this agent knocked.
 * Recovering the sealed static key and asserting it equals this value *pins* the
 * server identity, but is necessary — not sufficient — on its own: an on-path
 * attacker who chooses `serverEph` can compute `es = DH(serverEph, agentPub)` and
 * seal any static value (even the real server's) into the static field, so the
 * equality alone is forgeable. Authentication *completes* at the `ss`-keyed
 * timestamp/body opens below: `ss = DH(agentPriv, serverStaticPub)` requires the
 * server's static *private* key, which the attacker lacks — so a valid AEAD tag
 * there is what proves the reply came from that server. (The header digest is
 * integrity-only, not auth — all its inputs are public; see packet.ts.) The
 * browser is not a server, so the server-side replay / flood / staleness gates
 * and the peer-pool lookup are intentionally not ported.
 *
 * Throws if the header digest, either header AEAD tag, the server-key check, or
 * a present body AEAD tag fails — staged in that order, which also localizes a
 * drift. A zero-length body carries no body tag to open; dispatchers decide
 * whether that is valid for the authenticated reply type.
 */
export async function decryptReply(
  devicePriv: Uint8Array,
  expectedServerStaticPub: Uint8Array,
  packet: Uint8Array,
): Promise<DecryptedReply> {
  if (packet.length < HEADER_SIZE) {
    throw new Error(
      `reply too short: ${packet.length} bytes < ${HEADER_SIZE}-byte header`,
    );
  }
  // Upper bound mirrors Go's structural cap — the server reads packets into a
  // fixed `[PacketBufferSize]byte` (device.go), so nothing valid exceeds it.
  // Bounding the input here (before any DH/AEAD work) also bounds the body the
  // AEAD opens and the bytes `inflateZlib` can be handed, closing a
  // CPU/memory-amplification path with a single comparison.
  if (packet.length > PACKET_BUFFER_SIZE) {
    throw new Error(
      `reply too long: ${packet.length} bytes > ${PACKET_BUFFER_SIZE}-byte buffer`,
    );
  }
  // Version gate, ahead of every key agreement. A server still speaking 1.0 does
  // not fold HeaderCommon into the body AAD, so its body tag can never verify
  // here; saying so beats the opaque AEAD failure it would otherwise produce.
  const { major, minor } = getVersion(packet);
  if (major !== PROTOCOL_VERSION_MAJOR || minor < MIN_PROTOCOL_VERSION_MINOR) {
    throw new Error(
      `unsupported NHP protocol version ${major}.${minor}, want ${PROTOCOL_VERSION_MAJOR}.${MIN_PROTOCOL_VERSION_MINOR} or a later minor`,
    );
  }
  const header = packet.subarray(0, HEADER_SIZE);
  const sealedBody = packet.subarray(HEADER_SIZE);
  const T = HashType.BLAKE2S;

  // The agent's own static pubkey is the responder static that the header digest
  // and ChainHash1 bind (the server's RemotePubKey when it built the reply).
  const agentPub = x25519PublicKey(devicePriv);

  if (
    !equalBytes(
      headerDigest(agentPub, header),
      header.subarray(OFF_DIGEST, OFF_DIGEST + HASH_SIZE),
    )
  ) {
    throw new Error(
      "reply header digest mismatch (tampered, or wrong device key)",
    );
  }

  const counter = getCounter(header);
  const nonce = nonceForCounter(counter);
  const serverEph = header.subarray(
    OFF_EPHEMERAL,
    OFF_EPHEMERAL + PUBLIC_KEY_SIZE,
  );
  const staticField = header.subarray(
    OFF_STATIC,
    OFF_STATIC + STATIC_FIELD_SIZE,
  );
  const tsField = header.subarray(
    OFF_TIMESTAMP,
    OFF_TIMESTAMP + TIMESTAMP_FIELD_SIZE,
  );

  // ChainHash0/ChainKey0, then fold agentPub + serverEph → ChainHash1/ChainKey1.
  const chainHash = createChainHash(T);
  chainHash.update(INITIAL_HASH);
  let chainKey = mixKey(T, chainHash.sum(), INITIAL_CHAIN_KEY);
  chainHash.update(agentPub);
  chainHash.update(serverEph);
  chainKey = mixKey(T, chainKey, serverEph);

  // es = DH(agentPriv, serverEph): open the server's static key (AAD = ChainHash1).
  let aeadKey: Uint8Array;
  [chainKey, aeadKey] = keyGen2(
    T,
    chainKey,
    x25519SharedSecret(devicePriv, serverEph),
  );
  const serverStaticPub = aeadOpen(
    aeadKey,
    nonce,
    staticField,
    chainHash.sum(),
  );
  // Pins the server identity — necessary but not the authenticator (see doc): the
  // ss-keyed open below is what proves possession of the server's static key.
  if (!equalBytes(serverStaticPub, expectedServerStaticPub)) {
    throw new Error("reply from an unexpected server (static key mismatch)");
  }
  chainHash.update(staticField);

  // ss = DH(agentPriv, serverStatic): only the real server can derive this, so a
  // valid open here authenticates the reply. Opens the timestamp (AAD = ChainHash2).
  [chainKey, aeadKey] = keyGen2(
    T,
    chainKey,
    x25519SharedSecret(devicePriv, serverStaticPub),
  );
  const tsBytes = aeadOpen(aeadKey, nonce, tsField, chainHash.sum());
  const timestampNanos = new DataView(
    tsBytes.buffer,
    tsBytes.byteOffset,
    tsBytes.byteLength,
  ).getBigUint64(0, false);
  chainHash.update(tsField);

  // ChainHash3 -> ChainHash4: fold the HeaderCommon exactly as received, so the
  // body tag verifies only against the header the server sealed under. Editing
  // the flag word, the type, the declared size, the preamble or the version in
  // flight now breaks the open below; under 1.0 all of them were forgeable by
  // anyone holding this agent's static PUBLIC key. A zero-length body carries no
  // tag, so that one case is still covered only by the unkeyed digest — the
  // dispatcher's type gate is what contains it.
  chainHash.update(header.subarray(0, HEADER_COMMON_SIZE));
  const bodyAad = chainHash.sum();
  const bodyKey = keyGen2(T, chainKey, tsField)[1];
  let body =
    sealedBody.length === 0
      ? new Uint8Array(0)
      : aeadOpen(bodyKey, nonce, sealedBody, bodyAad);

  if (body.length > 0 && (getFlag(header) & NHP_FLAG_COMPRESS) !== 0) {
    body = await inflateZlib(body);
  }

  return {
    headerType: getTypeAndPayloadSize(header).type,
    counter,
    serverStaticPub,
    timestampNanos,
    body,
  };
}
