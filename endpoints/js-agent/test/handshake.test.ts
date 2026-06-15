import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { buildKnock, type KnockInputs } from "../src/crypto/handshake";
import { x25519PublicKey } from "../src/crypto/dh";
import {
  NHP_KNK,
  NHP_RKN,
  HEADER_SIZE,
  GCM_TAG_SIZE,
  MAX_SEALED_BODY_SIZE,
  COOKIE_SIZE,
  getTypeAndPayloadSize,
  getCounter,
} from "../src/crypto/packet";
import { toHex, utf8 } from "./hex";

// The TS half of the cross-language fence. The committed fixture
// (test/testdata/knock.json) is the single source of truth: this suite asserts
// buildKnock(...) reproduces its bytes, and the Go responder test
// (nhp/core/js_agent_roundtrip_test.go) decrypts the same bytes and recovers the
// values below. Drift on either side fails that side's suite.
//
// The deterministic inputs MUST stay in lockstep with the fixture and the Go
// test. Regenerate the fixture (and the Go test's expectations) together if any
// input changes here.
const SERVER_PRIV = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const DEVICE_PRIV = Uint8Array.from({ length: 32 }, (_, i) => i + 0x41);
const EPHEMERAL_PRIV = Uint8Array.from({ length: 32 }, (_, i) => i + 0x81);
const BODY = utf8(JSON.stringify({ test: "js-agent knock" }));
const TIMESTAMP_NANOS = 1700000000000000000n;
const COUNTER = 1n;
const PREAMBLE = 0x11223344;

// Resolve relative to this test file (not the cwd) so the fixture loads
// regardless of where vitest is invoked from — matching the Go side's intent.
const fixture = JSON.parse(
  readFileSync(new URL("./testdata/knock.json", import.meta.url), "utf8"),
) as {
  serverStaticPubHex: string;
  deviceStaticPubHex: string;
  bodyHex: string;
  packetHex: string;
};

function knock(overrides: Partial<KnockInputs> = {}): Uint8Array {
  return buildKnock({
    deviceStaticPriv: DEVICE_PRIV,
    serverStaticPub: x25519PublicKey(SERVER_PRIV),
    ephemeralPriv: EPHEMERAL_PRIV,
    timestampNanos: TIMESTAMP_NANOS,
    counter: COUNTER,
    preamble: PREAMBLE,
    headerType: NHP_KNK,
    body: BODY,
    ...overrides,
  });
}

describe("NHP knock handshake (cross-language fixture)", () => {
  it("reproduces the committed knock bytes the Go responder decrypts", () => {
    expect(toHex(knock())).toBe(fixture.packetHex);
  });

  it("derives the pubkeys + body recorded in the fixture", () => {
    expect(toHex(x25519PublicKey(SERVER_PRIV))).toBe(fixture.serverStaticPubHex);
    expect(toHex(x25519PublicKey(DEVICE_PRIV))).toBe(fixture.deviceStaticPubHex);
    expect(toHex(BODY)).toBe(fixture.bodyHex);
  });

  it("frames the packet as a 240-byte header + sealed body with a decodable HeaderCommon", () => {
    const pkt = knock();
    expect(pkt.length).toBe(HEADER_SIZE + BODY.length + GCM_TAG_SIZE);
    expect(getTypeAndPayloadSize(pkt)).toEqual({ type: NHP_KNK, size: BODY.length + GCM_TAG_SIZE });
    expect(getCounter(pkt)).toBe(COUNTER);
  });

  it("frames an empty body as a header-only packet (size 0, no body seal)", () => {
    // Mirrors Go encryptBody's empty-body branch (skip the seal, payload size 0).
    // A knock always carries a body, but the agent loop may emit a bodyless
    // re-knock, so the framing path is worth pinning even without a Go fixture.
    const pkt = knock({ body: new Uint8Array(0) });
    expect(pkt.length).toBe(HEADER_SIZE);
    expect(getTypeAndPayloadSize(pkt)).toEqual({ type: NHP_KNK, size: 0 });
  });

  it("rejects a body that overflows the server's payload buffer", () => {
    // A body of MAX_SEALED_BODY_SIZE bytes seals to MAX_SEALED_BODY_SIZE + tag — just over
    // the limit — so buildKnock throws instead of silently truncating the frame.
    expect(() => knock({ body: new Uint8Array(MAX_SEALED_BODY_SIZE) })).toThrow();
  });

  it("enforces the cookie / header-type invariant", () => {
    // The server folds a cookie into the digest iff NHP_RKN, so buildKnock rejects
    // a type/cookie mismatch up front rather than emitting a server-rejected digest.
    expect(() => knock({ headerType: NHP_RKN })).toThrow(); // RKN needs a cookie
    expect(() => knock({ cookie: new Uint8Array(COOKIE_SIZE) })).toThrow(); // KNK takes none
  });

  it("produces distinct nonces across counters (no knock/re-knock nonce reuse)", () => {
    // The nonce is derived from the counter, so a fresh counter per knock yields
    // a fresh nonce. The deeper guarantee is the per-knock ephemeral: it re-keys
    // the whole chain (including the constant-ss timestamp seal), so even a
    // counter collision across two knocks would not reuse an AES-GCM (key, nonce)
    // pair. This test pins the counter half — HeaderCommon[16:24] must differ.
    expect(toHex(knock({ counter: 1n }).subarray(16, 24))).not.toBe(
      toHex(knock({ counter: 2n }).subarray(16, 24)),
    );
  });
});
