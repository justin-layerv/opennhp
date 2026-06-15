import { describe, it, expect } from "vitest";
import { createKnock, browserEntropy } from "../src/agent/knock";
import { buildKnock } from "../src/crypto/handshake";
import { x25519PublicKey } from "../src/crypto/dh";
import {
  NHP_KNK,
  HEADER_SIZE,
  OFF_EPHEMERAL,
  PUBLIC_KEY_SIZE,
  nonceForCounter,
  getCounter,
  getTypeAndPayloadSize,
} from "../src/crypto/packet";
import { toHex, fromHex, utf8 } from "./hex";
import { fixedEntropy } from "./entropy";

const DEVICE_PRIV = fromHex("41".repeat(32));
const SERVER_PUB = x25519PublicKey(fromHex("01".repeat(32)));
const BODY = utf8(JSON.stringify({ headerType: NHP_KNK, resId: "r_jsagent" }));

const header = (p: Uint8Array) => p.subarray(0, HEADER_SIZE);

describe("createKnock (production NHP_KNK builder)", () => {
  it("wires buildKnock with the randomised inputs (deterministic, injected entropy)", () => {
    const eph = fromHex("aa".repeat(32));
    const counterBytes = fromHex("0011223344556677");
    const preambleBytes = fromHex("89abcdef");
    const ts = 1_700_000_000_000_000_000n;

    const created = createKnock(
      DEVICE_PRIV,
      SERVER_PUB,
      BODY,
      fixedEntropy([eph, counterBytes, preambleBytes], ts),
    );

    const expected = buildKnock({
      deviceStaticPriv: DEVICE_PRIV,
      serverStaticPub: SERVER_PUB,
      ephemeralPriv: eph,
      timestampNanos: ts,
      counter: 0x0011223344556677n,
      preamble: 0x89abcdef,
      headerType: NHP_KNK,
      body: BODY,
    });

    expect(toHex(created.packet)).toBe(toHex(expected));
    // the returned counter is the one on the wire, for reply correlation
    expect(created.counter).toBe(0x0011223344556677n);
    expect(getCounter(header(created.packet))).toBe(created.counter);
    expect(getTypeAndPayloadSize(header(created.packet)).type).toBe(NHP_KNK);
  });

  it("uses a fresh CSPRNG ephemeral each knock", () => {
    const a = createKnock(DEVICE_PRIV, SERVER_PUB, BODY);
    const b = createKnock(DEVICE_PRIV, SERVER_PUB, BODY);
    expect(toHex(a.packet)).not.toBe(toHex(b.packet));
    const ephA = header(a.packet).subarray(
      OFF_EPHEMERAL,
      OFF_EPHEMERAL + PUBLIC_KEY_SIZE,
    );
    const ephB = header(b.packet).subarray(
      OFF_EPHEMERAL,
      OFF_EPHEMERAL + PUBLIC_KEY_SIZE,
    );
    expect(toHex(ephA)).not.toBe(toHex(ephB));
  });

  it("uses a unique counter — and therefore a distinct nonce — per knock", () => {
    const a = createKnock(DEVICE_PRIV, SERVER_PUB, BODY);
    const b = createKnock(DEVICE_PRIV, SERVER_PUB, BODY);
    expect(a.counter).not.toBe(b.counter);
    expect(toHex(nonceForCounter(a.counter))).not.toBe(
      toHex(nonceForCounter(b.counter)),
    );
  });

  it("rejects a timestamp outside Go's int64 UnixNano range (both bounds)", () => {
    const chunks = [
      fromHex("aa".repeat(32)),
      fromHex("0011223344556677"),
      fromHex("89abcdef"),
    ];
    // at/above the signed-int64 ceiling, and below zero
    expect(() =>
      createKnock(
        DEVICE_PRIV,
        SERVER_PUB,
        BODY,
        fixedEntropy(chunks, 2n ** 63n),
      ),
    ).toThrow(/int64/i);
    expect(() =>
      createKnock(DEVICE_PRIV, SERVER_PUB, BODY, fixedEntropy(chunks, -1n)),
    ).toThrow(/int64/i);
  });

  it("accepts the inclusive upper boundary 2^63 - 1", () => {
    const chunks = [
      fromHex("aa".repeat(32)),
      fromHex("0011223344556677"),
      fromHex("89abcdef"),
    ];
    const created = createKnock(
      DEVICE_PRIV,
      SERVER_PUB,
      BODY,
      fixedEntropy(chunks, 2n ** 63n - 1n),
    );
    expect(created.counter).toBe(0x0011223344556677n);
  });

  it("stamps a wall-clock timestamp inside the int64 range by default", () => {
    expect(browserEntropy.nowNanos()).toBeGreaterThan(0n);
    expect(browserEntropy.nowNanos()).toBeLessThan(2n ** 63n);
  });
});
