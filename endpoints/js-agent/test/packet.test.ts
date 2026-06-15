import { describe, it, expect } from "vitest";
import {
  HEADER_SIZE,
  PUBLIC_KEY_SIZE,
  OFF_HEADER_COMMON,
  OFF_EPHEMERAL,
  OFF_IDENTITY,
  OFF_STATIC,
  OFF_TIMESTAMP,
  OFF_DIGEST,
  NHP_KNK,
  COOKIE_SIZE,
  headerDigest,
  nonceForCounter,
  setTypeAndPayloadSize,
  getTypeAndPayloadSize,
  setCounter,
  getCounter,
} from "../src/crypto/packet";
import { toHex } from "./hex";

describe("packet wire format", () => {
  it("has the Go HeaderCurve layout (240 bytes, fixed offsets)", () => {
    expect(HEADER_SIZE).toBe(240);
    expect([OFF_HEADER_COMMON, OFF_EPHEMERAL, OFF_IDENTITY, OFF_STATIC, OFF_TIMESTAMP, OFF_DIGEST]).toEqual([
      0, 24, 56, 136, 184, 208,
    ]);
  });

  it("computes the header digest matching the Go KAT (nhp/core/header_digest_kat_test.go)", () => {
    // Rebuild the Go KAT's fully-deterministic header byte-for-byte: HeaderCommon
    // 0xC0, Ephemeral 0xE1, Identity 0x1D, Static 0x57, Timestamp 0x71. The
    // responder static pubkey is 0xA0+i. The digest is over header[0:208] with
    // the initial-constant + pubkey prefix; the result is the hardcoded golden.
    const header = new Uint8Array(HEADER_SIZE);
    header.fill(0xc0, OFF_HEADER_COMMON, OFF_EPHEMERAL);
    header.fill(0xe1, OFF_EPHEMERAL, OFF_IDENTITY);
    header.fill(0x1d, OFF_IDENTITY, OFF_STATIC);
    header.fill(0x57, OFF_STATIC, OFF_TIMESTAMP);
    header.fill(0x71, OFF_TIMESTAMP, OFF_DIGEST);

    const serverPub = new Uint8Array(PUBLIC_KEY_SIZE);
    for (let i = 0; i < PUBLIC_KEY_SIZE; i++) serverPub[i] = 0xa0 + i;

    // No-cookie (NHP_KNK) golden.
    expect(toHex(headerDigest(serverPub, header))).toBe(
      "536091d2002ec93b89410e4e7e6f19ebddb47668ba00628f18cd9af72a724d33",
    );

    // NHP_RKN cookie branch: the cookie is appended to the digest input. The Go
    // KAT uses currCookie[i]=i and prevCookie[i]=0x80+i.
    const currCookie = Uint8Array.from({ length: COOKIE_SIZE }, (_, i) => i);
    const prevCookie = Uint8Array.from({ length: COOKIE_SIZE }, (_, i) => 0x80 + i);
    expect(toHex(headerDigest(serverPub, header, currCookie))).toBe(
      "1ff84595443585febc28a313876531337d47793924ea6f69079e7c5125bedbfd",
    );
    expect(toHex(headerDigest(serverPub, header, prevCookie))).toBe(
      "13e3f916f29dfca021f75784c2c318026b3e6876dc8939a3de53bf5bf07d06a3",
    );
  });

  it("derives the nonce as 4 zero bytes ‖ big-endian counter (Go NonceBytes)", () => {
    expect(toHex(nonceForCounter(0n))).toBe("000000000000000000000000");
    expect(toHex(nonceForCounter(0x0102030405060708n))).toBe("000000000102030405060708");
    expect(nonceForCounter(0n).length).toBe(12);
  });

  it("round-trips type + payload size through the preamble XOR, for any preamble", () => {
    const header = new Uint8Array(HEADER_SIZE);
    // The preamble obfuscates the type/size on the wire; decoding must recover
    // them regardless of its value (it's random in production).
    for (const preamble of [0x00000000, 0xdeadbeef, 0x12345678, 0xffffffff]) {
      setTypeAndPayloadSize(header, NHP_KNK, 1234, preamble);
      expect(getTypeAndPayloadSize(header)).toEqual({ type: NHP_KNK, size: 1234 });
    }
  });

  it("round-trips the 64-bit counter big-endian", () => {
    const header = new Uint8Array(HEADER_SIZE);
    setCounter(header, 0xfedcba9876543210n);
    expect(getCounter(header)).toBe(0xfedcba9876543210n);
    // counter lands at HeaderCommon[16:24]
    expect(toHex(header.subarray(16, 24))).toBe("fedcba9876543210");
  });
});
