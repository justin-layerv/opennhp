import { describe, it, expect } from "vitest";
import {
  aeadSeal,
  aeadOpen,
  AEAD_KEY_SIZE,
  AEAD_NONCE_SIZE,
  AEAD_TAG_SIZE,
} from "../src/crypto/aead";
import { toHex, fromHex, utf8 } from "./hex";

const KEY = fromHex(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
);
const NONCE = fromHex("505152535455565758595a5b");

describe("AES-256-GCM AEAD", () => {
  it("matches a known AES-256-GCM tag (key=0, nonce=0, empty plaintext/aad)", () => {
    // Standard AES-256-GCM KAT: encrypting nothing under an all-zero key and
    // nonce yields the empty ciphertext and this well-known 16-byte tag.
    const ct = aeadSeal(
      new Uint8Array(32),
      new Uint8Array(12),
      new Uint8Array(0),
      new Uint8Array(0),
    );
    expect(ct.length).toBe(AEAD_TAG_SIZE);
    expect(toHex(ct)).toBe("530f8afbc74536b9a963b4f1c4cb738b");
  });

  it("round-trips plaintext with AAD (Seal then Open)", () => {
    const plaintext = utf8("the quick brown fox");
    const aad = utf8("chain-hash-stand-in");
    const ct = aeadSeal(KEY, NONCE, plaintext, aad);
    expect(ct.length).toBe(plaintext.length + AEAD_TAG_SIZE);
    expect(toHex(aeadOpen(KEY, NONCE, ct, aad))).toBe(toHex(plaintext));
  });

  it("rejects a tampered tag", () => {
    const ct = aeadSeal(KEY, NONCE, utf8("payload"), utf8("aad"));
    const last = ct.length - 1;
    ct[last] = (ct[last] ?? 0) ^ 0x01; // flip a bit in the auth tag
    expect(() => aeadOpen(KEY, NONCE, ct, utf8("aad"))).toThrow();
  });

  it("rejects mismatched AAD (the handshake's chain-hash binding)", () => {
    const ct = aeadSeal(KEY, NONCE, utf8("payload"), utf8("aad-one"));
    expect(() => aeadOpen(KEY, NONCE, ct, utf8("aad-two"))).toThrow();
  });

  it("rejects a wrong-size key", () => {
    expect(() =>
      aeadSeal(
        new Uint8Array(AEAD_KEY_SIZE - 16),
        NONCE,
        utf8("x"),
        new Uint8Array(0),
      ),
    ).toThrow();
  });

  it("rejects a wrong-size nonce", () => {
    expect(() =>
      aeadSeal(
        KEY,
        new Uint8Array(AEAD_NONCE_SIZE - 1),
        utf8("x"),
        new Uint8Array(0),
      ),
    ).toThrow();
  });

  it("rejects a ciphertext shorter than the tag", () => {
    expect(() =>
      aeadOpen(
        KEY,
        NONCE,
        new Uint8Array(AEAD_TAG_SIZE - 1),
        new Uint8Array(0),
      ),
    ).toThrow();
  });

  it("exposes the NHP suite sizes", () => {
    expect([AEAD_KEY_SIZE, AEAD_NONCE_SIZE, AEAD_TAG_SIZE]).toEqual([
      32, 12, 16,
    ]);
  });
});
