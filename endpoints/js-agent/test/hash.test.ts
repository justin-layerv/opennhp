import { describe, it, expect } from "vitest";
import {
  HashType,
  HASH_SIZE,
  hash,
  createChainHash,
  nobleHash,
} from "../src/crypto/hash";
import { toHex, utf8 } from "./hex";

describe("hash primitives", () => {
  it("BLAKE2s-256('abc') matches the RFC 7693 KAT", () => {
    expect(toHex(hash(HashType.BLAKE2S, utf8("abc")))).toBe(
      "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    );
  });

  it("SHA-256('abc') matches the FIPS 180-4 KAT", () => {
    expect(toHex(hash(HashType.SHA256, utf8("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("one-shot hash concatenates its inputs: H(a, b) === H(a‖b)", () => {
    const a = utf8("foo");
    const b = utf8("bar");
    const concat = new Uint8Array([...a, ...b]);
    expect(toHex(hash(HashType.BLAKE2S, a, b))).toBe(
      toHex(hash(HashType.BLAKE2S, concat)),
    );
  });

  it("chain hash sum() peeks non-destructively (Go chainHash.Sum semantics)", () => {
    // The Noise chain hash absorbs material incrementally and reads its current
    // digest repeatedly without finalizing. This is the property PR-3's
    // handshake transcript depends on.
    const a = utf8("first");
    const b = utf8("second");
    const ch = createChainHash(HashType.BLAKE2S);

    ch.update(a);
    const s1 = toHex(ch.sum());
    const s1again = toHex(ch.sum()); // repeatable — sum() did not finalize
    ch.update(b);
    const s2 = toHex(ch.sum());

    expect(s1).toBe(s1again);
    expect(s1).toBe(toHex(hash(HashType.BLAKE2S, a))); // digest after first absorb
    expect(s2).toBe(toHex(hash(HashType.BLAKE2S, a, b))); // …and after the second
    expect(s1).not.toBe(s2);
  });

  it("every digest is HASH_SIZE bytes", () => {
    expect(hash(HashType.BLAKE2S, utf8("x")).length).toBe(HASH_SIZE);
    expect(hash(HashType.SHA256, utf8("x")).length).toBe(HASH_SIZE);
  });

  it("the chain hash works for SHA-256 too, not just BLAKE2s", () => {
    const a = utf8("first");
    const b = utf8("second");
    const ch = createChainHash(HashType.SHA256);
    ch.update(a);
    ch.update(b);
    expect(toHex(ch.sum())).toBe(toHex(hash(HashType.SHA256, a, b)));
  });

  it("nobleHash throws on an unsupported hash type", () => {
    expect(() => nobleHash(99 as HashType)).toThrow();
  });
});
