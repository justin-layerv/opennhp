import { describe, it, expect } from "vitest";
import {
  x25519PublicKey,
  x25519SharedSecret,
  X25519_KEY_SIZE,
} from "../src/crypto/dh";
import { toHex, fromHex } from "./hex";

// RFC 7748 §6.1 X25519 test vectors. These also pin parity with Go
// curve25519.X25519 (same standard), which is what the NHP server runs.
const ALICE_PRIV = fromHex(
  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
);
const ALICE_PUB =
  "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_PRIV = fromHex(
  "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
);
const BOB_PUB = fromHex(
  "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
);
const SHARED =
  "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

describe("X25519 DH", () => {
  it("derives the public key (RFC 7748 §6.1 Alice)", () => {
    expect(toHex(x25519PublicKey(ALICE_PRIV))).toBe(ALICE_PUB);
  });

  it("computes the shared secret (RFC 7748 §6.1)", () => {
    expect(toHex(x25519SharedSecret(ALICE_PRIV, BOB_PUB))).toBe(SHARED);
  });

  it("both parties derive the same secret (mirrors Go TestECDHSharedSecret)", () => {
    const alicePub = x25519PublicKey(ALICE_PRIV);
    const bobPub = x25519PublicKey(BOB_PRIV);
    expect(toHex(bobPub)).toBe(toHex(BOB_PUB)); // sanity: Bob's vector is consistent
    expect(toHex(x25519SharedSecret(ALICE_PRIV, bobPub))).toBe(
      toHex(x25519SharedSecret(BOB_PRIV, alicePub)),
    );
  });

  it("rejects a wrong-length peer key", () => {
    expect(() =>
      x25519SharedSecret(ALICE_PRIV, new Uint8Array(X25519_KEY_SIZE - 1)),
    ).toThrow();
  });

  it("rejects a low-order peer key (all-zeros) — fail-loud, matching Go", () => {
    // Go curve25519.X25519 errors on a low-order point (the shared secret would
    // be all-zeros); the wrapper documents the same fail-loud behavior. Lock it
    // so a future noble bump can't silently regress to returning a zero key.
    expect(() =>
      x25519SharedSecret(ALICE_PRIV, new Uint8Array(X25519_KEY_SIZE)),
    ).toThrow();
  });

  it("rejects a wrong-length private key (both entry points)", () => {
    expect(() =>
      x25519PublicKey(new Uint8Array(X25519_KEY_SIZE - 1)),
    ).toThrow();
    expect(() =>
      x25519SharedSecret(new Uint8Array(X25519_KEY_SIZE - 1), BOB_PUB),
    ).toThrow();
  });
});
