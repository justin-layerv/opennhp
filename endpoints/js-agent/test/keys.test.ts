import { describe, it, expect } from "vitest";
import {
  generateDeviceKeyPair,
  x25519KeyFromBase64,
  x25519KeyToBase64,
} from "../src/index";
import { x25519PublicKey } from "../src/crypto/dh";
import { fromHex, toHex } from "./hex";

const ALICE_PRIV = fromHex(
  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
);

describe("browser device key helpers", () => {
  it("generates an X25519 keypair and standard-base64 public key", () => {
    const keypair = generateDeviceKeyPair({
      randomBytes: (out) => out.set(ALICE_PRIV),
    });

    expect(toHex(keypair.deviceStaticPriv)).toBe(toHex(ALICE_PRIV));
    expect(toHex(keypair.deviceStaticPub)).toBe(
      toHex(x25519PublicKey(ALICE_PRIV)),
    );
    expect(keypair.browserAgentPublicKey).toBe(
      x25519KeyToBase64(keypair.deviceStaticPub),
    );
    expect(keypair.browserAgentPublicKey).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  });

  it("round-trips 32-byte X25519 keys through standard base64", () => {
    const publicKey = x25519PublicKey(ALICE_PRIV);
    const encoded = x25519KeyToBase64(publicKey);

    expect(encoded).toHaveLength(44);
    expect(toHex(x25519KeyFromBase64(encoded))).toBe(toHex(publicKey));
  });

  it("rejects malformed or wrong-length base64 keys", () => {
    expect(() =>
      x25519KeyFromBase64("not-base64url___________________________="),
    ).toThrow(/standard base64/);
    expect(() =>
      x25519KeyFromBase64(
        x25519KeyToBase64(new Uint8Array(32)).slice(0, 43) + "==",
      ),
    ).toThrow(/standard base64/);
    expect(() => x25519KeyToBase64(new Uint8Array(31))).toThrow(/32 bytes/);
  });
});
