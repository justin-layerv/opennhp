import { X25519_KEY_SIZE, x25519PublicKey } from "../crypto/dh.js";

/** Entropy seam for generating a browser device static keypair. */
export interface KeyPairEntropy {
  /** Fill `out` with cryptographically-strong random bytes, in place. */
  randomBytes(out: Uint8Array): void;
}

/** Production entropy: the browser CSPRNG. */
export const browserKeyPairEntropy: KeyPairEntropy = {
  randomBytes: (out) => {
    crypto.getRandomValues(out);
  },
};

/** The long-lived browser identity keypair used for qURL relay knocks. */
export interface DeviceKeyPair {
  /** X25519 device static private key, 32 bytes. Keep local to the browser. */
  deviceStaticPriv: Uint8Array;
  /** X25519 device static public key, 32 bytes. */
  deviceStaticPub: Uint8Array;
  /** Standard-base64 public key NHP forwards as `authenticated_agent_public_key`. */
  browserAgentPublicKey: string;
}

function assertX25519Key(label: string, key: Uint8Array): void {
  if (key.length !== X25519_KEY_SIZE) {
    throw new Error(
      `x25519 ${label} must be ${X25519_KEY_SIZE} bytes, got ${key.length}`,
    );
  }
}

function binaryString(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += String.fromCharCode(byte);
  }
  return out;
}

/** Encodes a 32-byte X25519 key using standard base64. */
export function x25519KeyToBase64(key: Uint8Array): string {
  assertX25519Key("key", key);
  return btoa(binaryString(key));
}

/** Decodes a standard-base64 32-byte X25519 key. */
export function x25519KeyFromBase64(value: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    throw new Error("x25519 base64 key must be 44 chars of standard base64");
  }

  const raw = atob(value);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    bytes[i] = raw.charCodeAt(i);
  }
  assertX25519Key("base64 key", bytes);
  return bytes;
}

/**
 * Generates the browser's qURL relay identity keypair.
 *
 * The private key stays in the browser. The public key is authenticated by NHP's
 * Noise handshake; during qurl.link relay bootstrap, NHP forwards it to
 * qurl-service as `authenticated_agent_public_key` after validating the token.
 */
export function generateDeviceKeyPair(
  entropy: KeyPairEntropy = browserKeyPairEntropy,
): DeviceKeyPair {
  const deviceStaticPriv = new Uint8Array(X25519_KEY_SIZE);
  entropy.randomBytes(deviceStaticPriv);
  const deviceStaticPub = x25519PublicKey(deviceStaticPriv);

  return {
    deviceStaticPriv,
    deviceStaticPub,
    browserAgentPublicKey: x25519KeyToBase64(deviceStaticPub),
  };
}
