// Test helper: mint a fully valid, signed qURL v2 fragment plus the trust store
// that verifies it. Used by the fragment-level / tamper / relay tests, mirroring
// the role of Go's signedFragment in fragment_test.go.
//
// WebCrypto ECDSA sign returns a raw r||s (P1363) signature but does NOT low-S
// normalize, so this helper normalizes s -> N-s when high so the produced fixture
// is a valid PINNED-encoding signature the verifier accepts (the verifier rejects
// high-S). This is the JS counterpart of the issuer signer's derToRawLowS step.
import { p256 } from "@noble/curves/nist.js";
import { base64UrlEncode } from "../src/qurl/base64url";
import { signingInput } from "../src/qurl/claims";
import { TrustStore } from "../src/qurl/truststore";

/** P-256 group order N (authoritative, from @noble/curves) and the low-S
 * threshold N/2 — shared by the signature/knock tests so the constants live once. */
export const N: bigint = p256.Point.Fn.ORDER;
export const HALF_ORDER: bigint = N >> 1n;
export const SCALAR_BYTES = 32;

export interface SignedFragment {
  /** The fragment body WITHOUT a leading "#". */
  body: string;
  /** A trust store containing the signing kid. */
  ts: TrustStore;
  /** The exact claims part (base64url) that was signed. */
  claimsB64: string;
  /** The secret part (base64url). */
  secretB64: string;
  /** The 64-byte raw r||s low-S signature. */
  rawSig: Uint8Array;
  /** The signing kid. */
  kid: string;
}

/** Big-endian render of a bigint into a fixed 32-byte scalar. */
export function bigIntToBe32(x: bigint): Uint8Array {
  const out = new Uint8Array(SCALAR_BYTES);
  for (let i = SCALAR_BYTES - 1; i >= 0; i -= 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** Big-endian decode of a fixed-width scalar to a bigint. */
export function beToBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc;
}

/** Normalizes a raw r||s signature to low-S (s <= N/2), as the issuer signer does. */
function toLowS(rawSig: Uint8Array): Uint8Array {
  const r = rawSig.subarray(0, SCALAR_BYTES);
  let s = beToBigInt(rawSig.subarray(SCALAR_BYTES));
  if (s > HALF_ORDER) {
    s = N - s;
  }
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(bigIntToBe32(s), SCALAR_BYTES);
  return out;
}

/**
 * Builds a valid signed fragment. `claimsB64Override` lets a caller sign a
 * specific claims encoding; otherwise a schema-valid baseline is used.
 */
export async function makeSignedFragment(
  claimsB64?: string,
  kid = "qurl-issuer-test-key",
): Promise<SignedFragment> {
  const claims = claimsB64 ?? baselineClaimsB64(kid);

  // Generate a P-256 issuer keypair (extractable so we can publish the SPKI DER).
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const spkiDer = new Uint8Array(
    await crypto.subtle.exportKey("spki", pair.publicKey),
  );

  const rawSig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      pair.privateKey,
      new Uint8Array(signingInput(claims)),
    ),
  );
  const lowS = toLowS(rawSig);

  const ts = await TrustStore.fromSpkiDerB64({
    [kid]: base64UrlEncode(spkiDer),
  });

  const secretB64 = base64UrlEncode(
    new TextEncoder().encode(
      `{"qurl_user_private_key_b64":"${base64UrlEncode(new Uint8Array(32).fill(9))}"}`,
    ),
  );
  const body = `qv2.${claims}.${secretB64}.${base64UrlEncode(lowS)}`;
  return { body, ts, claimsB64: claims, secretB64, rawSig: lowS, kid };
}

/** A schema-valid baseline claims object, base64url-encoded. */
export function baselineClaimsB64(kid = "qurl-issuer-test-key"): string {
  const json = baselineClaimsJSON(kid);
  return base64UrlEncode(new TextEncoder().encode(json));
}

/** A schema-valid baseline claims JSON string (tests perturb this). */
export function baselineClaimsJSON(kid = "qurl-issuer-test-key"): string {
  const cell = base64UrlEncode(new Uint8Array(32).fill(0x44));
  const user = base64UrlEncode(new Uint8Array(32).fill(0x55));
  const resource = base64UrlEncode(realP256SpkiDerSync());
  return JSON.stringify({
    v: 2,
    iss: "qurl-service",
    kid,
    iat: 1781910000,
    nbf: 1781910000,
    exp: 1781910300,
    jti: "qurl_01JTESTFIXTURE",
    cell_public_key_b64: cell,
    cell_id: "test-cell",
    relay_url: "https://relay.example.com",
    resource_public_key_b64: resource,
    qurl_user_public_key_b64: user,
  });
}

// A real P-256 SPKI DER (91 bytes) for the resource_public_key_b64 length window,
// generated once via noble (synchronous) so the baseline is realistic bytes.
let cachedResourceDer: Uint8Array | undefined;
function realP256SpkiDerSync(): Uint8Array {
  if (!cachedResourceDer) {
    const priv = p256.utils.randomSecretKey();
    const pubUncompressed = p256.getPublicKey(priv, false); // 0x04 || X || Y, 65 bytes
    cachedResourceDer = wrapUncompressedInSpki(pubUncompressed);
  }
  return cachedResourceDer;
}

/** A fresh, real 91-byte P-256 SPKI DER (length-window valid) for the resource
 * key. Unlike the cached baseline helper, this mints a new key per call — used by
 * tests that need a distinct resource key. */
export function freshP256SpkiDer(): Uint8Array {
  const priv = p256.utils.randomSecretKey();
  const point = p256.getPublicKey(priv, false); // 0x04 || X || Y, 65 bytes
  return wrapUncompressedInSpki(point);
}

// Wraps a 65-byte uncompressed P-256 point in the fixed DER SPKI prefix for
// id-ecPublicKey + prime256v1. The 26-byte prefix + 65-byte point = 91 bytes,
// the canonical KMS GetPublicKey length and the value the parser's window expects.
export function wrapUncompressedInSpki(point: Uint8Array): Uint8Array {
  const prefix = new Uint8Array([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00,
  ]);
  const out = new Uint8Array(prefix.length + point.length);
  out.set(prefix, 0);
  out.set(point, prefix.length);
  return out;
}
