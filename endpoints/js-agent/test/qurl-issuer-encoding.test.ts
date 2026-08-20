import { describe, it, expect } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { TrustStore } from "../src/qurl/truststore";
import { Base64UrlError } from "../src/qurl/base64url";
import { RelayAllowlist } from "../src/qurl/relay-url";
import { knockQurlV2 } from "../src/qurl/knock";
import { parseFragment, verifyFragment } from "../src/qurl/fragment";
import { signingInput } from "../src/qurl/claims";
import { base64UrlEncode } from "../src/qurl/base64url";
import { wrapUncompressedInSpki } from "./qurl-signed-fragment";
import { wrapQurlV2TransportFixture } from "./qurl-transport-fixture";
import type { RelayTransport } from "../src/agent/relay";

// Portal issuer-key ENCODING contract (the qurl.link browser verifier glue).
//
// The KMS-provided issuer public key is STANDARD base64 DER SPKI
// (`data.aws_kms_public_key.public_key`); the NHP server decodes it with
// base64.StdEncoding. The qurl.link BROWSER verifier instead calls
// `TrustStore.fromSpkiDerB64`, which decodes with STRICT unpadded base64url. So
// the Terraform root re-encodes the key from standard base64 to unpadded base64url
// before rendering it into the page:
//
//     replace(replace(replace(std, "+", "-"), "/", "_"), "=", "")
//
// These tests mirror that exact conversion and prove (a) the base64url-encoded key
// imports and verifies a real signed fragment, (b) the full page pattern
// (TrustStore + RelayAllowlist + knockQurlV2) reaches the relay POST after
// verification, and (c) the conversion is load-bearing: the RAW standard-base64
// key is rejected by the strict decoder. If this drifts, the portal and the NHP
// server would trust different bytes (or the portal would reject a valid key).

/** Terraform's exact standard-base64 -> unpadded-base64url rewrite. Uses
 * split/join (global replace) to match Terraform's replace() and stay within the
 * es2020 lib target (no String.prototype.replaceAll). */
function tfStdToUrl(std: string): string {
  return std.split("+").join("-").split("/").join("_").split("=").join("");
}

/** Node/WebCrypto standard-base64 (padded), as `aws kms get-public-key` emits. */
function toStdBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

const KID = "qurl-issuer-2026";
const RELAY_HOST = "relay.qurl.link.layerv.xyz";
const RELAY_URL = `https://${RELAY_HOST}`;

interface IssuerFixture {
  /** kid -> base64url SPKI DER, exactly as the portal config would carry it. */
  portalTrustStoreMap: Record<string, string>;
  /** kid -> standard base64 SPKI DER, exactly as KMS/the NHP server carry it. */
  kmsStdB64: string;
  privateKey: CryptoKey;
}

/** Mints a P-256 issuer key and returns both encodings of its SPKI DER. */
async function makeIssuer(): Promise<IssuerFixture> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const spkiDer = new Uint8Array(
    await crypto.subtle.exportKey("spki", pair.publicKey),
  );
  const kmsStdB64 = toStdBase64(spkiDer);
  return {
    portalTrustStoreMap: { [KID]: tfStdToUrl(kmsStdB64) },
    kmsStdB64,
    privateKey: pair.privateKey,
  };
}

// P-256 group order for low-S normalization (the verifier rejects high-S).
const N: bigint = p256.Point.Fn.ORDER;
const HALF_ORDER: bigint = N >> 1n;
function beToBig(b: Uint8Array): bigint {
  let a = 0n;
  for (const x of b) a = (a << 8n) | BigInt(x);
  return a;
}
function bigToBe32(x: bigint): Uint8Array {
  const o = new Uint8Array(32);
  for (let i = 31; i >= 0; i -= 1) {
    o[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return o;
}

/**
 * Builds a fully-linked signed fragment (PoP holds) signed by `issuer`, returning
 * the fragment string and the cell public key.
 */
async function makeSignedLinkedFragment(
  issuer: IssuerFixture,
): Promise<{ fragment: string; cellPub: Uint8Array }> {
  const userPriv = x25519.utils.randomSecretKey();
  const userPub = x25519.getPublicKey(userPriv);
  const cellPriv = x25519.utils.randomSecretKey();
  const cellPub = x25519.getPublicKey(cellPriv);
  const resPriv = p256.utils.randomSecretKey();
  const resDer = wrapUncompressedInSpki(p256.getPublicKey(resPriv, false));

  const claimsJSON = JSON.stringify({
    v: 2,
    iss: "qurl-service",
    kid: KID,
    iat: 1781910000,
    nbf: 1781910000,
    exp: 1781910300,
    jti: "qurl_01JENCODING",
    cell_public_key_b64: base64UrlEncode(cellPub),
    cell_id: "encoding-cell",
    relay_url: RELAY_URL,
    resource_public_key_b64: base64UrlEncode(resDer),
    qurl_user_public_key_b64: base64UrlEncode(userPub),
  });
  const claimsB64 = base64UrlEncode(new TextEncoder().encode(claimsJSON));

  const rawSig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      issuer.privateKey,
      new Uint8Array(signingInput(claimsB64)),
    ),
  );
  let s = beToBig(rawSig.subarray(32));
  if (s > HALF_ORDER) s = N - s;
  const lowS = new Uint8Array(64);
  lowS.set(rawSig.subarray(0, 32), 0);
  lowS.set(bigToBe32(s), 32);

  const secretB64 = base64UrlEncode(
    new TextEncoder().encode(
      `{"qurl_user_private_key_b64":"${base64UrlEncode(userPriv)}"}`,
    ),
  );
  const fragment = `qv2.${claimsB64}.${secretB64}.${base64UrlEncode(lowS)}`;
  return { fragment, cellPub };
}

describe("portal issuer-key encoding (std base64 -> base64url) contract", () => {
  it("imports a base64url-encoded KMS SPKI DER and verifies a real signature", async () => {
    const issuer = await makeIssuer();
    // The RAW KMS value is standard base64 (has padding, and usually + or /);
    // the portal value is the base64url rewrite.
    expect(issuer.portalTrustStoreMap[KID]).not.toMatch(/[+/=]/);

    const ts = await TrustStore.fromSpkiDerB64(issuer.portalTrustStoreMap);
    const { fragment } = await makeSignedLinkedFragment(issuer);
    const frag = parseFragment(fragment);
    // Crux: a key imported from the base64url encoding verifies the issuer sig.
    await expect(verifyFragment(frag, ts)).resolves.toBeUndefined();
  });

  it("drives the full page pattern (TrustStore + RelayAllowlist + knockQurlV2) to the relay POST after verify", async () => {
    const issuer = await makeIssuer();
    const ts = await TrustStore.fromSpkiDerB64(issuer.portalTrustStoreMap);
    const relayAllowlist = new RelayAllowlist([RELAY_HOST]);
    const { fragment } = await makeSignedLinkedFragment(issuer);

    let posted = false;
    // No live v2 server exists; capture the POST after all client-side checks pass.
    const transport: RelayTransport = async () => {
      posted = true;
      throw new Error("captured-after-verify");
    };
    await expect(
      knockQurlV2(wrapQurlV2TransportFixture(fragment), {
        trustStore: ts,
        relayAllowlist,
        authServiceId: "qurl",
        deps: { transport },
      }),
    ).rejects.toThrow("captured-after-verify");
    expect(posted, "must reach the relay POST after verify+relayUrl+PoP").toBe(
      true,
    );
  });

  it("rejects the RAW standard-base64 key (proves the base64url conversion is load-bearing)", async () => {
    const issuer = await makeIssuer();
    // Only meaningful when the std encoding actually carries a non-url char; a
    // P-256 SPKI is 91 bytes so it always has "==" padding, which strict base64url
    // rejects regardless.
    await expect(
      TrustStore.fromSpkiDerB64({ [KID]: issuer.kmsStdB64 }),
    ).rejects.toBeInstanceOf(Base64UrlError);
  });
});
