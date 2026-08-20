import { describe, it, expect } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  buildQurlV2KnockBody,
  assertPoPLinkage,
  knockQurlV2,
  QURL_V2_CLAIMS_USER_DATA_KEY,
  QURL_V2_ISSUER_SIG_USER_DATA_KEY,
} from "../src/qurl/knock";
import { NHP_KNK } from "../src/crypto/packet";
import { pubKeyFingerprint } from "../src/crypto/fingerprint";
import { parseFragment } from "../src/qurl/fragment";
import { RelayAllowlist } from "../src/qurl/relay-url";
import { base64UrlEncode } from "../src/qurl/base64url";
import { makeSignedFragment, freshP256SpkiDer } from "./qurl-signed-fragment";
import type { RelayTransport } from "../src/agent/relay";
import { wrapQurlV2TransportFixture } from "./qurl-transport-fixture";

// qURL v2 knock-construction tests. NO Go roundtrip fence exists for the v2 knock
// (the nhp qurl-v2 branch has no server-side v2 admission path yet), so these are
// JS-STRUCTURAL: they pin the plaintext body shape, the PoP linkage (invariant 2,
// checkable client-side), and the serverId/POST target via a mock transport —
// not a real server decrypt. The body is asserted in plaintext because createKnock
// AEAD-seals it (you can't read usrData back out of the packet).

/**
 * Builds a signed fragment whose secret private key genuinely DERIVES the signed
 * `qurl_user_public_key_b64` (so the PoP linkage holds), with a chosen cell key.
 * Returns the fragment plus the cell public key bytes for serverId assertions.
 */
async function makeLinkedFragment(): Promise<{
  body: string;
  ts: Awaited<ReturnType<typeof makeSignedFragment>>["ts"];
  cellPub: Uint8Array;
  resourceB64: string;
  relayUrl: string;
}> {
  // A real per-qURL X25519 keypair: secret priv must derive the signed user pub.
  const userPriv = x25519.utils.randomSecretKey();
  const userPub = x25519.getPublicKey(userPriv);
  // A real cell X25519 keypair (only the public key is embedded/used for serverId).
  const cellPriv = x25519.utils.randomSecretKey();
  const cellPub = x25519.getPublicKey(cellPriv);

  // Build claims carrying the matching user pub + chosen cell pub, then sign them
  // with makeSignedFragment's issuer key by passing the exact claims encoding.
  const resourceB64 = base64UrlEncode(freshP256SpkiDer());
  const relayUrl = "https://relay.example.com";
  const claimsJSON = JSON.stringify({
    v: 2,
    iss: "qurl-service",
    kid: "qurl-issuer-test-key",
    iat: 1781910000,
    nbf: 1781910000,
    exp: 1781910300,
    jti: "qurl_01JLINKED",
    cell_public_key_b64: base64UrlEncode(cellPub),
    cell_id: "linked-cell",
    relay_url: relayUrl,
    resource_public_key_b64: resourceB64,
    qurl_user_public_key_b64: base64UrlEncode(userPub),
  });
  const claimsB64 = base64UrlEncode(new TextEncoder().encode(claimsJSON));
  const sf = await makeSignedFragment(claimsB64);

  // Replace the secret part so the per-qURL private key matches the signed pubkey.
  const parts = sf.body.split(".");
  const secretB64 = base64UrlEncode(
    new TextEncoder().encode(
      `{"qurl_user_private_key_b64":"${base64UrlEncode(userPriv)}"}`,
    ),
  );
  const body = [parts[0], parts[1], secretB64, parts[3]].join(".");
  return { body, ts: sf.ts, cellPub, resourceB64, relayUrl };
}

describe("buildQurlV2KnockBody", () => {
  it("serializes the AgentKnockMsg body with the v2 shape (plaintext)", () => {
    const body = buildQurlV2KnockBody({
      authServiceId: "asp-1",
      resourcePublicKeyB64: "RESOURCEKEY",
      claimsB64: "CLAIMS",
      sigB64: "SIG",
    });
    const msg = JSON.parse(new TextDecoder().decode(body)) as Record<
      string,
      unknown
    >;
    // headerType is owned here (the #1154 wire-vs-body invariant), not the caller.
    expect(msg.headerType).toBe(NHP_KNK);
    expect(msg.aspId).toBe("asp-1");
    // resId is the signed resource public key, NOT the v1 bootstrap sentinel.
    expect(msg.resId).toBe("RESOURCEKEY");
    const usrData = msg.usrData as Record<string, string>;
    expect(usrData[QURL_V2_CLAIMS_USER_DATA_KEY]).toBe("CLAIMS");
    expect(usrData[QURL_V2_ISSUER_SIG_USER_DATA_KEY]).toBe("SIG");
    // The per-qURL private key is the handshake identity only — never in usrData.
    expect(JSON.stringify(msg)).not.toContain("private");
  });

  it("requires the resource key and both signed parts", () => {
    expect(() =>
      buildQurlV2KnockBody({
        authServiceId: "asp",
        resourcePublicKeyB64: "",
        claimsB64: "C",
        sigB64: "S",
      }),
    ).toThrow();
    expect(() =>
      buildQurlV2KnockBody({
        authServiceId: "asp",
        resourcePublicKeyB64: "R",
        claimsB64: "",
        sigB64: "S",
      }),
    ).toThrow();
  });
});

describe("assertPoPLinkage (invariant 2, checkable client-side)", () => {
  it("passes when the secret private key derives the signed user public key", async () => {
    const lf = await makeLinkedFragment();
    const frag = parseFragment(lf.body);
    expect(() => assertPoPLinkage(frag)).not.toThrow();
  });

  it("throws when the secret does not match the signed user public key", async () => {
    // makeSignedFragment's baseline uses a fill(0x55) signed user pub but a fill(9)
    // secret — deliberately mismatched, so PoP must fail.
    const sf = await makeSignedFragment();
    const frag = parseFragment(sf.body);
    expect(() => assertPoPLinkage(frag)).toThrow(/proof-of-possession/);
  });
});

describe("knockQurlV2 end-to-end (JS-structural; mock transport)", () => {
  it("derives serverId from the cell key and POSTs to relay/{serverId}", async () => {
    const lf = await makeLinkedFragment();
    let capturedServerId: string | undefined;
    let capturedPacket: Uint8Array | undefined;
    const transport: RelayTransport = async (serverId, packet) => {
      capturedServerId = serverId;
      capturedPacket = packet;
      // Short-circuit AFTER capture: forging a decryptable ACK needs the server
      // side (no v2 fence). Throwing here proves the knock reached the POST with
      // the right serverId/packet, which is the assertable structural contract.
      throw new Error("captured");
    };

    await expect(
      knockQurlV2(wrapQurlV2TransportFixture(lf.body), {
        trustStore: lf.ts,
        relayAllowlist: new RelayAllowlist(["relay.example.com"]),
        authServiceId: "asp-1",
        deps: { transport },
      }),
    ).rejects.toThrow("captured");

    expect(capturedServerId).toBe(pubKeyFingerprint(lf.cellPub));
    expect(capturedPacket).toBeInstanceOf(Uint8Array);
    expect(capturedPacket!.length).toBeGreaterThan(0);
  });

  it("rejects legacy qv2 public transport before sending", async () => {
    const lf = await makeLinkedFragment();
    let sent = false;
    const transport: RelayTransport = async () => {
      sent = true;
      return new Uint8Array();
    };
    await expect(
      knockQurlV2(lf.body, {
        trustStore: lf.ts,
        relayAllowlist: new RelayAllowlist(["relay.example.com"]),
        authServiceId: "asp-1",
        deps: { transport },
      }),
    ).rejects.toThrow(/invalid transport/);
    expect(sent, "must not POST legacy public transport").toBe(false);
  });

  it("rejects transport-valid malformed or tampered inner data before sending", async () => {
    const lf = await makeLinkedFragment();
    const validTransport = wrapQurlV2TransportFixture(lf.body);
    const reorderedParts = validTransport.split(".");
    expect(Number(reorderedParts[1])).toBeGreaterThanOrEqual(2);
    expect(reorderedParts[4]).not.toBe(reorderedParts[5]);
    [reorderedParts[4], reorderedParts[5]] = [
      reorderedParts[5]!,
      reorderedParts[4]!,
    ];

    const truncatedSignatureParts = validTransport.split(".");
    const finalIndex = truncatedSignatureParts.length - 1;
    truncatedSignatureParts[finalIndex] = truncatedSignatureParts[
      finalIndex
    ]!.slice(0, -1);
    expect(truncatedSignatureParts[finalIndex]).not.toBe("");

    for (const [name, transportFragment] of [
      ["impossible inner base64 length", "qv2t1.1.1.1.A.B.C"],
      ["reordered claims chunks", reorderedParts.join(".")],
      ["truncated non-empty signature", truncatedSignatureParts.join(".")],
    ] as const) {
      let sent = false;
      const transport: RelayTransport = async () => {
        sent = true;
        return new Uint8Array();
      };
      await expect(
        knockQurlV2(transportFragment, {
          trustStore: lf.ts,
          relayAllowlist: new RelayAllowlist(["relay.example.com"]),
          authServiceId: "asp-1",
          deps: { transport },
        }),
        name,
      ).rejects.toThrow();
      expect(sent, `${name} must fail before relay POST`).toBe(false);
    }
  });

  it("rejects (before sending) when the issuer signature does not verify", async () => {
    const lf = await makeLinkedFragment();
    // A trust store with a DIFFERENT key so verification fails.
    const otherSf = await makeSignedFragment(undefined, "kid-other");
    let sent = false;
    const transport: RelayTransport = async () => {
      sent = true;
      return new Uint8Array();
    };
    await expect(
      knockQurlV2(wrapQurlV2TransportFixture(lf.body), {
        trustStore: otherSf.ts,
        relayAllowlist: new RelayAllowlist(["relay.example.com"]),
        authServiceId: "asp-1",
        deps: { transport },
      }),
    ).rejects.toThrow();
    expect(sent, "must not POST when verification fails").toBe(false);
  });

  it("rejects (before sending) when relay_url is not on the allowlist", async () => {
    const lf = await makeLinkedFragment();
    let sent = false;
    const transport: RelayTransport = async () => {
      sent = true;
      return new Uint8Array();
    };
    await expect(
      knockQurlV2(wrapQurlV2TransportFixture(lf.body), {
        trustStore: lf.ts,
        relayAllowlist: new RelayAllowlist(["other.example.com"]),
        authServiceId: "asp-1",
        deps: { transport },
      }),
    ).rejects.toThrow(/relay_url/);
    expect(sent, "must not POST when relay_url is rejected").toBe(false);
  });

  it("rejects (before sending) when the PoP linkage fails", async () => {
    // Build a fragment whose secret does NOT derive the signed user pubkey.
    const sf = await makeSignedFragment(); // baseline: mismatched secret vs user pub
    let sent = false;
    const transport: RelayTransport = async () => {
      sent = true;
      return new Uint8Array();
    };
    await expect(
      knockQurlV2(wrapQurlV2TransportFixture(sf.body), {
        trustStore: sf.ts,
        relayAllowlist: new RelayAllowlist(["relay.example.com"]),
        authServiceId: "asp-1",
        deps: { transport },
      }),
    ).rejects.toThrow(/proof-of-possession/);
    expect(sent, "must not POST when PoP fails").toBe(false);
  });
});
