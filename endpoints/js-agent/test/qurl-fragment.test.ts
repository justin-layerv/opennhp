import { describe, it, expect } from "vitest";
import {
  parseFragment,
  parseAndVerifyFragment,
  verifyFragment,
  FragmentError,
} from "../src/qurl/fragment";
import { SignatureError } from "../src/qurl/signature";
import { UnknownKidError, TrustStore } from "../src/qurl/truststore";
import { base64UrlEncode, Base64UrlError } from "../src/qurl/base64url";
import { makeSignedFragment, baselineClaimsJSON } from "./qurl-signed-fragment";

// Fragment-level / tamper tests — the browser/headless port of Go's
// fragment_test.go (shape rejections, tamper-fails-signature, re-serialized-claims
// rejection, unknown-kid). Proves verification is over the EXACT received bytes,
// not a re-canonicalization.

describe("parseFragment shape rejections (mirrors Go TestParseFragment_ShapeRejections)", () => {
  it("rejects shape violations", async () => {
    const sf = await makeSignedFragment();
    const parts = sf.body.split(".");
    const cases: Array<{ name: string; frag: string }> = [
      { name: "wrong prefix", frag: ["qv1", ...parts.slice(1)].join(".") },
      { name: "too few parts", frag: parts.slice(0, 3).join(".") },
      { name: "too many parts", frag: sf.body + ".extra" },
      {
        name: "empty claims part",
        frag: [parts[0], "", parts[2], parts[3]].join("."),
      },
      {
        name: "empty secret part",
        frag: [parts[0], parts[1], "", parts[3]].join("."),
      },
      {
        name: "empty sig part",
        frag: [parts[0], parts[1], parts[2], ""].join("."),
      },
      {
        name: "padded base64 claims",
        frag: [parts[0], parts[1] + "==", parts[2], parts[3]].join("."),
      },
      {
        name: "non-base64url char",
        frag: [parts[0], parts[1] + "*", parts[2], parts[3]].join("."),
      },
    ];
    for (const tc of cases) {
      expect(
        () => parseFragment(tc.frag),
        `expected rejection for ${tc.name}`,
      ).toThrow();
    }
  });

  it("classifies wrong-shape vs bad-encoding errors", async () => {
    const sf = await makeSignedFragment();
    const parts = sf.body.split(".");
    expect(() => parseFragment(parts.slice(0, 3).join("."))).toThrow(
      FragmentError,
    );
    // A padded/non-canonical part is an encoding error, not a shape error.
    expect(() =>
      parseFragment([parts[0], parts[1] + "==", parts[2], parts[3]].join(".")),
    ).toThrow(Base64UrlError);
  });
});

describe("parseFragment strips a leading # (mirrors Go TestParseFragment_StripsLeadingHash)", () => {
  it("accepts both #fragment and fragment", async () => {
    const sf = await makeSignedFragment();
    await expect(
      parseAndVerifyFragment("#" + sf.body, sf.ts),
    ).resolves.toBeDefined();
    await expect(parseAndVerifyFragment(sf.body, sf.ts)).resolves.toBeDefined();
  });
});

describe("parseFragment rejects malformed UTF-8 in a part (fatal decode)", () => {
  it("throws FragmentError on a base64url-valid but non-UTF-8 claims part", async () => {
    const sf = await makeSignedFragment();
    const parts = sf.body.split(".");
    // 0xFF is never a valid UTF-8 byte. It is valid base64url once encoded, so it
    // passes the decoder and must be rejected at the fatal UTF-8 decode (not
    // silently replaced with U+FFFD) — matching the strict posture.
    const badClaims = base64UrlEncode(new Uint8Array([0xff, 0xfe, 0xfd]));
    const bad = [parts[0], badClaims, parts[2], parts[3]].join(".");
    expect(() => parseFragment(bad)).toThrow(FragmentError);
    expect(() => parseFragment(bad)).toThrow(/not valid UTF-8/);
  });
});

describe("verifyFragment tamper detection (mirrors Go TestVerify_TamperFailsSignature)", () => {
  it("fails when any signed binding is mutated and re-encoded with the original sig", async () => {
    const sf = await makeSignedFragment();
    const base = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(
          atob(sf.claimsB64.replace(/-/g, "+").replace(/_/g, "/")),
          (c) => c.charCodeAt(0),
        ),
      ),
    ) as Record<string, unknown>;

    const mutations: Array<{
      name: string;
      mutate: (c: Record<string, unknown>) => void;
    }> = [
      {
        name: "cell key",
        mutate: (c) =>
          (c.cell_public_key_b64 = base64UrlEncode(
            new Uint8Array(32).fill(0x77),
          )),
      },
      {
        name: "qurl key",
        mutate: (c) =>
          (c.qurl_user_public_key_b64 = base64UrlEncode(
            new Uint8Array(32).fill(0x66),
          )),
      },
      { name: "exp", mutate: (c) => (c.exp = (base.exp as number) + 1) },
      { name: "nbf", mutate: (c) => (c.nbf = (base.nbf as number) - 1) },
      {
        name: "jti",
        mutate: (c) => (c.jti = (base.jti as string) + "-tampered"),
      },
    ];

    for (const m of mutations) {
      const tampered = { ...base };
      m.mutate(tampered);
      const tamperedB64 = base64UrlEncode(
        new TextEncoder().encode(JSON.stringify(tampered)),
      );
      // Build a fragment with the tampered claims but the ORIGINAL signature.
      const body = `qv2.${tamperedB64}.${sf.secretB64}.${base64UrlEncode(sf.rawSig)}`;
      const frag = parseFragment(body);
      await expect(
        verifyFragment(frag, sf.ts),
        `tampered ${m.name} must fail signature`,
      ).rejects.toThrow(SignatureError);
    }
  });
});

describe("verifyFragment rejects re-serialized claims (mirrors Go TestVerify_ReserializedClaimsRejected)", () => {
  it("a byte-different but semantically-equal claims encoding fails the original sig", async () => {
    // Sign a claims with keys in one order; re-serialize with a DIFFERENT key
    // order and assert the original signature no longer verifies — proving
    // verification is over the received bytes, not a canonical form.
    const orderedJSON = baselineClaimsJSON();
    const claimsB64 = base64UrlEncode(new TextEncoder().encode(orderedJSON));
    const sf = await makeSignedFragment(claimsB64);

    const parsed = JSON.parse(orderedJSON) as Record<string, unknown>;
    // Reverse the key order to force byte-different output.
    const reordered: Record<string, unknown> = {};
    for (const k of Object.keys(parsed).reverse()) {
      reordered[k] = parsed[k];
    }
    const reB64 = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(reordered)),
    );
    expect(reB64).not.toBe(claimsB64);

    const body = `qv2.${reB64}.${sf.secretB64}.${base64UrlEncode(sf.rawSig)}`;
    const frag = parseFragment(body);
    await expect(verifyFragment(frag, sf.ts)).rejects.toThrow(SignatureError);

    // Sanity: the ORIGINAL bytes still verify.
    await expect(parseAndVerifyFragment(sf.body, sf.ts)).resolves.toBeDefined();
  });
});

describe("verifyFragment rejects an unknown kid (mirrors Go TestVerify_UnknownKIDRejected)", () => {
  it("throws UnknownKidError when the signing kid is not in the trust store", async () => {
    const sf = await makeSignedFragment(undefined, "kid-A");
    // A valid trust store that contains a DIFFERENT kid, so the fragment's kid
    // resolves to nothing.
    const otherTs = await trustStoreWithKid("kid-B");
    await expect(parseAndVerifyFragment(sf.body, otherTs)).rejects.toThrow(
      UnknownKidError,
    );
  });
});

/** Builds a trust store holding one fresh, valid P-256 key under `kid`. */
async function trustStoreWithKid(kid: string): Promise<TrustStore> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const der = new Uint8Array(
    await crypto.subtle.exportKey("spki", pair.publicKey),
  );
  return TrustStore.fromSpkiDerB64({ [kid]: base64UrlEncode(der) });
}
