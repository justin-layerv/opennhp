import { describe, it, expect, beforeAll } from "vitest";
import { issuerSignatureVectors } from "@layervai/qurl-conformance";
import {
  verifyIssuerSignature,
  SignatureHighSError,
  SignatureLengthError,
  SignatureError,
} from "../src/qurl/signature";
import {
  TrustStore,
  importIssuerKeyFromJwk,
  type EcPublicJwk,
} from "../src/qurl/truststore";
import { signingInputB64 } from "../src/qurl/claims";
import { base64UrlDecode, base64UrlEncode } from "../src/qurl/base64url";
import { parseAndVerifyFragment } from "../src/qurl/fragment";

// THE WEBCRYPTO LEG OF THE Go<->JS GOLDEN-VECTOR CONTRACT.
//
// This consumes the EXACT same fixture as the Go verifier — the issuer-signature
// vectors from the pinned @layervai/qurl-conformance package — and proves
// WebCrypto verification agrees with Go on the pinned P-256 raw r||s low-S wire
// encoding. The two divergence points it pins:
//   - the 0x00 domain separator (signing_input_b64 cross-check), and
//   - high-S rejection (WebCrypto's raw ECDSA accepts high-S; the JS gate must
//     reject it) plus wrong-length DER rejection.
//
// It FAILS (never skips) if the fixture is missing/unparseable, so the contract
// can never silently drop out of CI — mirrors Go's LoadVectorFile + the always-run
// TestGoldenVectors_Consume.

const EXPECT_ACCEPT = "accept";
const EXPECT_REJECT = "reject";
const REJECT_CLASS_HIGH_S = "high_s";
const REJECT_CLASS_WRONG_LENGTH = "wrong_length";
const DOMAIN_SEPARATION_PREFIX = "NHP-QURL-V2-ISSUER";

interface SignatureVector {
  name: string;
  expect: string;
  reason: string;
  claims_b64: string;
  sig_b64: string;
  sig_encoding: string;
  signing_input_b64: string;
}

interface VectorFile {
  description: string;
  algorithm: string;
  domain_separation_prefix: string;
  issuer: {
    kid: string;
    spki_der_b64: string;
    jwk: EcPublicJwk;
  };
  vectors: SignatureVector[];
}

function loadVectorFile(): VectorFile {
  // The bytes come from the pinned @layervai/qurl-conformance package (the same
  // bytes the Go verifier embeds). A missing import fails loudly on its own —
  // this is the contract, not an optional fixture. (Go's LoadVectorFile errors
  // rather than returning empty.)
  const vf = issuerSignatureVectors() as VectorFile;
  if (!vf.vectors || vf.vectors.length === 0) {
    throw new Error(
      "golden-vector fixture from @layervai/qurl-conformance has no vectors",
    );
  }
  return vf;
}

describe("qURL v2 issuer-signature golden vectors (WebCrypto leg)", () => {
  let vf: VectorFile;
  let ts: TrustStore;
  let key: CryptoKey;

  beforeAll(async () => {
    vf = loadVectorFile();
    // Structural pin so a JS port can rely on the separator (the most likely
    // place WebCrypto diverges).
    expect(vf.domain_separation_prefix).toBe(DOMAIN_SEPARATION_PREFIX);

    ts = await TrustStore.fromSpkiDerB64({
      [vf.issuer.kid]: vf.issuer.spki_der_b64,
    });
    key = ts.publicKeyForKid(vf.issuer.kid);
  });

  it("loads the shared fixture and pins its kid", () => {
    expect(vf.issuer.kid).toBeTruthy();
    expect(vf.vectors.length).toBeGreaterThanOrEqual(3);
  });

  it("verifies every vector exactly as the fixture declares (SPKI-DER key)", async () => {
    for (const v of vf.vectors) {
      // Cross-check: the signing input the fixture pins MUST equal the input
      // reconstructed from prefix + 0x00 + claims_b64. This is the check the
      // Go test performs on its own reconstruction (TestGoldenVectors_Consume).
      expect(signingInputB64(v.claims_b64), `signing_input for ${v.name}`).toBe(
        v.signing_input_b64,
      );

      const rawSig = base64UrlDecode(v.sig_b64);

      if (v.expect === EXPECT_ACCEPT) {
        await expect(
          verifyIssuerSignature(key, v.claims_b64, rawSig),
          `accept vector ${v.name} must verify`,
        ).resolves.toBeUndefined();
      } else if (v.expect === EXPECT_REJECT) {
        let threw: unknown;
        try {
          await verifyIssuerSignature(key, v.claims_b64, rawSig);
        } catch (e) {
          threw = e;
        }
        expect(threw, `reject vector ${v.name} must throw`).toBeDefined();
        // Map the documented rejection class to the exact error subtype, the way
        // Go's assertRejectClass maps to its sentinels.
        if (v.reason === REJECT_CLASS_HIGH_S) {
          expect(
            threw instanceof SignatureHighSError,
            `high-S vector expected SignatureHighSError, got ${String(threw)}`,
          ).toBe(true);
        } else if (v.reason === REJECT_CLASS_WRONG_LENGTH) {
          expect(
            threw instanceof SignatureLengthError,
            `wrong-length vector expected SignatureLengthError, got ${String(threw)}`,
          ).toBe(true);
        } else {
          expect(
            threw instanceof SignatureError,
            `reject vector ${v.name} expected SignatureError, got ${String(threw)}`,
          ).toBe(true);
        }
      } else {
        throw new Error(`unknown expect ${v.expect} for ${v.name}`);
      }
    }
  });

  it("verifies the accept vector through the full parseAndVerify fragment path", async () => {
    const accept = vf.vectors.find((v) => v.expect === EXPECT_ACCEPT);
    expect(accept, "fixture must have an accept vector").toBeDefined();
    // Build a full fragment around the accept claims/sig with a valid 32-byte
    // secret, and run the public entry point — proving the accept vector passes
    // the mandatory client path, not just the raw verifier.
    const privKeyB64 = base64UrlEncode(new Uint8Array(32).fill(9));
    const secretB64 = base64UrlEncode(
      new TextEncoder().encode(`{"qurl_user_private_key_b64":"${privKeyB64}"}`),
    );
    const body = `qv2.${accept!.claims_b64}.${secretB64}.${accept!.sig_b64}`;
    const frag = await parseAndVerifyFragment(`#${body}`, ts);
    expect(frag.claims.iss).toBe("qurl-service");
    expect(frag.claimsB64).toBe(accept!.claims_b64);
  });

  it("imports the issuer key from the fixture JWK and verifies the accept vector", async () => {
    // Mirrors Go's TestGoldenVectors_JWKMatchesSPKI: the JWK x/y must be
    // fixed-width 32-byte base64url (leading zeros preserved) or a strict
    // importKey rejects them. Verifying the accept vector with the JWK-derived
    // key catches a short-coordinate bug.
    expect(vf.issuer.jwk.kty).toBe("EC");
    expect(vf.issuer.jwk.crv).toBe("P-256");
    expect(base64UrlDecode(vf.issuer.jwk.x).length).toBe(32);
    expect(base64UrlDecode(vf.issuer.jwk.y).length).toBe(32);

    const jwkKey = await importIssuerKeyFromJwk(vf.issuer.jwk);
    const accept = vf.vectors.find((v) => v.expect === EXPECT_ACCEPT)!;
    await expect(
      verifyIssuerSignature(
        jwkKey,
        accept.claims_b64,
        base64UrlDecode(accept.sig_b64),
      ),
    ).resolves.toBeUndefined();
  });
});
