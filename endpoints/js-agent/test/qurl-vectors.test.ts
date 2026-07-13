import { describe, it, expect, beforeAll } from "vitest";
import { issuerSignatureVectors } from "@layervai/qurl-conformance";
import {
  verifyIssuerSignature,
  SignatureHighSError,
  SignatureLengthError,
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
const SIGNATURE_ENCODING_RAW_RS = "raw_r_s";
const SIGNATURE_ENCODING_DER = "der";

// Closed in lockstep with qurl-conformance and the Go leg; adding or re-encoding
// a reject class is a coordinated code change, not just a dependency bump.
const SIGNATURE_REJECT_CLASSES = {
  [REJECT_CLASS_HIGH_S]: {
    error: SignatureHighSError,
    encoding: SIGNATURE_ENCODING_RAW_RS,
  },
  [REJECT_CLASS_WRONG_LENGTH]: {
    error: SignatureLengthError,
    encoding: SIGNATURE_ENCODING_DER,
  },
} as const;
const SIGNATURE_REJECT_CLASS_NAMES = Object.keys(SIGNATURE_REJECT_CLASSES)
  .sort()
  .join(", ");

type SignatureRejectClass = keyof typeof SIGNATURE_REJECT_CLASSES;
type SignaturePayloadField =
  "claims_b64" | "sig_b64" | "sig_encoding" | "signing_input_b64";
const SIGNATURE_VECTOR_FIELDS = new Set([
  "name",
  "expect",
  "reject_class",
  "reason",
  "claims_b64",
  "sig_b64",
  "sig_encoding",
  "signing_input_b64",
]);

interface SignatureVector {
  name: string;
  expect: string;
  reject_class?: string | null;
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
  assertVectorFileShape(vf);
  return vf;
}

function assertVectorFileShape(vf: VectorFile): void {
  if (!vf.vectors || vf.vectors.length === 0) {
    throw new Error(
      "golden-vector fixture from @layervai/qurl-conformance has no vectors",
    );
  }
  const seenNames = new Set<string>();
  for (const v of vf.vectors) {
    const name = assertSignatureVectorShape(v);
    if (seenNames.has(name)) {
      throw new Error(
        `duplicate signature vector name ${JSON.stringify(name)}`,
      );
    }
    seenNames.add(name);
  }
}

function assertSignatureVectorShape(v: SignatureVector): string {
  if (typeof v.name !== "string" || v.name.trim() === "") {
    throw new Error("signature vector has empty name");
  }
  const name = v.name.trim();
  for (const fieldName of Object.keys(v)) {
    if (!SIGNATURE_VECTOR_FIELDS.has(fieldName)) {
      throw new Error(
        `signature vector ${name} has unknown field ${fieldName}`,
      );
    }
  }
  if (typeof v.reason !== "string" || v.reason.trim() === "") {
    throw new Error(`signature vector ${name} has empty reason`);
  }
  const requiredPayloadFields: Array<[SignaturePayloadField, string]> = [
    ["claims_b64", v.claims_b64],
    ["sig_b64", v.sig_b64],
    ["sig_encoding", v.sig_encoding],
    ["signing_input_b64", v.signing_input_b64],
  ];
  for (const [fieldName, value] of requiredPayloadFields) {
    if (typeof value !== "string" || value.trim() === "") {
      throw new Error(`signature vector ${name} has empty ${fieldName}`);
    }
  }
  // Keep the empty-field diagnostic distinct from the closed enum diagnostic.
  if (
    v.sig_encoding !== SIGNATURE_ENCODING_RAW_RS &&
    v.sig_encoding !== SIGNATURE_ENCODING_DER
  ) {
    throw new Error(
      `signature vector ${name} has sig_encoding ${v.sig_encoding}, want ${SIGNATURE_ENCODING_RAW_RS}|${SIGNATURE_ENCODING_DER}`,
    );
  }
  if (v.expect === EXPECT_ACCEPT) {
    if (v.sig_encoding !== SIGNATURE_ENCODING_RAW_RS) {
      throw new Error(
        `accept vector ${name} has sig_encoding ${v.sig_encoding}, want ${SIGNATURE_ENCODING_RAW_RS}`,
      );
    }
    if (v.reject_class !== undefined) {
      throw new Error(
        `accept vector ${name} must not carry reject_class ${JSON.stringify(v.reject_class)}`,
      );
    }
    return name;
  }
  if (v.expect === EXPECT_REJECT) {
    const rejectClassSpec = signatureRejectClassSpecFor(v.reject_class, name);
    if (v.sig_encoding !== rejectClassSpec.encoding) {
      throw new Error(
        `reject vector ${name} with reject_class ${v.reject_class} has sig_encoding ${v.sig_encoding}, want ${rejectClassSpec.encoding}`,
      );
    }
    return name;
  }
  throw new Error(`unknown expect ${v.expect} for ${name}`);
}

function signatureRejectClassSpecFor(
  rejectClass: string | null | undefined,
  name: string,
) {
  if (rejectClass === undefined) {
    throw new Error(`reject vector ${name} must carry reject_class`);
  }
  if (rejectClass === null) {
    throw new Error(`reject vector ${name} has reject_class null`);
  }
  if (rejectClass === "") {
    throw new Error(`reject vector ${name} has reject_class ""`);
  }
  const spec = SIGNATURE_REJECT_CLASSES[rejectClass as SignatureRejectClass];
  if (spec === undefined) {
    throw new Error(
      `reject vector ${name} has reject_class ${JSON.stringify(rejectClass)}, want one of ${SIGNATURE_REJECT_CLASS_NAMES}`,
    );
  }
  return spec;
}

const VALID_SIGNATURE_VECTOR: SignatureVector = {
  name: "accept_valid_low_s",
  expect: EXPECT_ACCEPT,
  reason: "valid signature",
  claims_b64: "claims",
  sig_b64: "sig",
  sig_encoding: "raw_r_s",
  signing_input_b64: "input",
};

function expectBadVector(
  override: Partial<SignatureVector>,
  message: string,
): void {
  const vector = { ...VALID_SIGNATURE_VECTOR, ...override };
  expect(() => assertSignatureVectorShape(vector)).toThrow(message);
}

const VALID_VECTOR_FILE: VectorFile = {
  description: "test fixture",
  algorithm: "test algorithm",
  domain_separation_prefix: DOMAIN_SEPARATION_PREFIX,
  issuer: {
    kid: "kid",
    spki_der_b64: "spki",
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: "x",
      y: "y",
    },
  },
  vectors: [VALID_SIGNATURE_VECTOR],
};

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

  it("rejects malformed vector shapes before verification", () => {
    expectBadVector({ name: "" }, "signature vector has empty name");
    expectBadVector(
      { reason: "" },
      "signature vector accept_valid_low_s has empty reason",
    );
    expectBadVector(
      { name: " accept_valid_low_s ", reason: "" },
      "signature vector accept_valid_low_s has empty reason",
    );
    expectBadVector(
      { unexpected: true } as Partial<SignatureVector>,
      "signature vector accept_valid_low_s has unknown field unexpected",
    );
    expectBadVector(
      { claims_b64: "" },
      "signature vector accept_valid_low_s has empty claims_b64",
    );
    expectBadVector(
      { sig_b64: "" },
      "signature vector accept_valid_low_s has empty sig_b64",
    );
    expectBadVector(
      { sig_encoding: "" },
      "signature vector accept_valid_low_s has empty sig_encoding",
    );
    expectBadVector(
      { sig_encoding: "pem" },
      "signature vector accept_valid_low_s has sig_encoding pem, want raw_r_s|der",
    );
    expectBadVector(
      { sig_encoding: SIGNATURE_ENCODING_DER },
      "accept vector accept_valid_low_s has sig_encoding der, want raw_r_s",
    );
    expectBadVector(
      { signing_input_b64: "" },
      "signature vector accept_valid_low_s has empty signing_input_b64",
    );
    expectBadVector(
      { reject_class: REJECT_CLASS_HIGH_S },
      `accept vector accept_valid_low_s must not carry reject_class "${REJECT_CLASS_HIGH_S}"`,
    );
    expectBadVector(
      { reject_class: "" },
      'accept vector accept_valid_low_s must not carry reject_class ""',
    );
    expectBadVector(
      { reject_class: null },
      "accept vector accept_valid_low_s must not carry reject_class null",
    );
    expectBadVector(
      { expect: EXPECT_REJECT },
      "reject vector accept_valid_low_s must carry reject_class",
    );
    expectBadVector(
      { expect: EXPECT_REJECT, reject_class: null },
      "reject vector accept_valid_low_s has reject_class null",
    );
    expectBadVector(
      { expect: EXPECT_REJECT, reject_class: "" },
      'reject vector accept_valid_low_s has reject_class ""',
    );
    expectBadVector(
      { expect: EXPECT_REJECT, reject_class: 123 as unknown as string },
      "reject vector accept_valid_low_s has reject_class 123, want one of high_s, wrong_length",
    );
    expectBadVector(
      { expect: EXPECT_REJECT, reject_class: "bogus" },
      'reject vector accept_valid_low_s has reject_class "bogus", want one of high_s, wrong_length',
    );
    expectBadVector(
      {
        expect: EXPECT_REJECT,
        reject_class: REJECT_CLASS_HIGH_S,
        sig_encoding: SIGNATURE_ENCODING_DER,
      },
      "reject vector accept_valid_low_s with reject_class high_s has sig_encoding der, want raw_r_s",
    );
    expectBadVector(
      {
        expect: EXPECT_REJECT,
        reject_class: REJECT_CLASS_WRONG_LENGTH,
        sig_encoding: SIGNATURE_ENCODING_RAW_RS,
      },
      "reject vector accept_valid_low_s with reject_class wrong_length has sig_encoding raw_r_s, want der",
    );
    expect(() =>
      assertSignatureVectorShape({
        ...VALID_SIGNATURE_VECTOR,
        expect: EXPECT_REJECT,
        reject_class: REJECT_CLASS_WRONG_LENGTH,
        sig_encoding: SIGNATURE_ENCODING_DER,
      }),
    ).not.toThrow();
  });

  it("rejects duplicate vector names before verification", () => {
    expect(() =>
      assertVectorFileShape({
        ...VALID_VECTOR_FILE,
        vectors: [
          VALID_SIGNATURE_VECTOR,
          {
            ...VALID_SIGNATURE_VECTOR,
            reason: "another vector with the same name",
          },
        ],
      }),
    ).toThrow('duplicate signature vector name "accept_valid_low_s"');
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
        const ExpectedError = signatureRejectClassSpecFor(
          v.reject_class,
          v.name,
        ).error;
        expect(
          threw instanceof ExpectedError,
          `${v.reject_class} vector expected ${ExpectedError.name}, got ${String(threw)}`,
        ).toBe(true);
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
