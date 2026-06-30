import { describe, it, expect } from "vitest";
import { parseClaims, parseSecret } from "../src/qurl/parse";
import { base64UrlEncode, Base64UrlError } from "../src/qurl/base64url";
import { KeyLengthError, StrictParseError } from "../src/qurl/claims";

// Strict-parser tests — the browser/headless port of the Go enumeration in
// `qurl-service` internal/qurlv2/parse_test.go. Each rejection case mirrors a Go
// case so the owner can compare them 1:1, and the strict-base64 (non-canonical /
// padded / alphabet) coverage matches strict_b64_test.go at the field layer.

/** A deterministic 32-byte (X25519-shaped) base64url key, like Go testX25519B64. */
function x25519B64(seed: number): string {
  return base64UrlEncode(new Uint8Array(32).fill(seed));
}

/** A length-window-valid resource public key (91 bytes, the canonical KMS SPKI
 * length). The parser only length-checks the resource key, so the exact bytes are
 * irrelevant here — only the 80..160 window matters. */
function resourceKeyB64(): string {
  const der = new Uint8Array(91);
  for (let i = 0; i < der.length; i += 1) der[i] = (i * 7 + 3) & 0xff;
  return base64UrlEncode(der);
}

/** A canonical, schema-valid claims JSON string — the baseline the tests perturb,
 * matching Go validClaimsJSON's exact field order so substring replaces line up. */
function validClaimsJSON(): string {
  return (
    `{` +
    `"v":2,` +
    `"iss":"qurl-service",` +
    `"kid":"qurl-issuer-key-2026-06",` +
    `"iat":1781910000,` +
    `"nbf":1781910000,` +
    `"exp":1781910300,` +
    `"jti":"qurl_01JABCDEF",` +
    `"cell_public_key_b64":"${x25519B64(1)}",` +
    `"cell_id":"cell-a",` +
    `"relay_url":"https://relay.example.com",` +
    `"resource_public_key_b64":"${resourceKeyB64()}",` +
    `"qurl_user_public_key_b64":"${x25519B64(2)}"` +
    `}`
  );
}

describe("parseClaims valid", () => {
  it("parses a schema-valid claims object", () => {
    const c = parseClaims(validClaimsJSON());
    expect(c.v).toBe(2);
    expect(c.iss).toBe("qurl-service");
    expect(c.kid).toBe("qurl-issuer-key-2026-06");
    expect(c.exp).toBe(1781910300);
    expect(c.cellId).toBe("cell-a");
  });

  it("treats cell_id as optional (absent → undefined, still parses)", () => {
    const base = validClaimsJSON();
    const absent = base.replace(`"cell_id":"cell-a",`, "");
    expect(absent).not.toBe(base);
    const c = parseClaims(absent);
    expect(c.cellId).toBeUndefined();
  });

  it("normalizes a present-but-empty cell_id to undefined (indistinguishable from absent)", () => {
    // present-empty and absent must be INDISTINGUISHABLE downstream (an
    // `=== undefined` check, not only a truthy check), matching the Go side.
    const base = validClaimsJSON();
    const presentEmpty = base.replace(`"cell_id":"cell-a",`, `"cell_id":"",`);
    expect(presentEmpty).not.toBe(base);
    const c = parseClaims(presentEmpty);
    expect(c.cellId).toBeUndefined();
  });
});

describe("parseClaims strict rejections (mirrors Go TestParseClaims_StrictRejections)", () => {
  const base = validClaimsJSON();
  const cases: Array<{ name: string; json: string }> = [
    { name: "duplicate key", json: base.replace(`"v":2,`, `"v":2,"v":2,`) },
    {
      name: "unknown field",
      json: base.replace(
        `"cell_id":"cell-a",`,
        `"cell_id":"cell-a","extra":"x",`,
      ),
    },
    {
      name: "null required value",
      json: base.replace(`"jti":"qurl_01JABCDEF",`, `"jti":null,`),
    },
    {
      name: "missing required",
      json: base.replace(`"jti":"qurl_01JABCDEF",`, ``),
    },
    {
      name: "float time",
      json: base.replace(`"exp":1781910300,`, `"exp":1781910300.0,`),
    },
    {
      name: "exponent time",
      json: base.replace(`"exp":1781910300,`, `"exp":1.7e9,`),
    },
    {
      name: "string time",
      json: base.replace(`"exp":1781910300,`, `"exp":"1781910300",`),
    },
    {
      name: "negative time",
      json: base.replace(`"nbf":1781910000,`, `"nbf":-1,`),
    },
    {
      // exp:0 — the parser rejects 0 ("required and must be non-zero").
      name: "zero time",
      json: base.replace(`"exp":1781910300,`, `"exp":0,`),
    },
    {
      // leading-zero integer is not canonical JSON / rejected by INTEGER_LITERAL.
      name: "leading-zero time",
      json: base.replace(`"exp":1781910300,`, `"exp":01781910300,`),
    },
    {
      // over MAX_UNIX_SECONDS (9_999_999_999) — out of the allowed range.
      name: "over-max time",
      json: base.replace(`"exp":1781910300,`, `"exp":10000000000,`),
    },
    {
      name: "array for scalar",
      json: base.replace(`"jti":"qurl_01JABCDEF",`, `"jti":["x"],`),
    },
    { name: "wrong version", json: base.replace(`"v":2,`, `"v":1,`) },
    {
      name: "nbf after exp",
      json: base.replace(`"nbf":1781910000,`, `"nbf":1781920000,`),
    },
    {
      name: "iat after exp",
      json: base.replace(`"iat":1781910000,`, `"iat":1781920000,`),
    },
    {
      name: "empty kid",
      json: base.replace(`"kid":"qurl-issuer-key-2026-06",`, `"kid":"",`),
    },
    {
      name: "empty jti",
      json: base.replace(`"jti":"qurl_01JABCDEF",`, `"jti":"",`),
    },
    {
      name: "empty relay_url",
      json: base.replace(
        `"relay_url":"https://relay.example.com",`,
        `"relay_url":"",`,
      ),
    },
    {
      name: "short cell key",
      json: base.replace(
        `"cell_public_key_b64":"${x25519B64(1)}"`,
        `"cell_public_key_b64":"AAAA"`,
      ),
    },
    { name: "top-level array", json: `[${base}]` },
    { name: "trailing data", json: `${base}{}` },
  ];

  for (const tc of cases) {
    it(`rejects ${tc.name}`, () => {
      let threw: unknown;
      try {
        parseClaims(tc.json);
      } catch (e) {
        threw = e;
      }
      expect(threw, `expected rejection for ${tc.name}`).toBeDefined();
      // Mirror Go: a strict-parse, key-length, or encoding error are all acceptable.
      const ok =
        threw instanceof StrictParseError ||
        threw instanceof KeyLengthError ||
        threw instanceof Base64UrlError;
      expect(ok, `unexpected error type for ${tc.name}: ${String(threw)}`).toBe(
        true,
      );
    });
  }
});

describe("parseClaims rejects non-canonical key fields (mirrors strict_b64_test.go)", () => {
  // A non-canonical 32-byte-key variant: flip the lowest sextet bit of the final
  // char. atob would accept it; the strict field decoder must reject it.
  function nonCanonical(canon: string): string {
    const alpha =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = canon[canon.length - 1]!;
    return canon.slice(0, -1) + alpha[alpha.indexOf(last) ^ 1]!;
  }

  it("rejects a non-canonical cell_public_key_b64", () => {
    const canon = x25519B64(1);
    const json = validClaimsJSON().replace(canon, nonCanonical(canon));
    expect(() => parseClaims(json)).toThrow(Base64UrlError);
  });

  it("rejects a non-canonical qurl_user_public_key_b64", () => {
    const canon = x25519B64(2);
    const json = validClaimsJSON().replace(canon, nonCanonical(canon));
    expect(() => parseClaims(json)).toThrow(Base64UrlError);
  });
});

describe("parseSecret (mirrors Go TestParseSecret_*)", () => {
  const secretJSON = (privB64: string): string =>
    `{"qurl_user_private_key_b64":"${privB64}"}`;

  it("parses a valid secret", () => {
    const s = parseSecret(secretJSON(x25519B64(9)));
    expect(s.qurlUserPrivateKeyB64).toBe(x25519B64(9));
  });

  const rejects: Array<{ name: string; json: string; wantKeyLen?: boolean }> = [
    {
      name: "unknown field",
      json: `{"qurl_user_private_key_b64":"AAAA","x":1}`,
    },
    { name: "missing required", json: `{}` },
    {
      name: "duplicate key",
      json: `{"qurl_user_private_key_b64":"AAAA","qurl_user_private_key_b64":"BBBB"}`,
    },
    { name: "null value", json: `{"qurl_user_private_key_b64":null}` },
    {
      name: "bad base64url",
      json: `{"qurl_user_private_key_b64":"not base64!!"}`,
    },
    {
      name: "short private key (3 bytes)",
      json: secretJSON(base64UrlEncode(new Uint8Array([1, 2, 3]))),
      wantKeyLen: true,
    },
    {
      name: "short private key (31 bytes)",
      json: secretJSON(base64UrlEncode(new Uint8Array(31))),
      wantKeyLen: true,
    },
    {
      name: "long private key (33 bytes)",
      json: secretJSON(base64UrlEncode(new Uint8Array(33))),
      wantKeyLen: true,
    },
    {
      name: "long private key (64 bytes)",
      json: secretJSON(base64UrlEncode(new Uint8Array(64))),
      wantKeyLen: true,
    },
  ];

  for (const tc of rejects) {
    it(`rejects ${tc.name}`, () => {
      let threw: unknown;
      try {
        parseSecret(tc.json);
      } catch (e) {
        threw = e;
      }
      expect(threw, `expected rejection for ${tc.name}`).toBeDefined();
      if (tc.wantKeyLen) {
        expect(
          threw instanceof KeyLengthError,
          `expected KeyLengthError for ${tc.name}, got ${String(threw)}`,
        ).toBe(true);
      }
    });
  }
});
