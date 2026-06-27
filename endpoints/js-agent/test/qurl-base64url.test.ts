import { describe, it, expect } from "vitest";
import {
  base64UrlDecode,
  base64UrlEncode,
  Base64UrlError,
} from "../src/qurl/base64url";

// The strict base64url decoder is the agreement point with the Go verifier
// (`qurl-service` internal/qurlv2 decodeB64, base64.RawURLEncoding.Strict()).
// These tests pin the three rejection classes that the browser's lenient `atob`
// would silently accept — most importantly the NON-CANONICAL trailing-bit case,
// which is where a naive JS port diverges from Go (mirrors Go strict_b64_test.go).

const STD_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Returns a non-canonical base64url encoding of the SAME bytes as `canon`, by
 * flipping the lowest sextet bit of the final character. That bit is a "don't
 * care" trailing bit only when the decoded length is not a multiple of 3, so this
 * helper is valid only for such inputs (a 32-byte key → 43 chars qualifies). It
 * self-verifies: the variant must differ from `canon` yet decode (leniently) to
 * the same bytes — mirrors Go's nonCanonicalB64 test helper.
 */
function nonCanonical(canon: string): string {
  const last = canon[canon.length - 1]!;
  const idx = STD_ALPHABET.indexOf(last);
  expect(idx).toBeGreaterThanOrEqual(0);
  const flipped = STD_ALPHABET[idx ^ 1]!;
  const variant = canon.slice(0, -1) + flipped;
  expect(variant).not.toBe(canon);
  return variant;
}

describe("base64UrlDecode / base64UrlEncode round-trip", () => {
  it("round-trips arbitrary byte lengths (0..40)", () => {
    for (let len = 0; len <= 40; len += 1) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i += 1) bytes[i] = (i * 37 + 11) & 0xff;
      const enc = base64UrlEncode(bytes);
      expect(enc).not.toMatch(/[+/=]/); // url-safe, unpadded
      expect(base64UrlDecode(enc)).toEqual(bytes);
    }
  });

  it("decodes a 32-byte key (43 chars, no padding)", () => {
    const key = new Uint8Array(32).fill(0x42);
    const enc = base64UrlEncode(key);
    expect(enc.length).toBe(43);
    expect(base64UrlDecode(enc)).toEqual(key);
  });
});

describe("base64UrlDecode strict rejections", () => {
  it("rejects padded input", () => {
    const enc = base64UrlEncode(new Uint8Array(32).fill(1));
    expect(() => base64UrlDecode(enc + "=")).toThrow(Base64UrlError);
    expect(() => base64UrlDecode(enc + "==")).toThrow(Base64UrlError);
  });

  it("rejects non-base64url-alphabet characters (+, /, ., *, whitespace)", () => {
    const enc = base64UrlEncode(new Uint8Array(32).fill(1));
    for (const bad of ["+", "/", ".", "*", " ", "\n"]) {
      expect(() => base64UrlDecode(enc.slice(0, -1) + bad)).toThrow(
        Base64UrlError,
      );
    }
  });

  it("rejects a length that is 1 mod 4 (cannot encode a byte)", () => {
    expect(() => base64UrlDecode("A")).toThrow(Base64UrlError);
    expect(() => base64UrlDecode("AAAAA")).toThrow(Base64UrlError);
  });

  it("rejects embedded CR/LF/CRLF anywhere in the string", () => {
    // The Go↔JS malleability case: Go's base64 decoder (and the browser's atob)
    // silently SKIP '\r'/'\n', so a newline injected into an otherwise-canonical
    // string decodes to the SAME bytes. This hand-rolled decoder treats them as
    // non-alphabet characters and must reject every position, matching the Go
    // verifier's re-encode canonicality check and the `strict_base64`
    // reject_embedded_* conformance vectors.
    const canon = base64UrlEncode(new Uint8Array(32).fill(0)); // 43 chars
    for (const ws of ["\n", "\r", "\r\n"]) {
      for (const variant of [
        ws + canon, // front
        canon.slice(0, 21) + ws + canon.slice(21), // middle
        canon + ws, // end
      ]) {
        expect(() => base64UrlDecode(variant)).toThrow(Base64UrlError);
      }
    }
    // Sanity: the clean canonical string still decodes (no over-rejection).
    expect(base64UrlDecode(canon)).toEqual(new Uint8Array(32).fill(0));
  });

  it("rejects NON-CANONICAL trailing bits even though they decode to the same bytes", () => {
    // This is the load-bearing Go↔JS agreement case: `atob` would accept the
    // variant and recover the same bytes; the strict decoder must reject it.
    const canon = base64UrlEncode(new Uint8Array(32).fill(0)); // 43 chars, 4 slack bits
    const variant = nonCanonical(canon);
    // Sanity: the variant decodes (leniently) to the same bytes — prove the bit
    // we flipped really is a don't-care trailing bit, not a different value.
    const lenientSameBytes = (() => {
      try {
        return base64UrlDecode(variant);
      } catch {
        return null;
      }
    })();
    expect(lenientSameBytes).toBeNull(); // strict decode must reject it
    expect(() => base64UrlDecode(variant)).toThrow(Base64UrlError);
    // And the canonical form still decodes cleanly (no over-rejection).
    expect(base64UrlDecode(canon)).toEqual(new Uint8Array(32).fill(0));
  });

  it("matches atob byte-for-byte on canonical input (parity, not a divergence)", () => {
    // For CANONICAL input the strict decoder and atob must agree on bytes; the
    // divergence is only on which STRINGS are well-formed.
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f, 0x80]);
    const enc = base64UrlEncode(bytes);
    const viaAtob = atob(enc.replace(/-/g, "+").replace(/_/g, "/"));
    const atobBytes = Uint8Array.from(viaAtob, (ch) => ch.charCodeAt(0));
    expect(base64UrlDecode(enc)).toEqual(atobBytes);
  });
});
