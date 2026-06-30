import { describe, it, expect } from "vitest";
import {
  assertCanonicalRawSignature,
  verifyIssuerSignature,
  SignatureLengthError,
  SignatureHighSError,
  SignatureScalarRangeError,
} from "../src/qurl/signature";
import {
  makeSignedFragment,
  N,
  HALF_ORDER,
  SCALAR_BYTES,
  bigIntToBe32,
  beToBigInt,
} from "./qurl-signed-fragment";
import { base64UrlDecode, base64UrlEncode } from "../src/qurl/base64url";
import { signingInput } from "../src/qurl/claims";

/** Decodes a base64url claims part to its raw JSON bytes. */
function decodeClaims(claimsB64: string): Uint8Array {
  return base64UrlDecode(claimsB64);
}

describe("assertCanonicalRawSignature (the gate WebCrypto omits)", () => {
  // ANTI-TRANSCRIPTION GUARD: signature.ts pins N as a literal (to keep the full
  // P-256 curve out of the size-budgeted bundle). This test pins that literal to
  // @noble/curves' authoritative N via the exact low-S BOUNDARY: s == N/2 must be
  // accepted (low-S) and s == N/2 + 1 must be rejected (high-S). If the literal
  // drifted from the real order, this boundary would shift and the test would
  // fail. r is fixed to 1 (in range) so only s is under test.
  it("pins the low-S threshold to @noble/curves' N (s==N/2 ok, s==N/2+1 high-S)", () => {
    const r = bigIntToBe32(1n);
    const atHalf = new Uint8Array(64);
    atHalf.set(r, 0);
    atHalf.set(bigIntToBe32(HALF_ORDER), SCALAR_BYTES);
    expect(() => assertCanonicalRawSignature(atHalf)).not.toThrow();

    const overHalf = new Uint8Array(64);
    overHalf.set(r, 0);
    overHalf.set(bigIntToBe32(HALF_ORDER + 1n), SCALAR_BYTES);
    expect(() => assertCanonicalRawSignature(overHalf)).toThrow(
      SignatureHighSError,
    );
  });

  it("accepts a valid 64-byte low-S signature", async () => {
    const sf = await makeSignedFragment();
    expect(() => assertCanonicalRawSignature(sf.rawSig)).not.toThrow();
  });

  it("rejects a non-64-byte signature (the wrong-length DER mistake)", () => {
    expect(() => assertCanonicalRawSignature(new Uint8Array(63))).toThrow(
      SignatureLengthError,
    );
    expect(() => assertCanonicalRawSignature(new Uint8Array(72))).toThrow(
      SignatureLengthError,
    );
  });

  it("rejects a high-S signature even though WebCrypto would accept it", async () => {
    const sf = await makeSignedFragment();
    // Flip the low-S signature back to high-S: s' = N - s.
    const r = sf.rawSig.subarray(0, SCALAR_BYTES);
    const s = beToBigInt(sf.rawSig.subarray(SCALAR_BYTES));
    const highS = N - s;
    expect(highS > HALF_ORDER).toBe(true);
    const tampered = new Uint8Array(64);
    tampered.set(r, 0);
    tampered.set(bigIntToBe32(highS), SCALAR_BYTES);
    expect(() => assertCanonicalRawSignature(tampered)).toThrow(
      SignatureHighSError,
    );

    // And prove WebCrypto's raw verify WOULD accept the high-S form — i.e. the
    // gate is load-bearing, not redundant. crypto.subtle.verify is malleable.
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      sf.ts.publicKeyForKid(sf.kid),
      new Uint8Array(tampered),
      // Reconstruct the signing input bytes for the accept claims.
      new Uint8Array(signingInput(sf.claimsB64)),
    );
    expect(
      ok,
      "WebCrypto raw ECDSA must accept high-S (proving our gate matters)",
    ).toBe(true);
  });

  it("rejects a zero scalar (r=0 or s=0)", () => {
    const zeroR = new Uint8Array(64);
    zeroR.set(bigIntToBe32(1n), SCALAR_BYTES); // s=1, r=0
    expect(() => assertCanonicalRawSignature(zeroR)).toThrow(
      SignatureScalarRangeError,
    );
    const zeroS = new Uint8Array(64);
    zeroS.set(bigIntToBe32(1n), 0); // r=1, s=0
    expect(() => assertCanonicalRawSignature(zeroS)).toThrow(
      SignatureScalarRangeError,
    );
  });

  it("rejects an out-of-range scalar (s >= N)", () => {
    const r = bigIntToBe32(1n);
    const sAtN = bigIntToBe32(N); // s == N, out of [1, N-1]
    const sig = new Uint8Array(64);
    sig.set(r, 0);
    sig.set(sAtN, SCALAR_BYTES);
    expect(() => assertCanonicalRawSignature(sig)).toThrow(
      SignatureScalarRangeError,
    );
  });
});

describe("verifyIssuerSignature", () => {
  it("verifies a freshly signed fragment over the exact claims bytes", async () => {
    const sf = await makeSignedFragment();
    await expect(
      verifyIssuerSignature(
        sf.ts.publicKeyForKid(sf.kid),
        sf.claimsB64,
        sf.rawSig,
      ),
    ).resolves.toBeUndefined();
  });

  it("fails when the claims bytes differ from what was signed", async () => {
    const sf = await makeSignedFragment();
    // Verify sf's signature against a one-byte-different claims encoding (append a
    // space inside the JSON so it stays valid base64 but is different bytes). The
    // signature is over the original bytes, so this must fail.
    const tamperedClaims = base64UrlEncode(
      new TextEncoder().encode(
        new TextDecoder().decode(decodeClaims(sf.claimsB64)) + " ",
      ),
    );
    expect(tamperedClaims).not.toBe(sf.claimsB64);
    await expect(
      verifyIssuerSignature(
        sf.ts.publicKeyForKid(sf.kid),
        tamperedClaims,
        sf.rawSig,
      ),
    ).rejects.toThrow();
  });

  it("fails for a wrong-length signature before any curve check", async () => {
    const sf = await makeSignedFragment();
    await expect(
      verifyIssuerSignature(
        sf.ts.publicKeyForKid(sf.kid),
        sf.claimsB64,
        new Uint8Array(70),
      ),
    ).rejects.toThrow(SignatureLengthError);
  });
});
