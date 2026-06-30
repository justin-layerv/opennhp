// ECDSA P-256 signature handling for the pinned qURL v2 wire format — the
// browser/headless port of the Go verifier (`qurl-service` internal/qurlv2/
// signature.go), kept rule-for-rule identical so the two agree on the golden
// vectors.
//
// The pinned wire signature is fixed-width raw r||s: exactly 64 bytes, each of r
// and s big-endian 32 bytes, with s low-S normalized (s <= N/2). The verifier
// MUST reject any signature that is not exactly 64 bytes, has a scalar outside
// [1, N-1], or is not low-S — BEFORE the curve check — so the encoding is
// enforced and not merely expected.
//
// CRITICAL Go<->JS divergence: WebCrypto's `crypto.subtle.verify` implements raw
// (malleable) ECDSA — it returns true for BOTH low-S and high-S signatures. So
// the low-S and scalar-range gates below cannot be delegated to WebCrypto; they
// are enforced here in JS around the WebCrypto call. The wrong-length DER vector
// is rejected by the same 64-byte gate before verify. (The actual curve
// verification stays on WebCrypto per the slice's contract; this module only adds
// the encoding gate WebCrypto omits.)
import { signingInput } from "./claims.js";

/** Exact length of a raw r||s P-256 signature. */
const P256_SIGNATURE_BYTES = 64;
/** Fixed big-endian width of each of r and s for P-256. */
const P256_SCALAR_BYTES = 32;

/**
 * P-256 group order N (the SEC 2 / FIPS 186-4 prime-order subgroup order).
 *
 * Pinned as a literal rather than read from `@noble/curves` ON PURPOSE: this is a
 * size-budgeted, SRI-pinned browser bundle, and importing `@noble/curves/nist.js`
 * here just to read `p256.Point.Fn.ORDER` would force esbuild to retain the entire
 * P-256 curve construction (nist.js is not otherwise in the bundle — dh.ts pulls
 * x25519 from the `ed25519.js` subpath), several KB for a single scalar. The
 * anti-transcription guard lives in the Node-only test (`qurl-signature.test.ts`),
 * which asserts this constant equals `p256.Point.Fn.ORDER` at zero bundle cost.
 */
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** Low-S threshold: a signature is low-S iff s <= N/2. Computed once at load. */
const HALF_ORDER: bigint = N >> 1n;

/**
 * Thrown when issuer-signature verification fails for any reason. Subtypes below
 * mirror the Go sentinels (ErrSignatureLength / ErrSignatureHighS /
 * ErrSignatureScalarRange) so consumers and the golden-vector test can match the
 * exact rejection class.
 */
export class SignatureError extends Error {
  constructor(message: string) {
    super(`qurlv2: issuer signature verification failed: ${message}`);
    this.name = "SignatureError";
  }
}

/** The wire signature is not exactly 64 bytes (raw r||s). Mirrors ErrSignatureLength. */
export class SignatureLengthError extends SignatureError {
  constructor(got: number) {
    super(
      `wire signature must be exactly ${P256_SIGNATURE_BYTES} bytes (raw r||s), got ${got}`,
    );
    this.name = "SignatureLengthError";
  }
}

/** s is not low-S normalized (s > N/2). Mirrors ErrSignatureHighS. */
export class SignatureHighSError extends SignatureError {
  constructor() {
    super("signature is not low-S normalized");
    this.name = "SignatureHighSError";
  }
}

/** r or s is not in [1, N-1]. Mirrors ErrSignatureScalarRange. */
export class SignatureScalarRangeError extends SignatureError {
  constructor() {
    super("signature scalar out of range [1, N-1]");
    this.name = "SignatureScalarRangeError";
  }
}

/** Big-endian decode of a fixed-width scalar to a bigint. */
function beToBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) {
    acc = (acc << 8n) | BigInt(b);
  }
  return acc;
}

/** True iff x is a valid ECDSA scalar in [1, N-1]. */
function scalarInRange(x: bigint): boolean {
  return x > 0n && x < N;
}

/**
 * Validates a 64-byte raw r||s wire signature, enforcing the full verifier
 * contract — exact length, scalars in [1, N-1], and low-S — and returns the raw
 * bytes unchanged (the form WebCrypto's P1363 verify consumes). A high-S,
 * wrong-length, or out-of-range signature throws here BEFORE any curve math, so
 * the pinned encoding is enforced and not merely expected. This is the gate
 * WebCrypto itself does not apply.
 */
export function assertCanonicalRawSignature(rawSig: Uint8Array): Uint8Array {
  if (rawSig.length !== P256_SIGNATURE_BYTES) {
    throw new SignatureLengthError(rawSig.length);
  }
  const r = beToBigInt(rawSig.subarray(0, P256_SCALAR_BYTES));
  const s = beToBigInt(rawSig.subarray(P256_SCALAR_BYTES));
  if (!scalarInRange(r) || !scalarInRange(s)) {
    throw new SignatureScalarRangeError();
  }
  if (s > HALF_ORDER) {
    // High-S: reject, do NOT normalize. Normalizing s -> N-s would make the
    // malleable variant verify, defeating the pinned low-S contract (and the
    // golden-vector high-S rejection).
    throw new SignatureHighSError();
  }
  return rawSig;
}

/**
 * Verifies a raw r||s wire signature over the qURL v2 signing input for
 * `claimsB64` using an imported P-256 public `key`.
 *
 * Order of operations (matters): the canonical-encoding gate
 * ({@link assertCanonicalRawSignature}) runs FIRST — rejecting non-64-byte,
 * out-of-range, and high-S signatures — then WebCrypto performs the ECDSA curve
 * check over the signing-input BYTES (prefix + 0x00 + exact claims bytes), which
 * it hashes with SHA-256 internally. We deliberately pass the pre-hash input, not
 * a digest. Returns nothing on success; throws {@link SignatureError} otherwise.
 */
export async function verifyIssuerSignature(
  key: CryptoKey,
  claimsB64: string,
  rawSig: Uint8Array,
): Promise<void> {
  const canonical = assertCanonicalRawSignature(rawSig);
  const input = signingInput(claimsB64);
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    // Fresh ArrayBuffer-backed copies: BufferSource rejects views whose backing
    // buffer may be a SharedArrayBuffer. Both are small.
    new Uint8Array(canonical),
    new Uint8Array(input),
  );
  if (!ok) {
    throw new SignatureError(
      "ECDSA verification failed over the signing input",
    );
  }
}
