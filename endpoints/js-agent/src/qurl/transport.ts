// Share-safe qURL v2 transport decoding.
//
// The cryptographic fragment remains `qv2.<claims>.<secret>.<sig>`. The public
// URL carries that artifact as bounded dot-delimited chunks so messaging clients
// do not stop link detection at an oversized component:
//
//   qv2t1.<claimsCount>.<secretCount>.<sigCount>.<claims chunks...>
//          <secret chunks...>.<signature chunks...>
//
// This module is intentionally outside fragment.ts. Transport decoding restores
// the exact inner qv2 bytes; the unchanged strict fragment parser then owns
// canonical base64 decoding, JSON parsing, signature encoding, and cryptographic
// verification.

/** The only accepted public qURL v2 transport prefix. */
export const QURL_V2_TRANSPORT_PREFIX = "qv2t1";

/** Canonical maximum width of every dot-delimited data chunk. */
export const QURL_V2_TRANSPORT_CHUNK_CHARS = 240;

// These are encoded-part caps from the canonical qv2 wire contract. Keep the
// derived chunk-count caps local to this boundary so a future wire-cap change
// cannot silently make the transport allocate or accept more than intended.
const CLAIMS_MAX_CHARS = 6 * 1024;
const SECRET_MAX_CHARS = 512;
const SIGNATURE_MAX_CHARS = 128;

const CLAIMS_MAX_CHUNKS = Math.ceil(
  CLAIMS_MAX_CHARS / QURL_V2_TRANSPORT_CHUNK_CHARS,
); // 26
const SECRET_MAX_CHUNKS = Math.ceil(
  SECRET_MAX_CHARS / QURL_V2_TRANSPORT_CHUNK_CHARS,
); // 3
const SIGNATURE_MAX_CHUNKS = Math.ceil(
  SIGNATURE_MAX_CHARS / QURL_V2_TRANSPORT_CHUNK_CHARS,
); // 1

/**
 * Absolute bound checked before `split()` or any input-sized allocation.
 *
 * prefix + three maximum-width count tokens + every canonical field at its cap
 * + one dot between all 34 tokens (prefix, three counts, thirty chunks).
 */
export const QURL_V2_TRANSPORT_MAX_CHARS =
  QURL_V2_TRANSPORT_PREFIX.length +
  String(CLAIMS_MAX_CHUNKS).length +
  String(SECRET_MAX_CHUNKS).length +
  String(SIGNATURE_MAX_CHUNKS).length +
  CLAIMS_MAX_CHARS +
  SECRET_MAX_CHARS +
  SIGNATURE_MAX_CHARS +
  (1 + 3 + CLAIMS_MAX_CHUNKS + SECRET_MAX_CHUNKS + SIGNATURE_MAX_CHUNKS - 1);

/** Thrown when the public qURL transport is malformed or non-canonical. */
export class QurlV2TransportError extends Error {
  constructor(message: string) {
    super(`qurlv2: invalid transport: ${message}`);
    this.name = "QurlV2TransportError";
  }
}

interface FieldSpec {
  label: "claims" | "secret" | "signature";
  maxChunks: number;
  maxChars: number;
}

const CLAIMS_SPEC: FieldSpec = {
  label: "claims",
  maxChunks: CLAIMS_MAX_CHUNKS,
  maxChars: CLAIMS_MAX_CHARS,
};
const SECRET_SPEC: FieldSpec = {
  label: "secret",
  maxChunks: SECRET_MAX_CHUNKS,
  maxChars: SECRET_MAX_CHARS,
};
const SIGNATURE_SPEC: FieldSpec = {
  label: "signature",
  maxChunks: SIGNATURE_MAX_CHUNKS,
  maxChars: SIGNATURE_MAX_CHARS,
};

const CANONICAL_POSITIVE_DECIMAL = /^[1-9][0-9]*$/;
const BASE64URL_ALPHABET = /^[A-Za-z0-9_-]+$/;

function parseChunkCount(raw: string, spec: FieldSpec): number {
  if (!CANONICAL_POSITIVE_DECIMAL.test(raw)) {
    throw new QurlV2TransportError(
      `${spec.label} chunk count must be canonical positive decimal`,
    );
  }
  const count = Number(raw);
  if (!Number.isSafeInteger(count) || count > spec.maxChunks) {
    throw new QurlV2TransportError(
      `${spec.label} chunk count exceeds ${spec.maxChunks}`,
    );
  }
  return count;
}

/**
 * Validates one field's already-bounded chunk span without reconstructing it.
 * Every non-final chunk is exactly 240 characters; the final chunk is 1..240.
 * This makes the representation unique for a given canonical qv2 part.
 */
function validateFieldChunks(
  parts: readonly string[],
  start: number,
  count: number,
  spec: FieldSpec,
): number {
  let fieldChars = 0;
  for (let i = 0; i < count; i += 1) {
    const chunk = parts[start + i]!;
    const isFinal = i === count - 1;
    if (chunk.length === 0) {
      throw new QurlV2TransportError(`${spec.label} chunk must not be empty`);
    }
    if (!isFinal && chunk.length !== QURL_V2_TRANSPORT_CHUNK_CHARS) {
      throw new QurlV2TransportError(
        `${spec.label} non-final chunk must be exactly ${QURL_V2_TRANSPORT_CHUNK_CHARS} characters`,
      );
    }
    if (chunk.length > QURL_V2_TRANSPORT_CHUNK_CHARS) {
      throw new QurlV2TransportError(
        `${spec.label} chunk exceeds ${QURL_V2_TRANSPORT_CHUNK_CHARS} characters`,
      );
    }

    fieldChars += chunk.length;
    if (fieldChars > spec.maxChars) {
      throw new QurlV2TransportError(
        `${spec.label} part exceeds ${spec.maxChars} characters`,
      );
    }

    // The transport owns framing, not the inner base64 encoding. Enforce only
    // the base64url alphabet here; after exact reconstruction, the unchanged qv2
    // parser owns impossible lengths and canonical trailing-bit rejection. That
    // separation ensures malformed/tampered inner bytes reach the one canonical
    // parser instead of creating a second, subtly different parsing authority.
    if (!BASE64URL_ALPHABET.test(chunk)) {
      throw new QurlV2TransportError(
        `${spec.label} chunk contains a non-base64url character`,
      );
    }
  }
  return start + count;
}

function joinChunks(
  parts: readonly string[],
  start: number,
  count: number,
): string {
  return parts.slice(start, start + count).join("");
}

/**
 * Decodes a public `qv2t1` fragment into the exact inner
 * `qv2.<claims>.<secret>.<sig>` fragment consumed by the strict parser.
 *
 * The input is the transport body with no leading `#` and must not be a full
 * URL. The browser boundary owns `location.hash.substring(1)`, keeping this
 * decoder aligned with the shared conformance entry point. Legacy `qv2.` public
 * transport and unknown transport versions are rejected.
 */
export function decodeQurlV2Transport(fragment: string): string {
  if (typeof fragment !== "string") {
    throw new QurlV2TransportError("fragment must be a string");
  }

  // Enforce the absolute ceiling before split or any other input-sized
  // allocation. A leading hash is URL syntax and is rejected at this body-only
  // boundary.
  if (fragment.length > QURL_V2_TRANSPORT_MAX_CHARS) {
    throw new QurlV2TransportError(
      `fragment exceeds ${QURL_V2_TRANSPORT_MAX_CHARS} characters`,
    );
  }

  const parts = fragment.split(".");
  if (parts.length < 4) {
    throw new QurlV2TransportError("expected prefix and three chunk counts");
  }
  if (parts[0] !== QURL_V2_TRANSPORT_PREFIX) {
    throw new QurlV2TransportError("unsupported transport prefix");
  }

  const claimsCount = parseChunkCount(parts[1]!, CLAIMS_SPEC);
  const secretCount = parseChunkCount(parts[2]!, SECRET_SPEC);
  const signatureCount = parseChunkCount(parts[3]!, SIGNATURE_SPEC);
  const expectedParts = 4 + claimsCount + secretCount + signatureCount;
  if (parts.length !== expectedParts) {
    throw new QurlV2TransportError(
      `expected ${expectedParts} dot-separated parts, got ${parts.length}`,
    );
  }

  const claimsStart = 4;
  const secretStart = claimsStart + claimsCount;
  const signatureStart = secretStart + secretCount;
  let cursor = validateFieldChunks(
    parts,
    claimsStart,
    claimsCount,
    CLAIMS_SPEC,
  );
  cursor = validateFieldChunks(parts, cursor, secretCount, SECRET_SPEC);
  cursor = validateFieldChunks(parts, cursor, signatureCount, SIGNATURE_SPEC);
  if (cursor !== parts.length) {
    // Defensive invariant: exact part-count validation above should make this
    // unreachable. Keep it fail-closed if the field walk changes later.
    throw new QurlV2TransportError("chunk layout is inconsistent");
  }

  const claims = joinChunks(parts, claimsStart, claimsCount);
  const secret = joinChunks(parts, secretStart, secretCount);
  const signature = joinChunks(parts, signatureStart, signatureCount);
  return `qv2.${claims}.${secret}.${signature}`;
}
