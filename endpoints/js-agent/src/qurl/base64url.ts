// Strict unpadded base64url (RFC 4648 §5) for qURL v2 — the single pinned wire
// encoding for every fragment part and key field.
//
// This is the agreement point with the Go verifier (`qurl-service`
// internal/qurlv2/claims.go `decodeB64`, which uses `base64.RawURLEncoding.Strict()`).
// Both sides MUST agree on which STRINGS are well-formed, not merely on which
// bytes a lenient decoder would recover. The browser's built-in `atob` is the
// hazard here: it is lenient and silently accepts THREE classes of input the Go
// strict decoder rejects, so this module hand-rolls the guards instead of
// trusting `atob`:
//
//   - padded encodings (a trailing "=");
//   - non-base64url-alphabet characters (including "+", "/", and ".", so a stray
//     field-separator dot fails);
//   - NON-CANONICAL trailing bits — when the decoded length is not a multiple of
//     3, the final base64 character has "don't care" low bits, and a lenient
//     decoder accepts ANY value for them, mapping multiple distinct strings to the
//     same bytes. Strict decoding requires those bits be zero, so exactly ONE
//     base64url string maps to a given byte slice.
//
// The non-canonical rule is the load-bearing one: it is both a signature-bypass
// guard (one string per byte slice — a verifier cannot be handed a re-spelled
// variant of a signed part) and the precise place a naive `atob`-based JS port
// diverges from Go. See `qurl-service` internal/qurlv2/strict_b64_test.go.

/** Thrown when a value is not valid unpadded base64url. Mirrors Go `ErrEncoding`. */
export class Base64UrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Base64UrlError";
  }
}

// The unpadded base64url alphabet (RFC 4648 §5). Index = 6-bit value.
const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Reverse lookup: char code -> 6-bit value, or -1 for a non-alphabet character.
const DECODE_TABLE: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i += 1) {
    table[ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/**
 * Decodes an unpadded-base64url string to bytes, rejecting padding, non-alphabet
 * characters, and non-canonical trailing bits.
 *
 * The implementation is a direct sextet decoder (not `atob`), so the canonical
 * checks are inherent rather than bolted on:
 *   - any character outside the base64url alphabet (including "=", "+", "/", ".")
 *     fails the table lookup;
 *   - a length of 1 mod 4 is structurally impossible for base64 and is rejected;
 *   - on the final partial group, the bits that do not contribute to an output
 *     byte are required to be zero (the canonical-trailing-bit rule), so a
 *     non-canonical re-spelling of the same bytes is rejected here rather than
 *     silently normalized.
 */
export function base64UrlDecode(s: string): Uint8Array {
  const len = s.length;
  // len % 4 === 1 cannot encode any whole byte: 1 base64 char carries 6 bits,
  // short of the 8 a single output byte needs. Go's decoder rejects this as
  // CorruptInputError; reject it here before the bit loop.
  if (len % 4 === 1) {
    throw new Base64UrlError(
      `invalid base64url length ${len} (length % 4 === 1 cannot encode a byte)`,
    );
  }

  const outLen = Math.floor((len * 3) / 4);
  const out = new Uint8Array(outLen);

  let acc = 0; // bit accumulator
  let accBits = 0; // number of valid bits currently in acc
  let outPos = 0;
  for (let i = 0; i < len; i += 1) {
    const code = s.charCodeAt(i);
    const val = code < 128 ? DECODE_TABLE[code]! : -1;
    if (val < 0) {
      throw new Base64UrlError(
        `invalid base64url character ${JSON.stringify(s[i])} at index ${i}`,
      );
    }
    // `acc` is a rolling bit buffer. JS `<<` truncates to 32 bits, but that is
    // harmless here: a byte is drained whenever accBits >= 8, so accBits stays <= 7
    // and acc never holds more than ~13 meaningful low bits — the high bits that
    // fall off the 32-bit edge were already consumed. Only the low `accBits` bits
    // are ever read (below and in the trailing-bit check).
    acc = (acc << 6) | val;
    accBits += 6;
    if (accBits >= 8) {
      accBits -= 8;
      out[outPos] = (acc >> accBits) & 0xff;
      outPos += 1;
    }
  }

  // Canonical-trailing-bit check: after emitting every whole byte, 0, 2, or 4
  // leftover bits remain (for len % 4 of 0, 3, or 2). Those bits are the final
  // base64 char's low "don't care" bits; the canonical encoding sets them to
  // zero. A lenient decoder (atob) ignores them, accepting non-canonical
  // variants; we require them zero so exactly one string maps to a given slice.
  if (accBits > 0) {
    const trailingMask = (1 << accBits) - 1;
    if ((acc & trailingMask) !== 0) {
      throw new Base64UrlError(
        "non-canonical base64url: trailing bits are not zero",
      );
    }
  }

  return out;
}

/**
 * Decodes an unpadded-base64url field, prefixing `label` (the field/part name)
 * onto any {@link Base64UrlError} so a decode failure says WHICH field was
 * malformed. The thrown error stays a `Base64UrlError`, so callers that match on
 * the type are unaffected. Used by every qURL v2 field/part decode so the
 * decode-and-attribute pattern lives in one place.
 */
export function base64UrlDecodeField(label: string, b64: string): Uint8Array {
  try {
    return base64UrlDecode(b64);
  } catch (e) {
    if (e instanceof Base64UrlError) {
      throw new Base64UrlError(`${label}: ${e.message}`);
    }
    throw e;
  }
}

/**
 * Encodes bytes as unpadded base64url. Mirrors Go `base64.RawURLEncoding`.
 *
 * Used for the golden-vector cross-check (re-encode a reconstructed signing input
 * and compare to the pinned `signing_input_b64`), so it must produce exactly the
 * canonical form `base64UrlDecode` accepts. Built directly from the sextet
 * alphabet rather than via `btoa`+substitution so the two directions share one
 * alphabet definition and the trailing bits are always zero by construction.
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  let out = "";
  let acc = 0;
  let accBits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    accBits += 8;
    while (accBits >= 6) {
      accBits -= 6;
      out += ALPHABET[(acc >> accBits) & 0x3f];
    }
  }
  if (accBits > 0) {
    // Pad the remaining bits on the LOW side with zeros to form the final sextet
    // — the canonical unpadded form (the discarded bits are zero).
    out += ALPHABET[(acc << (6 - accBits)) & 0x3f];
  }
  return out;
}
