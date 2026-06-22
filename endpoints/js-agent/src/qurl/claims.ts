// qURL v2 claim/secret schema, key-length discipline, and the issuer signing
// input — the browser/headless port of the Go security core (`qurl-service`
// internal/qurlv2/claims.go), kept field-for-field and rule-for-rule identical so
// the two verifiers agree.
//
// Design invariants enforced across this module and its siblings:
//   - The issuer signature is computed/verified over the EXACT base64url bytes of
//     the claims part as they appear on the wire, never a re-serialized object.
//   - Every key/identifier field is fixed-length base64url for its key type;
//     decode AND length-check before use (each field against its own size — the
//     resource key is a different algorithm/length than the X25519 keys).
//   - The strict parser is an allowlist: duplicate keys, unknown fields, missing
//     required fields, null, wrong types, arrays-for-scalars, out-of-range numbers,
//     and non-integer time fields are all rejected (see parse.ts).
import { base64UrlDecodeField, base64UrlEncode } from "./base64url.js";

/** The only supported qURL artifact version. Pinned; no payload negotiation. */
export const QURL_V2_VERSION = 2;

/** Literal first dot-token of a qURL v2 fragment. */
export const FRAGMENT_PREFIX = "qv2";

/** Expected value of the claims `iss` field. */
export const QURL_V2_ISSUER = "qurl-service";

/**
 * Fixed issuer signing-input prefix. The signing input is this ASCII prefix, then
 * a single 0x00 byte, then the EXACT unpadded-base64url claims bytes from the
 * wire. The 0x00 is one literal byte, not the two characters "\" and "0".
 */
export const DOMAIN_SEPARATION_PREFIX = "NHP-QURL-V2-ISSUER";

/** The single 0x00 separator byte between the prefix and the claims bytes. */
const DOMAIN_SEPARATOR_BYTE = 0x00;

/** A shared UTF-8 encoder (TextEncoder is stateless and reusable). */
const UTF8 = new TextEncoder();

/** The domain-separation prefix encoded once at module load (it is a constant);
 * `signingInput` reuses it rather than re-encoding the fixed ASCII every call. */
const DOMAIN_SEPARATION_PREFIX_BYTES = UTF8.encode(DOMAIN_SEPARATION_PREFIX);

// Key-length constants. Cell and per-qURL user keys are raw X25519 public keys
// (exactly 32 bytes). The per-qURL private key (the PoP credential) is a 32-byte
// X25519 scalar. The resource public key is a different algorithm — a P-256 KMS
// key in DER SPKI form — and is length-checked against its OWN window, per the
// design's "length-check each field against its own expected size".
const X25519_PUBLIC_KEY_BYTES = 32;
const X25519_PRIVATE_KEY_BYTES = 32;
// DER SPKI of an ECC_NIST_P256 resource public key. KMS returns 91 bytes; a small
// window (not an exact pin) tolerates an encoding nuance while still rejecting
// obviously-wrong blobs (empty, a raw 32-byte X25519 key, a multi-KB RSA key).
// These bounds match the Go side (minResourcePublicKeyDERBytes/max) so the formats
// stay merge-compatible.
const MIN_RESOURCE_PUBLIC_KEY_DER_BYTES = 80;
const MAX_RESOURCE_PUBLIC_KEY_DER_BYTES = 160;

/**
 * Bounds integer time fields so a hostile payload cannot inject an absurd value.
 * Year ~2286 — well past any plausible qURL expiry, and `Number.MAX_SAFE_INTEGER`
 * (~9.0e15) comfortably exceeds it, so these are exact integers in JS. Mirrors Go
 * `maxUnixSeconds`.
 */
export const MAX_UNIX_SECONDS = 9_999_999_999;

/** The signed qURL v2 claim set (Part 1). Only `cellId` is optional. */
export interface Claims {
  v: number;
  iss: string;
  kid: string;
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
  cellPublicKeyB64: string;
  cellId?: string;
  relayUrl: string;
  resourcePublicKeyB64: string;
  qurlUserPublicKeyB64: string;
}

/** The unsigned secret payload (Part 2): the per-qURL private key. */
export interface Secret {
  qurlUserPrivateKeyB64: string;
}

// Wire field-name constants, defined once and reused by the allowlist and the
// validators (parse.ts) so the wire field names live in exactly one place. These
// are the on-the-wire JSON keys (snake_case), distinct from the camelCase struct
// fields above.
export const CLAIM_FIELDS = {
  v: "v",
  iss: "iss",
  kid: "kid",
  iat: "iat",
  nbf: "nbf",
  exp: "exp",
  jti: "jti",
  cellPublicKeyB64: "cell_public_key_b64",
  cellId: "cell_id",
  relayUrl: "relay_url",
  resourcePublicKeyB64: "resource_public_key_b64",
  qurlUserPublicKeyB64: "qurl_user_public_key_b64",
} as const;

export const SECRET_FIELD_PRIVATE_KEY = "qurl_user_private_key_b64";

/** Required claim keys (all except the optional `cell_id`). */
export const REQUIRED_CLAIM_KEYS: readonly string[] = [
  CLAIM_FIELDS.v,
  CLAIM_FIELDS.iss,
  CLAIM_FIELDS.kid,
  CLAIM_FIELDS.iat,
  CLAIM_FIELDS.nbf,
  CLAIM_FIELDS.exp,
  CLAIM_FIELDS.jti,
  CLAIM_FIELDS.cellPublicKeyB64,
  CLAIM_FIELDS.relayUrl,
  CLAIM_FIELDS.resourcePublicKeyB64,
  CLAIM_FIELDS.qurlUserPublicKeyB64,
];

/** Full claim allowlist (required plus the optional `cell_id`). */
export const ALLOWED_CLAIM_KEYS: ReadonlySet<string> = new Set([
  ...REQUIRED_CLAIM_KEYS,
  CLAIM_FIELDS.cellId,
]);

export const REQUIRED_SECRET_KEYS: readonly string[] = [
  SECRET_FIELD_PRIVATE_KEY,
];
export const ALLOWED_SECRET_KEYS: ReadonlySet<string> = new Set([
  SECRET_FIELD_PRIVATE_KEY,
]);

/**
 * Thrown for any strict-schema violation (duplicate key, unknown field, missing
 * required field, null, wrong type, array-for-scalar, non-integer or out-of-range
 * time, bad version/issuer, empty required string, structurally-incoherent time
 * window). Mirrors Go `ErrStrictParse`.
 */
export class StrictParseError extends Error {
  constructor(message: string) {
    super(`qurlv2: strict parse failed: ${message}`);
    this.name = "StrictParseError";
  }
}

/** Thrown when a decoded key field is not its expected length. Mirrors Go `ErrKeyLength`. */
export class KeyLengthError extends Error {
  constructor(message: string) {
    super(`qurlv2: key field has unexpected length: ${message}`);
    this.name = "KeyLengthError";
  }
}

/**
 * Decodes a base64url key field and enforces an exact decoded length. Wraps a
 * base64 failure as-is (so callers can match `Base64UrlError`) and a length
 * mismatch as `KeyLengthError`.
 */
function decodeFixedLengthKey(
  field: string,
  b64: string,
  wantLen: number,
): Uint8Array {
  const raw = base64UrlDecodeField(field, b64);
  if (raw.length !== wantLen) {
    throw new KeyLengthError(
      `${field} decoded to ${raw.length} bytes, want ${wantLen}`,
    );
  }
  return raw;
}

/** Decodes a raw X25519 public key (32 bytes). */
export function decodeX25519PublicKey(field: string, b64: string): Uint8Array {
  return decodeFixedLengthKey(field, b64, X25519_PUBLIC_KEY_BYTES);
}

/** Decodes a raw X25519 private key (32 bytes) — the PoP credential in the secret. */
export function decodeX25519PrivateKey(field: string, b64: string): Uint8Array {
  return decodeFixedLengthKey(field, b64, X25519_PRIVATE_KEY_BYTES);
}

/**
 * Decodes a base64url resource public key (DER SPKI) and length-checks it against
 * its own window. Deliberately does NOT parse the bytes as a real P-256 SPKI here
 * — same scope decision as the Go side: on the verify path the claims are
 * issuer-signed, so a verifier that has checked the signature trusts the issuer to
 * have minted a structurally valid resource key; the field is not attacker-chosen
 * there. The structural P-256 parse is the admission/resource-key consumer's job
 * (a later slice), where the key is actually used for ECDH.
 */
export function decodeResourcePublicKey(b64: string): Uint8Array {
  const der = base64UrlDecodeField(CLAIM_FIELDS.resourcePublicKeyB64, b64);
  if (
    der.length < MIN_RESOURCE_PUBLIC_KEY_DER_BYTES ||
    der.length > MAX_RESOURCE_PUBLIC_KEY_DER_BYTES
  ) {
    throw new KeyLengthError(
      `${CLAIM_FIELDS.resourcePublicKeyB64} decoded to ${der.length} bytes, want ` +
        `${MIN_RESOURCE_PUBLIC_KEY_DER_BYTES}..${MAX_RESOURCE_PUBLIC_KEY_DER_BYTES}`,
    );
  }
  return der;
}

/**
 * Builds the exact bytes the issuer signs and verifiers verify:
 * `DOMAIN_SEPARATION_PREFIX` (ASCII) + a single 0x00 byte + the EXACT unpadded
 * base64url claims bytes from the wire. `claimsB64` is taken verbatim (never
 * re-serialized). This is the single source of the preimage so it cannot drift
 * between the verifier and the golden-vector cross-check.
 */
export function signingInput(claimsB64: string): Uint8Array {
  const prefix = DOMAIN_SEPARATION_PREFIX_BYTES;
  const claims = UTF8.encode(claimsB64);
  const out = new Uint8Array(prefix.length + 1 + claims.length);
  out.set(prefix, 0);
  out[prefix.length] = DOMAIN_SEPARATOR_BYTE;
  out.set(claims, prefix.length + 1);
  return out;
}

/**
 * Convenience for tests/consumers cross-checking the pinned `signing_input_b64`:
 * the base64url of {@link signingInput}.
 */
export function signingInputB64(claimsB64: string): string {
  return base64UrlEncode(signingInput(claimsB64));
}
