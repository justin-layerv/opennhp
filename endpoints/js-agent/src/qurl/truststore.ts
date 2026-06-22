// Issuer trust store: resolves a claim's `kid` to the imported P-256 public key
// used to verify the issuer signature. The browser/headless port of the Go
// TrustStore (`qurl-service` internal/qurlv2/truststore.go).
//
// The first-party client ships this store (the issuer trust anchor per `kid`, see
// the design's "Browser and Headless Flow"). Rotation is overlap-publish, expressed
// ENTIRELY through the contents of the map: during overlap it holds both the
// current and recently-retired kids; "retiring" a kid means removing it. Unknown
// or retired kids are rejected (ErrUnknownKID).
//
// Keys are imported as non-extractable WebCrypto `CryptoKey`s with `verify` usage
// only — they can never sign, and never leave the agent as raw bytes.
import { base64UrlDecode } from "./base64url.js";

/** Thrown when a claim's `kid` is not in the trust store. Mirrors Go ErrUnknownKID. */
export class UnknownKidError extends Error {
  constructor(kid: string) {
    super(`qurlv2: unknown issuer kid: ${JSON.stringify(kid)}`);
    this.name = "UnknownKidError";
  }
}

/** A minimal P-256 public-key JWK (the form the golden vectors publish for "jwk"). */
export interface EcPublicJwk {
  kty: "EC";
  crv: "P-256";
  /** Fixed-width 32-byte base64url x coordinate (leading zeros preserved). */
  x: string;
  /** Fixed-width 32-byte base64url y coordinate (leading zeros preserved). */
  y: string;
}

const ECDSA_P256_PARAMS: EcKeyImportParams = {
  name: "ECDSA",
  namedCurve: "P-256",
};

/**
 * Imports a P-256 issuer public key from DER SPKI bytes (the form AWS KMS
 * GetPublicKey returns and the form persisted in config). Non-extractable,
 * `verify`-only.
 */
export async function importIssuerKeyFromSpkiDer(
  der: Uint8Array,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    // Fresh ArrayBuffer-backed copy (BufferSource must not be SharedArrayBuffer-backed).
    new Uint8Array(der),
    ECDSA_P256_PARAMS,
    false,
    ["verify"],
  );
}

/**
 * Imports a P-256 issuer public key from a base64url DER SPKI string. Decoding
 * uses the strict unpadded base64url decoder so a padded/non-canonical key string
 * is rejected the same way every other qURL v2 field is.
 */
export async function importIssuerKeyFromSpkiDerB64(
  spkiDerB64: string,
): Promise<CryptoKey> {
  return importIssuerKeyFromSpkiDer(base64UrlDecode(spkiDerB64));
}

/**
 * Imports a P-256 issuer public key from a JWK. WebCrypto requires the JWK's
 * `key_ops`/`ext` to be consistent with the requested usage, so we build the
 * import JWK explicitly with `verify` usage rather than trusting caller-supplied
 * ops. A short (non-32-byte) coordinate is exactly the bug a strict importer
 * rejects — that is the property the golden-vector JWK test pins.
 */
export async function importIssuerKeyFromJwk(
  jwk: EcPublicJwk,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true },
    ECDSA_P256_PARAMS,
    false,
    ["verify"],
  );
}

/**
 * A resolved kid -> imported public key map. Built once from issuer key material
 * and queried per fragment.
 */
export class TrustStore {
  private readonly keys: Map<string, CryptoKey>;

  private constructor(keys: Map<string, CryptoKey>) {
    this.keys = keys;
  }

  /**
   * Builds a trust store from a kid -> base64url-DER-SPKI map (the on-disk/config
   * and KMS GetPublicKey form). Rejects an empty map (fail closed) and an empty
   * kid. Each key is imported as a non-extractable verify-only P-256 key; an entry
   * that is not a valid P-256 SPKI rejects here.
   */
  static async fromSpkiDerB64(
    derB64ByKid: Record<string, string>,
  ): Promise<TrustStore> {
    const entries = Object.entries(derB64ByKid);
    if (entries.length === 0) {
      throw new Error(
        "qurlv2: trust store must contain at least one issuer key",
      );
    }
    // Import the (independent) keys concurrently rather than awaiting each in turn.
    const imported = await Promise.all(
      entries.map(async ([kid, derB64]) => {
        if (kid === "") {
          throw new Error("qurlv2: trust store kid must not be empty");
        }
        return [kid, await importIssuerKeyFromSpkiDerB64(derB64)] as const;
      }),
    );
    return new TrustStore(new Map(imported));
  }

  /** Resolves the issuer public key for `kid`, or throws {@link UnknownKidError}. */
  publicKeyForKid(kid: string): CryptoKey {
    const key = this.keys.get(kid);
    if (key === undefined) {
      throw new UnknownKidError(kid);
    }
    return key;
  }
}
