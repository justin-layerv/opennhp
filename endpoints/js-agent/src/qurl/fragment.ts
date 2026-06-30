// qURL v2 fragment parsing + issuer-signature verification — the browser/headless
// port of the Go fragment path (`qurl-service` internal/qurlv2/fragment.go).
//
// A fragment is `qv2.<claims>.<secret>.<sig>` (four dot-tokens: the literal "qv2"
// prefix plus three base64url parts). The signature MUST be verified over the
// EXACT received claims bytes (`claimsB64`), never a re-serialization of the
// parsed Claims — re-canonicalization is a classic signature-bypass vector — so
// the Fragment retains the verbatim part strings.
import { base64UrlDecodeField } from "./base64url.js";
import { Claims, FRAGMENT_PREFIX, Secret } from "./claims.js";
import { parseClaims, parseSecret } from "./parse.js";
import {
  assertCanonicalRawSignature,
  verifyIssuerSignature,
} from "./signature.js";
import { TrustStore } from "./truststore.js";

/** Thrown when the fragment shape is invalid (wrong prefix, part count, or an
 * empty part). Mirrors Go ErrFragment. */
export class FragmentError extends Error {
  constructor(message: string) {
    super(`qurlv2: invalid fragment: ${message}`);
    this.name = "FragmentError";
  }
}

/** Exact number of dot-separated tokens: the "qv2" prefix + three parts. */
const FRAGMENT_PARTS = 4;

/** A fatal UTF-8 decoder: throws on malformed UTF-8 rather than substituting
 * U+FFFD. Stateless and reusable. */
const FATAL_UTF8 = new TextDecoder("utf-8", { fatal: true });

/** Decodes part bytes as strict UTF-8, re-wrapping a malformed-UTF-8 failure as a
 * {@link FragmentError} naming the part. */
function decodeUtf8Strict(label: string, bytes: Uint8Array): string {
  try {
    return FATAL_UTF8.decode(bytes);
  } catch {
    throw new FragmentError(`${label}: not valid UTF-8`);
  }
}

/** A parsed qURL v2 fragment. Verbatim part strings are retained for verification. */
export interface Fragment {
  /** Part 1 verbatim: the EXACT unpadded-base64url claims string from the wire.
   * Signature verification uses this, not a re-encoding of {@link claims}. */
  claimsB64: string;
  /** Part 2 verbatim (the unsigned secret). */
  secretB64: string;
  /** Part 3 verbatim (the base64url raw r||s issuer signature). */
  sigB64: string;
  /** The strict-parsed claim set. */
  claims: Claims;
  /** The strict-parsed secret. */
  secret: Secret;
  /** The decoded, encoding-validated 64-byte raw signature. */
  rawSig: Uint8Array;
}

/**
 * Parses the fragment body (everything after "#") into a {@link Fragment}. It
 * enforces the wire shape — literal "qv2" prefix, exactly three non-empty
 * base64url parts — strict-parses the claims and secret JSON, and decodes +
 * encoding-validates the signature part to the pinned 64-byte / low-S / in-range
 * form.
 *
 * It does NOT verify the issuer signature against a trust store (call
 * {@link verifyFragment}) and does NOT validate relay_url (call validateRelayUrl
 * after verification), matching the design's ordering: relay_url is acted on only
 * after signature verification succeeds.
 *
 * The input may include a leading "#"; it is stripped. Pass the fragment only
 * (no scheme/host).
 */
export function parseFragment(fragment: string): Fragment {
  const body = fragment.startsWith("#") ? fragment.slice(1) : fragment;

  const parts = body.split(".");
  if (parts.length !== FRAGMENT_PARTS) {
    throw new FragmentError(
      `expected ${FRAGMENT_PARTS} dot-separated parts (qv2.<claims>.<secret>.<sig>), got ${parts.length}`,
    );
  }
  const [prefix, claimsB64, secretB64, sigB64] = parts as [
    string,
    string,
    string,
    string,
  ];

  if (prefix !== FRAGMENT_PREFIX) {
    throw new FragmentError(
      `prefix must be ${JSON.stringify(FRAGMENT_PREFIX)}, got ${JSON.stringify(prefix)}`,
    );
  }
  if (claimsB64 === "" || secretB64 === "" || sigB64 === "") {
    throw new FragmentError("claims/secret/sig parts must all be non-empty");
  }

  // base64url-decode each part with the strict decoder, then strict-parse the
  // JSON. A padded/non-canonical/non-alphabet part fails in base64UrlDecodeField
  // (which prefixes the part name onto the Base64UrlError). The decoded bytes are
  // UTF-8-decoded in FATAL mode so malformed UTF-8 is rejected, not silently
  // replaced with U+FFFD — matching the strict, reject-anything-malformed posture
  // of the rest of this module (signature verification uses the raw claimsB64
  // bytes regardless, so this is strictness/faithfulness, not a security fix).
  const claims = parseClaims(
    decodeUtf8Strict(
      "claims part",
      base64UrlDecodeField("claims part", claimsB64),
    ),
  );
  const secret = parseSecret(
    decodeUtf8Strict(
      "secret part",
      base64UrlDecodeField("secret part", secretB64),
    ),
  );

  const rawSig = assertCanonicalRawSignature(
    base64UrlDecodeField("sig part", sigB64),
  );

  return { claimsB64, secretB64, sigB64, claims, secret, rawSig };
}

/**
 * Verifies the issuer signature on a parsed fragment against the trust store: it
 * resolves the public key for the parsed claims' `kid`, then verifies over the
 * EXACT received claims bytes ({@link Fragment.claimsB64}), enforcing the 64-byte
 * / low-S / in-range wire contract (the high-S gate WebCrypto omits). Throws on
 * any failure.
 */
export async function verifyFragment(
  frag: Fragment,
  ts: TrustStore,
): Promise<void> {
  const key = ts.publicKeyForKid(frag.claims.kid);
  await verifyIssuerSignature(key, frag.claimsB64, frag.rawSig);
}

/**
 * The mandatory client path: parse the fragment, then verify the issuer signature.
 * This MUST succeed before the client acts on relay_url / cell_public_key (it
 * chooses where to POST and what to encrypt to). relay_url HTTPS/allowlist
 * validation remains a separate post-verify step (validateRelayUrl).
 *
 * IMPORTANT — this is NOT a full admission gate. It proves only that the issuer
 * signed these exact claim bytes; it does NOT enforce LIVENESS (exp/nbf vs now).
 * The strict parser checks only the clock-free iat<=exp / nbf<=exp ordering
 * bounds (this package has no trusted clock). A caller that enforces expiry must
 * do so itself.
 */
export async function parseAndVerifyFragment(
  fragment: string,
  ts: TrustStore,
): Promise<Fragment> {
  const frag = parseFragment(fragment);
  await verifyFragment(frag, ts);
  return frag;
}
