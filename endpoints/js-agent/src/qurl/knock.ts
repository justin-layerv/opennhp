// qURL v2 knock construction — Browser and Headless Flow steps 3–7
// (docs/design/QURL_V2_KEYED_IDENTITY.md). Ties the verified fragment to the
// existing NHP relay knock path: the per-qURL private key from the unsigned
// `secret` is the agent static identity, the signed `cell_public_key` is the
// server static, the signed claims + issuer signature ride in the encrypted knock
// UserData, and the opaque packet is POSTed to `relay_url + "/relay/" + serverId`.
//
// This deliberately reuses the existing `knock()` / `createKnock` / `relayPost`
// path rather than forking a parallel seal+POST: passing the per-qURL key as
// `KnockRequest.deviceStaticPriv` and the cell key as `serverStaticPub` makes
// `serverId = pubKeyFingerprint(cellPub)` fall out automatically, so the cell we
// route to cannot diverge from the key the Noise handshake authenticates against.
//
// NOTE — there is no Go roundtrip fence for the v2 knock yet: the nhp `qurl-v2`
// branch has no server-side v2 admission path, so the UserData key names and resId
// encoding mirror the design's NHP Server Contract (`qurl_claims_b64` /
// `qurl_issuer_sig_b64`) and are not yet validated against a live server.
import { equalBytes } from "@noble/ciphers/utils.js";
import { NHP_KNK } from "../crypto/packet.js";
import { x25519PublicKey } from "../crypto/dh.js";
import { knock, type KnockDeps, type KnockResult } from "../agent/loop.js";
import {
  decodeX25519PrivateKey,
  decodeX25519PublicKey,
  CLAIM_FIELDS,
  SECRET_FIELD_PRIVATE_KEY,
} from "./claims.js";
import type { Fragment } from "./fragment.js";
import { parseAndVerifyFragment } from "./fragment.js";
import { validateRelayUrl, type RelayAllowlist } from "./relay-url.js";
import type { TrustStore } from "./truststore.js";
import { decodeQurlV2Transport } from "./transport.js";

/** UserData key carrying the EXACT base64url signed claims (Part 1, verbatim). */
export const QURL_V2_CLAIMS_USER_DATA_KEY = "qurl_claims_b64";
/** UserData key carrying the EXACT base64url issuer signature (Part 3, verbatim). */
export const QURL_V2_ISSUER_SIG_USER_DATA_KEY = "qurl_issuer_sig_b64";

/** Inputs for the v2 knock body — the per-deployment auth service id plus the
 * verbatim signed parts and the signed resource public key. */
export interface QurlV2KnockBodyParams {
  /** Deployment auth-service id (`aspId`), as in v1 — v2 lands behind the same
   * static qURL package near-term. */
  authServiceId: string;
  /** The signed protected-resource public key (base64url); the knock resource
   * identity (`resId`), per design step 5. NOT the v1 bootstrap sentinel. */
  resourcePublicKeyB64: string;
  /** Part 1 verbatim (the exact signed claims base64url string). */
  claimsB64: string;
  /** Part 3 verbatim (the exact issuer-signature base64url string). */
  sigB64: string;
}

/**
 * Serializes the qURL v2 knock body — Go `common.AgentKnockMsg`
 * (`nhp/common/nhpmsg.go`). The signed claims and issuer signature are forwarded
 * VERBATIM (the exact retained part strings, never a re-encode — the server
 * verifies over the received bytes). The per-qURL private key is the handshake
 * identity only and is intentionally NOT placed in UserData.
 *
 * `headerType` is set to `NHP_KNK` here, NOT by the caller: per the #1154
 * invariant it must equal the wire header type, and the server's
 * `knock_headertype_gate` rejects a mismatch. Owning it here means a caller cannot
 * miswire the body-vs-wire type. The JSON field names (`headerType`/`aspId`/`resId`/
 * `usrData`) are pinned to Go's struct tags.
 */
export function buildQurlV2KnockBody(
  params: QurlV2KnockBodyParams,
): Uint8Array {
  if (params.resourcePublicKeyB64 === "") {
    throw new Error("qurlv2 knock: resourcePublicKeyB64 is required");
  }
  if (params.claimsB64 === "" || params.sigB64 === "") {
    throw new Error("qurlv2 knock: claims and signature parts are required");
  }
  const msg = {
    headerType: NHP_KNK,
    aspId: params.authServiceId,
    // The knock resource identity is the signed resource public key (design step 5).
    resId: params.resourcePublicKeyB64,
    usrData: {
      [QURL_V2_CLAIMS_USER_DATA_KEY]: params.claimsB64,
      [QURL_V2_ISSUER_SIG_USER_DATA_KEY]: params.sigB64,
    },
  };
  return new TextEncoder().encode(JSON.stringify(msg));
}

/**
 * Asserts the proof-of-possession linkage (invariant 2): the public key derived
 * from the unsigned secret's per-qURL private key MUST equal the signed
 * `qurl_user_public_key_b64`. The server enforces this via the Noise handshake
 * (the authenticated agent key must equal the signed key); checking it
 * client-side fails fast on a tampered/mismatched secret rather than building a
 * knock the server will reject, and is the one PoP property checkable without a
 * server. Throws on mismatch.
 */
export function assertPoPLinkage(frag: Fragment): void {
  const priv = decodeX25519PrivateKey(
    SECRET_FIELD_PRIVATE_KEY,
    frag.secret.qurlUserPrivateKeyB64,
  );
  const signedPub = decodeX25519PublicKey(
    CLAIM_FIELDS.qurlUserPublicKeyB64,
    frag.claims.qurlUserPublicKeyB64,
  );
  const derivedPub = x25519PublicKey(priv);
  // equalBytes is the codebase's established constant-time pubkey compare (used in
  // crypto/ack.ts to pin the server static key); reuse it rather than hand-rolling.
  if (!equalBytes(derivedPub, signedPub)) {
    throw new Error(
      "qurlv2 knock: secret private key does not match the signed qurl_user_public_key_b64 " +
        "(proof-of-possession would fail at the server)",
    );
  }
}

/** Options for {@link knockQurlV2}. */
export interface QurlV2KnockOptions {
  /** Issuer trust anchors (per kid). Verification MUST succeed before the client
   * acts on relay_url / cell_public_key. */
  trustStore: TrustStore;
  /** The relay allowlist (deployment config). relay_url is validated against it
   * only after signature verification. */
  relayAllowlist: RelayAllowlist;
  /** Deployment auth-service id (`aspId`). */
  authServiceId: string;
  /** Injectable transport/entropy seams for tests (default: real relay + browser
   * entropy, as {@link knock}). */
  deps?: KnockDeps;
}

/**
 * Performs a full qURL v2 bootstrap knock from a `qv2t1.…` transport body
 * extracted from the public URL fragment:
 *
 *   1. decode the bounded share transport to the exact inner
 *      `qv2.<claims>.<secret>.<sig>` fragment;
 *   2. parse the canonical fragment and VERIFY the issuer signature (mandatory —
 *      this must succeed before any value from the claims is acted on);
 *   3. validate `relay_url` (HTTPS + allowlist; userinfo rejected) — only now,
 *      after verification;
 *   4. assert the proof-of-possession linkage (secret priv ↔ signed user pubkey);
 *   5. decode the per-qURL private key (agent static) and cell public key
 *      (server static);
 *   6. build the v2 knock body (signed claims + signature in UserData, resId =
 *      resource public key);
 *   7. knock through the relay via the existing path — `serverId =
 *      pubKeyFingerprint(cellPub)` and the POST to `relay_url + "/relay/" +
 *      serverId` are handled by {@link knock} / `relayPost`.
 *
 * Returns the discriminated {@link KnockResult}. Throws on a verification,
 * relay_url, PoP, or key-decoding failure before any packet is sent, and on a
 * transport/crypto fault during the knock (as {@link knock} does).
 *
 * LIVENESS HANDOFF (deliberate): this does NOT check `exp`/`nbf` vs the current
 * time. This package has no trusted clock (a browser clock is attacker-influenced
 * and skew-prone), and a client-side liveness check is not a security control — a
 * hostile client just deletes it. exp/nbf-vs-now is the SERVER-SIDE v2 admission
 * path's responsibility and MUST be enforced there before a qv2 link can open AC
 * (the same #1002-style server-side deferral the Go strict parser documents). The
 * strict parser still enforces the clock-free iat<=exp / nbf<=exp ordering bounds.
 * Keeping liveness off the client mirrors the Go library rule-for-rule and keeps
 * this flow from being mistaken for complete admission liveness. The server-side
 * enforcement is a tracked acceptance gate: layervai/nhp#2770.
 */
export async function knockQurlV2(
  fragment: string,
  opts: QurlV2KnockOptions,
): Promise<KnockResult> {
  // 1–2. Decode the public transport, then parse + MANDATORY issuer-signature
  // verification over the exact reconstructed claims bytes. `decode` accepts no
  // legacy public qv2 transport; the inner parser remains strict and unchanged.
  const innerFragment = decodeQurlV2Transport(fragment);
  const frag = await parseAndVerifyFragment(innerFragment, opts.trustStore);

  // 3. relay_url is acted on only AFTER verification succeeds.
  validateRelayUrl(frag.claims.relayUrl, opts.relayAllowlist);

  // 4. Fail fast if the secret doesn't match the signed user key.
  assertPoPLinkage(frag);

  // 5. The per-qURL private key is the agent static identity; the cell key is the
  //    server static. Both were already length-validated by the strict parser;
  //    decode again here to hand raw bytes to the knock path.
  const deviceStaticPriv = decodeX25519PrivateKey(
    SECRET_FIELD_PRIVATE_KEY,
    frag.secret.qurlUserPrivateKeyB64,
  );
  const serverStaticPub = decodeX25519PublicKey(
    CLAIM_FIELDS.cellPublicKeyB64,
    frag.claims.cellPublicKeyB64,
  );

  // 6–7. Build the v2 body and knock through the relay using the verified
  //      relay_url as the base; serverId/POST target are derived by `knock`.
  const body = buildQurlV2KnockBody({
    authServiceId: opts.authServiceId,
    resourcePublicKeyB64: frag.claims.resourcePublicKeyB64,
    claimsB64: frag.claimsB64,
    sigB64: frag.sigB64,
  });

  return knock(
    {
      deviceStaticPriv,
      serverStaticPub,
      relayBaseUrl: frag.claims.relayUrl,
      authServiceId: opts.authServiceId,
      // The v2 body is fully specified here; the loop seals it as-is instead of
      // building a v1 body.
      body,
    },
    opts.deps,
  );
}
