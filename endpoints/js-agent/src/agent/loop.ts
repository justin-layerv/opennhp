import { pubKeyFingerprint } from "../crypto/fingerprint.js";
import { decryptReply } from "../crypto/ack.js";
import { NHP_ACK, NHP_COK } from "../crypto/packet.js";
import {
  createKnock,
  buildKnockBody,
  browserEntropy,
  type KnockEntropy,
} from "./knock.js";
import { relayPost, type RelayTransport } from "./relay.js";

/** The server granted access: the resource-host and AC-token maps (keyed by
 * resource id), the granted duration, the relay-observed source address, and the
 * qURL destination to navigate to — from `ServerKnockAckMsg`
 * (`nhp/common/nhpmsg.go`). `aspToken` is AC-internal and intentionally
 * dropped. */
export interface KnockSuccess {
  kind: "success";
  resourceHosts: Record<string, string>;
  acTokens: Record<string, string>;
  openTimeSeconds: number;
  agentAddr: string;
  redirectUrl: string;
}

/** The server authenticated the knock but has no active session for this client
 * (deny code 52024, `ErrQurlSessionExpired`). The caller must restart qURL
 * bootstrap with the original token when it still has one; retrying a tokenless
 * re-knock cannot mint a new session. */
export interface KnockReResolve {
  kind: "reResolve";
}

/** The server returned an error ACK (an `errCode` other than success or 52024). */
export interface KnockServerError {
  kind: "serverError";
  errCode: string;
  errMsg: string;
}

/** The server was overloaded and issued a cookie challenge (`NHP_COK`). The
 * re-knock that answers it (`NHP_RKN` folding in the cookie) lands in PR-5c; for
 * now the caller surfaces a retry. */
export interface KnockCookieChallenge {
  kind: "cookieChallenge";
}

/** The outcome of a knock, for the caller (the qurl.link page, PR-6) to branch
 * on as data. Faults (transport, crypto, correlation) throw instead. */
export type KnockResult =
  KnockSuccess | KnockReResolve | KnockServerError | KnockCookieChallenge;

/** A single knock's inputs. `serverStaticPub` and `relayBaseUrl` are static
 * qurl.link deployment config. The initial qURL bootstrap passes
 * `qurlAccessToken` plus browser metadata that NHP forwards internally;
 * steady-state renewals pass `resourceId`. */
export interface KnockRequest {
  deviceStaticPriv: Uint8Array;
  serverStaticPub: Uint8Array;
  relayBaseUrl: string;
  authServiceId: string;
  resourceId?: string;
  qurlAccessToken?: string;
  qurlUserAgent?: string;
  /**
   * A pre-serialized `AgentKnockMsg` body to seal as-is, bypassing the v1 body
   * builder. The qURL v2 path supplies its own body (signed claims + issuer
   * signature in `usrData`, `resId` = resource public key); when set, the
   * v1-only `resourceId`/`qurlAccessToken`/`qurlUserAgent` fields are ignored. The
   * caller owns serialization and MUST set the body's `headerType` to `NHP_KNK`
   * (the #1154 wire-vs-body invariant) — {@link buildQurlV2KnockBody} does. The
   * seal/POST/dispatch path is otherwise unchanged, so v2 routes through the same
   * `createKnock`/relay/`decryptReply` machinery as v1.
   */
  body?: Uint8Array;
}

/** Injectable seams: a mock relay transport and pinned entropy. Production
 * defaults to {@link relayPost} over `relayBaseUrl` and {@link browserEntropy}. */
export interface KnockDeps {
  transport?: RelayTransport;
  entropy?: KnockEntropy;
}

// Go error codes (`nhp/common/errors.go`): success and the qURL session-expired
// deny. Compared as strings — `ServerKnockAckMsg.ErrCode` is a string field.
const ERR_SUCCESS = "0";
const ERR_QURL_SESSION_EXPIRED = "52024";

/** Success is `"0"` (explicit) OR `""` (implicit) — mirrors Go
 * `common.IsSuccessErrCode` (errors.go). `ServerKnockAckMsg.ErrCode` has no
 * `omitempty`, so an empty string is a valid success on the wire; treating it as
 * an error would drop a real grant's tokens. */
function isSuccessErrCode(errCode: string): boolean {
  return errCode === "" || errCode === ERR_SUCCESS;
}

/** The subset of `ServerKnockAckMsg` fields the loop reads. All optional — this
 * is the shape of an untrusted `JSON.parse`, and a field may be absent. */
interface ServerKnockAck {
  errCode?: string;
  errMsg?: string;
  resHost?: Record<string, string>;
  acTokens?: Record<string, string>;
  opnTime?: number;
  agentAddr?: string;
  redirectUrl?: string;
}

/**
 * Performs one qURL knock through the relay and dispatches the server's reply.
 *
 * Builds the `AgentKnockMsg` body, wraps it in an `NHP_KNK` packet
 * ({@link createKnock}), POSTs it to the relay (transport), then decrypts and
 * authenticates the reply ({@link decryptReply} recovers the server static key
 * and verifies it is the one knocked). Dispatch:
 *   - `NHP_ACK` → correlate the reply counter to the knock, then map the
 *     `errCode`: `0` → success, `52024` → reResolve, else serverError.
 *   - `NHP_COK` → cookieChallenge (overload; the re-knock is PR-5c).
 *
 * Returns a discriminated {@link KnockResult}. Throws only on faults: a transport
 * error ({@link RelayError}), a crypto failure (`decryptReply`), an ACK that does
 * not correlate to this knock, an unexpected (authenticated) reply type, or a
 * malformed ACK body (empty or invalid JSON — a TCB-level fault, since the body
 * is server-authenticated by the time it is parsed, not attacker-reachable).
 */
export async function knock(
  req: KnockRequest,
  deps: KnockDeps = {},
): Promise<KnockResult> {
  const entropy = deps.entropy ?? browserEntropy;
  const transport = deps.transport ?? relayPost(req.relayBaseUrl);

  // The qURL v2 path supplies a fully-formed body; v1 builds one from the request.
  const body =
    req.body ??
    buildKnockBody({
      authServiceId: req.authServiceId,
      resourceId: req.resourceId,
      qurlAccessToken: req.qurlAccessToken,
      qurlUserAgent: req.qurlUserAgent,
    });
  const { packet, counter } = createKnock(
    req.deviceStaticPriv,
    req.serverStaticPub,
    body,
    entropy,
  );

  // serverId is PR-1's relay routing id — the cell's server-pubkey fingerprint,
  // the key relay.toml is indexed by. Derived from `serverStaticPub` rather than
  // carried as separate config, so the cell we route to can't diverge from the
  // key the crypto authenticates against.
  const serverId = pubKeyFingerprint(req.serverStaticPub);
  const replyBytes = await transport(serverId, packet);
  const reply = await decryptReply(
    req.deviceStaticPriv,
    req.serverStaticPub,
    replyBytes,
  );

  if (reply.headerType === NHP_COK) {
    // Overload cookie-challenge — already authenticated by decryptReply. The
    // server now echoes the knock counter on the wire so the relay can dispatch
    // it (#2648), while this loop still only surfaces the challenge until the
    // NHP_RKN cookie-answer path lands. COK counter correlation belongs on that
    // path, along with validation that the cookie body is present; replaying a
    // COK here cannot grant access.
    return { kind: "cookieChallenge" };
  }
  if (reply.headerType !== NHP_ACK) {
    throw new Error(
      `unexpected reply type ${reply.headerType} (expected NHP_ACK or NHP_COK)`,
    );
  }

  // Defense-in-depth: the ACK echoes the knock's counter (responder.go sets the
  // reply counter to the request's). decryptReply already proved the reply came
  // from the knocked server and HTTPS already pairs response to request, so this
  // only catches a buggy/misrouting relay or a stale-ACK replay.
  if (reply.counter !== counter) {
    throw new Error(
      `ACK counter ${reply.counter} does not match knock ${counter}`,
    );
  }
  if (reply.body.length === 0) {
    throw new Error("ACK body is empty (header-only reply)");
  }

  const ack = JSON.parse(
    new TextDecoder().decode(reply.body),
  ) as ServerKnockAck;
  // A missing errCode is the Go zero value — implicit success (isSuccessErrCode).
  const errCode = ack.errCode ?? "";

  if (errCode === ERR_QURL_SESSION_EXPIRED) {
    return { kind: "reResolve" };
  }
  if (!isSuccessErrCode(errCode)) {
    return {
      kind: "serverError",
      errCode,
      errMsg: ack.errMsg ?? "",
    };
  }
  return {
    kind: "success",
    resourceHosts: ack.resHost ?? {},
    acTokens: ack.acTokens ?? {},
    openTimeSeconds: ack.opnTime ?? 0,
    agentAddr: ack.agentAddr ?? "",
    redirectUrl: ack.redirectUrl ?? "",
  };
}
