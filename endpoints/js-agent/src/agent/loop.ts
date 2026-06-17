import { pubKeyFingerprint } from "../crypto/fingerprint.js";
import { decryptReply } from "../crypto/ack.js";
import { NHP_ACK, NHP_COK, HEADER_SIZE, getCounter } from "../crypto/packet.js";
import {
  createKnock,
  buildKnockBody,
  browserEntropy,
  type KnockEntropy,
} from "./knock.js";
import { relayPost, type RelayTransport } from "./relay.js";

/** The server granted access: the resource-host and AC-token maps (keyed by
 * resource id), the granted duration, and the agent's source address as the
 * server saw it — from `ServerKnockAckMsg` (`nhp/common/nhpmsg.go`).
 *
 * The success ACK also carries `redirectUrl` (the `*.qurl.site` destination) and
 * `preActions` (pre-access steps); both are deliberately not surfaced yet —
 * whether the page needs the ACK's copy or already holds them from the qURL
 * resolve step is a PR-6 design question, and the field is backward-compatible to
 * add later. `aspToken` is AC-internal and intentionally dropped. */
export interface KnockSuccess {
  kind: "success";
  resourceHosts: Record<string, string>;
  acTokens: Record<string, string>;
  openTimeSeconds: number;
  agentAddr: string;
}

/** The server authenticated the knock but has no active session for this client
 * (deny code 52024, `ErrQurlSessionExpired`). The caller must re-resolve the
 * qURL link to mint a fresh session and knock again — *not* retry this knock. */
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
  | KnockSuccess
  | KnockReResolve
  | KnockServerError
  | KnockCookieChallenge;

/** A single knock's inputs. `serverStaticPub`, `relayBaseUrl`, `authServiceId`,
 * and `resourceId` come from the qURL resolve; `deviceStaticPriv` is the agent's
 * static key. */
export interface KnockRequest {
  deviceStaticPriv: Uint8Array;
  serverStaticPub: Uint8Array;
  relayBaseUrl: string;
  authServiceId: string;
  resourceId: string;
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
 * malformed ACK body (the `JSON.parse` — a TCB-level fault, since the body is
 * server-authenticated by the time it is parsed, not attacker-reachable).
 */
export async function knock(
  req: KnockRequest,
  deps: KnockDeps = {},
): Promise<KnockResult> {
  const entropy = deps.entropy ?? browserEntropy;
  const transport = deps.transport ?? relayPost(req.relayBaseUrl);

  const body = buildKnockBody({
    authServiceId: req.authServiceId,
    resourceId: req.resourceId,
  });
  const { packet, counter } = createKnock(
    req.deviceStaticPriv,
    req.serverStaticPub,
    body,
    entropy,
  );

  // serverId is PR-1's relay routing id — the cell's server-pubkey fingerprint,
  // the key relay.toml is indexed by. Derived from `serverStaticPub` rather than
  // taken from the resolve separately, so the cell we route to can't diverge from
  // the key the crypto authenticates against. (qurl-service returns both at
  // resolve; the design contract is that they agree — serverId == fingerprint.)
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
    // NHP_RKN cookie-answer path lands.
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
  const replyCounter = getCounter(replyBytes.subarray(0, HEADER_SIZE));
  if (replyCounter !== counter) {
    throw new Error(
      `ACK counter ${replyCounter} does not match knock ${counter}`,
    );
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
  };
}
