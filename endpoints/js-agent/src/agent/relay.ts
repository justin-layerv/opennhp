/**
 * Delivers a knock packet to the NHP-Relay and returns the server's reply
 * packet. Injectable so the agent loop can be exercised without HTTP (a mock in
 * tests); production uses {@link relayPost}. `serverId` is the server-pubkey
 * fingerprint that routes the relay to the right cell.
 */
export type RelayTransport = (
  serverId: string,
  packet: Uint8Array,
) => Promise<Uint8Array>;

/**
 * A relay that did not return a `200 application/octet-stream` reply — a
 * transport fault (unknown server, malformed/oversize packet, forward failure,
 * shutdown, or server timeout), distinct from an authenticated server *deny*
 * (which comes back inside a decryptable `NHP_ACK`). `status` is the HTTP status,
 * or `0` for a transport-level failure with no HTTP response (request timeout or
 * a network error).
 */
export class RelayError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "RelayError";
    this.status = status;
  }
}

/** Default per-request timeout. A knock is one relay→server→relay round trip, so
 * seconds is generous; the bound exists so a network/TLS hang can't leave the
 * agent loop (and the qurl.link page) awaiting the transport forever. */
const DEFAULT_RELAY_TIMEOUT_MS = 10_000;

/**
 * Builds the production {@link RelayTransport}: `POST {relayBaseUrl}/relay/{serverId}`
 * with the raw packet as an `application/octet-stream` body, returning the
 * server's reply packet bytes. Mirrors the relay HTTP contract in
 * `endpoints/relay/relay.go` (`handleRelay`): 200 → reply bytes; any other status
 * (404 unknown server, 400 malformed/oversize, 405 wrong method [unreachable —
 * this always POSTs], 502/503/504 forward/shutdown/timeout) throws
 * {@link RelayError}. A request timeout
 * (`timeoutMs`, default {@link DEFAULT_RELAY_TIMEOUT_MS}) or a network failure
 * also throws `RelayError` (with `status` 0).
 *
 * `serverId` is a URL-safe pubkey fingerprint (PR-1), so it is interpolated into
 * the path as-is — the relay reads it with a raw `TrimPrefix(path, "/relay/")`.
 */
export function relayPost(
  relayBaseUrl: string,
  timeoutMs = DEFAULT_RELAY_TIMEOUT_MS,
): RelayTransport {
  const base = relayBaseUrl.replace(/\/+$/, "");
  return async (serverId, packet) => {
    const url = `${base}/relay/${serverId}`;
    let resp: Response;
    try {
      resp = await fetch(url, {
        method: "POST",
        // Cross-origin: this triggers a CORS preflight (octet-stream is not a
        // safelisted Content-Type). The relay's Access-Control-Allow-Headers
        // (endpoints/relay/cors.go) must list every header sent here — adding a
        // request header (auth, trace, idempotency-key, …) WITHOUT updating it
        // makes the browser preflight fail with no server-side error. Keep in sync.
        headers: { "Content-Type": "application/octet-stream" },
        // Fresh ArrayBuffer-backed copy: BodyInit rejects Uint8Array<ArrayBufferLike>
        // (the backing buffer may be a SharedArrayBuffer). The packet is small.
        body: new Uint8Array(packet),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      // AbortSignal.timeout rejects with a DOMException "TimeoutError"; a network
      // failure rejects with a TypeError. Both are transport faults — surface a
      // RelayError (status 0) so the loop/page has one fault type to handle.
      const why =
        e instanceof DOMException && e.name === "TimeoutError"
          ? `timed out after ${timeoutMs}ms`
          : e instanceof Error
            ? e.message
            : String(e);
      throw new RelayError(0, `relay POST ${url} failed: ${why}`);
    }
    if (!resp.ok) {
      const detail = (await resp.text().catch(() => "")).trim();
      throw new RelayError(
        resp.status,
        `relay POST ${url} -> ${resp.status}${detail ? `: ${detail}` : ""}`,
      );
    }
    return new Uint8Array(await resp.arrayBuffer());
  };
}
