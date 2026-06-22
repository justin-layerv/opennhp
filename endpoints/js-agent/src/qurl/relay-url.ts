// relay_url validation — the browser/headless port of the Go validator
// (`qurl-service` internal/qurlv2/relay.go).
//
// Per the design, relay_url "must be HTTPS, must pass the qURL deployment
// allowlist, and is used only after client-side issuer signature verification
// succeeds." This is therefore a SEPARATE step from parsing/verifying: a caller
// runs validateRelayUrl only after the fragment's issuer signature is known good.
// Keeping it out of the parser prevents acting on an attacker-chosen relay_url
// before the signature is verified, and keeps the allowlist (deployment config)
// out of the pure crypto core.

/** Thrown when relay_url is not HTTPS, carries userinfo, or is not on the
 * allowlist. Mirrors Go ErrRelayURL. */
export class RelayUrlError extends Error {
  constructor(message: string) {
    super(`qurlv2: relay_url rejected: ${message}`);
    this.name = "RelayUrlError";
  }
}

/**
 * The set of host[:port] origins a relay_url may target, from deployment config.
 * An empty allowlist rejects every relay_url (fail closed) — a deployment must
 * explicitly enumerate its relays. Entries are compared case-insensitively on
 * host; an entry without a port matches any port for that host, an entry with a
 * port matches only that exact host:port.
 *
 * Default-port note: this matcher uses the WHATWG `URL` parser, which strips the
 * https default port (`:443`) from both `host` and `port`. So a `relay.example.com:443`
 * allowlist ENTRY will not match `https://relay.example.com` (the URL's port is
 * normalized away) — this is fail-closed (it can only reject a legitimate relay,
 * never admit an off-allowlist one). To allow a 443 relay, enumerate the BARE host
 * (`relay.example.com`), which the design recommends as the any-port form and which
 * matches default + explicit ports via the hostname fallback. This is the one
 * deliberate divergence from the Go validator's literal `url.Host` match; the
 * security-relevant behavior (HTTPS-only, userinfo rejection, off-allowlist
 * rejection) is identical.
 */
export class RelayAllowlist {
  private readonly hosts: Set<string>;

  /** Builds an allowlist from host or host:port entries (case-insensitive). */
  constructor(entries: readonly string[]) {
    this.hosts = new Set();
    for (const raw of entries) {
      const e = raw.trim().toLowerCase();
      if (e === "") {
        continue;
      }
      // Surface the WHATWG default-port footgun at CONFIG time, not as a mysterious
      // runtime rejection: an entry written with an explicit ":443" never matches an
      // https URL (the parser strips the default port). We keep the literal entry
      // (so match semantics stay exact and we don't silently over-broaden to
      // any-port), but warn so the operator switches to the bare host.
      if (e.endsWith(":443")) {
        console.warn(
          `qurlv2 RelayAllowlist: entry ${JSON.stringify(raw)} has an explicit :443 ` +
            `default port and will NOT match an https relay_url (WHATWG strips :443). ` +
            `Use the bare host ${JSON.stringify(e.slice(0, -":443".length))} to allow it.`,
        );
      }
      this.hosts.add(e);
    }
  }

  /** True iff `authority` (host or host:port) is on the allowlist. */
  has(authority: string): boolean {
    return this.hosts.has(authority);
  }

  /** True iff this allowlist has no entries (rejects everything, fail closed). */
  get isEmpty(): boolean {
    return this.hosts.size === 0;
  }
}

/**
 * Validates a claim's relay_url against the HTTPS requirement and the allowlist.
 * MUST be called only after the issuer signature has been verified. Throws
 * {@link RelayUrlError} when the URL is unacceptable; returns normally otherwise.
 *
 * Rejections, matching the Go validator and its tests:
 *   - a `null`/undefined allowlist or one with no entries (fail closed);
 *   - an unparseable URL;
 *   - a scheme other than https (case-insensitive);
 *   - a missing host;
 *   - ANY embedded userinfo (`https://allowed@evil`, `https://user:pass@host`) —
 *     the classic allowlist-bypass vector, rejected before the host is even
 *     consulted, so a userinfo-decoy URL is rejected even when its REAL host is
 *     itself allowlisted;
 *   - a host (or host:port) not on the allowlist.
 */
export function validateRelayUrl(
  relayUrl: string,
  allow: RelayAllowlist | null | undefined,
): void {
  if (!allow || allow.isEmpty) {
    throw new RelayUrlError("no allowlist configured");
  }

  let u: URL;
  try {
    u = new URL(relayUrl);
  } catch {
    throw new RelayUrlError(`unparseable url ${JSON.stringify(relayUrl)}`);
  }

  // WHATWG includes the trailing ":" on `protocol`; compare case-insensitively.
  if (u.protocol.toLowerCase() !== "https:") {
    throw new RelayUrlError(
      `scheme must be https, got ${JSON.stringify(u.protocol)}`,
    );
  }
  if (u.hostname === "") {
    throw new RelayUrlError("missing host");
  }
  // Reject embedded credentials BEFORE consulting the allowlist. This is the
  // bypass guard: `https://allowed.example.com@evil.example.com` parses to
  // hostname=evil with "allowed.example.com" in username; rejecting any userinfo
  // means the real target is never admitted — and even a userinfo-bearing URL
  // whose real host IS allowlisted is rejected (the guard, not the allowlist,
  // makes the call).
  if (u.username !== "" || u.password !== "") {
    throw new RelayUrlError("userinfo not permitted");
  }

  const hostname = u.hostname.toLowerCase();
  // u.port is "" for the default port (WHATWG strips :443 for https). Build the
  // host[:port] key the same way, so an explicit non-default port is matched and
  // a default port is matched by the bare-hostname fallback below.
  const hostWithPort = u.port === "" ? hostname : `${hostname}:${u.port}`;

  if (allow.has(hostWithPort)) {
    return;
  }
  // A hostname-only allowlist entry matches any port.
  if (allow.has(hostname)) {
    return;
  }
  throw new RelayUrlError(
    `host ${JSON.stringify(hostWithPort)} is not on the relay allowlist`,
  );
}
