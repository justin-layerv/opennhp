# Session Enforcement Architecture

## Status: Implemented (2026-05)

**Author:** posey
**Related PRs:**
- `layervai/qurl-service#514` — resource authz endpoint + OpenTime ↔ session_duration coupling
- `layervai/traefik-plugins#146` — qurl-router consumes the new endpoint on `*.qurl.site`
- `layervai/nhp#1929` — sandbox tfvars + SSM-doc cleanup
- `layervai/traefik-plugins#147` — `hqdatamiddleware` plugin source deletion
- `layervai/nhp#1930` — dead `nhp_session_ttl` cookie removal

## TL;DR

For `*.qurl.site` and custom-domain traffic, **session enforcement is server-side**: the Traefik `qurl-router` plugin calls `GET /internal/v1/resource/:id/authorize?client_ip=X` (or the domain-keyed sibling) against `qurl-service` on every request, with a positive-only cache bounded by `min(15s, remaining_session_seconds)`.

We deliberately rejected a stateless-cookie approach (NHP signs an authz cookie at resolve time, qurl-router verifies it locally) even though it offers lower latency and lower load. The decision was driven by four feature requirements that don't compose with stateless cookies: **revocation**, **`one_time_use`**, **`max_sessions`**, and **audit/billing bookkeeping**.

This document captures the trade-off analysis so a future maintainer doesn't relitigate it cold — and so the conditions for revisiting are explicit.

## Background

A 1-second `session_duration` ([qurl-service#498](https://github.com/layervai/qurl-service/pull/498)) is the marketed floor for short-lived qURLs. In May 2026 we found this floor was structurally not enforced for `*.qurl.site` traffic. The investigation surfaced a longer-standing architectural drift that this document records.

### The legacy cookie-driven attempt

The deleted `hqdatamiddleware` plugin implemented a token-bootstrap reverse proxy:

1. User arrives at the protected resource with `?access_token=<JWT>` in the URL.
2. Plugin decrypts the JWT (AES-GCM), extracts `ServiceInfo` (target host/port/scheme), generates a `session_id` UUID, stores `session_id → ServiceInfo` in an in-process cache (`Apps`).
3. Sets a `session_id` cookie + strips the token from the URL.
4. Subsequent requests look up `session_id` in `Apps` → proxy to cached backend.
5. Cache miss = "Authorization Expired" denial page.

The architecture predates the current `qurl-service`-driven resolve flow. The current flow consumes the `at_*` token at the `qurl.link` step and redirects to `qurl.site` with only NHP cookies (no `?access_token` query). The bootstrap branch of `hqdatamiddleware` was therefore structurally unreachable — `nhp_session_ttl` was set, but no router middleware ever read it.

A three-PR fix chain ([qurl-service#498](https://github.com/layervai/qurl-service/pull/498) + [traefik-plugins#143](https://github.com/layervai/traefik-plugins/pull/143)) tried to fence the cookie path. Each PR was internally correct but bottomed out at unreachable code.

### The current architecture (post-supersession PRs)

```
                qurl-service authoritative
                       │
                       │ session row (DDB):
                       │   pk=resource_id, sk=session_id
                       │   src_ip, ttl, created_at
                       │
   ┌───────────────────┴───────────────────┐
   │                                       │
   │ resolve creates session               │ authz reads session
   │                                       │
   ▼                                       ▼
NHP server                            qurl-router (Traefik)
qurl plugin                           on AC instances
   │                                       ▲
   │ POST /internal/v1/resolve             │
   │ → returns OpenTime, SessionDuration   │ GET /internal/v1/resource/:id/authorize
   │                                       │ → 200 {remaining_seconds: N}
   │ NHP knock (OpenTime → iptables)       │ → 403 if no matching session
   │                                       │
   ▼                                       │
Browser ──redirect──> r_xxx.qurl.site ─────┘
```

Two enforcement layers, both coupled to per-qURL `session_duration`:

| Layer | Mechanism | Coupled how |
|---|---|---|
| L3 (kernel) | iptables/ipset pinhole, timeout = `OpenTime` on the NHP knock packet | `qurl-service` returns `OpenTime = min(defaultOpenTime, sessionDuration)` so the pinhole closes when the session expires. NHP AC has a `openTimeSec == 1` special-case (`endpoints/ac/msghandler.go:154-156`) that also collapses the temp-port window to 1s. |
| L7 (HTTP) | `qurl-router` calls `qurl-service` resource authz on every cache-miss request | `qurl-service` filters sessions by TTL in Go (DDB TTL reaper lags up to 48h); positive-cache TTL = `min(15s, remaining_seconds)` |

End-to-end: after `session_duration` seconds, both L3 (no more bytes flowing) and L7 (HTTP denied) close together.

## Alternative considered: stateless signed cookie

**Shape:** NHP server mints a signed cookie `{resource_id, client_ip, session_id, expires_at}` with HMAC at resolve time. `qurl-router` verifies signature + expiry + client_ip locally on every request. No qurl-service call on the data path.

This is roughly the architecture `hqdatamiddleware` reached for, modernized as a signed cookie instead of a URL-bearing JWT.

### Where cookies win

1. **Latency**: cold-path saves ~10-40ms per request (no qurl-service round trip, no 2 DDB ops).
2. **Throughput**: no API call rate amplification. At 1s `session_duration` and 100 concurrent users on a busy page, the server-side authz path generates ~5,000 qurl-service calls/sec; cookies would generate zero data-path calls.
3. **Graceful degradation**: qurl-service can be down and `*.qurl.site` keeps serving (within cookie lifetime). Server-side authz fails closed after the 15s positive-cache window expires.
4. **Plugin simplicity**: qurl-router doesn't need an HTTP client for authz — pure verify + proxy.

### Where cookies lose (and why we rejected them)

#### 1. Revocation is broken

Current: `DELETE /v1/qurls/:id` or session-kill from compliance / incident-response *immediately* affects future requests. The next authz call hits qurl-service, finds no matching session, denies.

Cookies: the cookie remains valid until its baked-in `expires_at`. Mitigations all defeat the win:

- Server-side denylist → back to per-request API call (no longer "stateless")
- Very short cookie lifetime + refresh mechanism → more complexity, refresh interval *is* the revocation window
- Periodic re-check from qurl-router → just API calls at a lower rate (this is the hybrid option below)

#### 2. `one_time_use` becomes leaky

The current resolve handler atomically consumes the `at_*` token on first knock (`SET status='consumed' WHERE status='active'` — DDB conditional update). Subsequent visits to `qurl.link` with the same token fail.

But once a cookie is minted on that first resolve, the user can revisit the protected resource indefinitely within the cookie's lifetime. The cookie is held by the user; nothing on the qurl-router side knows the token was supposed to be one-shot. Defeats the marketed one-time-use guarantee.

#### 3. `max_sessions` becomes leaky

The DDB session row count is the source of truth for "this qURL has been activated by ≤ N distinct client_ips." A stolen or shared cookie can be replayed from anywhere within the cookie's lifetime — distributing the cookie circumvents the cap. Server-side authz checks the live session table; cookies trust the bearer.

#### 4. Audit & billing bookkeeping

`qurl-service` writes session records used for:
- Billing usage metrics (per-customer session counts)
- Audit log (who accessed what when, from where)
- Dashboards (active-sessions, expiring-soon)

Decoupling cookies from server-side session writes either drops this data or requires parallel bookkeeping (cookie-mint → write session, cookie-verify → write access event). At that point you're paying the DB writes anyway — the cookie just shifts them to a different point in the flow.

#### 5. Cross-resource scoping is touchy

Cookies scoped to `.qurl.site` at the parent-domain level can be sent to *any* subdomain. Per-resource cookies (name = `qurl_authz_r_xxx`) or `resource_id` in the signed payload (with reject-on-mismatch) both work but add complexity. Each qURL a user touches lands a new cookie; browser per-domain cookie count caps (~50) become a concern for power users.

The current design has none of this — there's no resource-scoped state in the browser.

#### 6. HMAC secret blast radius

`qurl-router` running in Traefik on each AC instance would need the same HMAC secret NHP uses to sign cookies. We already have `NHP_INTERNAL_AUTH_SECRET` for nhp-server ↔ qurl-service signing. Adding the AC Traefik plugin as a third consumer:

- Expands the principal set that can read the secret (AC instance role + secret rotation operators)
- A compromised AC instance can now forge authz cookies for any user (currently it can only deny — failure mode is loss of availability, not loss of confidentiality)

The current design needs no shared secret at the plugin layer: qurl-router has a service token for calling the internal API, but that token only lets it *ask* whether a client is authorized, not *assert* that they are.

#### 7. Cookie-theft amplification

A stolen authz cookie under the cookie design is a stolen session, period — the attacker has the credential. Under the server-side design, the attacker also needs to either (a) be on the same source IP (sessions are scoped by `src_ip`) or (b) be inside an iptables pinhole opened for the victim's IP. There's still a stolen-NHP-token problem (`nhp_token` / `nhp_refresh_token` are bearer credentials), but it's bounded by NHP's existing scoping.

## The case where cookies are clearly better: 1-second sessions

For `session_duration ≈ 1s`, the cookie design is both correct and faster:

- Cookie Max-Age = 1 → browser drops the cookie at 1s → next request has no cookie → denied. Zero qurl-service load.
- Server-side authz path: API call + 2 DDB ops per refresh (auth cache TTL clamped to 1s). At 100 concurrent users actively refreshing, ~5k calls/sec — a real load.

**This is the trigger for revisiting.** Today, 1-second sessions are a corner case (demos, security-sensitive one-time views). If the product roadmap moves them into the modal configuration (e.g., default for some pricing tier, or a UX-driven push-button "ephemeral access" feature), the server-side architecture stops being the right trade-off.

## Hybrid option (the right shape if perf becomes the constraint)

If 1-second sessions hit DDB scaling before the feature-compose issues bite:

```
Resolve mints cookie + writes session row
                │
                ▼
Browser → r_xxx.qurl.site
                │
                ▼
qurl-router:
  1. Verify cookie HMAC + expiry + client_ip (fast path)
  2. If cookie valid AND last-authz check < 60s ago: proxy
  3. Else: call qurl-service authz (revocation + audit refresh)
     → on 403: drop cached entry, deny
     → on 200: refresh cached "last-authz" timestamp
```

Trade: 1-2 orders of magnitude fewer API calls in steady state, at the cost of a ≤60s revocation-effective-time window. Whether 60s is acceptable depends on what revocation is for. Incident response usually tolerates it; compliance kills might not.

This is **not implemented today**. Don't build it preemptively — the current design's perf envelope is fine for typical workloads.

## Decision

**Server-side authz is correct for the current feature set.** Specifically:

- `qurl-router` calls `qurl-service` `/internal/v1/resource/:id/authorize` on the `*.qurl.site` branch
- `qurl-router` calls `qurl-service` `/internal/v1/domain/:domain/authorize` on the custom-domain branch
- Positive-only cache, bounded by `min(15s, remaining_seconds)` (the new `*.qurl.site` path) or `15s` (the older domain path)
- Fail-closed on any error
- L3 pinhole (`OpenTime`) coupled to per-qURL `session_duration` in qurl-service's resolve response

## When to revisit

Reopen this trade-off if **any** of the following becomes true:

1. **1-second `session_duration` becomes the modal configuration** (not a corner case). Watch for: tier-default short sessions, "ephemeral access" feature rollout, or repeated customer requests for sub-15s sessions.
2. **qurl-service authz throughput hits a hard wall.** Symptoms: sustained 5xx on `/internal/v1/resource/:id/authorize`, DDB throttled-read alarms on `qurl-resources` or `qurl-sessions`, ECS auto-scaling saturated.
3. **A new feature requires sub-15s revocation latency.** The current architecture's effective revocation window is bounded by the positive-auth cache (15s ceiling). If compliance / incident response needs sub-second revocation, server-side authz can deliver it (drop the cache TTL), but at amplified API call cost.
4. **`max_sessions` and `one_time_use` get reworked or removed.** Two of the four blocker features. If they're deprecated, the cookie option becomes meaningfully more viable.

If revisiting: the hybrid option is the most likely right answer, not pure cookies.

## Monitoring (post-rollout)

To detect when we're approaching the revisit thresholds:

| Metric | Source | Watch for |
|---|---|---|
| `/internal/v1/resource/:id/authorize` p99 latency | qurl-service ECS service | rising past ~30ms p99 |
| `/internal/v1/resource/:id/authorize` error rate | qurl-service ECS service | non-zero 5xx |
| `qurl-resources` + `qurl-sessions` throttled-read count | CloudWatch DDB metrics | any non-zero sustained value |
| qurl-router authz API call rate | (not currently emitted — add a metric if revisiting) | rate ÷ active users |
| Effective revocation latency | manual probe: revoke a qURL, observe time-to-deny | > 15s sustained |

## References

- `endpoints/server/staticplugins/qurl/main.go::AuthWithHttp` — the resolve handler that mints sessions
- `endpoints/ac/msghandler.go:152-156` — the `openTimeSec == 1` special-case on the AC
- `qurl-service/internal/service/resolve_service.go::AuthorizeResourceAccess` — the authz service method
- `qurl-service/internal/service/resolve_service.go::buildResolveOutput` — OpenTime ↔ SessionDuration coupling
- `traefik-plugins/plugins-local/src/github.com/traefik/qurl-router/qurl_router.go::authorizeResourceAccess` — the consumer
- The deleted `hqdatamiddleware` plugin source (recover from git history at `layervai/traefik-plugins` pre-PR #147 if needed for archeology)
