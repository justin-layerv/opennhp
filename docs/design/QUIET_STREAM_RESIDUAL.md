# Quiet-Stream Residual — L3 Flush Design

This document records a known residual gap in the L3 flush
mechanism (`endpoints/ac/expiry_scheduler.go` + `expiry_*_flusher_*.go`)
and the operational mitigation we've chosen.

## The gap

When the L3 flush scheduler fires at the deadline:

- **iptables mode**: `ConntrackFlusher` issues `conntrack -D`
  removing entries from kernel conntrack. The next packet from
  the affected flow hits the netfilter ESTABLISHED bypass — but
  there's no longer an established entry, so it falls through to
  the ipset deny → RST/DROP. The flow is killed on the **next
  packet attempt**.

- **eBPF/XDP mode**: `BpfFlusher` deletes the allow-rule entry
  from the appropriate pinned map (`/sys/fs/bpf/spp` etc.). The
  XDP program's `conn_track` entry naturally inherits the
  remaining lifetime of the allow-rule (`ttl_ns = expire_time -
  now_at_create`), so it's *also* expired by clock arithmetic.
  The next packet triggers `check_conn_expiry` →
  `bpf_map_delete_elem(&conn_track)` → `XDP_DROP`. Again: flow
  killed on the **next packet attempt**.

**Both modes share the same residual: a connection that's quiet
at flush time (no inbound or outbound traffic) lingers in the
kernel TCP stack until *something* triggers a packet attempt.**

Possible triggers:
1. Client sends data.
2. Backend sends data.
3. Either side's TCP keepalive fires.
4. A network event closes the connection (TCP RST, FIN).

For an active streaming connection (SSE, WebSocket actively
exchanging messages), the next packet arrives within
milliseconds — flow terminates immediately.

For a **quiet streaming connection** with no current activity,
the linger time is bounded by TCP keepalive. Linux defaults:

| sysctl | Default | Worst-case linger |
|---|---|---|
| `net.ipv4.tcp_keepalive_time` | **7200 s** (2 hours) | — |
| `net.ipv4.tcp_keepalive_intvl` | 75 s | — |
| `net.ipv4.tcp_keepalive_probes` | 9 | — |

So on a default-tuned Linux backend, a fully quiet TCP
connection could linger up to **2 hours past the session
deadline** before the kernel reaps it.

## Why we don't fix this from the AC

Three obvious options were considered and rejected:

1. **Forge a TCP RST from the AC.** Requires raw-socket
   privileges and knowledge of the TCP sequence numbers on the
   live connection — but the AC isn't on the TCP-handling path
   (it's an XDP/iptables gateway, not a Layer 4 proxy). The
   AC can't observe seq numbers, so it can't fabricate a valid
   RST. Discarded.

2. **Iterate kernel conntrack on every flush + send RST.**
   Possible via NFQUEUE redirection but adds a per-packet
   userspace bounce — fundamentally incompatible with the XDP
   line-rate path. Discarded.

3. **Aggressive `conn_track` ttl_ns shortening at the
   kernel/XDP layer.** Would force `check_conn_expiry` to fire
   at the next packet within shorter windows — but doesn't
   help quiet flows (no next packet to check).

## The mitigation: backend-side TCP keepalive

For every service protected behind a qURL, the operator tunes
the BACKEND server's TCP keepalive to reap quiet connections
quickly. Recommended values:

| sysctl | Recommended | Worst-case linger |
|---|---|---|
| `net.ipv4.tcp_keepalive_time` | **10 s** | — |
| `net.ipv4.tcp_keepalive_intvl` | 5 s | — |
| `net.ipv4.tcp_keepalive_probes` | 3 | — |

Total worst-case quiet-flow lifetime past session end: ~25 s.

These are server-level sysctls — set on every protected backend.
For protected services running in Docker or behind Traefik, the
keepalive setting on the BACKEND application's listening socket
is what matters (not the proxy's). Reverse-proxy configurations
that terminate TCP at the proxy (Traefik in TCP-passthrough mode
does not) need the same tune on the proxy's listening socket.

Application-layer alternatives that also work:

- **HTTP/2 PING frames** at < 25 s interval — most HTTP/2
  servers ship with PING enabled and tunable to short intervals.
- **WebSocket ping/pong** at < 25 s — standard heartbeat
  practice for production WebSocket services.
- **Application-layer heartbeat** (e.g., SSE "comment" lines
  every N seconds).

Any of these triggers a packet on the connection well within
the 25 s window, ensuring the kernel reaps the entry promptly
when its allow-rule / conntrack TTL has elapsed.

## What the design contract accepts

Under the L3-only enforcement target (qurl-router L7 layer
removed in the post-L3-flush-rollout PR), the security
guarantee is:

> **No new TCP connection is admitted past
> `session_duration`. Existing TCP connections terminate within
> `25 s` of session end PROVIDED the backend follows the TCP
> keepalive recommendation above. Without keepalive tuning,
> quiet connections may persist up to the kernel default
> (2 hours).**

This is a documented, explicit gap. Operators are responsible
for the keepalive tune as part of qURL onboarding.

For threat models where 25 s of residual data flow on a quiet
connection is unacceptable, qURL is not the right primitive —
those callers need application-layer enforcement (session
revoke on the protected service itself).

## Operational checklist (for backend onboarding)

When onboarding a new service behind qURL, the runbook should
include:

1. Apply the `tcp_keepalive_*` sysctls listed above to the
   backend host (or its container's network namespace if not
   sharing the host stack).
2. Confirm application-level heartbeats fire at < 25 s
   intervals on any long-lived connection type (HTTP/2 PING,
   WebSocket ping, SSE comments).
3. If the backend is behind Traefik in TCP-passthrough mode,
   apply the sysctls to the Traefik host as well (Traefik holds
   the TCP socket; the backend doesn't see the client TCP
   directly).
4. Verify post-onboarding via the smoke test
   (`tests/smoke/l3_flush_quiet_stream_test.go` — to be added
   in the same PR rollout) that a quiet 5-second session
   genuinely closes within 30 s of expiry.

## See also

- `SCHEDULER_SCALING.md` — scheduler architecture + SLO
  rationale.
- `SESSION_ENFORCEMENT_ARCHITECTURE.md` — overall enforcement
  model.
- `expiry_scheduler.go` — scheduler implementation + godoc.
- `expiry_bpf_flusher_linux.go` — the eBPF-mode rationale for
  not iterating conn_track (because `check_conn_expiry` handles
  the active-flow termination naturally).
