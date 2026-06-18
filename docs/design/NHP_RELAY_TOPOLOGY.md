# NHP-Relay Topology — Taking nhp-server Off the Internet

## Status: Proposed — Planning (2026-06)

**Author:** Justin
**Tracking issue:** [layervai/nhp#2208](https://github.com/layervai/nhp/issues/2208)

This document is the design spine for issue #2208. The epic spans many PRs
across three repos and several weeks; this doc exists so the work can be
sequenced and reviewed against a single locked decision rather than
re-litigated PR-by-PR. It is **planning**, not implemented — no behaviour
changes with this PR. Each implementation step below lands as its own PR (or
PR chain).

## TL;DR

Today `nhp-server` is internet-facing: a public NLB exposes UDP `62206` for
agent knocks, and the qURL resolve path reaches the server's HTTP plugin
surface (port `8888`). `nhp-server` is the policy engine and the NHP-AOP
**signing authority** for AC operations, so public exposure forces it to
defend the full internet threat model.

We move it private behind a new **NHP-Relay** — the only internet-facing NHP
control-plane surface — and bring the qURL flow into alignment with the
canonical NHP workflow:

```
Browser (JS NHP-Agent) ──► NHP-Relay (internet-facing) ──► NHP-Server (private)
                                                                  │
                                                                  │ NHP-AOP (unchanged)
                                                                  ▼
                                                                NHP-AC
```

The two decisions this doc locks:

1. **Re-knock authorization model** (issue item 3): on each agent re-knock the
   server **re-consults qurl-service for fresh policy** (option *a*). We reject
   the session-bound-token alternative (option *b*) for the same reasons
   `SESSION_ENFORCEMENT_ARCHITECTURE.md` rejected stateless authz cookies:
   revocation, `one_time_use`, `max_sessions`, and audit/billing do not compose
   with a token the server trusts without re-checking. See
   [Decision: re-knock authorization](#decision-re-knock-authorization).

2. **Renewal moves from L7 to the agent.** The AC's HTTP `/refresh` plane
   ([`endpoints/ac/httpac.go`](../../endpoints/ac/httpac.go)) is deleted; renewal
   becomes spec Step 8 — the agent re-knocks before Access Duration expires, the
   server emits a fresh NHP-AOP, and the AC re-Schedules through its **existing**
   AOP handler. See [Renewal cutover](#renewal-cutover).

No new NHP wire message types are introduced. `NHP_RKN` (agent re-knock) and
`NHP_RLY` (relay→server) already exist in
[`nhp/core/packet.go`](../../nhp/core/packet.go), as does the `NHP_RELAY` device
type. The NHP-AOP wire format is reused as-is.

## Implementation approach: adopt upstream via port

OpenNHP upstream already ships this entire feature — the relay
(`endpoints/relay/`), the server-side `HandleRelayForward`, the
`common.RelayForwardMsg` envelope, and a browser JS agent (`endpoints/js-agent/`
with an HTTPS-POST `relay.ts` transport). Our fork merely stubbed the relay out
during the "separate modules" refactor and marked the relay commits **SKIP** in
`docs/UPSTREAM_SYNC.md`. So we **adopt** upstream's design rather than build a
parallel one. (An abandoned from-scratch attempt — PR #2523, which minted an
incompatible envelope plus a needless reply type — was closed.)

Honest scope: this is a **port (~3–4 focused days for the Go side), not a verbatim
sync** — our `nhp/core` has diverged (no `loadbalance` package, no
`utils.PubKeyFingerprint`, and `core.ConnectionData` lacks the `RealRemoteAddr` /
source-stickiness fields upstream's handler uses). The port:

- **Transport is HTTPS POST** (upstream's). WebSocket was quantified and rejected:
  it saves ~100 ms on invisible background re-knocks but costs ~300× concurrent
  connections at scale and permanent upstream divergence, and its one unique
  benefit (server push) is unused by our pull-based revocation model.
- **Avoids touching `core.ConnectionData`** by adapting `HandleRelayForward` to our
  existing `endpoints/server/forward.go` synthetic-`ConnData` pattern (how the
  `NHP_FWD` path already injects an externally-supplied source address). A core
  change is the last resort — isolated and `-race`-tested if forced.
- **Ports upstream's relay security fixes** — relay DoS + source-IP validation
  (`e2c5336a`) and the X-Forwarded-For tightening (`ad98e1f4`) — which our
  `UPSTREAM_SYNC.md` previously skipped. These provide the relay-edge hardening the
  Relay threat model section below requires.

## Background

### Why nhp-server is exposed today

Browsers cannot speak NHP (no raw UDP, no Noise handshake in page JS today), so
the qURL flow **synthesizes the knock server-side**: qurl-service calls the
server's internal resolve plugin, which constructs an `NHP_KNK` on the agent's
behalf. There is no NHP-Agent in the loop. This is a deliberate, documented
deviation from spec Step 1 (`docs/ARCHITECTURE.md`), and it is the reason two
public surfaces exist:

- **UDP `62206` via the public NLB** — raw agent knocks (the OpenNHP agent path).
- **The internal resolve plugin on the server HTTP surface (port `8888`)** — the
  qurl.link resolver that synthesizes knocks for browser-originated sessions.

Because `nhp-server` signs every NHP-AOP the AC acts on, an attacker who can
reach it gets to attack the policy/signing authority directly: knock-flood,
spec-fuzzing, and any zero-day in NHP packet parsing land on the most
security-critical service in the system.

### How renewal works today (L7-driven)

For `*.qurl.site` and custom-domain traffic, per-request session enforcement is
already server-side: the Traefik `qurl-router` plugin calls qurl-service's
`/internal/v1/resource/:id/authorize` on every request, with a positive-only
cache bounded by `min(15s, remaining_session_seconds)` (see
[`SESSION_ENFORCEMENT_ARCHITECTURE.md`](SESSION_ENFORCEMENT_ARCHITECTURE.md)).

Separately, the **L3 firewall window** the AC opened must be *renewed* before it
expires. Today that renewal is also L7-driven: `qurl-router` (co-located on the
AC host) calls the AC's **loopback-only** HTTP `/refresh/:token?srcip=…` plane
([`endpoints/ac/httpac.go`](../../endpoints/ac/httpac.go)), which re-issues the
firewall window through `HandleAccessControl`, capped at the absolute deadline
(`FirstKnockTime + OpenTime`, #1942). `common.HttpRefreshRequest`
([`nhp/common/types.go`](../../nhp/common/types.go)) is the request type for that
plane.

This `/refresh` plane is the footprint the epic removes; it exists solely to
renew firewall windows that the canonical NHP workflow renews with a re-knock.
See [Renewal cutover](#renewal-cutover) for exactly what gets deleted.

### What already exists in core

The relay topology is **spec-aligned**, and the protocol primitives are already
present — only the *services* are missing:

| Primitive | Where | Status |
|---|---|---|
| `NHP_RKN` (agent re-knock) | [`nhp/core/packet.go`](../../nhp/core/packet.go) | Defined; server gates it in [`knock_headertype_gate.go`](../../endpoints/server/knock_headertype_gate.go) and dispatches it in [`udpserver.go`](../../endpoints/server/udpserver.go); the Go agent constructs it in [`endpoints/agent/knock.go`](../../endpoints/agent/knock.go) |
| `NHP_RLY` (relay→server) | [`nhp/core/packet.go`](../../nhp/core/packet.go) | Header type + `NHP_RELAY` device type defined; **no relay service consumes it yet** |
| NHP-AOP renewal on the AC | [`endpoints/ac/`](../../endpoints/ac/) AOP handler | Existing; a fresh AOP already re-Schedules the firewall window |

The issue and the NHP spec refer to these as relay message *types 9 and 10*, but
that is the spec's prose numbering, **not** the wire value: the `iota` block in
`nhp/core/packet.go` starts at `NHP_KPL = 0`, so the actual constants are
`NHP_RKN = 8` and `NHP_RLY = 9`. Reference them by name — anyone who hard-coded
the spec's `9`/`10` would be wrong *today*.

## Target architecture

### NHP-Relay

We **adopt the upstream OpenNHP relay** (`endpoints/relay/`, today a bare
`package relay` stub in our fork) rather than build one — see
[Implementation approach](#implementation-approach-adopt-upstream-via-port). It
is an internet-facing service that:

- Accepts browser-originated NHP traffic over **HTTPS POST** (`POST
  /relay/{serverId}`, body = one inner NHP packet; browsers cannot send UDP). The
  Noise handshake and AEAD bodies are **end-to-end between the JS agent and the
  server**; the relay does not hold session keys.
- In the AWS relay deployment, the public ALB terminates client TLS and
  re-encrypts the ALB-to-relay backend leg over HTTPS. The relay treats the
  ALB-only security group path as the trusted ingress/authz boundary; the
  per-instance backend certificate is an in-VPC encryption control, not a target
  identity proof, because the ALB does not validate target certificates today.
- Forwards each inner packet to the **private** `nhp-server` inside an
  authenticated `NHP_RLY` envelope (`common.RelayForwardMsg{SourceAddr,
  InnerPacket}`) over a persistent UDP/Noise connection, and returns the server's
  reply — matched back to the originating request by the **inner packet's
  counter** (the server replies with the normal `NHP_ACK`/`NHP_COK`; no new reply
  wire type).
- Is sized for initial knock + periodic renewals only. It replaces the public
  NLB as the single internet-facing NHP surface.

Because keys are end-to-end (above), the relay is a **forwarder, not a trust
anchor**: it never sees plaintext or the AOP signing key, and validates only what
`core.Device.DisableRelayPeerValidation` permits. A relay compromise yields a
packet-forwarding position, not the signing authority.

### Relay threat model — what moves and what does not

The "forwarder, not a trust anchor" framing is about **confidentiality and
integrity**: keys stay end-to-end and the signing authority stays private, so a
relay compromise cannot forge AOPs. It is *not* a statement about
**availability**. Moving the public surface from `nhp-server` to the relay
**relocates the DoS/abuse burden; it does not remove it.** The relay now runs the
HTTP + `NHP_RLY`-framing path on attacker-controlled bytes (it forwards the inner
packet opaquely, but still parses the HTTP body, extracts the inner-packet counter,
and is the front door), so it is the service that absorbs knock-flood, spec-fuzzing,
and any packet-parsing zero-day that motivated taking `nhp-server` private in the
first place.

These are therefore **non-optional properties of the relay**, not "forwarder"
details a reader can discount. Adopting upstream's relay (plus its previously-skipped
security fixes `e2c5336a` / `ad98e1f4`) is what supplies them — they are inherited and
verified, not reinvented:

- **Rate-limiting / flood control** at the relay edge (per-IP and global),
  sized for initial-knock + renewal volume with headroom for abuse.
- **Parser hardening** of the `NHP_RLY` framing on untrusted input — bounded
  allocations, strict length checks, no parse work before cheap structural
  validation (mirror the server-side gates in
  [`endpoints/server/knock_headertype_gate.go`](../../endpoints/server/knock_headertype_gate.go)).
- **Resource sizing under flood** and a degradation story that fails closed
  without taking the private `nhp-server` down with it.
- **Source-IP integrity** for the AC pinhole. The relay stamps
  `RelayForwardMsg.SourceAddr` from the edge-observed client IP (deployment:
  ALB-appended, rightmost `X-Forwarded-For`), and `nhp-server` accepts that
  value only from a Noise-authenticated, `relay.toml`-registered `NHP_RELAY`
  peer before using it as the synthetic knock source. This is the independent
  trust root that replaces the pre-cutover qurl-service caller-asserted
  `HttpKnockRequest.SrcIp` vector tracked in #1210.

The win is real but specific: the *blast radius* of an edge compromise shrinks
from "policy + signing authority" to "packet forwarder," and the hardened
surface is a small, single-purpose service instead of the full server.

### JS NHP-Agent (browser)

A browser NHP-Agent (separate deliverable, likely a new repo) that performs the
Noise handshake, constructs `NHP_KNK` / `NHP_RKN`, and parses `NHP_ACK`. WASM-backed
crypto for performance; bundle small enough to load from the qurl.link or
fileviewer page. It also owns the **re-knock scheduler** (renew at `Access Duration − margin`,
10–20% margin + jitter to avoid thundering-herd).

> **Background-tab renewal is the scheduler's hardest requirement, not a
> footnote.** Browsers clamp background `setTimeout` (≥1 min) and fully suspend
> timers under memory pressure / bfcache, so a backgrounded tab can sail past its
> renewal deadline — the Page Visibility "renew on foreground" handler then fires
> only *after* the L3 window has already closed mid-session. The JS-agent PR
> (item 4) must pick an explicit contract: a server/relay-side **grace window**
> that tolerates a late re-knock, or a documented **"backgrounded sessions may
> need a fresh knock on return"** UX. Naïve `setTimeout` renewal is insufficient.

### The canonical flow

With the JS agent and relay in place, the qURL flow becomes the canonical NHP
workflow (spec pages 22–23, Steps 1–8; see [Spec compliance](#spec-compliance))
rather than a server-side synthesis:

1. JS agent performs the Noise handshake and sends `NHP_KNK` → relay → server.
2. Server authorizes (consults qurl-service), emits NHP-AOP to the AC, replies
   `NHP_ACK` to the agent (← relay).
3. AC opens the L3 firewall window for the agent's source IP.
4. …agent accesses the resource…
5. Before Access Duration expires, the JS agent's scheduler fires a **re-knock**
   (`NHP_RKN`) → relay → server (spec Step 8).
6. Server **re-consults qurl-service** (option *a*; see below), emits a fresh
   NHP-AOP, the AC re-Schedules the firewall window through its existing handler.

## Spec compliance

This topology *implements* the canonical NHP workflow rather than deviating from
it. References below are to the CSA whitepaper **"Stealth Mode SDP for Zero Trust
Network Infrastructure — Introducing the Network-infrastructure Hiding Protocol
(NHP)"** (CSA Zero Trust Working Group, 2026) — verifiable against the PDF.

| Design choice here | Spec backing |
|---|---|
| **Browser JS NHP-Agent** | *NHP Core Components* (p. 21): the NHP-Agent "can exist as a client, SDK, **browser**, application, or other similar entity." |
| **`common.RelayForwardMsg{SourceAddr, InnerPacket}` as the `NHP-RLY` (type 9) body** | Appendix 2, *NHP-RLY (Relay) Message* (p. 53): "initiated by the NHP relay server… forward messages that require the **NHP proxy source address to be retained**… the carried message is the **original NHP protocol request packet… without additional encryption or compression**." That is exactly `SourceAddr` + opaque `InnerPacket`. |
| **`NHP_RKN` (type 8) = cookie-retry re-knock** | Appendix 2, *NHP-RKN (Re-Knock) Message* (p. 53): "a second knock using a cookie… same fields as NHP-KNK; however, the HMAC calculation must also use the cookie value obtained from NHP-COK." |
| **No new reply wire type** (server replies with the normal `NHP-ACK`, matched by the inner-packet counter) | `NHP-RLY` carries the *request*; the spec defines no separate relay-reply type — the server's `NHP-ACK` (type 2) is the response. |
| **Agent-driven renewal** (replacing the AC `/refresh` L7 plane) | Workflow **Step 8** (p. 23): "the NHP-Agent must negotiate a renewal of the open-door session by **repeating steps 1–7**." |
| **Relay source-address preservation via `X-Forwarded-For`** | Workflow **Step 4** (p. 23): intermediaries perform "**source IP preservation (via PROXY protocol or X-Forwarded-For headers)**… as supported by modern proxies like NGINX or HAProxy." Reinforced by the NHP-AOP NAT note (p. 50) on per-session tokens for NAT'd agents — which the qURL session model supplies. |
| **NHP-Server (auth) decoupled from NHP-AC (enforcement)** | pp. 8, 16, 20–21: NHP "decouples the authentication and access control features"; Server = Policy Engine, AC = Policy Enforcement Point (NIST SP 800-207). |
| **Taking the server private behind the relay** | The protocol's purpose — *Network-infrastructure Hiding* — and threat model (pp. 8, 12): "hiding all ports and services," DDoS mitigation by "concealing IP addresses." A non-internet-reachable server is the strongest form of this. |

**One spec nuance (not a deviation).** The *summary* message-type table (Table 4,
p. 29) words NHP-RKN/NHP-RLY loosely ("forward requests" / "forward responses"),
which reads slightly differently from the **authoritative Appendix-2 detail**
(p. 53) cited above. The two are internally inconsistent within the spec itself;
this design follows the detailed Appendix-2 definition — which is also exactly
what **OpenNHP**, the spec's official open-source reference implementation
(Appendix 1, p. 47), does. Matching the reference implementation keeps us
interoperable with the canonical NHP ecosystem.

## Cloud deployment: cells & autoscaling

### Cell routing

The relay is LayerV's **cell router**. We run one cloud cell today and will add
more; each cell is an independent stack (its own NHP-Server + AC fleet,
qurl-service, DynamoDB). Because the relay is the single internet-facing surface,
it is the natural place to route a browser's knock to the customer's cell — which
is exactly upstream's **multi-cluster relay model**: `POST /relay/{serverId}`,
where `serverId` is a cell's **server-pubkey fingerprint**, and the relay holds one
config entry per cell (fingerprint → that cell's endpoint + server pubkey). So
**one cell = one entry**; adding a cell is a config change, not a protocol change.
This is why P2's `utils.PubKeyFingerprint` is the cell-routing key, and why the
multi-cluster routing is **ported, not stripped** (upstream `d0836539`).

**Customer→cell mapping lives in the control plane, not the relay.** The knock is
end-to-end encrypted and opaque to the relay, so the relay *cannot* see the
customer — it routes by the opaque `serverId` only ("forwarder, not trust anchor").
The customer→cell decision belongs in **qurl-service**, which already owns the
customer→resource resolve: at `qurl.link` resolve time it returns the cell's
`serverId` + server pubkey, and the JS-agent then `POST`s to `/relay/{serverId}`.
A customer is "homed" to one cell (their resources/AC live there); qurl-service's
mapping must stay consistent with that homing — a wrong `serverId` routes to a cell
without the customer's resource and the knock fails.

**Build the seam now, deploy single-cell.** With one cell, the JS-agent still
addresses `/relay/{serverId}` and resolve still returns a `serverId` — just a
constant today. The per-customer mapping and extra relay config entries activate
when cell 2 arrives, with no protocol or relay change. This keeps the contract
multi-cell-ready without building the mapping logic yet.

This seam is already partly real in the IaC, not just aspirational:
`terraform/modules/compute` carries a `cell_id` variable, tags resources with
`Cell = var.cell_id`, and documents the `${name_prefix}[-${cell_id}]-server` secret
convention (current cell today, `cell{N}` next) — so the relay's per-cell config and
secret naming slot into an existing cell model.

### Autoscaling

The relay composes with NHP-Server/AC autoscaling because it rides today's
shared-key model ([`PER_INSTANCE_SERVER_KEYS.md`](PER_INSTANCE_SERVER_KEYS.md): all
servers in an ASG share one keypair, so any instance behind the NLB decrypts). That
doc plans to migrate *direct* connections to per-instance keys, but **retains** the
shared key for the NLB/registration path the relay uses (see coupling #1 below), so
the relay's footing is stable:

- **Relay fleet** — now availability-critical (the only internet-facing surface), so
  it must autoscale. Give the relay fleet a **single shared keypair**, mirroring the
  server's shared-ASG-key in Secrets Manager. The real convention is
  `${name_prefix}[-${cell_id}]-<component>` (`terraform/modules/compute/main.tf:9-14`):
  the *server* secret is per-cell (`nhp-{env}-server` for the current cell,
  `nhp-{env}-cell{N}-server` for future ones, since server fleets are per-cell). The
  relay secret stays **singular** — `nhp-{env}-relay`, with no `cell{N}` variant —
  because one relay fleet fronts *all* cells and routes by `serverId`; a per-cell
  relay secret would imply a per-cell relay identity, contradicting the shared-router
  model (the stale assumption P5/P6 must not bake in). Then `relay.toml` stays a
  one-entry trust list and relay scale-out
  is a non-issue. The relay holds no session keys (inner crypto is end-to-end), so
  the shared identity's blast radius is just its source-IP trust. **Avoid
  per-instance relay keys** — they would force a dynamic registry.

  > **Scale-out works, with one server-side dependency — `DisableRelayPeerValidation =
  > true`.** The shared keypair means N relay instances present N source IPs but a single
  > peer entry. The server's default `CheckRecvAddress`
  > ([`nhp/core/peer.go`](../../nhp/core/peer.go)) pins a peer to one source IP within a 5s
  > `MinimalPeerAddressHoldTime` window, so with validation ON a fleet would have
  > all-but-one instance's `NHP_RLY` rejected under load. Setting
  > `DisableRelayPeerValidation = true` — a *per-peer-type* device option set via the
  > server's `SetOption` config path ([`endpoints/server/config.go`](../../endpoints/server/config.go),
  > affecting NHP_RELAY peers only) — skips that source-IP pin (and the rest of the
  > responder's per-peer validation block; incompatible with a multi-IP fleet). The
  > relay stays authenticated by the Noise IK handshake (a sender cannot produce a
  > server-accepted `NHP_RLY` under the relay's pubkey without the fleet private key)
  > **plus** `HandleRelayForward`'s `lookupRelayPeer` registration check
  > ([`endpoints/server/relay.go`](../../endpoints/server/relay.go) — with the flag on,
  > `lookupRelayPeer` is the load-bearing relay-pubkey authz gate, not
  > belt-and-suspenders). So the fleet authenticates by pubkey
  > + `relay.toml` registration, **not** by address — exactly the "source-IP trust is the
  > blast radius" posture above. **5b-2 (#2208) deploys the relay as an autoscaling fleet
  > (one instance per AZ baseline, 2/AZ ceiling, ALB-request-count target tracking); 5c sets
  > the flag and registers the relay pubkey.** The relay's IP is never registered — the contract to the server's
  > `relay.toml` is the **pubkey**. #2541 (a dynamic DDB relay registry replacing static
  > `relay.toml`) is a *separate* enhancement, NOT a prerequisite for the fleet.
- **Relay→cell-server handshake** — the relay handshakes to each cell's **shared
  server endpoint key** (the same one agents/ACs use via the NLB/CloudMap), so any
  healthy instance in that cell decrypts; server scale/refresh is transparent.
- **`relay.toml` under server autoscaling** — the shared relay pubkey is delivered to
  **every** server instance (and every cell) via the normal config path, so each
  scaled-out / blue-green / refreshed server trusts the relay from boot; no
  registration race.

**Two forward-looking couplings to not lose:**

1. The relay forwards through the NLB/CloudMap to each cell's **shared
   registration/endpoint key** — the same path the planned
   **per-instance-server-keys** migration explicitly *retains* (that doc's collision
   is specific to an AC opening *direct* connections to multiple per-instance
   servers, which the relay never does). So the relay is implicitly covered **as long
   as that shared key is retained**; the watch-item is the converse — if the shared
   registration key is ever dropped entirely, the relay→server path needs its own
   per-cell-key story.
2. The static `relay.toml` load path already exists (P3a — `updateRelayPeers` /
   `relayPeerMap`), so the wipe hazard below is a real path, not hypothetical. If a
   **dynamic relay registry** (DDB / `NHP_AOL`-style) ever replaces `relay.toml`, it
   would need the *same kind* of boot guard `agent.toml` already has — the
   server-side check in [`endpoints/server/config.go`](../../endpoints/server/config.go)
   that refuses boot when `agent.toml` coexists with a cloud DDB *agent* registry (a
   pattern to replicate; there is **no** equivalent `relay.toml` guard today) —
   otherwise a `relay.toml` watcher fire would wipe DDB-resolved relay peers. Tracked
   as a tripwire in #2541.

**The relay is cross-cell shared infra:** its availability and routing affect all
cells (its blast radius is cross-cell *routing / source-IP*, never sessions), and a
new cell must be in the relay's config **before** qurl-service assigns customers to
it.

## Decision: re-knock authorization

**Decision: option (a) — the server re-consults qurl-service on every re-knock.**

Issue item 3 frames the choice:

- **(a)** qurl-service consulted per re-knock — per-renewal policy refresh;
  correct; more load.
- **(b)** session-bound token issued at initial `NHP_ACK`; re-knocks present the
  token; qurl-service consulted only on initial knock + token expiry — less
  load; harder to revoke mid-session.

We choose **(a)**, and the justification is precedent, not preference. Option
(b) is the **stateless-token pattern that `SESSION_ENFORCEMENT_ARCHITECTURE.md`
already rejected** for the per-request authz plane. The feature requirements that
doc enumerates (its "When to revisit" section is the canonical, living list)
apply unchanged to a *renewable* re-knock token:

- **Revocation.** A token the server trusts until expiry keeps renewing a
  session that an operator (or `qurl-router`) revoked seconds ago. Re-consulting
  qurl-service makes the next re-knock the revocation point.
- **`one_time_use`.** A renewable token is by construction reusable.
- **`max_sessions`.** Concurrency limits can change between knocks; only a fresh
  consult sees the current count.
- **Audit / billing.** Each renewal is a billable, auditable event; option (b)
  hides renewals from qurl-service between token-expiry boundaries.

**The decision rests on correctness, not load.** This matters because the load
argument is *weaker* here than in the SESSION doc, not stronger: a re-knock fires
once per renewal interval (minutes), whereas the rejected stateless cookie was
weighed against per-*request* authz (orders of magnitude more frequent). So a
future "but re-knocks are rare — just trust a token between them" challenge does
not reopen (b); it fails on the same revocation / `one_time_use` / `max_sessions`
/ audit grounds regardless of frequency. Load merely confirms there is no
countervailing pressure: option (a) costs one consult per re-knock — the issue's
own sizing (~33 re-knocks/sec for 10K sessions at a 5-minute cadence) is trivial,
current prod knock volume is far lower (single-digit knocks/hour), and the
`min(15s, remaining)` positive cache already bounds any consult amplification.

This keeps the renewal authz model **identical** to the per-request authz model:
qurl-service is the single source of session truth, consulted on a bounded
cadence, with no server-trusted bearer token in the loop.

#### Mechanism (no new knock field, no new qurl-service endpoint)

The consult **reuses the existing** `GET /internal/v1/resource/:id/authorize?client_ip=X`
— the same endpoint `qurl-router` already calls per request
([`SESSION_ENFORCEMENT_ARCHITECTURE.md`](SESSION_ENFORCEMENT_ARCHITECTURE.md)). The
`at_*` access token is consumed at the `qurl.link` `/resolve` step and is **gone** by
knock time (the browser carries only NHP cookies to `qurl.site`), so the knock cannot
and need not carry a token. Identity is **`AgentKnockMsg.ResourceId`** (already on the
wire) plus the **relay-forwarded client IP** (`common.RelayForwardMsg.SourceAddr`). The
server-side QURL `AuthWithNHP` — today an `ErrPluginNotRegistered` stub
([`endpoints/server/staticplugins/qurl/plugin.go`](../../endpoints/server/staticplugins/qurl/plugin.go))
— calls that endpoint and dispatches the AOP via `handleNhpOpenResource`. Because
`NHP_KNK` and `NHP_RKN` both route through `HandleKnockRequest`→`AuthWithNHP`, renewal
re-consults automatically. (Three small `/authorize`-contract items live in the
qurl-service repo and must be confirmed before implementation: lookup by
`resource_id`+`client_ip`+TTL, whether a `session_id` must be preserved across renewal,
and IP-scoping under `max_sessions`.)

### Conditions for revisiting (when (b) would win)

Reopen this decision only if **all** of the following hold, and record the
load-test evidence here:

- Measured re-knock rate drives qurl-service `/authorize` p99 or error budget
  past its SLO, *and*
- the `min(15s, remaining)` positive cache cannot absorb it, *and*
- a token design exists that preserves revocation latency, `one_time_use`,
  `max_sessions`, and per-renewal audit (e.g. short-TTL token + revocation
  bloom) — i.e. option (b) without its correctness cost.

Absent all three, (a) stands.

## Renewal cutover

The L7 `/refresh` renewal path is replaced, not re-engineered:

| Today (L7-driven) | Target (agent-driven, spec Step 8) |
|---|---|
| `qurl-router` calls AC loopback `/refresh/:token` on `/authorize` success | JS agent re-knocks (`NHP_RKN`) before expiry |
| AC `HandleHttpRefreshOperations` re-issues the firewall window | Server emits fresh NHP-AOP; AC re-Schedules via existing AOP handler |
| Renewal signal rides the L7 request path | Renewal signal is a first-class NHP message |

Deletions this unlocks (each a Phase 3 PR):

- [`endpoints/ac/httpac.go`](../../endpoints/ac/httpac.go) — gin engine,
  `http.Server`, loopback listener, TLS handling, related config.
- `endpoints/ac/httpac_refresh_test.go`.
- `common.HttpRefreshRequest` in
  [`nhp/common/types.go`](../../nhp/common/types.go).
- The `/refresh` call path in the `qurl-router` plugin (traefik-plugins repo).

> **L3 enforcement note.** Once the `qurl-router` `/refresh` call is removed
> (step 10), L3 flush-on-expiry becomes the sole enforcement for QURL session
> lifecycle — today's per-request L7 authz masks any L3 gap because a revoked
> token still fails the next `/authorize`. That masking is what made #2213 a hard
> blocker for step 10 (temp-handler kernel rules must be admin-revocable once L7
> stops gating). #2213 is now **closed**; the gate below tracks the rest.

## PR-chain sequencing

Each numbered item is its own PR (or PR chain); the phase headers note where
work parallelizes. The canonical, living roadmap is the issue — this section
captures the **dependency reasoning** (the blocker graph below) that the issue
thread worked out across several PRs.

### Phase 1 — Prerequisites (parallel)

1. **JS NHP-Agent** — Noise handshake, `NHP_KNK`/`NHP_RKN` construction, `NHP_ACK`
   parsing, WASM crypto. (Owner-TBD repo.)
2. **NHP-Relay service** (`endpoints/relay/`) — browser-reachable transport →
   `NHP_RLY` forward to private server, and the return path. Internet-facing
   replacement for the server NLB.
3. **Re-knock authorization** — option (a), locked above. Implementation =
   server re-consults qurl-service on `NHP_RKN`.
4. **Re-knock scheduler in the JS agent** — `Access Duration − margin`, jitter,
   and an explicit **background-tab renewal contract** (grace window or documented
   re-knock-on-return UX; see the JS-agent note above — naïve `setTimeout` is
   clamped/suspended in background tabs).

### Phase 2 — Cutover (sequential)

5. Deploy NHP-Relay in sandbox alongside the existing public path; flag-gate
   which clients use which.
6. Migrate the qURL viewer to the JS-agent → relay path; validate initial knock,
   renewal, session expiry, multi-tab.
7. Retire the qurl-service internal resolve plugin on `nhp-server` (the
   synthesized-knock path) once the relay path is proven.
8. Move `nhp-server` to private subnets; tear down the public UDP `62206` NLB.

### Phase 3 — Footprint cleanup (parallel after Phase 2)

> **Intra-phase ordering — retire the caller before (or with) the callee.** Step
> 10 (remove the `qurl-router` `/refresh` call) must land before or together with
> step 9 (delete the AC `/refresh` plane it calls); never delete the callee while
> a flag-gated fraction still routes `/refresh` through L7. "Parallel after Phase
> 2" is safe only because step 6's cutover already made the `/refresh` call dead
> for migrated traffic.

9. Delete the AC HTTP `/refresh` plane (see [Renewal cutover](#renewal-cutover)).
10. Delete the `qurl-router` `/refresh` call path (traefik-plugins). **This is the
    highest-risk step in the chain** — after it, L3 flush-on-expiry is the *sole*
    enforcement for QURL session lifecycle (L7 authz no longer masks an L3 gap).
    **Pre-ramp gate:** the L3-flush observability + race-stress CI follow-ups
    (#2173 / #2189 / #2188 / #2194) must be green, and the alarm-at-1 metric work
    (#2216) filed, before the flag ramps.
11. Prod rollout, following the same sandbox-soak → cutover → retire → privatize
    cadence.

### Dependency / blocker graph

```
#2201 (Cancel multi-session race) ── closed by #2209 ✓ ┐
#2205 (NAT'd temp-access FlowKey) ── folded into #2213 ┤
#2213 (temp-handler lifetime mismatch / revocation) ── closed ✓
                                                       └─► step 9 / step 10 unblocked
```

- Steps 9 and 10 refine the L3 lifecycle this work depends on. Their original
  hard blockers — #2201, #2205, #2213 — are all resolved (#2205's fix landed
  inside #2213; #2201 via #2209). The remaining pre-ramp gate for step 10 (the
  L3-flush observability/CI follow-ups + the alarm-at-1 metric work) is stated
  inline on the step-10 line above so it cannot be ramped past unseen.
- The `AccessEntry` pointer-identity guards (#2214 / #2215) are recommended
  before any `AccessEntry` pool/reuse refactor that the relay path might
  introduce, but are not hard blockers for the topology change itself.

## Out of scope

- **Raw OpenNHP agents on UDP `62206`.** If any customer still needs the raw
  NHP-agent path, a minimal public listener stays. If LayerV's surface is
  QURL-only, the entire public NLB goes away with step 8. This doc does not
  decide that; it is gated on a customer-surface audit.
- **NHP-AOP wire format.** Reused unchanged.
- **Application-layer changes to the fileviewer / qurl.link page** beyond
  mounting the JS NHP-Agent.
- **Relay multi-server fan-out.** The relay forwards to `nhp-server`; existing
  server-to-server forwarding (`NHP_FWD` / `NHP_FRT`, see
  [`PLUGGABLE_STORAGE_BACKEND.md`](PLUGGABLE_STORAGE_BACKEND.md)) is unchanged and
  sits behind the relay.

## Related design docs

- [`SESSION_ENFORCEMENT_ARCHITECTURE.md`](SESSION_ENFORCEMENT_ARCHITECTURE.md) —
  the per-request authz model and the stateless-token rejection this decision
  reuses.
- [`QUIET_STREAM_RESIDUAL.md`](QUIET_STREAM_RESIDUAL.md) — L3 flush-on-expiry,
  the sole enforcement after step 10.
- [`PLUGGABLE_STORAGE_BACKEND.md`](PLUGGABLE_STORAGE_BACKEND.md) — per-AC server
  assignment and the server-to-server forward mesh behind the relay.
