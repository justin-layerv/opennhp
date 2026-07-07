# Relay Active-Cell Routing

## Status

Accepted design decision for [#2658](https://github.com/layervai/nhp/issues/2658)
as of 2026-07-02.

## Decision

NHP-Relay can become the NHP-server blue/green switch point, but only under the
current shared server-identity model:

- keep one cell-level NHP-server identity key;
- keep one `serverId` per cell, derived from that shared server public key;
- route relay traffic for that `serverId` only to the active server color;
- keep AC blue/green listener behavior out of scope until AC has its own
  cell-aware routing design.

Do not model blue and green as separate relay cells for the current migration.
Color-specific relay cells would require separate server identities, qURL
bootstrap contract changes, client drain semantics, and a wider key-topology
migration. That is a valid future design only if a separate product/security
decision accepts that blast radius.

## Terminology

This doc keeps "cell" and "color" separate:

- a **cell** is a customer/failure-domain stack with its own NHP-server fleet,
  AC fleet, qURL-service state, and shared server identity;
- a **color** is the blue or green deploy slot inside one cell.

Relay `serverId` values identify cells, not deploy colors. The active-color
switch chooses which color inside the addressed cell receives the relay-forwarded
knock.

## Current Constraints

The relay already routes by server public-key fingerprint: `POST
/relay/{serverId}` selects one configured `[[servers]]` entry. The handler
registers `/relay/` as a prefix and trims that prefix into a local `serverID`;
some older comments call the suffix `{id}`. This doc uses `serverId` for the
same wire value because qURL/bootstrap callers treat it as the cell's
server-fingerprint identifier. Follow-up relay work in #2645/#3014 should
normalize touched code comments toward `serverId` rather than reviving `{id}` as
a separate concept. In Terraform today, the root relay module renders one cell
entry using `module.compute.server_public_key_b64` and
`module.compute.internal_nlb_dns_name`. qURL bootstrap also receives that same
`module.compute.server_public_key_b64`.

That means clients cannot distinguish blue from green today, and they should not
need to. The active-color decision belongs in the relay target source behind the
stable cell identity, not in the browser-visible `serverId`.

The original internal relay NLB was an interim both-attach design: one internal
UDP target group fronted both blue and green server ASGs. That kept the relay
path reachable across a color flip, but it did not make the relay path
active-color-only. A fraction of relay knocks could still land on the
warm-standby color.

That interim state is not safe for one-time qURLs. A standby server can accept a
relay knock far enough to commit qURL admission, then fail the AC-open if that
standby is not in the live AC assignment set. The internal relay listener must
therefore route only to the active server color.

## Accepted Routing Model

### First implementation: active-color internal target source

Use the existing shared server identity and make the relay's target source
active-color-only. The low-risk first step is tracked in
[#2645](https://github.com/layervai/nhp/issues/2645):

1. Add blue and green internal UDP target groups for the relay-to-server hop.
2. Attach each server ASG only to its own internal target group.
3. Flip the internal relay NLB listener in the same blue/green switch path that
   updates `/<environment>/nhp/server/active-color`.
4. Add validation that reconciles active color with the internal listener target
   group.
5. Preserve the current standby health and post-switch knock-readiness gates.

This still uses an NLB listener internally, so it is not the final "relay-owned
dynamic resolver" endpoint. It is the conservative bridge that removes
both-color relay routing without touching browser/qURL identity contracts.
The steady state is active-color-only; during a blue/green switch there is still
a brief transition window between listener flips and full AC/server convergence.
That remaining window belongs to the dynamic relay resolver and AC routing work
tracked in [#3014](https://github.com/layervai/nhp/issues/3014) and
[#3015](https://github.com/layervai/nhp/issues/3015).

### Final implementation: dynamic relay active-color resolver

The final relay-owned switch point is tracked in
[#3014](https://github.com/layervai/nhp/issues/3014). That work should replace
deploy-time relay ASG refreshes or static target config with an explicit runtime
active-color resolver, such as SSM-backed state or a small registry. It must
define:

- cache and TTL behavior;
- fail-closed behavior when active-color state is unreadable;
- relay-path readiness smokes before state changes;
- rollback that is at least as fast and auditable as the current active-color
  switch;
- validation that reconciles the active-color state with the actual relay target
  source.

The final resolver should still preserve the shared `serverId` unless a separate
server identity migration is accepted.

## Client And Drain Behavior

With one stable `serverId`, clients do not need to learn a new key or URL when
blue/green switches. New knocks and re-knocks continue to post to the same
`/relay/{serverId}` path, and the relay target source selects the active color.

Existing browser sessions should be treated as active-color-following for
renewals. If the active color changes mid-session, the next relay-forwarded
re-knock may hit the new color. That is acceptable only while the shared
server-identity contract and qURL/session state remain color-independent. The
session-state invariant is anchored by the qURL keyed-identity design's re-knock
authorize path, which keys renewal on authenticated qURL plus session facts
rather than server color (see
[`QURL_V2_KEYED_IDENTITY.md`](QURL_V2_KEYED_IDENTITY.md#nhp-server-contract)).
The deploy workflow must therefore keep the current server/AC convergence gates
and must not scale down the old server color until post-switch knock readiness
passes.

If a future design makes server identity color-specific, this section must be
reopened. In that model, qURL bootstrap would need to return the active color's
key, and clients holding the old `serverId` would need an explicit drain or
renewal policy.

## AC Interaction

This decision does not eliminate AC NLB listener flips. Relay fronts browser
knocks to NHP-server; AC remains a separate path with separate blue/green
semantics and readiness gates.

Any claim that release-time AC listener flips are eliminated requires the
AC-specific design tracked in
[#3015](https://github.com/layervai/nhp/issues/3015). Until then, AC keeps its
current blue/green switch and rollback model.

## Migration Path

1. Document this shared-identity active-color decision (#2658).
2. Land #2645 before the relay carries real traffic at scale:
   active-color-only internal UDP target groups, listener switch, drift guard,
   and validation.
3. Add a relay-path smoke/readiness check to the deploy workflow before old-color
   scale-down if the relay path becomes production traffic.
4. Migrate to the #3014 dynamic relay resolver only after the first
   active-color-only routing step is stable.
5. Keep AC listener flips unchanged until #3015 produces and implements an
   AC-specific routing decision.

## DE Acceptance Checklist

A DE should reject an implementation of this decision if it:

- changes the qURL bootstrap server key without an explicit migration plan;
- creates blue/green `serverId` values as an incidental Terraform detail;
- claims AC listener flips are solved by server relay routing;
- removes or weakens standby health, relay-path smoke, or post-switch
  knock-readiness gates;
- rolls relay instances as the only way to change active color in the final
  dynamic-resolver implementation;
- lacks reconciliation between `/<environment>/nhp/server/active-color` and the
  actual relay target source.
