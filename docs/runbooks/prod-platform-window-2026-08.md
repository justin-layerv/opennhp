# Prod platform launch window — late August 2026

One ordered sequence for the attended outage window that brings production
current. The prod-rollout-ledger entries stay the source of truth for each
task's exact steps; this runbook sequences them, resolves where they collide,
and records the window-scoped decisions. Links are repo-relative; entries live
under [`prod-rollout-ledger/`](prod-rollout-ledger/).

**Scope decisions (Justin, 2026-08-24):** prod Control/Hub bootstrap is IN
scope. Billing stays off (`deploy_billing = false` stands). Tenant home-cell
pinning ships as the day-0 posture (#3980). Production launches with exactly
one assignable cell (cell0). The Connector-Authority customer feature set
beyond the bootstrap (creso, routing-identity cutover, credential recovery,
share-lifecycle *activation*) stays out — a dozen entries mark it
production-blocked, and nothing in this window changes that.

## Verified baseline (2026-08-24)

- Prod fleet runs `c74d03ff5` (2026-05-29); prod root tfstate last written
  2026-06-01. Everything merged since rides this window's first apply as one
  accumulated diff.
- `promote-to-prod.yml` has never fully passed: last success 2026-05-15, four
  failures 2026-05-21→06-02 (the final one only at `QURL Smoke (prod)`), no
  runs since. The workflow has changed since it last ran.
- Prod Control has never been applied (no `nhp/prod/control` state object).
  `hub.nhp.layerv.ai` resolves to the wildcard AC NLB — the documented unsafe
  baseline. `relay.layerv.ai` does not resolve (required by apply 1's
  precheck). `/layerv-nhp-prod/qurl-scanner-lambda-image-tag` does not exist.
- SES production access is GRANTED (50k/day). The
  `layerv-nhp-prod-agent-otp-pepper` secret does NOT exist yet — Terraform
  creates it in apply 1; seeding it is a scheduled in-window step.
- CRID is dark in prod for two independent reasons: the deployed image
  predates the resolve surface, and resource-key provisioning has never been
  enabled (zero keyed rows of 4,240).
- Custom-domain cert renewal: the 15-minute scan rule was manually disabled
  2026-07-07 and the deployed Lambda was hot-patched out of band the same
  night ([#3282](https://github.com/layervai/nhp/issues/3282)). Main carries
  the fixed dependency set; the window's apply re-enables the rule (the
  resource declares no `state`) and redeploys the Lambda together.

## Three coordinated releases, one window

Three ledger entries each describe themselves as a single attended release and
none acknowledges the others. They merge as follows; their entries carry the
detailed steps:

1. [Relay / qURL v2 / js-agent / eBPF two-apply](prod-rollout-ledger/2026-08-07-prod-activation-relay-v2-ebpf.md)
   — the main-root activation. Apply 1 → fleet rolls → apply 2.
2. [Durable session control](prod-rollout-ledger/2026-08-22-pr-3928-durable-session-control.md)
   + [durable AC attachment](prod-rollout-ledger/2026-08-23-pr-3935-durable-ac-attachment.md)
   — same promote, and they dictate the roll order: **AC canary/fleet reaches
   real-flush readiness before the server canary/fleet advances.** The
   matching qurl-go / qurl-connector releases cut in lockstep
   ([exact-session retirement](https://github.com/layervai/qurl-connector/blob/main/docs/runbooks/prod-rollout-ledger/2026-08-23-pr-609-exact-session-retirement-cutover.md)).
3. [Unlock the production Control root](prod-rollout-ledger/2026-08-06-unlock-prod-control-root.md)
   — a separate Terraform root, so it runs as a parallel lane, with two
   couplings to the main-root lane called out below.

**The #3926 gate must be resolved before any of this starts.**
[Share-lifecycle cutover](prod-rollout-ledger/2026-08-21-pr-3926-qurl-share-lifecycle-cutover.md)
forbids a full prod apply from a main revision containing it until its
cross-repo set is ready and the production rollout is *separately authorized*
— and main contains it. The window's authorization must explicitly cover
#3926 (its sandbox IAM pre-grant sequence complete, the FRP fork tag pinned,
the cross-repo contract set landed), or the window deploys from a reviewed
revision that excludes it. Existing production resources stay
`sharing_desired_state`-off either way; #3926's *activation* is not in scope,
only its presence in the deployed revision.

## Pre-window (all before the outage starts)

Ordered roughly by lead time; owner = whoever runs the window unless noted.

1. **Authorize #3926** (above) — written sign-off on the source PRs.
2. **Registration + OTP go-live gates**
   ([entry](prod-rollout-ledger/2026-07-08-agent-registration-ses.md)): the
   flags are already committed true, so the window's first apply IS the
   launch; there is no in-window abort point. SES production access ✅
   (verified 2026-08-24). Remaining: confirm the SNS alarm-email
   subscriptions for `bootstrap_alb_alarm_email_subscriptions`, schedule the
   pepper-seed step (below), assign the operator watching
   `-agent-otp-send-failed-spike` / `-agent-otp-bounce`.
3. **Promote pipeline health**: re-sync sandbox server/AC image tags (skew
   hard-fails `scripts/trigger-prod-deploy.sh`; re-check after deploy churn
   settles), clear/understand the `failed` deploy-state marker, and rehearse
   the changed workflow at least through its preflight jobs. Budget the
   window assuming first-run failures — the pipeline is 0-for-4 lifetime.
4. **Sandbox soak red since 2026-08-21** (`knock.deny resource_not_found
   resource_id=qurl-tunnel-server`): triage before the window — release #2's
   pre-rollout requires the sandbox journeys green.
5. **Catalog backfill** ([qurl-service entry](https://github.com/layervai/qurl-service/blob/main/docs/runbooks/prod-rollout-ledger/2026-08-07-nhp-catalog-backfill.md)):
   run against prod (bounded, then unbounded, zero `FAILED` rows) — prod has
   zero dynamic `q_` catalog rows and resolves fail closed without them. Its
   own entry orders it before the NHP server deploys; it is safe against
   live traffic, so run it pre-window.
6. **Connector-authority image publisher production leg** (qurl-service):
   the publish job is sandbox-only today; the Control runtime apply needs a
   governed prod digest. The prod foundation apply creates the role trusting
   `repo:layervai/qurl-service:environment:<publisher-env>`; the qurl-service
   workflow needs the matching production leg + GitHub environment. Also
   close the publisher-IAM gap noted in
   [its entry](prod-rollout-ledger/2026-07-20-connector-authority-publisher-iam.md).
7. **Control-lane early work — run before the window** (invisible to
   customers, all state in the never-applied Control root): the foundation
   apply at dark gates, `publish-hub-image.yml` `target_environment=production`,
   and the connector-authority image publish. Constraint that keeps the
   *catalog* out of this early lane: the catalog row advertises UDP 443,
   which production doesn't serve until the
   [port-443 cutover](prod-rollout-ledger/2026-08-01-udp-client-edge-port-443.md)
   applies in the main-root lane. Pre-brief the
   [normalizer wedge](prod-rollout-ledger/2026-08-11-pr-3839-control-refresh-only-digest.md)
   and record the attended-vs-auto governance decision
   ([entry](prod-rollout-ledger/2026-08-08-sandbox-control-auto-deploy.md)).
8. **eBPF flip gates** (all verified against the exact image the window
   deploys): tc_egress `spp` map fix present (else fleet-wide AC crash-loop),
   health-port marshal fix present, arch lockstep re-run, deny-telemetry
   alarms exist. Entries: [arch](prod-rollout-ledger/2026-06-30-issue-2816-ac-ebpf-arch-match.md),
   [spp hash](prod-rollout-ledger/2026-07-02-ac-ebpf-tc-egress-spp-hash.md),
   [health port](prod-rollout-ledger/2026-07-02-pr-3025-ac-ebpfxdp-health-port.md),
   [telemetry alarms](prod-rollout-ledger/2026-07-02-issue-2849-ebpf-deny-telemetry-sampling.md),
   [object smoke](prod-rollout-ledger/2026-06-28-pr-2859-ac-ebpf-object-smoke.md).
9. **qURL v2 gates**: the
   [issuer-infra checklist](prod-rollout-ledger/2026-07-01-qurl-v2-issuer-infra.md)
   (supersedes the 2026-06-22 admission entry), the
   [CRID provisioning sign-off](https://github.com/layervai/qurl-service/blob/main/docs/runbooks/prod-rollout-ledger/2026-08-12-crid-backfill-phase-2c.md),
   the destructive-KMS Deny exhaustiveness question (#2990), and the
   traefik-plugins `/authorize` rate-limit sizing +
   [manual prod plugin deploy](https://github.com/layervai/traefik-plugins/blob/main/docs/runbooks/prod-rollout-ledger/2026-06-24-pr-230-qurl-v2-disable-positive-auth-cache.md)
   (merge does NOT deploy prod; revokes are masked ≤15s on v2 L7 until it
   does).
10. **Auth0 `qurl:agent` scope in production** — still unverified
    ([qurl-service entry](https://github.com/layervai/qurl-service/blob/main/docs/runbooks/prod-rollout-ledger/2026-08-07-pr-1353-agent-enrollment-scope.md));
    includes the website #742→#703 ancestry repair.
11. **Open decisions to close pre-window**: the
    [FRPS owner-missing threshold](prod-rollout-ledger/2026-07-14-pr-3258-frps-owner-missing-alarm.md)
    (its alarm goes red at apply otherwise); whether the
    [resource-key maintenance window](https://github.com/layervai/qurl-service/blob/main/docs/runbooks/prod-rollout-ledger/2026-07-12-pr-1206-resource-public-rest-ids.md)
    folds into this outage (creates are paused anyway — recommended) with the
    regional KMS CMK quota preflight; qurl-connector v0.6.1 actually cut
    (v0.6.0 shipped no binaries).

## Window sequence

**Lane A — main root (releases #1+#2, one attended promote):**

1. Preflight: `trigger-prod-deploy.sh` green; plan review pays specific
   attention to the relay VPC surgery (`ReplaceRouteTableAssociation` on live
   private subnets — forward-only), the ~29 Auth0 state forgets
   (`destroy=false`; abort on any `will be destroyed` under `module.auth0`),
   the Chatbot destroy guard from the tfvars operator note, and
   `aws_autoscaling_group.frps` showing no replace.
2. Apply 1 (flags as committed today). Immediately after: seed the OTP pepper
   (≥32 chars), verify the SES identity reaches Verified/DKIM-Successful,
   confirm relay DNS + target group.
3. Fleet rolls, in release #2's order: AC canary/fleet to real-flush
   readiness (this also activates eBPF — run the Tier-1 smoke with
   `allow_ssm_probes=true`), then server canary/fleet (protocol 1.1). Publish
   the regenerated `nhp-agent.min.js`+SRI within minutes of the fleet
   completing, not hours
   ([protocol 1.1 entry](prod-rollout-ledger/2026-08-03-pr-3693-nhp-protocol-1-1-header-aad.md)).
   Known conscious break: qurl-go SDKs ≤v0.2.0 go permanently dark.
4. Apply 2 (`qurl_v2_issuance_enabled` + `qurl_link_js_agent_enabled`
   together) only after fleet health + relay targets healthy. This is the
   customer-visible cutover and the point where v2 rollback stops being
   "revert" and becomes "re-mint".
5. Verifications: the activation entry's mint-and-knock journey, relay proven
   by the server-side `RelayForward` metric (not health checks), CRID resolve
   returning 200 on api.layerv.ai after the prod resource-key backfill phase
   runs.

**Lane B — Control root (release #3, foundation/publishes already done
pre-window):**

6. After Lane A's port-443 cutover is live: runtime apply with the reviewed
   contract + gates — **expect two applies** (alias staging fails the
   `foundation_contract` precondition on the first; re-plan and re-apply is
   the documented behavior, not a fault). Day-0 config includes tenant
   pinning on (#3980).
7. Hub edge + catalog materialization; explicit `hub.nhp.layerv.ai` A-alias
   via `prod-hub-dns-update.yml`
   ([entry](prod-rollout-ledger/2026-08-19-qurl-integrations-1227-prod-hub-dns.md))
   — wildcard resolution is not proof; read back the alias target.
8. CLI trust: fingerprint the Hub identity key, commit in qurl-integrations,
   flip the connector
   [hub trust pin](https://github.com/layervai/qurl-connector/blob/main/docs/runbooks/prod-rollout-ledger/2026-08-03-issue-421-hub-trust-pin-release-flip.md)
   — this un-freezes ALL connector customer artifact publishing.
9. Cell0 handoff: source-lock removal PR +
   `connector_authority_cell_from_control_enabled=true`, canary one server,
   roll the ASG (Lane A's fleet is already durable-profile; this is a second,
   smaller roll).
10. Post-bootstrap: `REGISTRY/CELL#cell0` `general_assignable=true` by strong
    read; the full CLI customer journey (publish → serving → CRID resolve →
    traffic); every Authority alarm proven by one synthetic failure with a
    page receipt (`treat_missing_data=notBreaching` — green is not evidence);
    tenant-pin readback per
    [its entry](prod-rollout-ledger/2026-08-24-tenant-cell-pinning-day0.md).

## Known mid-window behaviors (pre-brief; none is a fault to debug)

- Authority runtime same-color roll = two applies (above).
- A `NRestarts>=1` crash-gate trip whose log shows docker exit 125 + a
  CloudWatch log-stream failure is the known false positive, not the #1096
  panic — do not spend the retained live-env lock on it.
- SSM `Overview.Status` reports the PREVIOUS execution — poll the ground
  truth the consumer reads, not the orchestrator's aggregate.
- First-activation decisions must be explicit: the deploy script has
  previously decided a first activation from live state the activation itself
  creates. If a component looks "already dark, keep dark," check whether the
  window is its first activation.
- First cert-renewal scan after re-enable will page
  `cert-renewal-scan-missing` once (missing data breaching on first tick) —
  expected; watch `RenewalStatusRecovered`/`RenewalProcessingFailures` per
  [the renewal-state entry](prod-rollout-ledger/2026-07-07-custom-domain-renewal-state.md).

## Post-window (staged, each after its own burn-in)

- Scanner: write the replicated SHA to the (now-existing) image-tag param,
  then `qurl_scanner_lambda_enabled` → `qurl_scanner_sqs_emit_enabled` →
  `qurl_scanner_tombstone_write_enabled`, one dispatch each.
- The strict flips explicitly deferred by their entries: forward-hop
  attestation, F5 pubkey-revoke, active-resource recheck sequence,
  browser-rejected alarm actions.
- CIS Security Hub evaluation (~18h) for the CloudTrail alarm set.
- WAF: the bootstrap-ALB count-only watch (2–4 weeks of real traffic) before
  the #2238 enforce flip — AnonymousIpList/CRS only; AmazonIpReputationList
  stays count-only permanently. The
  [hosting-provider override](prod-rollout-ledger/2026-06-15-qurl-connector-347-bootstrap-waf-hosting-provider.md)
  must be live before any AnonymousIpList drop.
- Website release PR #703 (staging→production, carries the CRID
  announcement) merges once the promote has shipped and CRID resolve is
  live; bump the post date first.
- `qurl_enforce_internal_alb_only` stage-2: sandbox flip + verify, then prod.
- Ledger hygiene: delete completed entries as their boxes close (the
  inventory that fed this runbook found four stale-done candidates and one
  superseded entry — 2026-06-22 admission — noted in their sections).

## Rollback semantics worth memorizing

Forward-only points, in the order the window crosses them: relay route-table
associations (apply 1), the durable-profile minimum floor (release #2's point
of no return — after it, stop admission and forward-fix), first qv2 link
minted (apply 2 — rollback becomes re-mint), protocol 1.1 rollback rolls
senders back before receivers, and a full Control gate-dark return is a
Hub teardown that must stay attended.
