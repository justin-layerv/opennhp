# Prod release — 2026-08

The first production promotion since 2026-05-15. ~1,000 commits, and the ledger
carries steps the pipeline does **not** perform. This is the consolidated list,
derived from every gating entry under `prod-rollout-ledger/`.

Read the whole thing before dispatching. The steps that bite are the ones with
no machine gate behind them.

---

## 0 · Before dispatch

- [ ] **Re-run `./scripts/trigger-prod-deploy.sh --dry-run` immediately before dispatching.**
      The promote takes its images from whatever sandbox last deployed, so
      anything merged since your last check is silently absent from the artifact
      you promote. This has already nearly shipped an AC image carrying a live
      CVE. Confirm the candidate SHA equals `origin/main`.
- [ ] **Confirm AWS is healthy.** A promote reads SSM at a dozen points. During
      a slow period reads fail intermittently and the preflight aborts on
      phantom state. If `aws sts get-caller-identity` is taking >5s or failing
      intermittently, wait.
- [ ] **SES**: production access granted for `notify.layerv.ai` in us-east-2
      (done 2026-08-07), and an operator standing by for the two zero-threshold
      OTP alarms — they page on the **first** send failure or bounce.
- [ ] **On-call acknowledgement** of `server_handler_panic` and
      `connector-registration-handler-absent` paging profiles.

## 1 · Catalog backfill — **hard blocker, run twice**

Prod has **zero `q_` catalog rows**. From `deploy-server` onward the NHP server
resolves routing from the catalog and **fails closed with HTTP 500** on a miss
— no body fallback. Prod qurl-service (`db5d703`) predates the catalog writer
(#855), so nothing has ever written those rows and there is no automatic
backfill.

**Expect a couple of dozen rows written, not 533.** These are three different
counts and confusing them will read as a failed run:

| count | what it is |
| --- | --- |
| 533 | `r_` resource records in the resources table |
| **~23** | active, non-expired qURL tokens needing a `q_` catalog row |
| ~79 | tokens skipped as `not active` (revoked/consumed — correctly no row) |

**Do not treat any of these as fixed — read the dry run's own `rows pending`
line.** Two prod dry runs about four hours apart on 2026-08-08 returned 25/83
and then 23/79: the pending count drifts *down* as tokens expire, which moves it
faster than the ~0.6/day mint rate moves it up, and the total shrinks as expired
rows are reaped. A run reporting `FAILED: 0` and a `rows pending` count in this
range is healthy; an exact match to a number written here is not the
test.

- [ ] **Run 1 — must COMPLETE before `deploy-server` starts.** Running it
      earlier is harmless: until `deploy-server` the old server still resolves
      from the response body, so nothing depends on the rows yet.
      ```
      qurl-nhp-catalog-backfill \
        --tokens-table  layerv-nhp-prod-cell0-qurl-access-tokens \
        --catalog-table layerv-nhp-prod-cell0-resources \
        --expect-account 235500187906 --default-open-time 300 --limit 3 --apply
      # spot-check those 3 rows, then re-run unbounded with --apply
      ```
- [ ] **Run 2 — after `deploy-qurl` completes.** Between `deploy-server` and
      `deploy-qurl` **neither side writes catalog rows**: the new server needs
      them, the old qurl-service does not write them. Anything minted in that
      ~1–1.5h window has no row. Current mint rate is ~0.6/day so the expected
      count is ~0.04, but the second run makes it structurally closed rather
      than statistically unlikely. The tool is idempotent.

## 2 · Manual steps the pipeline does not do

- [ ] **`QURL_AGENT_OTP_PEPPER`** (`${name_prefix}-agent-otp-pepper`, ≥32 chars).
      Terraform creates and seeds it via `terraform_data.agent_otp_pepper_seed`
      — confirm the local-exec succeeded (there is deliberately no plan-time
      check, so nothing else will tell you). If seeding by hand, it must be set
      **before** any qurl-service task with `QURL_AGENT_OTP_ENABLED=true`
      starts, or the task refuses to serve OTP.
- [ ] **Roll the AC ASG after the apply.** `ac_filter_mode = 1` only updates the
      launch template. Without the roll the datapath stays on iptables while the
      config claims otherwise.
- [ ] **Invoke Tier 1 smoke with `allow_ssm_probes=true`.** Without it the AC
      eBPF object gate skips by policy and proves nothing.
- [ ] **Apply 2 only** — publish the regenerated
      `terraform/modules/qurl-link/frontend/nhp-agent.min.js` and its SRI within
      **minutes** of the fleet reaching 1.1. That gap is the browser outage
      window.

## 3 · Ordering that is not enforced by the pipeline

- [ ] **Review the rendered plan for `ReplaceRouteTableAssociation` on live prod
      private subnets.** `deploy_relay = true` also flips
      `enable_extensible_private_route_tables`, creating a peered DMZ VPC on
      `10.201.0.0/16` and a Resolver firewall. The apply grants itself the IAM
      and waits on `time_sleep.relay_dmz_iam_propagation`. Designed for one
      apply; never run outside sandbox. **This is the only step in the release
      with no machine gate — a person reading the plan is the gate.**
- [ ] **Server and AC promote together, then refresh the AC** (#3088 AZ fanout).
- [ ] **AC user data staged before the target-group cutover** (#3050/#3058) —
      confirm the `nhp-health` entrypoint answers `/nhp-ac/ready` before the
      public qURL target groups depend on it, or every AC target goes unhealthy.
- [ ] **UDP 443**: the apply moves `aws_lb_listener.https` 443→8443 and
      `aws_lb_listener.udp` 62206→443 in one graph. `depends_on` orders the TLS
      listener off 443 first; if that ordering is lost the apply fails with
      `DuplicateListener` rather than corrupting the edge. Both are in-place
      `ModifyListener` calls.
- [ ] **Protocol 1.1**: fleet first, bundle second. There is no deploy order
      that avoids breakage — only one that bounds it.

## 4 · Expected transients — do NOT treat as incidents

- **Mixed-version `RKN` rejection** while the server fleet rolls (#2695). Old
  instances reject cross-instance `RKN` until every server is on the new path.
- **~5–15 min of CloudFront 502s on legacy `resolve.qurl.link`** while the
  origin port change propagates (UDP 443). Native UDP and knock are unaffected.
- **Multi-minute zero-healthy-target window on the relay target group** during
  the HTTPS backend swap (#2681).
- **Fresh alarms fire `ok_actions`** as they transition INSUFFICIENT_DATA → OK
  (~5 OK notifications to Slack/email).
- **`*-custom-update_assume_role_policy` and the CIS IAM/SG alarms can ALARM
  during the apply itself** — the CI role edits IAM trust policies and security
  groups, which is exactly what those filters match.
- **A stale AC still on 62206 fails registration** until refreshed.

## 5 · Watch during and after

| signal | meaning |
| --- | --- |
| `ErrUnsupportedProtocolVersion` (32022) | **decaying** = cached 1.0 bundles draining, expected. **Flat and non-decaying** = a customer agent stuck on an old SDK; will not self-heal, needs an outbound conversation. |
| `agent-otp-send-failed-spike`, `agent-otp-bounce` | threshold 0, launch-blocking. A wire failure is invisible to the user — they simply never get a code. |
| `OverloadCookieMintFailure` by `Reason` | any non-zero = a server meant to reject-with-cookie and could not. |
| `RevocationAgedOut` (raw) | not cosmetic — a revoke target was never proven delivered. |
| `EbpfPerfLostSamples` | must stay `Sum = 0` after the eBPF flip; any non-zero period blocks/rolls back the flip. |
| `EbpfDenyTelemetrySuppressed` | flat under normal load. |
| `MetricAgentLookupPubkeyCollision` / `…CandidateOverflow` / `…SchemaMismatch` | agent-key reader guardrails (#2927). |
| `QurlResolveFailResolveCatalog` | **the backfill's signal.** Any sustained non-zero means catalog rows are missing — see §1. |

## 6 · After the release

- [ ] **[website#703](https://github.com/layervai/website/pull/703)** — merge
      only **after** qurl-service `c13be39` is live in prod. It switches the
      dashboard to the kind-first credential API (#1350, breaking, no
      back-compat window). Merging first breaks API key creation.
- [ ] **qurl-scanner follow-up apply** — prod has never had its first scanner
      apply, so `/layerv-nhp-prod/qurl-scanner-lambda-image-tag` does not exist.
      Terraform seeds it `"latest"` with `ignore_changes` and reads its CURRENT
      value at plan time, so enabling the gate in the creating apply fails on
      `ParameterNotFound`. Sequence: this apply creates the parameter (gate
      off) → write the replicated SHA (`c13be39`, already in the prod repo) →
      a follow-up apply flips `qurl_scanner_lambda_enabled`, then
      `sqs_emit`, then `tombstone_write`, each after its own burn-in.
- [ ] **Unblock qurl-service #823** (drop the `resources` field) once the
      catalog path is healthy in prod.

## Not in this release

Control / Hub / Connector Authority and the HTTP-lifecycle retirement. Prod
Control has never been applied and its activation is gated by
[#3456](https://github.com/layervai/nhp/issues/3456) — the Authority has no
working image-roll or rollback path yet, so a bad image in prod would have no
governed way back. The fleet's canary auto-rollback does not extend to Lambdas.
