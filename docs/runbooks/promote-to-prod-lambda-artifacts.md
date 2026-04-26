# Runbook: promote-to-prod Lambda artifact-pass invariant

## TL;DR

Every prod-deployed Lambda whose ZIP is built via `data "archive_file"` needs a paired upload (in `terraform-plan`) + download (in `terraform-apply`) in `.github/workflows/promote-to-prod.yml`. Sandbox plan/apply share a runner so the gap is silent there; prod splits them across runners and apply fails with `Error: reading ZIP file (.../<lambda>.zip): open ...: no such file or directory`.

> **Operator note:** all 12 non-optional uploads use `if-no-files-found: error`, which means flipping any of these toggles to `false` in `terraform/environments/prod/terraform.tfvars` now hard-fails the **`terraform-plan` job** (specifically the upload step that runs after the plan command) unless the matching upload + download pair is also removed in the same patch. (**10 conditional toggles + 2 always-on Lambdas → 12 non-optional artifacts**: `deploy_ac` covers two artifacts; `deploy_developer_portal` covers two; `enable_secret_reconciliation` is transitively gated under `deploy_ac`; `deploy_qurl_link` and `enable_resolve_cloudfront` jointly gate `lambda-cloudfront-cidr-drift`; `lambda-compute-keygen` and `lambda-nhp-keypair-keygen` are always-on inside their parent modules and not toggle-gated at all.)
>
> ```
> centralized_cert_enabled        (lambda-acme-cert)
> deploy_ac                       (lambda-ac-keygen, lambda-ac-secret-reconciliation)
> deploy_developer_portal         (lambda-playground-proxy, lambda-developer-portal-auth0-cleanup)
> deploy_status_page              (lambda-status-page-aggregator)
> deploy_qurl_link                (lambda-cloudfront-cidr-drift)
> enable_canary_deployment        (lambda-canary-orchestrator)
> enable_resolve_cloudfront       (lambda-cloudfront-cidr-drift)
> enable_secret_reconciliation    (lambda-ac-secret-reconciliation)
> enable_termination_cleanup      (lambda-compute-termination-cleanup)
> enable_stale_finding_watchdog   (lambda-stale-finding-watchdog)
> ```
>
> This is intentional — the 2026-04-24 hot-patch (#1328) took the toggle-only shortcut and silently disabled the watchdog — but it's the *opposite* of the prior implicit "toggle alone is fine" pattern. Don't reach for this paired change at 3am without reading the [intentional disable](#when-you-intentionally-need-to-disable-a-lambda-in-an-emergency) section first.

## When you'd hit this

- You add a new Lambda backed by `data "archive_file"` and ship a PR that passes sandbox CI.
- Promote-to-prod fails at **Terraform Apply (prod)** with `reading ZIP file ... no such file or directory`.
- You verify the Terraform code is correct — the `archive_file` exists, the path is right, and `enable_<lambda> = true` for prod.

The diff between sandbox green and prod red is purely the workflow split, not the Terraform.

## Fix

Add two steps to `.github/workflows/promote-to-prod.yml`, mirroring the existing `acme-cert` / `canary-orchestrator` / `playground-proxy` blocks:

1. In the **terraform-plan (prod)** job, after the existing Lambda upload steps:
   ```yaml
   - name: Upload <name> Lambda
     uses: actions/upload-artifact@<pinned-sha>  # match neighbours
     with:
       name: lambda-<name>
       path: terraform/modules/<module>/<lambda-path>/<name>.zip
       retention-days: 1
   ```

2. In the **terraform-apply (prod)** job, after the existing Lambda download steps:
   ```yaml
   - name: Download <name> Lambda
     uses: actions/download-artifact@<pinned-sha>  # match neighbours
     with:
       name: lambda-<name>
       path: terraform/modules/<module>/<lambda-path>
   ```

Pin the action SHAs to whatever the existing Lambda upload/download steps in the same file use. Match the artifact `name:` exactly between upload and download.

> **The artifact name MUST start with `lambda-`.** The structural-symmetry test in `tests/scripts/test_promote_to_prod_gating.py` (`_assert_lambda_artifact_symmetry`) filters by that prefix to enforce upload↔download pairing. A future Lambda artifact named `watchdog-lambda` (or any other shape) would silently bypass the gate.

### When you intentionally need to disable a Lambda in an emergency

**Short answer:** disable the toggle *and* remove (or comment out) the corresponding upload + download steps in `promote-to-prod.yml` in the same patch. The 2026-04-24 hot-patch (#1328) took the toggle-only shortcut and silently disabled the watchdog; the loud-fail at plan exists to make a repeat impossible — the trade-off is intentional: ergonomics for impossible-to-silently-disable.

**Why the loud-fail fires:** all 12 non-optional uploads use `if-no-files-found: error` (per the policy in the [Currently covered Lambdas](#currently-covered-lambdas) table). The upload step fails *at plan-time* if the zip isn't produced, which happens whenever:

- A Lambda's `data "archive_file"` evaluates to `count = 0` (because its conditional toggle was flipped — `var.enable_stale_finding_watchdog`, `var.enable_secret_reconciliation`, `var.enable_termination_cleanup`, etc.), or
- A Lambda's parent module's `count` evaluates to 0 (because `var.deploy_ac`, `var.deploy_developer_portal`, `var.deploy_status_page`, etc. was flipped to false), or
- The source `.py` file is missing or unreadable.

#### Cross-toggle footguns (read first if you're chasing an unrelated incident)

The loud-fail policy means **flipping a toggle that gates one Lambda transitively can hard-fail terraform-plan even when you're trying to disable something else entirely.** Two specific cases that don't read as Lambda-related at the variable name:

- **GuardDuty disable trips the watchdog.** `lambda-stale-finding-watchdog` materializes only when `var.enable_guardduty && var.enable_stale_finding_watchdog && (alerts || email_alerts)` (see `terraform/modules/security/stale_finding_watchdog.tf`). An operator chasing a GuardDuty incident — flipping `var.enable_guardduty` to `false`, or zeroing out `guardduty_alert_emails` — will hard-fail the watchdog upload with no obvious connection. Same emergency-disable rule applies: pair the upstream toggle change with the workflow upload/download removal in the same patch.
- **QURL disable trips the CloudFront CIDR drift Lambda.** `lambda-cloudfront-cidr-drift` is gated by `var.deploy_qurl_link && var.enable_resolve_cloudfront`. Flipping `deploy_qurl_link` to disable QURL link will hard-fail the cloudfront-cidr-drift upload — the variable name doesn't hint at \"there's a Lambda gated on this.\" Same paired-removal rule.

If you're 3am-debugging a hard-fail in the `terraform-plan` job and the failing upload step name looks unrelated to whatever you just changed, check this section first.

#### The lone `ignore` exception

The single exception to the loud-fail policy is `lambda-custom-domain-cert`, which uses `if-no-files-found: ignore` deliberately. **The rule is NOT "feature-gated → ignore"** — `deploy_ac`, `deploy_developer_portal`, `enable_canary_deployment`, etc. are also feature-gated and they all use `error`. The actual reason `custom-domain-cert` is on `ignore`: the pattern predates the loud-fail policy, and we kept it intact as a future prod rollback / toggle-off escape hatch (`promote-to-prod.yml` only runs in prod, so the toggle's flexibility has to live in this workflow). [#1382](https://github.com/layervai/nhp/issues/1382) tracks the trade-off where `continue-on-error: true` on the matching download also masks transient artifact-API failures while the toggle is on.

> **What the loud-fail policy does NOT cover:** the structural test now fences artifact `name:` pairing AND `path:` symmetry (download `path:` matches the parent dir of upload `path:`) — closing the typo case [#1381](https://github.com/layervai/nhp/issues/1381) originally tracked. **It does NOT verify the upload `path:` matches the actual `archive_file.output_path` in terraform** — a typo on the workflow upload side (e.g. `terraform/modules/ac/lamda/foo.zip` while terraform writes to `…/lambda/foo.zip`) would pass this PR's checks symmetrically and only fail at apply time. Closing that gap requires the structural test to parse terraform; tracked under [#1380](https://github.com/layervai/nhp/issues/1380)'s terraform-tree-walker option, alongside the broader "added an `archive_file` with no upload/download anywhere" case.

### Per-step comment-density convention

The workflow's upload block has intentional asymmetry: most uploads carry a one-line toggle annotation (`# Module-level toggle: var.X` or `# Conditional toggle: var.Y`); two are longer.

- **`lambda-stale-finding-watchdog`**: longer comment because the watchdog is the security control whose silent disable started this whole bug class (#1137). The comment names the AND-chain that gates it so an operator reading the workflow doesn't have to grep terraform.
- **`lambda-custom-domain-cert`**: longer comment because it's the lone `ignore` exception to the loud-fail policy.

Don't trim those two to match the others, and don't expand the others to match those two. The asymmetry encodes which steps deserve in-line WHY versus which carry their full context in the runbook.

## How to verify

1. Trigger a prod plan dry-run (`gh workflow run promote-to-prod.yml --ref <branch> -f run_terraform=true ...`) and confirm the new upload step runs in the plan job and the download step runs in the apply job. **Until [#1380](https://github.com/layervai/nhp/issues/1380) lands, this dry-run is the only way to catch the "added a new `archive_file` but no upload/download anywhere" case** — the structural-symmetry test only catches mismatched pairs, not entirely-missing pairs.
2. Confirm the artifact appears under the run's **Artifacts** panel with size > 0.
3. Confirm prod terraform apply succeeds.

Sandbox is unaffected — `build-and-push.yml` runs plan and apply in the same job, so the ZIP stays on disk between them. No regression risk.

## Currently covered Lambdas

The PR that closed #1326 swept the workflow for every prod-deployed `data "archive_file"` Lambda — both inside `terraform/modules/**` and at the **root** of `terraform/` itself (`cloudfront_cidr_drift` lives in `terraform/main.tf` rather than in a sub-module). As of that sweep, the workflow uploads + downloads:

Listed in the same order they appear in `.github/workflows/promote-to-prod.yml`'s terraform-plan job (visual diff against the workflow stays straightforward). 12 non-optional uploads on **error** + 1 allowlisted **ignore** = 13 total `lambda-*` artifacts.

| Artifact name | Source path | Gating toggle (true in prod) | `if-no-files-found` |
|---|---|---|---|
| `lambda-acme-cert` | `terraform/modules/acme-cert/build/lambda-acme-cert.zip` | `var.centralized_cert_enabled` | **error** |
| `lambda-canary-orchestrator` | `terraform/modules/canary-deployment/lambda/canary_orchestrator.zip` | `var.enable_canary_deployment` | **error** |
| `lambda-playground-proxy` | `terraform/modules/developer-portal/lambda/playground_proxy.zip` | `var.deploy_developer_portal` | **error** |
| `lambda-stale-finding-watchdog` | `terraform/modules/security/lambda/stale_finding_watchdog.zip` | `var.enable_stale_finding_watchdog` (+ `enable_guardduty`, alerts) | **error** |
| `lambda-ac-keygen` | `terraform/modules/ac/keygen_lambda.zip` | `var.deploy_ac` | **error** |
| `lambda-ac-secret-reconciliation` | `terraform/modules/ac/lambda/ac_secret_reconciliation.zip` | `var.enable_secret_reconciliation` (direct) + `var.deploy_ac` (transitive via `module.ac`) | **error** |
| `lambda-compute-keygen` | `terraform/modules/compute/keygen_lambda.zip` | always-on | **error** |
| `lambda-compute-termination-cleanup` | `terraform/modules/compute/lambda/server_termination_cleanup.zip` | `var.enable_termination_cleanup` | **error** |
| `lambda-developer-portal-auth0-cleanup` | `terraform/modules/developer-portal/lambda/auth0_cleanup.zip` | `var.deploy_developer_portal` | **error** |
| `lambda-nhp-keypair-keygen` | `terraform/modules/nhp-keypair/keygen_lambda.zip` | always-on | **error** |
| `lambda-status-page-aggregator` | `terraform/modules/status-page/lambda/status_aggregator.zip` | `var.deploy_status_page` | **error** |
| `lambda-cloudfront-cidr-drift` | `terraform/lambda/.build/cloudfront_cidr_drift.zip` | `var.deploy_qurl_link` + `var.enable_resolve_cloudfront` | **error** |
| `lambda-custom-domain-cert` | `terraform/modules/custom-domain-cert/build/lambda-custom-domain-cert.zip` | `var.deploy_custom_domain_cert` | ignore (feature-gated) |

`archive_file` blocks not in this table are either (a) not deployed in prod (e.g. `module.billing.*` is gated `deploy_billing=false`; `module.e2e_echo_server.*` defaults `deploy_e2e_echo_server=false`; `module.auth0.auth0_rotation` is gated `auth0_enable_rotation=false`; `module.data.etcd_tls_lambda` and `module.data.secrets_rotation` are gated `deploy_etcd=false`) or (b) re-instantiations of an already-covered module (e.g. `module.canary_deployment_ac` shares `lambda-canary-orchestrator`'s zip).

If you flip any of those `deploy_*` / `enable_*` toggles to `true` in prod, **also** add the matching upload/download steps in `.github/workflows/promote-to-prod.yml` for whichever new Lambda becomes in-scope. The structural-symmetry test does NOT catch the "added a new Lambda but no upload/download anywhere" case — it only catches "uploaded without download" or vice versa. Tracked as a known limitation in [#1380](https://github.com/layervai/nhp/issues/1380), which sketches three options (terraform-tree walker, CODEOWNERS rule, naming-convention enforcement test) for closing the omission gap.

> **Granularity is per `data "archive_file"` block, NOT per module.** Modules like `compute` (with `keygen_lambda` + `termination_cleanup`) have multiple `archive_file` blocks; each needs its own upload/download pair. If you add a third Lambda to a module that already has uploads, you still need to add a new pair — one upload doesn't cover the whole module.

> **Sibling Lambdas in the same module share a download directory — by design.** For example, `lambda-playground-proxy` and `lambda-developer-portal-auth0-cleanup` both download into `terraform/modules/developer-portal/lambda/`. Their artifact contents are different files (`playground_proxy.zip` vs `auth0_cleanup.zip`), so they coexist; "tidying up" by giving each its own subdirectory would break terraform's `archive_file.output_path` reference and re-introduce the apply-time `reading ZIP file` failure. If you ever need to split them, also update the matching `output_path` in the module's `archive_file` block.

> **Re-instantiated modules share `archive_file` output_path — by design.** If you re-instantiate a module that contains an `archive_file` (e.g. `module.canary_deployment_ac` re-uses `./modules/canary-deployment` alongside `module.canary_deployment`), the second instantiation writes to the **same** `${path.module}/...` zip the first one does. Idempotent today (same source content), but a future PR that gives one of the instances component-specific Lambda code would race on disk and produce nondeterministic output. The structural-symmetry test won't catch this — the artifact name still appears once. If you find yourself re-instantiating a module with an `archive_file`, audit the source-content invariance or split the module.

## History

This invariant was first violated by `stale_finding_watchdog` (#1137 added the Lambda; the matching `promote-to-prod.yml` upload/download steps were not added). The 2026-04-24 prod release hot-patched the symptom by setting `enable_stale_finding_watchdog = false` in `terraform/main.tf`, then #1326 added the artifact pass for the watchdog **and swept the rest of the workflow** for the same latent bug class — covering every prod-deployed Lambda built via `data "archive_file"` anywhere under `terraform/` (sub-modules + the root). This runbook exists so the next contributor adding a `data "archive_file"` Lambda — anywhere in `terraform/`, not just `terraform/modules/` — doesn't reintroduce the silent sandbox-passes / prod-fails footgun.

## Related

- Issue #1326 — workflow fix and hot-patch revert.
- Issue #1137 — original stale-finding watchdog Lambda that hit this.
- `.github/workflows/promote-to-prod.yml` — the workflow that the invariant lives in.
- `.github/workflows/build-and-push.yml` — the sandbox path where plan/apply share a runner.
