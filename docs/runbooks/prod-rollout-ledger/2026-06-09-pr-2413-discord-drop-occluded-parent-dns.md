# 2026-06-09 · PR #2413 · Drop nhp management of occluded discord parent DNS

- **Owner:** prod rollout coordinator
- **Source:** nhp PR #2413; completes the qurl-integrations-infra discord D3 re-home — `connector.layerv.ai` subzone delegation (qurl-integrations-infra PR #945 + `docs/runbooks/connector-dns-delegation.md`)

Drops nhp's Terraform management of the now-occluded parent `discord.connector.layerv.ai` A-alias and its `_077a5990…` ACM-validation CNAME, via `removed { destroy = false }` (state-only — the AWS records stay). Completes the DNS-ownership convergence: these records are now authoritative in the qurl-integrations in-account `connector.layerv.ai` zone. No serving change — the parent copies are already occluded by the delegation.

- [ ] Rollout: dispatch the gated prod apply (`promote-to-prod`, terraform apply = true; image/deploy flags OFF or pinned to current prod tags — infra-only). **Review the rendered plan before approving:**
      - **State-only:** `destroy = 0`, no AWS resource added/changed/destroyed. **Any destroy or AWS-side change ⇒ STOP** (the `removed` blocks are `destroy = false`).
      - **Expect two state removals** in the mgmt `layerv.ai` zone — `aws_route53_record.discord_bot_alias` and `…discord_bot_cert_validation_v2` forgotten from state. Also state-only and benign (NOT a STOP): a **third** forget of `…discord_bot_cert_validation_legacy` (the pre-existing inert `removed` block, if it was never applied to prod state) and/or a state **`move`** line `discord_bot_cert_validation → …_legacy` (the inert `moved` block, if that rename was never applied). All are `destroy = 0`, no AWS change.
      - **Zero state removals ⇒ STOP / investigate.** The change is premised on these two resources being in nhp's prod state; zero forgets means they were never applied (premise wrong) — investigate rather than approve a silent no-op.
- [ ] Post-rollout: confirm zero AWS-side change — `dig +short discord.connector.layerv.ai` still resolves via the child zone → v2 ALB and `curl https://discord.connector.layerv.ai/health` → 200; the `connector-dns-resolution-check.yml` monitor stays green.
- [ ] Rollback: this PR touches no AWS record (`destroy = false`), so there is nothing to restore. If nhp must re-manage the records, `terraform import` them back (do NOT re-create — the A-alias has `allow_overwrite` OFF and would collide with the live record).
- [ ] Cross-repo: the documented delegation rollback (delete parent NS → un-occlude → legacy ALB) STAYS VALID after this PR because `destroy = false` keeps the occluded records. Their irreversible deletion is deferred to the old-stack teardown (qurl-integrations-infra `prod-rollout-ledger/2026-06-07-pr-932-discord-prod-rehome-v2.md`).

Delete this entry once the state-only apply is verified (two state removals, zero AWS changes).
