# 2026-07-09 · qURL v2 software key custody (KMS as a paid entitlement)

- **Owner:** prod rollout coordinator
- **Source:** nhp branch `justin/qurl-kms-hardware-terraform` (this PR) + qurl-service branch `justin/qurl-kms-hardware-entitlement`

Makes per-resource KMS custody a paid per-customer add-on; unentitled owners get
software custody (P-256 generated in-process, private half envelope-wrapped under
a single shared CMK, stored in the new `qurl-resource-key-material` table). This
PR provisions the shared envelope CMK, the material table, IAM, and the new
`QURL_V2_RESOURCE_KEY_*` env; the qurl-service PR is the code that reads them.
Deploy order matters: qurl-service now lists the material table in its schema
registry and its config requires the envelope-key ARN whenever resource keys are
enabled.

- [ ] **Pre-rollout (deploy ORDER — lockstep):** Apply this nhp Terraform FIRST
      (creates `qurl-resource-key-material`, the envelope CMK, the task-role
      envelope grant (`task_qurl_v2_resource_key_envelope`), and emits
      `QURL_V2_RESOURCE_KEY_ENVELOPE_KMS_ARN` +
      `QURL_V2_RESOURCE_KEY_SOFTWARE_DEFAULT=true`). Only then deploy the
      companion qurl-service image. Deploying qurl-service first red-lines it:
      its schema reconciler 503s on the missing material table, and
      `Config.Validate` fails without the envelope-key ARN. (See CLAUDE.md
      "qURL schema-registry ↔ TF lockstep".)
- [ ] **Rollout:** Sandbox ships with the ramp ON
      (`qurl_v2_resource_key_software_default = true` — cost decision
      2026-07-09: stop minting per-resource CMKs for unentitled owners
      immediately). The software path goes live at the first deploy of the
      custody-aware image; run the post-rollout verification right after that
      deploy rather than after a separate flip. Rollback = set the flag false
      and apply (new resources revert to hardware custody).
- [ ] **Post-rollout (verify, ramp on):** Create a resource for an unentitled
      owner → row has `resource_key_custody=software`, empty `resource_kms_key_arn`,
      a `qurl-resource-key-material` item exists; CloudTrail shows `GenerateDataKey`
      (encryption context `purpose=qurl-v2-resource-software-key`) and **no**
      per-resource `CreateKey`. Confirm a qv2 knock still admits (software public
      key works as the NHP identity). Watch
      `qurl.resource_key.provision.total{custody=software}` and
      `qurl.resource_key.custody_lookup_error.total`.
- [ ] **Rollback:** Set `qurl_v2_resource_key_software_default = false` and apply
      → new resources revert to hardware custody. Existing software-custody
      resources keep working (the public key is unchanged and the private key is
      unused by v2 admission); no data migration is required or attempted.
- [ ] **Cross-repo:** qurl-service `justin/qurl-kms-hardware-entitlement` must
      deploy AFTER this Terraform applies. Enabling a paid customer on hardware
      custody additionally needs the entitlement setter / Stripe add-on mapping
      (qurl-service follow-up) — not required for this rollout.

## Resource-key reaper (added 2026-07-09, same PR)

One-time backlog sweep ran 2026-07-09 (operator creds; keys in a 7-day
PendingDeletion window — evidence/stats in qurl-service PR #1176). Remaining
tasks:

- [ ] **Recurring reaper enable:** after the reaper qurl-service image deploys,
      this PR's `qurl_v2_resource_key_reaper_enabled = true` (sandbox tfvars)
      emits `QURL_V2_RESOURCE_KEY_REAPER_*` + grants `tag:GetResources`; verify
      the first in-app sweep logs `resource-key reaper sweep complete` and
      `qurl.resource_key.reap.total{result=reaped}` moves while `result=error`
      and `result=refused` stay flat.
- [ ] **Post-verify (~2026-07-17, after the pending window):** sandbox tagged
      Enabled resource-key CMK population ≈ live keyed resources (hundreds, not
      thousands); monthly KMS charge drops accordingly.
- [ ] **Prod:** resource keys are not enabled in prod (no keys exist) — no prod
      sweep needed; reaper stays default-off there until qv2 enablement.
