# 2026-07-27 · qurl-service#1237 · agent-key inventory gate on prod deploys

- **Owner:** prod rollout coordinator
- **Source:** [qurl-service#1237](https://github.com/layervai/qurl-service/issues/1237) · [qurl-service#1240](https://github.com/layervai/qurl-service/issues/1240) · [qurl-service#1317](https://github.com/layervai/qurl-service/pull/1317) · [qurl-service#1324](https://github.com/layervai/qurl-service/pull/1324)

Adds a `qurl-agent-key-inventory` job that blocks `deploy-qurl` on a complete
strongly consistent scan of the prod qurl api-key and agent-key tables. It has
an **ordering dependency**: the job cannot succeed until the IAM grant in this
same PR is applied, and it cannot succeed against a qurl image that predates
qurl-service#1324.

- [ ] Pre-rollout: apply the terraform in this PR **before** the first
      promotion that runs the new job. The
      `aws_iam_role_policy.qurl_agent_key_inventory` resource adds
      `dynamodb:Scan` on `layerv-nhp-prod-*-qurl-api-keys` and
      `-qurl-agent-keys` to the promotion role; without it the job fails closed
      with an AWS error and blocks `deploy-qurl`. Applying the IAM early is
      harmless — it is a read-only grant with no runtime consumer until the job
      runs. It is a standalone inline policy on purpose: `context_lookups` is a
      relay-DMZ boundary resource that ordinary deploys must leave a no-op, and
      the role is already at the 10-attachment managed-policy limit.
- [ ] Pre-rollout: confirm the qurl image tag being promoted is post
      qurl-service#1324, which added `/app/qurl-agent-key-inventory` to the
      api image. Older tags fail the job's `--version` startup smoke with an
      explicit "image predates #1324" error. The first prod promotion after
      this lands is the one to watch.
- [ ] Rollout: on the first gated promotion, read the retained
      `qurl-agent-key-inventory-prod` artifact and confirm
      `result: PASS`. **Prod has never been inventoried** — sandbox found four
      pre-contract rows in cell0 (qurl-service#1240), so a non-zero prod
      blocker count is a realistic first outcome, not necessarily a bug in the
      gate. If it blocks, do **not** bypass: remediation is an explicitly
      authorized, condition-fenced repair per the procedure recorded on
      qurl-service#1240, followed by a fresh gate run.
- [ ] Rollout: prod currently runs a single cell, and the gate scans the one
      prefix in `PROD_QURL_TABLE_PREFIX`. If a second prod cell lands, the gate
      must run once per cell prefix — a single-cell run would report PASS while
      the other cell went unchecked.
- [ ] Post-rollout: the residual pre-contract population in sandbox is legacy
      `schema_version` rows tracked by qurl-service#1036. The gate's
      `--require-schema-v1` flag stays **off** until nhp-server stops accepting
      a missing `schema_version` as legacy version 0
      (`internalauth.IsSupportedQURLAgentKeysSchemaVersion`). Per the
      reader-first rule in `docs/design/QURL_AGENT_KEYS_SCHEMA.md`, flip the
      flag and remove reader legacy acceptance in the same coordinated
      rollout — never the flag first.
- [ ] Rollback: revert this PR. The job disappears and `deploy-qurl` returns to
      its previous gate set. The IAM grant is read-only and safe to leave in
      place, or remove it in the same revert; nothing consumes it once the job
      is gone.
