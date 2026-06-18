# 2026-06-12 · PR #2467 · F5 revoked-pubkey admin rollout

- **Owner:** prod rollout coordinator
- **Source:** [#2467](https://github.com/layervai/nhp/pull/2467), [#2477](https://github.com/layervai/nhp/issues/2477)

PR #2467 adds the `nhp-license-admin list-revoked`, `revoke`, and `unrevoke`
commands for `ACAssignment.RevokedPubKeys`. The write path is operator-driven,
but prod readiness depends on the incident operator/admin role being able to
read and update the AC assignments table before F5 strict mode is used during an
incident.

- [ ] Pre-rollout: confirm the incident operator/admin role for
      `nhp-license-admin revoke` / `unrevoke` has `dynamodb:GetItem` and
      `dynamodb:UpdateItem` on the prod AC assignments table via
      `dynamodb_write_policy_arn` or an equivalent least-privilege grant (#2477).
- [x] Pre-rollout: from a trusted operator shell or current prod admin profile, run
      `nhp-license-admin list-revoked --region <prod-region> --ac-assignments-table <prod-table> --ac-id <known-ac-id>`
      to confirm region, table, and IAM wiring before an incident. _Done/current 2026-06-18: `AWS_PROFILE=layerv-prod AWS_REGION=us-east-2 go run ./licenseadmin/main list-revoked --region us-east-2 --ac-assignments-table layerv-nhp-prod-cell0-ac-assignments --ac-id layerv-ac-tf` returned `version: 36688` and `revoked_pubkeys: (none)`, proving the CLI/table/region/read path. The separate incident operator/admin role attachment check remains open._
- [ ] Strict-mode flip: keep `NHP_AC_PUBKEY_REVOKE_VERIFY=false` until the F5
      alarms are OK and ACAssignment pre-provisioning is ready, as described in
      the F5 runbook.
- [ ] Rollback: stop using the new admin commands and clear any mistaken denylist
      entries with `nhp-license-admin unrevoke`; if strict enforcement itself
      causes customer impact, flip `NHP_AC_PUBKEY_REVOKE_VERIFY=false` while
      preserving the audit trail for follow-up.
