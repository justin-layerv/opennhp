# 2026-08-10 · PR #3820 · Retire the UDP-proof runtime-attestation SSM parameters

- **Owner:** sandbox rollout coordinator
- **Source:** #3820 · #3799 (attended proof removal) · #3804 (state-object cleanup)

The runtime-attestation store published two parameters for the attended UDP
proof's deployment-manifest producer to read. That producer was deleted in
#3799, so since then they have been published for nobody. Verified 2026-08-10
that nothing reads them: no collector or repair asset does a `get-parameter`, no
checker asserts them, and their only documented consumer was the deleted script.

This PR removes them from the module. **`sandbox-runtime-attestation` has no
deploy workflow** — no `.github/workflows/*` applies it — so merging does not
delete the live parameters. They persist until someone applies the root.

- [ ] Rollout: apply `terraform/environments/sandbox-runtime-attestation` from a
      reviewed plan. This root also owns the live attestation channel for the
      cell0, cell1 and qRTS fleets, so any participant beyond the two parameters
      is a stop condition.

      **Measured** on this PR's branch against live state (2026-08-10,
      refresh-enabled, `-lock=false`) — `Plan: 0 to add, 0 to change, 2 to
      destroy`, 18 resources total:

      | Action | Resources |
      |---|---|
      | `delete` | `aws_ssm_parameter.runtime_attestation_bucket_arn`, `aws_ssm_parameter.runtime_attestation_collector_contract` |
      | `no-op` (16) | `aws_s3_bucket` + its 6 configuration resources, `aws_kms_key`, `aws_kms_alias`, the repair `aws_ssm_document`, 3 × `aws_ssm_association` (one per attested fleet), 3 × `aws_iam_role_policy` |

      Re-plan before applying rather than reusing that result — it was taken
      pre-merge and live state moves.
- [ ] Post-rollout: confirm
      `aws ssm describe-parameters --parameter-filters
      "Key=Name,Option=BeginsWith,Values=/sandbox/nhp/udp-proof"` returns zero
      parameters, and that a fresh runtime attestation still lands in the bucket
      for each attested fleet (the collector runs on a timer, so the next write
      proves the channel survived).
- [ ] Rollback: re-add the two `aws_ssm_parameter` resources and re-apply. They
      hold public identifiers and digests only — no secret material — so
      restoring them is a plain re-create with no key or grant implications.

Delete this entry once the apply is recorded.
