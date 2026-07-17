# qURL agent transaction IAM plan fixtures

These are minimized, sanitized `terraform show -json` outputs from Terraform
1.14.3 with the root's locked AWS provider 6.55.0. They retain the top-level
plan status fields and the complete target resource change consumed by
`check-qurl-agent-transact-iam.py`.

- `create-terraform-1.14.3.json` came from the read-only plan against the exact
  production staged root before the policy existed.
- `no-op-terraform-1.14.3.json` came from the same resource configuration and
  provider schema using a local synthetic state plus `-refresh=false`; it made
  no AWS API call and performed no apply. The checker-facing JSON is the real
  Terraform 1.14.3 no-op shape, including `applyable: false`, identical
  `before`/`after`, and identity fields.

Only generated metadata not read by the checker (configuration, prior state,
and timestamp) was removed. Regenerate both fixtures when the pinned Terraform
or AWS provider version changes. At the same time, revalidate the exact plan
and apply session policies, including S3 list/native-lock behavior and KMS
decrypt/encrypt/data-key actions; fixture compatibility alone does not prove
the backend authorization contract still holds.
