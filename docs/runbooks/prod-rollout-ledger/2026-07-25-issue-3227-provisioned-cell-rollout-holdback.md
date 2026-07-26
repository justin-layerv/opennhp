# 2026-07-25 · Issue #3227 · Provisioned-cell rollout holdback

- **Scope:** sandbox Control only.
- **Reason:** qurl-service published a new Connector Authority image after the
  provisioned-cell catalog was reviewed but before its two rows were applied.
  The trusted Control checker correctly rejects the resulting combined
  Authority-image update plus catalog create.
- **Mechanism:** retain the exact reviewed `provisioned_cells` value used by
  the Authority identity contract, but hold
  `provisioned_cell_catalog_materialization_enabled=false`. The module then
  emits no DynamoDB catalog rows and projects the exact empty catalog output
  (`{}`). Do not empty or fabricate the Authority contract to separate these
  transitions.
- **Authority image:** this PR also advances the checked-in sandbox basis to
  the immutable digest published by qurl-service deployment run `30187097917`
  from qurl-service source commit
  `e16c9bcffba430d1aae41f0442adc91771bee038`. The generated Control contract
  separately records NHP source commit
  `44169944e44b6ee990261eb2bc5f06653569185b`, the commit that last changed the
  checked-in measurement-basis blob, and its evidence SHA-256
  `080ee0590adb720bf58e59af9d6090647c52186f059f170a2f74c771f3390de9`;
  those are evidence provenance, not the Authority image's source.

## Required rollout sequence

- [ ] Merge this temporary holdback and dispatch `Control Sandbox Update` from
  that exact `main` commit with all three existing runtime/Hub gates set to
  `true`. Review, apply, and verify only the admitted exact
  `plan_mode=authority-image-update` transition: the foundation contract moves
  the reviewed image and repeated basis evidence, the three Authority functions
  move from the reviewed `d50...` digest to `97d...`, and their six blue/green
  aliases advance to the provider-computed versions. A retry after a partial
  apply may contain only the remaining bounded subset of those ten updates.
- [ ] Merge the prepared restoration code change that sets the sandbox
  `provisioned_cell_catalog_materialization_enabled` default to `true`, replaces
  the temporary fail-closed `false` validation with a fail-closed `true`
  validation, and keeps the root wrapper passing that validated variable. A
  tfvars override alone is intentionally rejected. Leave the reviewed catalog
  and Authority identity unchanged, and delete this temporary ledger entry in
  that restoration PR.
- [ ] Resume the existing provisioned-cell ledger: review, apply, and verify
  only its exact `plan_mode=provisioned-cell-catalog` two-row create.

## Rollback

Before the catalog rows exist, rollback the restoration code change so the
sandbox default and validation both hard-lock
`provisioned_cell_catalog_materialization_enabled=false`. After either row
exists, do not remove it through a normal rollback; `prevent_destroy` is
expected to reject that plan, and operators must follow the drain/migrate
procedure in the provisioned-cell catalog ledger.
