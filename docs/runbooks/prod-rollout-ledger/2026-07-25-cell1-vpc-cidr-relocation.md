# 2026-07-25 · Sandbox cell1 VPC CIDR relocation

- **Owner:** attended sandbox rollout operator
- **Source:** prerequisite for [nhp#3454](https://github.com/layervai/nhp/pull/3454)
- **Runbook:** [sandbox-cell1-vpc-cidr-relocation.md](../sandbox-cell1-vpc-cidr-relocation.md)

Relocate the already-applied cell1 VPC from Control's `10.102.0.0/16` to the
audited-free `10.104.0.0/16` before Connector Authority admits cell1 callers.
This is an attended, downtime-accepted sandbox migration; never apply it from an
ordinary main-push deployment.

Shared-module production safety was checked read-only on 2026-07-25:
`layerv-nhp-prod-server` was at min/max/desired `3/10/3` with no suspended
processes. Terraform intentionally leaves future operator/deploy/incident
process suspensions externally owned until an explicit resume; the creating
deploy/maintenance/incident workflow must verify its own readback and cleanup,
so this migration does not add a speculative second alarm owner. A future
server VPC replacement also intentionally replaces every enabled same-VPC
server NLB; the trigger is scoped to the security group's `vpc_id`, so unrelated
security-group replacement does not cascade into NLB downtime. Static NLB names
make a VPC move an attended
destroy-before-create operation with downtime, not an ordinary prod apply.
Terraform `1.14.3` read-only, `-refresh=false`, `-lock=false` targeted plans
against the PR source then proved the current shared-module effect is
plan-neutral: sandbox cell0's enabled
`module.nhp.module.compute.aws_lb.server_internal[0]` was an exact no-op with
the same before/after VPC ID and no replacement path (saved-plan SHA-256
`d8959503a808e5b4bda293e82b3ef7faa1ca6598b18049bbc4c8abba5a9c01ef`);
prod has no enabled internal NLB instance, and its public server NLB was likewise
an exact no-op with the same before/after VPC ID and no replacement path in the
bounded plan. These targeted plans establish the attribute-scoped lifecycle
behavior for the affected NLBs but do not replace the mandatory clean, full
prod plan before any prod apply.
A refresh-enabled live-AWS Terraform `1.14.3` plan from Terraform source
commit `29d45a43e880bad57d903194fad5cd448359d787` at
`2026-07-26T01:46Z` also confirmed that the in-place Route 53 change has the
real provider shape
`after_unknown.alias=[{"name":true,"zone_id":true}]` (binary plan SHA-256
`a6db6b67c10ca64130ec3cbb7a51cfdc3de5a5b29dc6c84bc27c50fe9451af64`);
the checker still failed closed on the intentionally undrained blue ASG.
The ownership assumption was source-audited against `origin/main`
`cedf738f232a3af37b1f2bf51be87b64f6b96c50`: the suspension/resume terms have
zero matches under `.github`, `scripts`, and `terraform`, and the cell1
Terraform root has zero references under `.github/workflows` and `scripts`.
There is no existing auto-resume consumer or unattended cell1 apply path to
preserve.

- [ ] Pre-rollout: repeat the all-enabled-region/global routing audit, capture
      the cell1 public-key hash, DNS alias, active color, and exact ASG
      capacities/suspensions, then suspend launch/policy processes and drain
      both ASGs to min/max/desired `0/0/0`. Prove zero instances and zero EC2
      instance ENIs in the old VPC with
      `scripts/check-sandbox-cell1-vpc-relocation-preflight.sh`.
- [ ] Pre-rollout: only after the drain, create a refresh-enabled Terraform
      `1.14.3` saved plan and JSON from the exact reviewed, signed
      `REVIEWED_SOURCE_SHA`; require that SHA to equal both local `HEAD` and
      `origin/main`, and require a completely clean worktree. The fail-closed
      checker must accept the exact `50 add / 10 change / 50 destroy`
      inventory, the ASG dependency on the new private subnets, in-place
      DNS-record update, and no-op server identity, KMS, DynamoDB,
      plugin-bucket, and retained SSM resources. Record the source SHA and saved
      plan's SHA-256, and separately seal the generated compute-keygen archive
      consumed by Lambda `filename`. Do not use `terraform init -upgrade` or
      allow source, ignored inputs/artifacts, `.terraform.lock.hcl`, or the
      sealed archive to change before applying that saved plan.
- [ ] Rollout: immediately before apply, rerun the zero-fleet/ENI preflight and
      verify the same plan SHA-256. Apply only that saved plan; do not target,
      re-plan, apply any default-VPC restoration, or delete/regenerate identity
      material.
- [ ] Post-rollout: restore each ASG's captured min/max/desired values and only
      the processes this run suspended. Prove the active ASG and UDP target
      group healthy, the alias targets the replacement NLB, authoritative and
      public DNS have converged after the Route 53 propagation window, the
      public-key hash is unchanged, and positive direct-UDP plus negative
      off-source NHP probes pass before unblocking nhp#3454.
- [ ] Rollback: keep or return both ASGs to `0/0/0` with launch/policy processes
      suspended, merge and source-seal a reviewed rollback configuration, then
      generate a new refresh-enabled rollback saved plan from live state.
      Require the checker in `--direction rollback` mode and a new recorded
      SHA-256, apply only that plan, then restore captured capacities and prove
      health, DNS, identity, and UDP again. Never restore the account default
      VPC; its deletion is intentional and unrelated. A partial failed apply
      requires a new merged, reviewed exact-state recovery envelope; never
      weaken the checker, hand-edit state, or improvise a targeted apply.
      Recovery and rollback must repeat the exact ignored-artifact inventory
      and checksum seal before applying their newly reviewed saved plans.
