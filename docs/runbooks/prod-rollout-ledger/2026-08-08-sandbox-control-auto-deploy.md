# 2026-08-08 · Sandbox Control auto-deploy · prod parity decision

- **Owner:** prod rollout coordinator
- **Source:** this PR · Connector Authority foundation [#3227](https://github.com/layervai/nhp/issues/3227) · [unlock the production Control root](2026-08-06-unlock-prod-control-root.md)

Sandbox Control now applies automatically from `build-and-push.yml`, with its
seven runtime gates committed in `.github/control-sandbox-runtime-gates.json`.
Production Control has no gate file and no automatic leg, deliberately. The
prod Control bootstrap must not inherit either by accident, and whoever lands
the reviewed production Control workflow owns the explicit decision.

- [ ] Rollout (prod Control workflow): decide explicitly whether production
      Control auto-applies or stays attended-only, and record the decision in
      `.github/workflows/README.md`. Sandbox choosing automatic is not a
      precedent for prod: sandbox carries no customer data, and the prod root
      holds the Control tables, KMS keys, and the OTP pepper.
- [ ] Rollout (prod Control workflow): if prod gets a gate file, it must be a
      SEPARATE file. `control-sandbox-runtime-gates.py` hardcodes the sandbox
      path as its default and the sandbox dependency rules; pointing prod at the
      sandbox file would apply sandbox's gate shape to production.
- [ ] Rollout: the prod foundation apply runs with all gates at their committed
      DARK defaults (per the unlock entry). Do not add a prod gate file before
      that first apply — a non-dark gate file would contradict the reviewed
      bootstrap sequence, which needs the ECR repository and publisher role to
      exist before any digest can be consumed.
- [ ] Rollback: reverting this PR returns sandbox Control to attended-only
      dispatch. It does not revert live sandbox state, and the gate file's
      values remain the record of what live sandbox is running — re-read them
      from the file before any subsequent attended plan.

- [ ] **Decide whether the compensating controls should actually be enforcing.**
      Unattended apply gave up the human plan-review gate. The two things named
      as replacing it are both advisory today, measured on main 2026-08-09:
      - CODEOWNERS on the gate file: `require_code_owner_reviews=false` and
        `enforce_admins=false`, so it requests review rather than requiring it.
      - The `check-control-leg-surfaced.sh` fence (C5 shared writer lock, C6
        gate-reader capture form, C7 fully-dark teardown refusal): it runs in
        `validate-workflows`, which is **not** in main's six required status
        checks, so weakening it turns CI red without blocking a merge.

      Neither is a defect in this PR — both surfaces work and fail loudly. But
      "the one remaining human control point" is only true if one of them
      blocks. Enabling `require_code_owner_reviews`, or adding
      `validate-workflows` to the required checks, is a branch-protection
      decision with repo-wide consequences (it would also gate ordinary
      admin merges), so it is deliberately left to the repository owner rather
      than changed as a side effect of this work.

## Emergency sandbox rollback (read before you need it)

Turning the gates dark is **three** edits, not one, and finding that out
mid-incident is the failure this section exists to prevent:

1. `.github/control-sandbox-runtime-gates.json` — the gates themselves.
2. `tests/scripts/test_control_sandbox_runtime_gates.py`, the `LIVE` dict.
   `test_committed_file_matches_the_recorded_live_shape` pins the file to the
   exact current shape on purpose, so a gate flip is a deliberate two-file edit
   rather than a one-character slip. Skip this and CI goes red on the rollback.
3. An attended `control-sandbox-update.yml` dispatch. A **fully** dark gate file
   fails the automatic leg closed — an all-dark shape is a teardown of the Hub
   and the Authority runtime, not a deploy, and it is not something the
   unattended leg does off a config edit. A **partial** rollback (some gates
   dark) does auto-apply on the next push.

Fastest real rollback is usually reverting the offending gate commit, not
hand-editing to dark: it restores both files together and lands a shape the
automatic leg will apply.

Since #3822 the gate file is a registered plan input for `terraform-plan-pr.yml`,
so expect the rollback PR to run a real sandbox Control plan instead of skipping.
That is the point — you see what the revert does before it merges — but budget
for it mid-incident: the plan must satisfy
`scripts/check-connector-authority-foundation.sh` and
`check-control-sandbox-first-apply.py`, and neither admits an unnamed destructive
transition. A partial rollback to a previously-applied shape plans clean; a
rollback that deletes proof resources does not, and needs the attended path.
