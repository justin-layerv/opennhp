# Remove Control's orphaned attended-UDP-proof gate inputs

The attended UDP proof was removed in #3799 (files only). Its runner root has
since been destroyed, its emptied Terraform state object deleted (#3804), the
observability-parity exemption dropped, the orphaned proof-readiness workflow
removed and its App credentials revoked (#3806). One governed task remains, and
it is **also a latent sandbox-deploy blocker**.

## Why this is now urgent, not just tidy

`build-and-push.yml`'s `Require exact warm pools before a proof selector apply`
step fails closed whenever the Control plan has changes to apply:

```
if [[ "$selected" == 'none' || "$selected" != "$prepared" ]]; then … exit 0; fi
… exit 1
```

The committed gates are `selected_color: green` / `prepared_color: green`, so
neither skip condition holds and the step falls through to `exit 1`. Its guard
is `steps.plan.outputs.control_status == 'applied'`, so it has been **skipped**
on every recent run only because sandbox Control happened to be converged. The
next Control change that actually needs applying wedges the sandbox deploy.

## The gate file is NOT the lever — measured, not assumed

The step's own error suggests dispatching with `proof_policy_selected_color=none`.
**Flipping the gate alone does not work.** #3810 tried exactly that; the
resulting Control plan was rejected by
`scripts/check-connector-authority-foundation.sh`:

```
ERROR: dark Connector Authority plan contains destructive actions:
  ...aws_lambda_provisioned_concurrency_config.authority_proof_standby["...ca-ia"]  [delete]
  ...authority_proof_standby["...ca-icr"] [delete]
  ...authority_proof_standby["...ca-pm"]  [delete]
  ...authority_proof_standby["...ca-ra"]  [delete]
```

Those are the warm pools. That fence runs **unconditionally in every lane** —
the PR plan (`terraform-plan-pr.yml`), the attended plan *and* saved-plan apply
(`control-sandbox-update.yml` lines 403 and 731), and the unattended deploy leg
— with no mode flag or bypass. Its only proof-related allowance,
`authority_proof_prepare_recovery_allowed`, is an exact-shape whitelist for a
*prepare recovery* whose comment says it exists to stop "any destructive action
from borrowing that recovery lane". A pure teardown is not that shape.

## The sanctioned ordering

`docs/design/AUTHORITY_PROOF_MUTATION_CONTROLS.md` § Rollback ordering is the
authority, and it does not start with a gate flip:

1. Return IA/RA/ICR to the prior warm versions **through the governed alias
   controller**.
2. Disable the consumer-staging gate while both aliases remain unchanged.
3. Publish and warm the resulting non-proof version through the governed
   controller and point both aliases at it. This exact convergence is required
   before the proof-control gate may close.
4. Only then dispatch with runtime functions still enabled and attended proof
   mutation disabled — the strict `authority-proof-disable` plan, which
   `check-control-sandbox-first-apply.py` recognises as a named transition. It
   removes the controller's inline invoke policy through its explicit alias
   dependency, then `proof_controller`, ca-pm, the DynamoDB endpoint principal,
   the ca-pm resource/alarm graph and the proof alias output, with IA/RA/ICR and
   all six aliases exact no-ops.
5. Verify the Control state/live lanes without the proof slice and require a
   refresh-enabled dark no-op before considering rollback complete.

Only after live state is dark can the code go: the three `proof_policy_*` inputs
in `.github/workflows/control-sandbox-update.yml`, their entries in
`.github/control-sandbox-runtime-gates.json`, the six `authority_proof_*`
variables in **both** `terraform/control/environments/{sandbox,prod}/variables.tf`,
the `authority_proof_policy_*` plumbing in
`terraform/modules/connector-authority-foundation/`, and the now-dead fail-closed
branch in `build-and-push.yml`. Prod's six variables are validation-locked
closed, so prod is code-only with no resource change.

- [ ] Run the governed alias-controller rollback (steps 1–3 above).
- [ ] Dispatch the strict `authority-proof-disable` plan (step 4) and verify
      (step 5).
- [ ] Delete the code once live state is dark.

## Two traps for whoever does this

`.github/workflows/terraform-plan-pr.yml` **hard-codes** the generator flags
rather than reading the gate file, so its PR-time convergence plan reflects live
instead of planning to destroy it. Every gate change must edit that list too, or
the PR lane plans to re-create what was just retired. Switching it to
`control-sandbox-runtime-gates.py flags` would end this drift class.

`tests/scripts/test_control_sandbox_runtime_gates.py` holds `LIVE` as a literal
mirror of the committed gates, deliberately, and
`tests/scripts/test_check_control_sandbox_first_apply.py` pins the PR lane's
flag list. Both must move with any gate change.

## Live state as of 2026-08-10

`layerv-nhp-sandbox-ca-pm` is deployed (13 Authority functions in sandbox), and
the committed gates read `proof_mutation_controls_enabled: true`,
`proof_policy_consumers_staged: true`, `selected`/`prepared` both `green`, with
warm pools on ca-ia, ca-icr, ca-pm and ca-ra. This is real deployed
infrastructure, not a paper flag.

**Do not delete `2026-07-24-connector-authority-runtime-slice.md` or
`2026-07-26-authority-proof-mutation-controls.md` before this completes** — with
the design doc they are the only runbooks for it.

Delete this entry once the code removal has landed.
