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

**Steps 1–3 are unreachable — see the next section before attempting them.**

- [ ] Restore the `layerv-nhp-sandbox-udp-proof-controller` IAM role, and decide
      which root owns it now. This clears the **Terraform** wedge (the apply);
      it does not restore a caller for steps 1–3. See "the orphan is not
      independently removable" below. Do **not** try to delete the orphaned
      policy instead; the module forbids it.
- [ ] Reinstate a caller for the controller, or widen its trust policy — it is
      GitHub-OIDC-only and its workflow was revoked (#3806). Required before
      steps 1–3, not before the apply unblock above.
- [ ] Decide the ordering for retiring the rollout selector now that it is known
      to replace the Hub task definition (measured below), then execute it.
- [ ] Dispatch the strict `authority-proof-disable` plan (step 4) and verify
      (step 5).
- [ ] Delete the code once live state is dark.

## Measured 2026-08-10 — two blockers, both verified against live sandbox

The ordering above assumes a live governed alias controller. There is not one,
and there has not been since this root was destroyed.
`docs/design/AUTHORITY_PROOF_MUTATION_CONTROLS.md` § Rollback ordering now
carries the correction; the evidence:

| Probe | Result |
|---|---|
| `iam get-role layerv-nhp-sandbox-udp-proof-controller` | `NoSuchEntity` |
| `lambda get-policy` on ca-pm (function, and `green` alias) | `ResourceNotFoundException` |

So steps 1–3 have no caller and no permission. **Do not attempt them.**

### Blocker 1 — orphaned invoke policy (undocumented until now)

`aws_iam_role_policy.authority_proof_controller_invoke[0]` still manages an
inline policy on that deleted role. Its `count` keys off
`authority_proof_mutation_controls_enabled`, not off the role existing, so
destroying the runner root left it in Control's graph pointing at nothing.

This is a latent **apply** failure, not a guard failure: any plan that changes
the proof alias set re-renders the policy and calls `PutRolePolicy` on a role
that is gone. It is a no-op today only because the alias set has not moved.

This must be resolved before anything else — **by restoring the role, not by
deleting the policy**; see "the orphan is not independently removable" below for
why the module forbids the latter. It is also why the sanctioned steps 1–3
cannot simply be "restored": the identity they need was deleted out from under
Control.

### Blocker 2 — retiring the selector is not a small change

Measured with a local read-only plan against live state (serial 95) at
`consumers_staged=false, selected=none, prepared=none`:
**`1 to add, 16 to change, 5 to destroy`.**

Dropping the colours moves `authority_proof_policy_effective_color` green → blue,
which repoints the proof alias everywhere it is referenced:

- `aws_ecs_task_definition.hub[0]` **replaced** and `aws_ecs_service.hub[0]`
  redeployed (the Hub public config embeds the proof alias ARN)
- `aws_iam_role_policy.hub_task[0]`, `aws_vpc_endpoint.interface["lambda"]`, and
  the `authority_proof_mutation_alias_arn` output all change
- both ca-pm aliases move; 5 `authority_exec` policies update
- the 4 `authority_proof_standby` pools are deleted

IA/RA/ICR aliases stay exact no-ops, and every surviving warm pool keeps its
value (`steady == rollout_active == rollout_standby == 2` in the basis). But a
Hub task-definition replacement is a live Hub redeploy riding along with a
"gate flip", which is what #3809's review caught. Decide deliberately whether to
accept that or decompose it; do not let it arrive unattended.

### The orphan is not independently removable — measured, then refused

The obvious next move is to drop the orphaned policy on its own. **It does not
work, and the module says so.** `authority_proof_mutation_fence_valid`
(`authority_runtime_contract.tf`) requires, whenever
`authority_proof_mutation_controls_enabled` is true, exactly one controller role
ARN equal to the deterministic `layerv-nhp-<env>-udp-proof-controller` ARN. Its
own comment states the intent: *the only admitted controller identity is the
deterministic role whose selected-alias policy Control owns in this same plan.*

Control owning that policy and the capability being enabled are welded together
on purpose. So the policy cannot leave while the capability is on, and turning
the capability off is the `authority-proof-disable` transition — step 4, which
requires all six aliases to already be no-ops, which requires steps 1–3, which
require the controller. That is the whole deadlock, and its cause is that an IAM
role Control depends on was deleted by a different root.

Two measured notes for whoever picks this up:

- `terraform plan -refresh-only` against live state does cleanly detect
  `authority_proof_controller_invoke[0]` as *deleted outside Terraform*, and it
  is the **only** drift in the root. But **do not run a refresh-only apply on its
  own**: the module still declares the resource, so once state forgets it every
  subsequent plan wants to create it against a role that does not exist, turning
  a latent apply failure into a guaranteed one.
- Because the capability must stay enabled until step 4, the cheapest correct
  unblock is to **restore the IAM role** rather than to fight the contract.
  Nothing needs to assume it for Control's plan to become applyable again — the
  contract only requires the role to exist so Control can own a policy on it.
  Its definition is recoverable from history at
  `be7f2b5bd^:terraform/modules/udp-proof-runner/iam.tf`
  (`aws_iam_role.controller`). Decide deliberately which root should own it now,
  given the runner root that used to is gone.

  **Restoring the role does not restore the ability to run steps 1–3.** That
  role's trust policy admits only `sts:AssumeRoleWithWebIdentity` federated to
  the GitHub OIDC provider and conditioned on
  `repo:<repo>:environment:<environment>` — there is no AWS principal in it, so
  no operator or CLI session can assume it, and the workflow that did was
  removed with its App credentials revoked in #3806. Treat these as two separate
  wedges: restoring the role clears the **Terraform** one (the apply), while
  invoking the controller additionally needs a caller that no longer exists.
  Anyone planning steps 1–3 must budget for reinstating one, or for widening
  that trust policy deliberately.

### The remaining blocker still needs a fence lane

`scripts/check-connector-authority-foundation.sh` admits no proof-related delete
in any lane, and retiring the selector requires four. The guard that rejects
today's state also blocks its own remediation — the same class as
`2026-08-06-unlock-prod-control-root.md`. The lane must be justified by the
corrected live-first ordering; an allowance shaped to admit a **code-first**
teardown stays forbidden, which is why #3809 was closed.

Note the pattern before reaching for that lane. This fence has now refused three
separate proposals — #3810's gate flip, #3809's code-first teardown, and an
attempt to drop the orphaned invoke policy on its own — and on all three it was
right, the last one enforced by the module contract rather than the fence. Treat
a fourth refusal as evidence the sequence is still wrong, not as a fourth
allowance to write.

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
