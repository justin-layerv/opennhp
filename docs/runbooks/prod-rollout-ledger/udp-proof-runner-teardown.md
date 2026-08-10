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

- [x] Release the orphaned `authority_proof_controller_invoke` grant. Done by
      deleting the resource **and** adding a `removed` block with
      `destroy = false`, which plans as a state-only `forget`. Measured: drift 0,
      zero destroys, foundation fence clean, no alias/warm-pool/Hub movement.
      Restoring the IAM role is **not** required — see "the orphan is
      independently removable" below.
- [ ] Claim the four pre-existing unclaimed addresses that also block the apply:
      `terraform_data.foundation_contract` and `aws_iam_role_policy.authority_exec`
      for ca-ia, ca-iro-cell0, ca-iro-cell1 (pending DynamoDB SSE `kms:Decrypt`
      grants). Unrelated to the proof work; blocks the apply with or without it.
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

It is **not** latent. Measured against live state (serial 95) at the committed
gates, the baseline plan is `1 to add, 4 to change, 0 to destroy` — and the
"add" is this policy, so the `PutRolePolicy` failure is live today. Resolved by
forgetting the grant; see "the orphan is independently removable" below. Steps
1–3 still cannot be "restored", but not because of this role — see the
correction in that section.

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

### The orphan IS independently removable — #3818's claim, corrected

#3818 recorded that dropping the orphaned policy alone "does not work, and the
module says so", reasoning from `authority_proof_mutation_fence_valid`. **That
is wrong, and it was measured before being corrected here.**

The precondition constrains the *variable*
`authority_proof_mutation_controller_role_arns` — it never requires the policy
**resource** to exist. The weld between "Control owns the policy" and "the
capability is enabled" is asserted in a code comment, not in the condition. With
the resource removed, `terraform plan` succeeds: `4 to change, 0 to destroy`.

Deleting the resource alone is still not sufficient, but for a different and
smaller reason: the already-deleted policy stays in state, so a plain removal
leaves a drift `delete` that `check-connector-authority-foundation.sh` folds
into destructive actions and refuses. The fix is a `removed` block with
`lifecycle { destroy = false }`, which plans as **`forget`** — Terraform
releases the address from state and calls no AWS delete API, because AWS deleted
it already. Measured: `DRIFT: 0`, zero destroys, and the fence passes on its own
terms ("Connector Authority foundation contract is clean"). **No fence allowance
was needed**, so this is not the `2026-08-06-unlock-prod-control-root.md`
guard-deadlock class after all — the guard was refusing a *historical*
out-of-band deletion, and `forget` states that fact instead of arguing with it.

Restoring the IAM role — #3818's recommendation — is therefore unnecessary, and
would recreate the cross-root ownership seam that caused this in the first
place.

Two corrections that travel with it:

- `terraform plan -refresh-only` still must not be applied on its own, for the
  reason #3818 gives: the resource would be recreated by every later plan. The
  `removed` block is what makes the release safe, because it drops the resource
  from the config in the same change.
- **Steps 1–3 are unreachable for a stronger reason than a deleted role.** The
  governed zero-spill alias controller was never *built* — it exists only as
  prose in the design doc and module comments, and there is no `update-alias` or
  `publish-version` anywhere in `.github/` or `scripts/`. Terraform is the sole
  manager of the six aliases. `layerv-nhp-sandbox-udp-proof-controller` only
  ever held `lambda:InvokeFunction` on ca-pm's alias; it was the attended proof
  *invoke* identity, never an alias manager, so restoring it would not make
  steps 1–3 reachable. The ordering is also unsatisfiable in principle: while
  the gate is on, the standby colour reads
  `data.aws_lambda_alias.authority_proof_policy_live`, so blue is frozen
  (IA/RA/ICR blue=6, green=12) and the only lever that frees it is the
  `authority-proof-disable` plan — the very plan required to move nothing.

### A third blocker: four pre-existing unclaimed addresses

`check-control-sandbox-first-apply.py` also refuses the **baseline** plan, on
four addresses no transition claims: `terraform_data.foundation_contract` plus
`aws_iam_role_policy.authority_exec` for ca-ia, ca-iro-cell0 and ca-iro-cell1
(pending DynamoDB SSE `kms:Decrypt` grants). That is unrelated to the proof work
and blocks the apply independently. Sandbox Control is therefore wedged on three
gates, not one: this checker, the foundation fence, and the apply itself.

## One trap for whoever does this

`tests/scripts/test_control_sandbox_runtime_gates.py` holds `LIVE` as a literal
mirror of the committed gates, deliberately. It must move with any gate change.

Expect the gate edit itself to draw a plan: since #3822 the gate file is a
registered plan input, and `terraform-plan-pr.yml` derives its flags from it, so
a gate-only PR plans the retirement rather than skipping. That plan renders the
all-dark shape rather than failing closed, and then meets
`check-control-sandbox-first-apply.py`, which admits only named transitions —
so the `authority-proof-disable` lane (step 4) is a prerequisite for the
teardown PR going green, not a follow-up.

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
