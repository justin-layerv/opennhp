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

**Steps 1–3 are both unreachable and unnecessary — skip them.** See "Measured"
below for why they cannot be run, and "The disable transition, measured" for why
running them would not buy anything.

- [x] Release the orphaned `authority_proof_controller_invoke` grant. Done by
      deleting the resource **and** adding a `removed` block with
      `destroy = false`, which plans as a state-only `forget`. Measured: drift 0,
      zero destroys, foundation fence clean, no alias/warm-pool/Hub movement.
      Restoring the IAM role is **not** required — see "the orphan is
      independently removable" below.
- [ ] Claim the baseline plan so the apply can proceed. This is the critical
      path: it lands #3797's grants and the `forget` from #3828 (checklist item
      above) together, and unwedges Control. Four addresses are unclaimed, and
      they are **two different kinds of change**: the three
      `aws_iam_role_policy.authority_exec` entries for ca-ia, ca-iro-cell0 and
      ca-iro-cell1 are #3797's ticket-handle grants — **not `kms:Decrypt`** —
      while `terraform_data.foundation_contract` is a synthetic in-state marker
      that re-renders when its inputs move, not a grant at all. See "the third
      blocker, re-measured" below. Unrelated to the proof work; blocks the apply
      with or without it.
- [x] Prove the consumer image tolerates the four `CONNECTOR_AUTHORITY_PROOF_*`
      variables being absent. It does, by construction — see "the image
      tolerates their absence" below. **All four must go together**; a partial
      removal fails closed.
- [ ] Amend `AUTHORITY_PROOF_MUTATION_CONTROLS.md`: its six-aliases-no-op rule,
      which the measured disable plan does not meet; and its description of the
      slice as ca-pm only, which has been two functions since ca-pcr landed.
- [x] Close the rollout window (live-first). The gate flip to
      `proof_policy_*_color: none` plus `blue_green_alias_hold_enabled: true`
      produces the retirement plan; both fences admit it as
      `authority-proof-rollout-retirement`. Landing this darkens live state.
      Measured against serial 100: 1 add, 9 change, 5 destroy -- the four
      standby pools and the Hub task definition. With the blue/green hold live,
      IA/RA/ICR aliases do not move at all.
- [x] Close the rollout window and align the switch pointer (nhp #3846): the
      selector colours go to `none` and the contract's
      `selected_authority_color` moves to green -- where live Hub traffic
      already points -- in one measured apply (13 add / 8 change / 17 destroy,
      Hub task definition no-op, zero drift). The four standby pools delete and
      steady provisioned concurrency re-homes blue => green with a brief
      (~2-4 min) sandbox warm-capacity gap, accepted by the owner. Admitted as
      `authority-proof-rollout-retirement` composed with the image roll; the
      strict `authority-proof-disable` transition remains for the later
      full-dark step (proof gate off, ca-pm/ca-pcr removed).
- [x] Teardown step 1 (nhp #3848): consumer staging off. IA/RA/ICR republish
      without the proof env, exec policies drop the PROOF read, ca-pm's pending
      steady capacity restores, and no alias moves (consumers stay pinned while
      the gate is on). Measured 1 add / 7 change / 0 destroy at serial 112.
- [x] Teardown step 2 (nhp #this): `proof_mutation_controls_enabled` off. The
      real live plan (serial 113) deletes exactly the ca-pm/ca-pcr graphs (31
      destroys), nulls both proof outputs, drops the pair from the DynamoDB
      endpoint principals, and the freed IA/RA/ICR standby aliases catch up
      under the hold while the serving green aliases stay no-ops. Admitted as
      composed-authority-proof-disable-with-authority-standby-alias-advance;
      foundation fence clean via the pair-leaving-the-graph witness.
- [ ] Verify the refresh-enabled dark no-op after the apply, then delete the
      proof code (root outputs, module plumbing, checker proof lanes) and this
      ledger entry. This subsumes retiring the rollout selector — measured below,
      it is not a separate step.
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
`aws_iam_role_policy.authority_exec` for ca-ia, ca-iro-cell0 and ca-iro-cell1.
That is unrelated to the proof work and blocks the apply independently. Sandbox
Control is therefore wedged on three gates, not one: this checker, the
foundation fence, and the apply itself.

### The third blocker, re-measured — and it is not `kms:Decrypt`

Re-planned against live state after #3824 merged: **`0 to add, 39 to change,
0 to destroy`**, not the `1 to add, 4 to change` measured earlier. Two things
changed underneath.

**The three IAM changes are #3797's, not DynamoDB SSE `kms:Decrypt`.** An
earlier revision of this entry recorded them that way; measured, the three
policies each gain one statement:

| Address | Added statement |
|---|---|
| `authority_exec["…ca-ia"]` | `AuthorityTicketHandleWrite` — `dynamodb:PutItem` on `ASSIGNMENT_TICKET#*` |
| `authority_exec["…ca-iro-cell0"]` | `AuthorityTicketHandleRead` — `dynamodb:GetItem` on `ASSIGNMENT_TICKET#*` |
| `authority_exec["…ca-iro-cell1"]` | the same read grant |

Those are the ticket-handle store grants from `ecc84cc89` (#3797, "grant the
Authority the IAM its handle store needs"), merged and still unapplied. Same
four addresses, different cause — and the difference matters: this is a merged
fix waiting to land, so whoever writes the claiming transition should shape it
around #3797's grants rather than an SSE change that is not in the plan.

**The fourth address is a different kind of change entirely.**
`terraform_data.foundation_contract` holds no IAM. It is the module's synthetic
contract marker — a `merge()` of the account, table prefix, region, image URI,
runtime contract and the proof gate values — so it re-renders whenever any of
those inputs moves. Here that is the image digest below. A transition claiming
these four must therefore admit one marker re-render plus three exact policy
additions, not four grants.

**A pending Authority image deploy has accumulated behind the wedge.**
`image_uri` moves `…88493a → …0ef227` across all thirteen functions, carrying
their aliases with it; that is the bulk of the 39. `authority-image-uri-move`
already exists as a composable transition — confirm it claims this half rather
than assuming it. #3828's `forget` does appear in the plan, so its code is in,
but it only takes effect on the apply that is still blocked.

Consequently the version numbers quoted below (`green 12 → 13`, `blue 6 → 13`)
are stale and will shift once the image deploy lands. The *structural*
conclusion is unaffected — the consumer delta is env-only on an unchanged image
because it comes from the gate, not the digest — but re-measure the versions
before quoting them.

> Local plans cannot be validated with the checker:
> `check-control-sandbox-first-apply.py` requires a plan produced by exactly
> Terraform 1.14.3, and rejects one built with a newer CLI ("Terraform plan must
> use exact 1.14.3"). Match the pinned version locally if you need to run the
> checker against a plan you made yourself.

## The disable transition, measured — steps 1–3 are also unnecessary

The section above establishes steps 1–3 are unreachable. Measuring the plan they
gate shows they are **unnecessary**, which is the stronger reason to skip them.

Planned locally, read-only, refresh enabled, against live state with
`authority_proof_mutation_controls_enabled` off (which forces the consumer and
colour gates off with it): **`1 to add, 19 to change, 37 to destroy`**.

The 37 destroys are the intended teardown: the whole graph for both proof
functions — ca-pm (`mutate_proof_agent`) and its sibling ca-pcr
(`prepare_proof_credential_recovery`) — covering functions, four aliases, exec
roles/policies, log groups, sixteen alarms and their provisioned concurrency,
plus the four `authority_proof_standby` pools. The DynamoDB and lambda interface
endpoint policies drop the ca-pm principal.

The single add is not a new resource. Plan actions are exactly `delete × 36`,
`update × 19` and one `delete,create` — `aws_ecs_task_definition.hub[0]`, task
definitions being immutable — so the Hub task definition is replaced and its
service redeployed, because the Hub config embeds the proof alias ARNs and both
outputs go null. `37 destroy` is the 36 deletes plus that replacement's delete;
`1 add` is its create. This is the same Hub redeploy Blocker 2 measured, and it
rides along with any path that drops the colours — so retiring the selector is
not a separate step to sequence; this transition subsumes it.

> **ca-pcr is real, and the design doc is what is stale.** The proof slice is
> two functions, not one: `EXPECTED_PROOF_FUNCTIONS` in
> `.github/scripts/generate-connector-authority-runtime-contract.py` binds both
> `ca-pm → mutate_proof_agent` and `ca-pcr → prepare_proof_credential_recovery`,
> and the module fence requires exactly two expected proof names. Live, ca-pcr's
> v1 dates to 2026-07-29, it now sits at v5 with `blue = green = 5` and one
> provisioned execution on blue. It is absent from "Live state" below because
> that list covers the proof-policy *rollout* standby pools and ca-pcr was never
> in the rollout set — which is why this plan deletes `authority_proof_standby`
> for ia/icr/pm/ra but `authority["…ca-pcr"]` for pcr.

**What steps 1–3 were protecting is benign in the current state.** Their job is
to converge the consumer aliases onto a common non-proof version before the pin
drops, and step 4's rule is that all six stay exact no-ops. They do not — all
six move. But measured, the three consumers change by *exactly* one thing:

    image_uri unchanged; removed env
      CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX
      CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL
      CONNECTOR_AUTHORITY_PROOF_MIN_LEASE_SECONDS
      CONNECTOR_AUTHORITY_PROOF_OWNER_ID

so the alias moves are `green 12 → 13` and `blue 6 → 13` on an **unchanged
image**. All three consumers were pinned together at the same pair, which is why
one version pair describes all six aliases. **Green is what actually serves** —
723 invocations over seven days against 7 on blue — and green is already on the
configured image digest, so the serving path drops four environment variables
and nothing else. Blue skips the six intermediate versions 7–12 because the
proof pin froze it at v6 on 2026-07-26, but blue takes about one call a day.

### The image tolerates their absence — by construction, not by luck

The enablement fence in `2026-07-26-authority-proof-mutation-controls.md` warned
that enabling ahead of image support fails closed at init with
`configuration_invalid`, so removal needed proving rather than assuming. It is
proven: `internal/connectorauthorityruntime/config.go` in qurl-service reads all
four through `loadProofPolicy(lookup, requiredPolicy)`, whose first exit is

    if presentCount == 0 && !requiredPolicy {
        return nil
    }

and the consumer operations pass `requiredPolicy = false` — `issue_assignment`
at one call site, `refresh_assignment` and `issue_credential_recovery` at
another. With all four absent they return cleanly and leave
`proofPolicyEnabled` false. Only `mutate_proof_agent` passes `true`, and ca-pcr
has its own owner/prefix-only path.

**The one real constraint: all four must be removed together.** Any partial set
hits `presentCount != len(names)` and returns `errInvalidConfiguration`, so a
half-applied change bricks the consumers at init. The measured plan removes all
four in one step, which satisfies this — but do not let anything split them.

Caveat on the evidence: this is qurl-service `origin/main`, not a checkout
pinned to the deployed digest `sha256:3b32d89f…`. The gate is designed to be
two-way — Terraform adds the consumer operations to
`authority_proof_operations` only while `consumers_staged` is true, and
IA/RA/ICR ran without these variables before 2026-07-26 — so a regression here
would be a defect rather than a design change, but confirm the digest's commit
if you want this airtight.

One thing still to prove rather than assume before dispatching:

- Step 4's six-aliases-no-op rule is genuinely not met. Amend
  `AUTHORITY_PROOF_MUTATION_CONTROLS.md` to say what the rule protects and why
  an env-only move on an unchanged image satisfies it — do not diverge silently.

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
