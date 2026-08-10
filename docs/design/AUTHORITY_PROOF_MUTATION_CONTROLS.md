# Safe Ephemeral Authority Mutation Controls

## Status

The NHP Terraform slice implemented here is dark ca-pm capability only.
`authority_proof_mutation_controls_enabled` defaults false in both Control
roots and is validation-locked false in prod, so no resource is created and no
prod surface exists. Enabling the sandbox gate creates ca-pm and atomically
attaches its selected-alias invoke policy to the deterministic pre-created
proof-controller role; it does not modify IA/RA/ICR or make the attended proof
operational. The substantive qurl-service behaviour and the governed consumer
alias rollout are specified — not built — below.

This unblocks the `nhp-orchestrator` inventory row
`orchestrator.real_hub_authority_and_two_cells`, whose requirement ends with
"and safe ephemeral mutation controls".

## Why a control is needed at all

Five qurl-go scenarios are blocked on the deployed Authority's ability to change
authorization state for one uniquely tagged ephemeral agent:

| Scenario | Mutation it needs |
|---|---|
| `reassignment.cell0_to_cell1` | force one cell0-to-cell1 move at a newer generation |
| `reassignment.stale_assignment_rejection` | the same move (staleness is its by-product) |
| `assignment.lease_expiry_refresh` | shorten the derived assignment lease |
| `recovery.device_credential` | revoke the ephemeral device credential |
| `recovery.two_cell_completion_refresh` | the move plus the revoke |

`reassignment.cell0_to_cell1` is the load-bearing one: its adapter is already
written and running in the strict chain, and
`validateCell0ToCell1Reassignment` already demands
`previous.CellID == "cell0"`, `current.CellID == "cell1"`, a different endpoint
host, a different server-key digest, and
`current.AssignmentGeneration > previous.AssignmentGeneration`. Nothing on the
client side can produce that; only a real Authority move can.

### The two DNS rows do not belong here

`dns.hub_authoritative_address_refresh` and
`dns.cell_authoritative_address_refresh` require `dns_resolution` evidence and
ask for a changed DNS *answer*, then re-resolution of the authoritative name.
That is a resolver/Route53 mutation, not an authorization-state mutation, and
the proof doc already classes DNS cases as client-side paths driven through the
public SDK. They are excluded from this control and belong to the proof runner's
own resolver-control surface, alongside the existing
`negative.hub_dns_failure` / `negative.cell_dns_failure` adapters.

## Design

### The client never self-asserts

The mutation is performed **out of band**, by the attended NHP controller,
before the qurl-go strict workflow observes anything. The SDK has no control
channel and must not acquire one: `installLifecycleHTTPTrap` fails the run on
any HTTP call, and the whole point of the row is that the move is real.

Ordering works because warm open is a purely local state load — registration and
warm open are asserted *identical* — so the only network step that must see the
move is the reassignment refresh:

```
controller: arm directive for agent X (pinned cell0, move to cell1, short lease)
controller: dispatch qurl-go strict workflow
   client: RegisterAgentRuntime          -> cell0            (Authority honours the pin)
   client: OpenRegisteredAgentRuntime    -> cell0, identical (local load, no network)
   client: RefreshAgentRuntime(adopt)    -> cell1, gen+1     (Authority performs the move)
   client: RefreshAgentRuntime           -> cell1, same gen  (ordinary sticky refresh)
```

The directive is claimed by agent id. The attended proof is serialized and the
runner is one-use, so exactly one ephemeral agent is in flight per grant.

### Three independent observers

The client is never the only witness. A real move is corroborated by:

1. **The mutation receipt** returned by the control: agent id, previous and new
   cell and generation, Authority request id, image digest, timestamp.
2. **The manifest producer** (`terraform/modules/udp-proof-runner/manifest_producer.tf`),
   a separate read-only trusted-main role that already reads the Authority table
   and the deployed function versions, attesting the observed post-state.
3. **The client's own schema-v2 sidecar**, produced only from real SDK returns.

The three must agree on cell and generation. A client-side claim alone proves
nothing, which is exactly the property the proof design demands.

## Fencing

Five independent fences. Any one of them alone keeps the control out of
production and away from ordinary traffic.

1. **It does not exist in prod.** `authority_proof_mutation_controls_enabled`
   is validation-locked false in `terraform/control/environments/prod/variables.tf`,
   and the module precondition `authority_proof_mutation_fence_valid` additionally
   requires `environment == "sandbox"`. Prod cannot plan the function, so there
   is no prod surface to reason about.

2. **It is a separate operation family.** Proof operations live in
   `authority_contract_proof_operation_suffixes`, never in the hub or cell
   suffix maps. The caller-capacity closures are keyed on those two maps, so a
   proof operation can never acquire a hub or cell preinvoke budget, and
   `authority_selected_alias_targets` publishes the proof alias under its own
   `proof` key. The Hub task policy builds from `.hub` and each cell server
   policy from `.cells`, so **no runtime caller can name the alias**. A test
   asserts the alias is absent from both.

3. **Only the deterministic attended controller may invoke it.** The
   proof-runner root pre-creates
   `layerv-nhp-sandbox-udp-proof-controller` but owns no Authority policy or
   alias input. The Control saved plan creates one inline policy on that exact
   role whose only action is `lambda:InvokeFunction` and whose only resource is
   Control's selected qualified ca-pm alias. The alias and policy therefore move
   atomically; an operator cannot retain or supply an inactive alias ARN. The
   module keeps the no-`aws_lambda_permission` posture.

4. **IAM confines the data.** Placement item actions are conditioned on
   `dynamodb:LeadingKeys` restricted to exactly the dedicated proof tenant
   partition (`OWNER#` + SHA-256 of the proof owner id, derived in Terraform
   exactly as `agentPlacementOwnerPK` derives it) plus the `PROOF` directive
   partition. Replay Get/Put/Update has its own `StringLike` fence restricted to
   `HUB_REQUEST#MutateProofAgent#*`; a generic `HUB_REQUEST#*` grant is never
   admitted. `REGISTRY` is readable but not writable, so cell provisioning stays
   Terraform-owned. `api_keys`, `agent_keys`, and `customers` are absent
   entirely, and `dynamodb:DeleteItem` is never granted. **A wholly incorrect
   handler still cannot touch another tenant or operation's replay state**,
   because IAM denies the request before DynamoDB evaluates it.

5. **Capacity is one attended call.** The contract rejects a proof controller
   whose replicas, preinvoke limit, burst, or refill exceed one.

The runtime handler adds its own agent-namespace check
(`CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX`, `qurl-go-sandbox-`) and a bounded
directive TTL, but those are defence in depth, not the fence.

## Repo split

| Piece | Repo | State |
|---|---|---|
| Proof operation family, contract closure, capacity algebra | **nhp** | implemented |
| Prod lock, sandbox gate, root wiring | **nhp** | implemented |
| Separate `proof` alias target, absent from hub/cell | **nhp** | implemented |
| Execution-role `LeadingKeys` data fence | **nhp** | implemented |
| Fence contract tests | **nhp** | implemented |
| Generated proof caller/function and root inputs | **nhp** | implemented, explicit sandbox opt-in only |
| Controller invoke grant on the proof alias | **nhp** (Control) | implemented atomically with selected ca-pm alias; proof-runner owns role only |
| IA/RA/ICR proof-policy rollout | **nhp + qurl-service** | later governed selected-alias rollout; intentionally absent here |
| `MoveAssignment` cross-cell transaction | **qurl-service** | specified below |
| Proof directive store and lease override | **qurl-service** | specified below |
| `MutateProofAgent` operation, handler, codec | **qurl-service** | specified below |
| `ConnectorAuthorityOperationMutateProofAgent` constant | **qurl-conformance** | specified below |
| Device-credential revoke | **none — already exists** | see below |

### Device-credential revoke needs no new code

`ControlAPIKeyRepository.Revoke` already performs the full native-agent revoke
transaction (`revoked_at`, a fresh `revoked_device_fence_b64`, the `agent_count`
decrement, the active-to-revoked head advance). It is reachable today from the
authenticated Control HTTP API, and `IssueCredentialRecovery` already fails with
`revoke_required` while the head is active. The attended harness should revoke
the ephemeral proof agent's credential through that existing authenticated path.
Do **not** add revoke capability to the Authority mutation control; its execution
role deliberately cannot reach `api_keys` at all.

## qurl-service implementation spec

### 1. qurl-conformance (must ship first, as v0.10.0)

Export one new operation constant:

```go
ConnectorAuthorityOperationMutateProofAgent = "MutateProofAgent"
```

It must not appear in any production dispatch table or NHP numeric-code mapping.

### 2. Operation registration

- `internal/connectorauthorityruntime/config.go`: add
  `operationMutateProofAgent Operation = conformance.ConnectorAuthorityOperationMutateProofAgent`;
  add `operationMutateProofAgent: "pm"` to the `physicalFunctionName` suffix map;
  leave it out of `isCellOperation` so the function name stays bare
  (`layerv-nhp-<env>-ca-pm`).
- **Fail closed at cold start** if the operation is selected while
  `environmentID != "sandbox"`, or while `CONNECTOR_AUTHORITY_PROOF_OWNER_ID` is
  empty. This mirrors the Terraform fence inside the binary so a
  mis-provisioned function refuses to reach READY rather than serving.
- `runtime.go`: new `operationFactory` method plus a `buildConfigured` case.
- `wiring.go`: construct only the placement repository and the new proof writer.
  Do **not** construct `ControlAPIKeyRepository`, any KMS client, Redis, or SES.
- `dynamodb_sse.go`: the operation's closed table set is exactly
  `connector-authority`.

New environment variables, rendered by this dark capability slice for
MutateProofAgent only:
`CONNECTOR_AUTHORITY_PROOF_OWNER_ID`, `CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX`,
`CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL`, `CONNECTOR_AUTHORITY_PROOF_MIN_LEASE_SECONDS`,
plus the existing `CONNECTOR_AUTHORITY_CELL_DNS_SUFFIX`.

The independent consumer-staging gate publishes a new IA, RA, and ICR version
with these variables plus read-only `GetItem` access to the `PROOF` partition
and an explicit write deny. It reads and preserves both live alias versions
byte-for-byte. Staging is not activation: the attended proof remains blocked by
authenticated deployment evidence until the separate governed zero-spill
selected-alias rollout activates all three consumers.

### 3. Wire contract (`internal/connectorauthority/lambda_wire.go`)

`DecodeMutateProofAgentRequest` with the existing strict `decodeRequest[T]`
machinery (exact-field allowlist, `version` lexeme `1`, duplicate/unknown/null/
alias/trailing rejection). Fields:

```
version                (exact lexeme 1)
hub_request_id         (64 lowercase hex; replay key, same as ia/ra/icr)
mutation               ("arm" | "move" | "expire_lease")
agent_id               (must carry the proof agent prefix)
grant_correlation_id   (the controller's dispatch correlation id)
pinned_cell_id         ("arm" only)
target_cell_id         ("arm" and "move")
lease_seconds          ("arm" and "expire_lease"; >= the configured minimum)
```

Closed error vocabulary:
`invalid_request`, `identity_rejected`, `directive_absent`, `directive_expired`,
`reassignment_in_progress`, `unavailable`. Route through the existing
`uniqueErrorCode` so zero or multiple matches fail closed to `unavailable`.

Success response carries the receipt: `agent_id`, `previous_cell_id`,
`previous_assignment_generation`, `new_cell_id`, `new_assignment_generation`,
`lease_expires_at`, `mutated_at`.

### 4. Directive store

New item type in `layerv-nhp-<env>-control-connector-authority`:

```
pk = "PROOF"
sk = "GRANT#" + agentID
attributes: owner_id_hash, pinned_cell_id, target_cell_id, lease_seconds,
            grant_correlation_id, state, claimed_at, created_at, updated_at, ttl
```

`ttl` is mandatory and bounded by `CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL`, so
an abandoned run cannot leave an armed mutation behind. Every write is a
conditional transaction; `arm` refuses to overwrite an unexpired directive for a
different correlation id.

### 5. Reads that honour a directive

`IssueAssignment` and the lease producers must consult the directive **only**
for an agent inside the proof tenant whose id carries the proof prefix:

- Initial placement uses `pinned_cell_id` instead of the HRW selector. This is
  what makes registration land deterministically on cell0 and lets the harness
  set `QURL_GO_SANDBOX_EXPECTED_CELL_ID=cell0`.
- `AgentAssignmentLeaseLifetime` is replaced by `lease_seconds` in all three
  producers (`agent_assignment_issue.go`, `agent_assignment_refresh.go`,
  `agent_credential_recovery_issue.go`). The recovery replay verifier recomputes
  the lease from `GrantIssuedAt + AgentAssignmentLeaseLifetime` and **must be
  updated in lockstep**, or the shortened lease will fail its own replay check.
- Every other tenant and every non-prefixed agent id keeps the same request
  semantics; the lookup must be skipped entirely, not merely ignored. In this
  dark capability PR, IA/RA/ICR are not republished and neither of their aliases
  advances. The later governed rollout must preserve that zero-spill invariant.

### 6. The cross-cell move — the substantive work

None of this exists today. `AgentPlacementRepository` is deliberately read-only,
there is no generation increment anywhere, and no writer ever sets
`state = "moving"`; the only assignment writer is the create-only generation-1
`Put` inside `ActivateConnectorRegistration`.

Implement `MoveAssignment` as **two** transactions so the intermediate state is
observable and fail-closed, matching the stated invariant that a move "marks the
assignment moving, relocates every dependent state item, increments generation,
and only then exposes the new binding":

**Transaction A — mark moving.** Conditional `Update` on the assignment row
fenced with the existing `assignmentCondition` predicate (`cell_id`,
`assignment_generation`, `state`, `created_at`, `updated_at` storage spellings),
setting `state = "moving"` and a new `updated_at`. While moving,
`RefreshAssignment` already returns `reassignment_in_progress`, so a client that
races the move is correctly refused rather than handed a torn binding.

**Transaction B — relocate and expose.** One `TransactWriteItems` containing:
- `ConditionCheck` on the target cell row fencing `status`, `endpoint_revision`,
  `nhp_host`, `nhp_port`, `server_public_key_b64`, `selection_weight`,
  `updated_at` — the same cell fence activation uses.
- `Update` on the assignment row conditioned on `state = "moving"` and the exact
  generation from transaction A, setting `cell_id = target`,
  `assignment_generation = previous + 1`, `state = "active"`, new `updated_at`.
- Relocation of every dependent item keyed by cell: the device-credential head,
  the completion locator, and any completion-candidate sentinel. Enumerate these
  from the repository package rather than hardcoding a list, and fail closed on
  an unrecognised dependent item rather than leaving it behind.

Add an `allowsProofAgentMove` predicate to `control_client.go`'s `confinedTransact`
allowlist; without it the transaction is rejected pre-I/O with
`ErrControlBoundaryViolation`, which is the desired default.

The owner counter is **not** touched: a move relocates a placement, it does not
create or destroy one.

### 7. Tests qurl-service must carry

- DynamoDB-Local proof that a move advances generation by exactly one, flips
  `active -> moving -> active`, relocates every dependent item, and leaves the
  owner counter unchanged.
- A concurrent `RefreshAssignment` during the moving window returns
  `reassignment_in_progress` and never a torn binding.
- Directive lookup is skipped entirely for a non-proof owner and for a
  proof-tenant agent whose id lacks the prefix.
- Cold start fails closed when the operation is selected with
  `environmentID = "prod"` or an empty proof owner.
- The shortened lease survives the recovery replay verifier.

## Ordering

1. qurl-conformance v0.10.0 exports the operation constant.
2. qurl-service implements the operation, the move, and the directive store, and
   publishes a new Authority image digest.
3. Apply `sandbox-udp-proof-runner` to establish the deterministic
   `controller_role_arn`. That state owns the role only and accepts no
   Authority alias input.
4. Dispatch the Control sandbox workflow with runtime functions and attended
   proof mutation explicitly enabled. The generator adds exactly
   `proof_controller` capacity and `layerv-nhp-sandbox-ca-pm`, and emits the
   canonical proof owner/controller root variables. In that same saved plan,
   Control creates the selected qualified alias and attaches the controller's
   exact invoke policy. IA/RA/ICR and both aliases remain unchanged.
5. Apply the consumer-staging gate, then run the separate governed zero-spill
   IA/RA/ICR selected-alias activation. Staging alone is insufficient and the
   authenticated deployment evidence reports the consumers not ready until all
   three selected aliases expose the exact proof-policy environment.
6. Only after that rollout, the attended proof arms a directive, runs the strict
   workflow, and cross-checks the three observers.
7. Only then may qurl-go's blocked rows move off `todo`, together with the
   `implemented`/`blocking` gate literal and the reviewed inventory mapping
   digest in all seven places.

Steps 1 through 5 change no qurl-go scenario status. Nothing in this design
weakens a fail-closed check or converts an unavailable operation into a
simulated green result.

## Rollback ordering

> [!IMPORTANT]
> **The ordering below is unreachable as written since #3804.** It assumes a
> live governed alias controller. The `udp-proof-runner` root that owned the
> controller identity was destroyed and its state object deleted before this
> rollback ever ran, so steps 1-3 have no caller. Measured 2026-08-10:
> `layerv-nhp-sandbox-udp-proof-controller` returns `NoSuchEntity`, and ca-pm
> carries no resource-based policy on the function or on its `green` alias — so
> nothing can invoke the controller and nothing would be permitted to if it
> could.
>
> **They are also unnecessary, which is the stronger reason: skip them
> permanently rather than waiting for them to become reachable.** Their purpose
> is to converge the consumer aliases onto a common non-proof version before the
> pin drops. Measured on the disable plan, the three consumers change by exactly
> one thing — the four `CONNECTOR_AUTHORITY_PROOF_*` variables are removed, the
> image is unchanged — so the alias moves are `green 12 → 13` and `blue 6 → 13`
> on that same image, and green, the colour that serves, is already on the
> configured digest. The governed alias controller was also never built: it
> exists only as prose here and in module comments, Terraform is the sole
> manager of the six aliases, and the proof-controller role only ever held
> `lambda:InvokeFunction` on ca-pm's alias. Restoring it would not make steps
> 1-3 reachable.
>
> Step 4 onward still applies. See
> `docs/runbooks/prod-rollout-ledger/udp-proof-runner-teardown.md` for the
> measured plan, the remaining blockers, and the open task to amend the
> six-aliases-no-op invariant that step 4 states below.

Rollback uses the governed alias controller plus two exact Control saved plans.
First return IA/RA/ICR to the prior warm versions, then disable the
consumer-staging gate while both aliases remain unchanged. Publish and warm the
resulting non-proof version through the governed controller and point both
aliases at it; this exact convergence is required before the proof-control gate
may close. Only then dispatch with runtime functions still enabled and attended
proof mutation disabled. The strict
`authority-proof-disable` plan removes the
controller's inline invoke policy through its explicit alias dependency, then
removes exactly `proof_controller` and ca-pm from the foundation, ca-pm from the
DynamoDB endpoint principals, the complete ca-pm resource/alarm graph, and the
proof alias output. IA/RA/ICR and all six aliases remain exact no-ops in this
final plan. Verify the
Control state/live lanes without the proof slice and require a refresh-enabled
dark no-op before considering rollback complete.

### Why it became unreachable: the cross-root ownership seam

`aws_iam_role_policy.authority_proof_controller_invoke` is the seam. Control
manages an inline policy on a role it does not own — the resource comment says
so directly: *the role itself is pre-created by the udp-proof-runner root*. Its
`count` keys off `authority_proof_mutation_controls_enabled`, **not** off the
role existing, so destroying the runner root did not remove it from Control's
graph. The grant's own design note ("rollback removes this grant before deleting
the alias") describes an ordering the runner-root teardown bypassed.

Consequences, both measured rather than reasoned:

- The orphan is a latent **apply** failure, not just a guard failure. Any
  Control plan that changes the proof alias set re-renders this policy and calls
  `PutRolePolicy` against the deleted role. It is a no-op today only because the
  alias set has not moved. A refresh-enabled lane finds the policy absent and
  plans a create, which fails the same way.
- Retiring the rollout selector is **not** a small IAM-only change. A local
  read-only plan of `consumers_staged=false, selected=none, prepared=none`
  against live state (serial 95) is `1 to add, 16 to change, 5 to destroy`.
  Dropping the colours moves `authority_proof_policy_effective_color` from green
  to blue, which repoints the proof alias everywhere it is referenced: the Hub
  public config, so `aws_ecs_task_definition.hub[0]` is **replaced** and
  `aws_ecs_service.hub[0]` redeployed; the Hub task role; the lambda interface
  endpoint policy; and the proof alias output. Both ca-pm aliases move.
  IA/RA/ICR aliases stay exact no-ops, as does every surviving warm pool
  (`steady == rollout_active == rollout_standby == 2` in the measurement basis).

Two consequences for whoever resumes this. First, any correct sequence must
delete resources — the orphaned invoke policy, and the four
`authority_proof_standby` pools — and
`scripts/check-connector-authority-foundation.sh` admits no proof-related delete
in any lane, so the fence must gain an exact-shape allowance before any of this
can pass. That is the same guard-deadlock class as
`docs/runbooks/prod-rollout-ledger/2026-08-06-unlock-prod-control-root.md`: the
guard that rejects the broken state also blocks its own remediation. Second, the
allowance must be justified by *this* corrected ordering. An allowance added to
admit a code-first teardown — deleting the Terraform and then destroying what it
managed — remains forbidden, because it inverts the live-first rule above.
