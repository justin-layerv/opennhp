# Sandbox cell1 VPC CIDR relocation

This one-time attended runbook moves the already-applied `sandbox-cell1` VPC
from `10.102.0.0/16` to `10.104.0.0/16`. The move has an explicit sandbox
downtime window. It preserves the server identity secret/key, DynamoDB data,
KMS keys, plugin bucket, stable `cell1.nhp.layerv.xyz` record name, and SSM
deployment state.

The account default VPC is out of scope. Its planned deletion is intentional:
do not recreate it before, during, or after this runbook.

## Fixed contract

- AWS account: `767397897469`
- Region: `us-east-2`
- Terraform: exactly `1.14.3`
- Source: one explicitly reviewed, signed NHP `main` commit containing this
  relocation; set its full SHA as `REVIEWED_SOURCE_SHA`
- State root: `terraform/environments/sandbox-cell1`
- Old cell1 CIDR: `10.102.0.0/16`
- New cell1 CIDR: `10.104.0.0/16`
- Expected forward plan: exactly `50 add / 10 change / 50 destroy`
- Public endpoint: UDP `cell1.nhp.layerv.xyz:62206`
- ASGs:
  - `layerv-nhp-sandbox-cell1-server`
  - `layerv-nhp-sandbox-cell1-server-green`

Stop on any deviation. Do not use `-target`, an auto-approved apply, or a plan
created before the fleet drain.

There is no hidden unattended owner to coordinate with. A read-only source
audit of `origin/main` at
`cedf738f232a3af37b1f2bf51be87b64f6b96c50` found zero matches for
`suspend-processes`, `resume-processes`, `SuspendedProcesses`, or
`suspended_processes` under `.github`, `scripts`, or `terraform`, and zero
references to `terraform/environments/sandbox-cell1` under
`.github/workflows` or `scripts`. No current workflow relies on Terraform to
resume a suspension, and no unattended workflow applies this root. This
attended runbook owns the freeze, explicit readback, and restoration.

## 1. Revalidate routing and capture rollback evidence

Use an attended shell and a private, mode-`0700` evidence directory:

```bash
set -euo pipefail
export AWS_PROFILE=layerv
export AWS_REGION=us-east-2
export TF_ROOT=terraform/environments/sandbox-cell1
: "${REVIEWED_SOURCE_SHA:?set the full reviewed post-merge NHP main SHA}"
evidence="$(mktemp -d)"
chmod 700 "$evidence"

test "$(pwd -P)" = "$(git rev-parse --show-toplevel)"
test "$(aws sts get-caller-identity --query Account --output text)" = 767397897469
test "$(/tmp/terraform-1.14.3/terraform version -json | jq -r .terraform_version)" = 1.14.3
[[ "$REVIEWED_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]
git fetch --quiet origin \
  refs/heads/main:refs/remotes/origin/main
test "$(git rev-parse HEAD)" = "$REVIEWED_SOURCE_SHA"
test "$(git rev-parse origin/main)" = "$REVIEWED_SOURCE_SHA"
source_verification="$(
  gh api repos/layervai/nhp/commits/main
)"
test "$(jq -r .sha <<<"$source_verification")" = "$REVIEWED_SOURCE_SHA"
test "$(jq -r .commit.verification.verified <<<"$source_verification")" = true
test "$(jq -r .commit.verification.reason <<<"$source_verification")" = valid
source_status="$(git status --porcelain=v1 --untracked-files=all)"
test -z "$source_status"
ignored_files="$(git ls-files --others --ignored --exclude-standard)"
test -z "$ignored_files"
printf '%s\n' "$REVIEWED_SOURCE_SHA" >"$evidence/source.sha"
```

`REVIEWED_SOURCE_SHA` is the exact post-sequencing source reviewed for this
attended apply, not merely whatever commit is current when the window begins.
Use a fresh checkout: the initial ignored-file check must also be empty, so an
ignored override, auto-loaded variable file, generated archive, provider tree,
or unrelated local artifact cannot masquerade as reviewed source.
The GitHub commit-verification read is intentional: a local keyring may not
contain GitHub's signing key for a verified merge commit. If `origin/main`
advances, GitHub does not report the exact commit signature as valid, or the
worktree contains any tracked, staged, untracked, or ignored change, stop and
review the new exact source.
The action-inventory checker is deliberately fail-closed, but it is not a
substitute for source provenance: several expected updates (including the
server IAM policy, launch template, and init script) can carry different values
without changing their Terraform action kind.

Repeat `scripts/check-control-vpc-cidr-overlap.sh` for `10.104.0.0/16` in every
enabled sandbox-account region and repeat the global Direct Connect gateway and
Cloud WAN inventory. Stop on overlap, IPAM, Transit Gateway, VPN, Client VPN,
Direct Connect, Cloud WAN, pagination, or parse uncertainty. The 2026-07-25
read-only audit passed all 17 enabled regions; that evidence is not a substitute
for this last pre-apply readback.

Capture the exact live ASG state, active color, current DNS alias, and a hash of
the public half of the server identity. The hash proves continuity without
writing private key material:

```bash
groups=(
  layerv-nhp-sandbox-cell1-server
  layerv-nhp-sandbox-cell1-server-green
)

aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "${groups[@]}" \
  --output json >"$evidence/asgs-before.json"
test "$(jq '.AutoScalingGroups | length' "$evidence/asgs-before.json")" = 2

aws ssm get-parameter \
  --name /sandbox-cell1/nhp/server/active-color \
  --query 'Parameter.Value' --output text >"$evidence/active-color.txt"
grep -Eq '^(blue|green)$' "$evidence/active-color.txt"

aws route53 list-resource-record-sets \
  --hosted-zone-id Z10394893FM38A1RXLL32 \
  --query "ResourceRecordSets[?Name == 'cell1.nhp.layerv.xyz.']" \
  --output json >"$evidence/dns-before.json"
test "$(jq 'length' "$evidence/dns-before.json")" = 1

aws secretsmanager get-secret-value \
  --secret-id layerv-nhp-sandbox-cell1-server \
  --query SecretString --output text |
  jq -er .publicKey |
  sha256sum |
  awk '{print $1}' >"$evidence/server-public-key.sha256"
grep -Eq '^[0-9a-f]{64}$' "$evidence/server-public-key.sha256"

dig +noall +answer cell1.nhp.layerv.xyz \
  >"$evidence/dns-answers-before.txt"
```

Confirm the cell1 DynamoDB tables still contain only expected greenfield
canary/test state. If any customer data or unexplained item appears, stop and
obtain a data migration/backup plan before replacing the VPC.

## 2. Freeze launch paths and drain both ASGs

Reject a pre-existing state that cannot be restored without overriding an
operator's `Launch` suspension:

```bash
scripts/check-sandbox-cell1-vpc-relocation-preflight.sh \
  "$AWS_PROFILE" "$AWS_REGION" 10.102.0.0/16 pre-drain |
  tee "$evidence/pre-drain-preflight.txt"
```

This fails when an ASG has positive minimum or desired capacity while `Launch`
was already suspended. Stop and resolve that state explicitly before beginning
the relocation; the runbook never guesses whether an operator suspension is
stale.

Suspend every process that could launch or policy-scale an instance, while
leaving `Terminate` available for the drain:

```bash
freeze_processes=(
  AlarmNotification
  AZRebalance
  InstanceRefresh
  Launch
  ReplaceUnhealthy
  ScheduledActions
)

for group in "${groups[@]}"; do
  aws autoscaling suspend-processes \
    --auto-scaling-group-name "$group" \
    --scaling-processes "${freeze_processes[@]}"
  aws autoscaling update-auto-scaling-group \
    --auto-scaling-group-name "$group" \
    --min-size 0 \
    --max-size 0 \
    --desired-capacity 0
done
```

Wait for both groups to report no instances. Termination lifecycle hooks may
make this take several minutes:

```bash
while :; do
  remaining="$(
    aws autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "${groups[@]}" \
      --query 'length(AutoScalingGroups[].Instances[])' \
      --output text
  )"
  test "$remaining" = 0 && break
  sleep 15
done

scripts/check-sandbox-cell1-vpc-relocation-preflight.sh \
  "$AWS_PROFILE" "$AWS_REGION" 10.102.0.0/16 drained |
  tee "$evidence/drain-preflight.txt"
```

The preflight fails unless both groups are exactly min/max/desired `0/0/0`,
contain no instance in any lifecycle state, retain every required suspension,
and the old tagged VPC has no ENI attached to an EC2 instance. NLB, NAT, and VPC
endpoint service ENIs are expected to remain until Terraform replaces their
owners.

## 3. Generate and seal the saved plan after the drain

Keep the reviewed provider selection fixed. Do not run
`terraform init -upgrade`, delete or edit `.terraform.lock.hcl`, or use a
different Terraform or provider selection between this plan and its saved-plan
apply. If the committed lock file differs from the reviewed head at any point,
keep the fleet frozen and stop.

```bash
git diff --exit-code HEAD -- "$TF_ROOT/.terraform.lock.hcl"
git fetch --quiet origin \
  refs/heads/main:refs/remotes/origin/main
test "$(git rev-parse HEAD)" = "$(cat "$evidence/source.sha")"
test "$(git rev-parse origin/main)" = "$(cat "$evidence/source.sha")"
source_status="$(git status --porcelain=v1 --untracked-files=all)"
test -z "$source_status"
ignored_files="$(git ls-files --others --ignored --exclude-standard)"
test -z "$ignored_files"
/tmp/terraform-1.14.3/terraform -chdir="$TF_ROOT" init \
  -input=false \
  -lockfile=readonly
git diff --exit-code HEAD -- "$TF_ROOT/.terraform.lock.hcl"
git fetch --quiet origin \
  refs/heads/main:refs/remotes/origin/main
test "$(git rev-parse HEAD)" = "$(cat "$evidence/source.sha")"
test "$(git rev-parse origin/main)" = "$(cat "$evidence/source.sha")"
source_status="$(git status --porcelain=v1 --untracked-files=all)"
test -z "$source_status"
ignored_files="$(
  git ls-files --others --ignored --exclude-standard -- \
    . ":(exclude)$TF_ROOT/.terraform/**"
)"
test -z "$ignored_files"
/tmp/terraform-1.14.3/terraform -chdir="$TF_ROOT" plan \
  -input=false \
  -refresh=true \
  -out="$evidence/cell1-10.104.tfplan"
/tmp/terraform-1.14.3/terraform -chdir="$TF_ROOT" show \
  -json "$evidence/cell1-10.104.tfplan" \
  >"$evidence/cell1-10.104.tfplan.json"

python3 .github/scripts/check-sandbox-cell1-cidr-relocation-plan.py \
  "$evidence/cell1-10.104.tfplan.json"
sha256sum "$evidence/cell1-10.104.tfplan" \
  >"$evidence/cell1-10.104.tfplan.sha256"
generated_artifact=terraform/modules/compute/keygen_lambda.zip
ignored_files="$(
  git ls-files --others --ignored --exclude-standard -- \
    . ":(exclude)$TF_ROOT/.terraform/**"
)"
test "$ignored_files" = "$generated_artifact"
generated_artifact_path="$(git rev-parse --show-toplevel)/$generated_artifact"
sha256sum "$generated_artifact_path" \
  >"$evidence/cell1-generated-artifact.sha256"
```

The checker enforces the exact `50/10/50` inventory. It also rejects a plan
that was created while either ASG had nonzero min/max/desired capacity, changes
the server identity/KMS/DynamoDB/plugin-bucket/retained-SSM resources, replaces
the public DNS record rather than updating its alias in place, points the alias
away from the reviewed compute NLB, changes any of the nine reviewed subnet
ranges, or disconnects compute from the new networking module outputs.

The plan generates exactly one ignored artifact outside the pinned
`.terraform` tree: `terraform/modules/compute/keygen_lambda.zip`. The source
file and archive-provider selection are reviewed, and the runbook separately
seals the resulting archive because the saved-plan hash does not bind bytes
that Lambda's `filename` reads from the filesystem during apply.

The DNS unknown-value contract is based on real provider output, not only the
test fixture. A refresh-enabled live-AWS plan produced with Terraform `1.14.3`
and the reviewed lock from Terraform source commit
`29d45a43e880bad57d903194fad5cd448359d787` at
`2026-07-26T01:46Z` reported format version `1.2`, the exact `50/10/50`
inventory, and this Route 53 change:
`actions=["update"]`,
`after_unknown.alias=[{"name":true,"zone_id":true}]`. The saved binary plan's
SHA-256 was
`a6db6b67c10ca64130ec3cbb7a51cfdc3de5a5b29dc6c84bc27c50fe9451af64`.
As expected before the attended drain, the checker then rejected that live plan
because the blue ASG still had `min_size=1`; this evidence validates the
provider JSON shape without bypassing the drain gate.

The checker and preflight names describe two distinct scopes. The
`cidr-relocation-plan` checker validates the sealed Terraform plan's exact CIDR
transition, while the `vpc-relocation-preflight` script validates the wider live
AWS fleet drain and VPC inventory. Do not substitute one for the other.

Manually inspect the saved plan as the second line of defense. In particular:

- the public NLB is destroy-before-create because AWS cannot move it between
  VPCs and its static name prevents create-before-destroy;
- both ASGs update to the newly created private subnet IDs while their launch
  and policy paths remain frozen and their capacity remains zero;
- the Route 53 record updates in place to the replacement NLB;
- the server secret/keygen invocation, cookie secrets, KMS keys, DynamoDB
  tables, plugin bucket, active color, image/deploy parameters, and ASG-name
  parameters remain no-op.

## 4. Apply the exact saved plan

Immediately before apply, recheck the drain and the sealed plan:

```bash
scripts/check-sandbox-cell1-vpc-relocation-preflight.sh \
  "$AWS_PROFILE" "$AWS_REGION" 10.102.0.0/16 drained
(cd "$evidence" && sha256sum -c cell1-10.104.tfplan.sha256)
git diff --exit-code HEAD -- "$TF_ROOT/.terraform.lock.hcl"
git fetch --quiet origin \
  refs/heads/main:refs/remotes/origin/main
test "$(git rev-parse HEAD)" = "$(cat "$evidence/source.sha")"
test "$(git rev-parse origin/main)" = "$(cat "$evidence/source.sha")"
source_status="$(git status --porcelain=v1 --untracked-files=all)"
test -z "$source_status"
ignored_files="$(
  git ls-files --others --ignored --exclude-standard -- \
    . ":(exclude)$TF_ROOT/.terraform/**"
)"
test "$ignored_files" = terraform/modules/compute/keygen_lambda.zip
(cd "$evidence" && sha256sum -c cell1-generated-artifact.sha256)

/tmp/terraform-1.14.3/terraform -chdir="$TF_ROOT" apply \
  -input=false \
  "$evidence/cell1-10.104.tfplan"
```

Do not re-plan between the SHA check and apply. Do not target resources. If
either preflight or the saved-plan SHA fails, keep the fleet frozen and stop.

## 5. Restore the captured fleet, not configuration defaults

Restore the exact captured min/max/desired values. Resume `Launch` only when it
was not suspended before this run, then wait for the captured desired capacity:

```bash
for group in "${groups[@]}"; do
  row="$(jq -cer --arg name "$group" \
    '.AutoScalingGroups[] | select(.AutoScalingGroupName == $name)' \
    "$evidence/asgs-before.json")"
  aws autoscaling update-auto-scaling-group \
    --auto-scaling-group-name "$group" \
    --min-size "$(jq -r .MinSize <<<"$row")" \
    --max-size "$(jq -r .MaxSize <<<"$row")" \
    --desired-capacity "$(jq -r .DesiredCapacity <<<"$row")"

  if ! jq -e \
    '.SuspendedProcesses[]? | select(.ProcessName == "Launch")' \
    <<<"$row" >/dev/null; then
    aws autoscaling resume-processes \
      --auto-scaling-group-name "$group" \
      --scaling-processes Launch
  fi
done
```

For each group, wait until the number of `InService` + `Healthy` instances
equals its captured desired capacity. Require at least one healthy target in
the target group selected by the captured active color. Only then resume each
of the other five freeze processes that was not already suspended in
`asgs-before.json`; never resume a process that was suspended before this run:

```bash
post_launch_processes=(
  AlarmNotification
  AZRebalance
  InstanceRefresh
  ReplaceUnhealthy
  ScheduledActions
)

for group in "${groups[@]}"; do
  row="$(jq -cer --arg name "$group" \
    '.AutoScalingGroups[] | select(.AutoScalingGroupName == $name)' \
    "$evidence/asgs-before.json")"
  for process in "${post_launch_processes[@]}"; do
    if ! jq -e --arg process "$process" \
      '.SuspendedProcesses[]? | select(.ProcessName == $process)' \
      <<<"$row" >/dev/null; then
      aws autoscaling resume-processes \
        --auto-scaling-group-name "$group" \
        --scaling-processes "$process"
    fi
  done
done
```

## 6. Prove endpoint and identity continuity

Verify state and AWS live reads agree that the VPC and every cell1 subnet are
inside `10.104.0.0/16`, and no tagged `10.102.0.0/16` cell1 VPC remains.
Confirm `/sandbox-cell1/nhp/server/udp-listener-arn` names the replacement
UDP/62206 listener and the Route 53 alias target equals the replacement NLB.

[Route 53 documents](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-to-elb-load-balancer.html)
that ELB alias changes generally propagate to all Route 53 servers within 60
seconds. The alias itself inherits the ELB resource TTL. Record the TTL shown by
the pre-cutover answer, poll the authoritative `layerv.xyz` name servers for the
new answer, then wait for the larger of that observed TTL and the 60-second
Route 53 propagation window before requiring multiple independent public
resolvers to return only replacement-NLB addresses. Treat a mixed old/new
answer as an incomplete cutover, not a pass.

Recompute the server public-key hash using the command from step 1 and compare
it exactly:

```bash
aws secretsmanager get-secret-value \
  --secret-id layerv-nhp-sandbox-cell1-server \
  --query SecretString --output text |
  jq -er .publicKey |
  sha256sum |
  awk '{print $1}' >"$evidence/server-public-key-after.sha256"
cmp "$evidence/server-public-key.sha256" \
  "$evidence/server-public-key-after.sha256"
```

Finally, run the direct native NHP UDP positive proof through
`cell1.nhp.layerv.xyz:62206` and the off-source/unauthenticated negative probe.
Do not unblock Connector Authority cell1 callers until fleet health, target
health, DNS, identity, and both UDP results are all recorded on the PR.

## 7. Retire the one-time migration gates

After the successful cutover and continuity proof are durably recorded, open a
cleanup PR that deletes this runbook, the one-time plan checker and live
preflight, their fixtures/tests, and their Makefile/workflow references. Delete
the rollout-ledger entry in the same PR, as required by the ledger README.

Keep the permanent compute-module lifecycle ownership, NLB VPC replacement
trigger, `tests/scripts/test_compute_lifecycle_contract.py` and its
Makefile/workflow invocations, `10.104.0.0/16` allocation, and durable topology
documentation. The one-time gates deliberately pin the migration's
`max_capacity == 2`, exact `50/10/50` action inventory, and
Terraform/provider JSON shape; retaining them after the migration would turn
reviewed safety constraints into stale CI coupling.

## Rollback

If apply or post-apply proof fails, stop cell1 activation. Keep the groups
frozen at `0/0/0`; if they were already restored, repeat the step-2 freeze and
drain and rerun its ENI preflight.

The ordinary rollback checker covers a fully applied forward relocation. If a
failed apply leaves only a subset of the reviewed replacements in state, do
not weaken the checker, hand-edit state, or improvise a targeted apply. Capture
the failed run, live state, and fresh full plan; merge a dedicated exact
observed-state recovery PR, repeat the signed-main/clean-tree source seal for
its new commit, repeat step 3's exact ignored-artifact inventory and checksum
seal, then apply only its newly sealed saved plan after the step 4 checksum
verification. Cell1 remains disabled while that recovery is reviewed.

Merge a reviewed rollback configuration, repeat the signed-main/clean-tree
source seal in step 1 for that exact rollback commit, and change all three
pinned sources together: `terraform.tfvars`'s `vpc_cidr`, the variable default,
and the variable's exact-CIDR validation must each return to
`10.102.0.0/16`. Changing only tfvars cannot plan because the forward
configuration deliberately rejects any CIDR other than `10.104.0.0/16`.
Create a new refresh-enabled Terraform `1.14.3` saved plan from the current
live state, repeat step 3's exact ignored-artifact inventory and checksum seal,
and run:

```bash
python3 .github/scripts/check-sandbox-cell1-cidr-relocation-plan.py \
  "$evidence/cell1-rollback.tfplan.json" \
  --direction rollback
sha256sum "$evidence/cell1-rollback.tfplan" \
  >"$evidence/cell1-rollback.tfplan.sha256"
```

Review it manually, recheck zero capacity/instances/instance ENIs with
`scripts/check-sandbox-cell1-vpc-relocation-preflight.sh "$AWS_PROFILE"
"$AWS_REGION" 10.104.0.0/16 drained`, verify the new rollback plan SHA immediately
before apply, verify the sealed generated-artifact SHA as in step 4, and apply
only that saved plan. Restore the originally captured ASG state and repeat all
health, DNS, identity, and UDP proofs. Reusing the preserved server secret must
restore the same identity. Never delete or regenerate identity resources as a
shortcut, and never recreate the account default VPC.
