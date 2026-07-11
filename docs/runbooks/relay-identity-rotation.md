# Relay identity rotation

The relay fleet shares one X25519 identity. The private key remains in the
existing Secrets Manager secret; servers receive only public keys through
Terraform. Rotation is a dual-trust rollout, not an in-place secret overwrite.

## Safety rules

- Run the helper with the AWS profile for the target environment and the exact
  region. It validates the caller account, secret, Lambda, environment, and
  version topology before changing anything.
- Never use `get-secret-value`, Terraform variables, shell tracing, logs, or
  command output to move private key material. The identity Lambda returns only
  public keys and version IDs.
- Keep the old private version labeled `AWSPREVIOUS` until the rotation and
  rollback window are complete.
- Treat every labeled identity version as part of the rotation safety boundary.
  `status` validates `AWSPREVIOUS` as strictly as `AWSCURRENT` and
  `AWSPENDING`, so an unreadable or malformed previous version blocks forward
  `promote` as well as `rollback`. This is intentional: repair or investigate
  the identity history before changing stages; do not bypass validation merely
  because promotion does not directly select the previous version.
- Do not promote until every server instance trusts both keys.
- Do not retire old server trust until every relay instance reports the new
  public-key fingerprint.
- Treat the public-only SSM key as a live server launch-template input. Outside
  the canonical current/additional role swap, changing that parameter makes the
  next Terraform apply publish a new server launch-template version; the next
  normal server deployment then rolls that trust change across both ASGs.
  Terraform apply alone does not converge running instances. During promotion,
  the duplicate-key guard must instead fail every unrelated apply until the
  byte-identical role-swap patch is committed and reviewed.
- Block all Terraform applies from promotion until the current/additional role
  swap is committed and its plan is byte-identical for server user data. During
  this intentional fail-closed window, the newly current key is still listed as
  additional trust, so any unrelated apply must fail the duplicate-key guard.
  The required `Terraform Plan (PR)` check also invokes the read-only confirmed
  status path and therefore goes red on every unrelated Terraform-touching PR
  while `AWSCURRENT` and the public parameter diverge. Do not bypass that red
  check. Complete the in-progress `promote` repair, or after verifying topology
  use `sync-current`, then re-run the plan only after the public parameter
  matches `AWSCURRENT`.
- Treat `lambda:InvokeFunction` on the multi-action identity/keygen Lambda as a
  privileged rotation capability. The handler validates the environment and
  parameter path, while its `SecretId` blast radius is enforced by the Lambda
  role's resource-scoped IAM rather than an additional handler equality check.
  Invoke can stage a pending version but cannot promote one; promotion requires
  the operator's separate Secrets Manager stage permission. Keep invoke narrowly
  granted and audit every invocation. The separate `${name_prefix}-relay-status`
  Lambda is not a rotation capability: its distinct handler accepts only
  `confirmed-status`, and its execution role has no relay-identity mutation
  permissions. The sandbox PR-plan role may invoke only that exact status ARN.
- The multi-action identity/keygen Lambda has one reserved concurrency slot and
  serializes every helper action, not only mutations. A concurrent `stage`,
  `sync-current`, or helper `status` can therefore return the helper's
  `identity Lambda invocation failed` throttle error. Terraform uses the
  separate read-only status Lambda, so a PR-plan status read does not consume
  the keygen function's singleton slot. Wait for the in-flight keygen operation,
  re-run helper `status`, and verify topology before retrying; do not treat a
  client-side throttle as an identity fault or evidence that any mutation
  occurred.
- Terraform intentionally does not self-heal a deleted or corrupted public-only
  parameter. The static `publish_public_key` migration invocation does not rerun
  on Lambda code or out-of-band SSM changes; use only the validated
  `sync-current` recovery procedure below.

The former Terraform design read the complete relay secret into state. PR 0
removes that data source, but the versioned state bucket retains historical
snapshots. Continue treating all historical Terraform state as secret-bearing;
this change prevents new state refreshes from rematerializing the private key.

## Inspect and stage

```bash
AWS_PROFILE=layerv scripts/rotate-relay-identity.sh \
  --environment sandbox --region us-east-2 status

token=$(uuidgen | tr '[:upper:]' '[:lower:]')
AWS_PROFILE=layerv scripts/rotate-relay-identity.sh \
  --environment sandbox --region us-east-2 \
  stage --token "$token"
```

Record the returned current and pending version IDs and the pending **public**
key. A retry with the same UUID is idempotent; a different existing pending
version fails closed.

## Establish overlap

1. Add the pending public key to
   `relay_additional_trusted_public_keys_b64` for the environment. Keep the list
   sorted and duplicate-free.
2. Apply Terraform. This publishes a new server launch-template version but
   does **not** replace any running server instance by itself.
3. Roll every server ASG onto that launch-template version using the concrete
   environment deployment mechanism below, and wait for both rolls to finish.
   Do not infer convergence from a successful Terraform apply.
4. Verify both old-identity and pending-identity relay traffic reaches the
   server authorization path. Existing relays continue using the old current
   private key during this step.
5. Re-run `status` immediately before promotion and confirm the exact recorded
   `AWSCURRENT` and `AWSPENDING` IDs are unchanged.

### Roll every server ASG

Sandbox servers use blue/green deployment. One deployment refreshes only the
standby ASG and then makes it active; run the server-only deployment **twice**
with the same already-active image tag to refresh both colors and return traffic
to the original color. The dispatcher polls each workflow to completion:

```bash
export GH_TOKEN="$(gh auth token)"
export GITHUB_REPOSITORY=layervai/nhp

initial_color=$(AWS_PROFILE=layerv AWS_REGION=us-east-2 \
  aws ssm get-parameter \
    --name /sandbox/nhp/server/active-color \
    --query Parameter.Value --output text)

server_tag=$(AWS_PROFILE=layerv AWS_REGION=us-east-2 \
  .github/scripts/resolve-active-image-tag.sh sandbox server)

for pass in 1 2; do
  AWS_PROFILE=layerv AWS_REGION=us-east-2 \
    .github/scripts/dispatch-and-poll-blue-green.sh \
      sandbox server "$server_tag"
done

final_color=$(AWS_PROFILE=layerv AWS_REGION=us-east-2 \
  aws ssm get-parameter \
    --name /sandbox/nhp/server/active-color \
    --query Parameter.Value --output text)
test "$final_color" = "$initial_color"
```

Record both successful workflow URLs. For both the active and standby server
ASGs, require every `InService` instance's launch-template version to equal its
ASG's configured target version, then use SSM Run Command to prove each running
`/opt/layerv/nhp-server/etc/relay.toml` contains exactly the expected public-key
set. Launch time alone is not proof of rendered trust. A single blue/green
dispatch is insufficient because the previous active color remains as the warm
standby. Prod relay remains count-zero in PR 0; before prod relay identity
rotation is enabled, its rollout ledger must name and verify the prod server
deployment mechanism that replaces every server ASG instance.

## Promote and roll the relay fleet

```bash
AWS_PROFILE=layerv scripts/rotate-relay-identity.sh \
  --environment sandbox --region us-east-2 \
  promote \
  --expected-current-id OLD_VERSION_ID \
  --expected-pending-id NEW_VERSION_ID \
  --confirm PROMOTE:NEW_VERSION_ID
```

Promotion moves `AWSCURRENT` with both exact version IDs, publishes the new
public-only SSM parameter, and removes `AWSPENDING`. It is safe to retry: the
helper detects normal, partial-repair, and already-complete topologies.

**Terraform apply freeze starts at promotion and ends only after step 1 below
is committed and its no-server-diff plan is reviewed.** Coordinate the freeze
before invoking promotion; reserve the deploy lock and prepare the exact
old-key role-swap patch plus reviewers in advance so promotion and that patch's
merge/apply are one coordinated window. Do not bypass the duplicate-key
precondition and do not permit unrelated applies in the window.

Then:

1. Move the old public key into
   `relay_additional_trusted_public_keys_b64`. Because root canonically sorts
   the current and additional keys, this role swap must create no server user
   data or launch-template diff.
2. Refresh the relay fleet through `deploy-relay.sh` and verify every running
   relay instance reports the new public-key fingerprint.
3. Remove the old additional public key, apply, and use the same complete
   server-ASG roll procedure above. Do not treat the launch-template update as
   instance convergence.
4. Prove old-key traffic is rejected and new-key traffic remains accepted.

The CI helper resolves the single canonical ASG parameter and polls its instance
refresh to completion. The sandbox job's 20-minute timeout includes the
approximately 15-minute refresh ceiling plus AWS API overhead.

## Rollback

Before old trust is retired, keep both keys trusted and use the guarded rollback
operation to move `AWSCURRENT` back to the exact recorded `AWSPREVIOUS` version
and sync the public-only SSM parameter:

`AWSPREVIOUS` must pass the same canonical encoding, environment, and derived
X25519 keypair validation as `AWSCURRENT`. This is intentionally strict: an
unvalidatable previous private version is not a degraded rollback candidate; it
is an identity incident that must block rollback rather than strand relays on
unproven key material.

```bash
AWS_PROFILE=layerv scripts/rotate-relay-identity.sh \
  --environment sandbox --region us-east-2 \
  rollback \
  --expected-current-id NEW_VERSION_ID \
  --expected-previous-id OLD_VERSION_ID \
  --confirm ROLLBACK:OLD_VERSION_ID
```

Swap current/additional roles without a server rollout and refresh the relay
fleet back to the old identity. Remove the unused new public key only after
verification. The rollback operation is safe to retry after a partial stage
move; `sync-current` is also available to validate and republish the actual
current public key without changing version stages.

After old trust is retired, first re-add the old public key and use the complete
server-ASG roll procedure above. Prove dual trust before moving `AWSCURRENT`
back. Then sync the public parameter, refresh relays, verify the old identity,
and only then remove the new public key.

If the exact version IDs or topology do not match the recorded state, stop. Do
not relabel a best-guess version and do not overwrite the secret.

## Recover the public-only parameter

Terraform deliberately ignores rotation-managed value changes and the
`publish_public_key` invocation does not rerun for Lambda code or out-of-band
SSM drift. If the public-only parameter is deleted or corrupted, Terraform must
fail closed rather than automatically mint or guess identity material.

1. Run `status` and verify the recorded `AWSCURRENT` version ID and public-key
   fingerprint against the last known-good rotation evidence.
2. Run `sync-current`. It invokes the non-generating `publish-current` action,
   recreating or overwriting only the public parameter from the validated
   existing `AWSCURRENT` keypair.
3. Re-run `status`, read the public SSM parameter, and confirm the public keys
   match. Then run a saved Terraform plan and require no relay trust or server
   `user_data` diff before resuming deploys.

If `AWSCURRENT` is absent or invalid, `sync-current` fails. Treat that as an
identity incident; do not run `ensure-current` or create a replacement key.
