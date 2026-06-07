# Terraform state bucket KMS migration (SSE-S3 → SSE-KMS)

Resolves [#1128](https://github.com/layervai/nhp/issues/1128). Migrates the
Terraform remote-state buckets from `AES256` (SSE-S3) to `aws:kms` (SSE-KMS)
so that every state decrypt is logged in CloudTrail with the caller identity
and the encryption key is rotatable.

| Env | Bucket | Account | Region | State key |
|-----|--------|---------|--------|-----------|
| sandbox | `layerv-terraform-state-767397897469` | 767397897469 (`AWS_PROFILE=layerv`) | us-east-2 | `nhp/sandbox/terraform.tfstate` |
| prod | `layerv-terraform-state-235500187906` | 235500187906 (`AWS_PROFILE=layerv-prod`) | us-east-2 | `nhp/prod/terraform.tfstate` |

## Why this is an out-of-band / operator procedure, not a Terraform/CI change

The state buckets are **bootstrap-layer infrastructure**: they were created
out-of-band before the env stacks and are **not managed by any Terraform in
this repo** (a state bucket cannot live in the state it stores). The env
stacks only reference them by name in `environments/<env>/backend.tf`, and the
CI Terraform role (`nhp-<env>-github-actions`) is deliberately granted
**object-level access only** to them — it cannot change their encryption
config:

- The CI role's `terraform-state` policy grants `s3:GetObject/PutObject/
  DeleteObject/ListBucket` on the bucket — **no** `s3:PutEncryptionConfiguration`
  (`terraform/modules/ecr/main.tf`, `S3StateAccess`).
- The CI role's bucket-management statements that *do* carry
  `s3:PutEncryptionConfiguration` are scoped to `layerv-nhp-*`,
  `traefik-plugins-*`, `bootstrap-alb-*`, `layerv-nhp-*-qurl-link` — the
  `layerv-terraform-state-*` bucket is intentionally excluded.
- The CI role's KMS admin statement has `kms:CreateKey` / `CreateAlias` /
  `PutKeyPolicy` but **not** `kms:EnableKeyRotation`.

Keeping CI's authority over the crown-jewels bucket minimal is the correct
posture. So the CMK and the bucket default change are done by an **account
admin out-of-band** (Phase A/B), and the **only** code change is the backend
`kms_key_id` cutover (Phase C), which runs on the CI role's *existing*
permissions.

## Lockout risk — why a same-account CMK is safe

Switching a Terraform state bucket to SSE-KMS is high-blast-radius: get it
wrong and principals that read/write state can no longer decrypt it, freezing
all IaC. This migration is safe because:

- **IAM delegation stays enabled.** The CMK uses the standard root-delegation
  key policy (`arn:aws:iam::<acct>:root` → `kms:*`), so principals' IAM
  policies govern key access (KMS requires this statement or IAM grants have
  no effect).
- **CI already has the KMS perms.** The CI role holds same-account
  `kms:GenerateDataKey*` + `kms:Decrypt` (`modules/ecr` `KMSForEncryption` /
  `KMSDecryptInAccount`, conditioned on `aws:ResourceAccount = <acct>`). With
  a same-account CMK + root delegation, **no new IAM grant is required** for CI
  to read/write KMS-encrypted state. Verified by IAM policy simulation for
  **both** CI roles (`nhp-sandbox-github-actions`, `nhp-prod-github-actions`):
  `s3:PutObject`/`s3:GetObject` on the state object + `kms:Decrypt`/
  `kms:GenerateDataKey` return `allowed` on a same-account key ARN with the
  matching `aws:ResourceAccount`. (Prod verification is the explicit gate in
  Phase C step 0.)
- **Operators are account admins** → covered by root delegation. Verified:
  the sandbox operator IAM user has `AdministratorAccess`; the prod operator
  path is `OrganizationAccountAccessRole`.
- **No bucket policy exists** on the state buckets (IAM-only access) → no Deny
  statement to trip.
- **Proven end-to-end in sandbox.** With the sandbox CMK in place, the operator
  wrote and read back a scratch object on the real `layerv-terraform-state-
  767397897469` bucket under `--server-side-encryption aws:kms --ssekms-key-id
  alias/terraform-state` — `head-object` reported `aws:kms` + the CMK ARN and
  `get-object` decrypted cleanly (scratch object then deleted). This confirms
  the bucket accepts SSE-KMS with the CMK and that decrypt works in-account.

Re-verify the CI role before the prod cutover — the full state-write path, not
just the KMS half (substitute the prod role/account; IAM simulation evaluates
the identity policy, not the key policy, so a hypothetical key ARN is fine):

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<acct>:role/nhp-<env>-github-actions \
  --action-names kms:Decrypt kms:GenerateDataKey s3:PutObject s3:GetObject \
  --resource-arns \
    "arn:aws:kms:us-east-2:<acct>:key/00000000-0000-0000-0000-000000000000" \
    "arn:aws:s3:::layerv-terraform-state-<acct>/nhp/<env>/terraform.tfstate" \
  --context-entries ContextKeyName=aws:ResourceAccount,ContextKeyValues=<acct>,ContextKeyType=string \
  --query 'EvaluationResults[].{Action:EvalActionName,Resource:EvalResourceName,Decision:EvalDecision}' \
  --profile <env-profile> --output table
```

Each action is evaluated against each resource, so expect `allowed` for the
`kms:*` actions on the key ARN and the `s3:*` actions on the bucket ARN; the
cross pairs (e.g. `s3:PutObject` on the key ARN) show `implicitDeny`, which is
expected. The gate passes when the four matched pairs are all `allowed`.

Residual risk: any *scoped* role that reads state but lacks same-account KMS
perms would break. None identified (the drift/reconciliation roles do not read
TF state). IAM simulation covers the identity-policy half only; **sandbox is
migrated and validated first** (Phase A→D), which empirically surfaces any
missed principal — including key-policy or SCP effects simulation can't see —
before prod.

## The `encrypt = true` gotcha (read before you start)

The S3 backend with `encrypt = true` and **no** `kms_key_id` sends
`x-amz-server-side-encryption: AES256` on every `PutObject`, which **overrides
the bucket default**. So changing only the bucket *default* encryption leaves
the state objects AES256. **The state objects become KMS-encrypted only after
`kms_key_id` is added to the `backend "s3"` block (Phase C).** The two phases
clear two different things and **both are required to close #1128**: Phase C
(backend `kms_key_id`) encrypts the state *objects* — the per-decrypt audit
trail — while Phase B (bucket *default* → `aws:kms`) is what flips the
`s3-default-encryption-kms` Config rule (it checks the bucket default, not
objects). Phase C alone leaves that Config finding red.

---

## Phase A — Create the CMK (per account, admin, out-of-band)

Run once per account. Set the two variables for the target env, then run the
block verbatim.

> **Sandbox (`767397897469`) Phase A is already complete** — the CMK
> `alias/terraform-state` (key `289dbe35-ab5a-4752-8564-4c96c607c9f4`) exists
> with annual rotation enabled. Skip this section for sandbox; run it for prod
> (`235500187906`).

```bash
# prod: PROFILE=layerv-prod  ACCT=235500187906   (sandbox is done — see above)
PROFILE=layerv-prod
ACCT=235500187906
REGION=us-east-2

# 1. Write the root-delegation key policy to a file. Use file:// — an inline
#    --policy "{...}" with shell-escaped quotes mangles the principal ARN
#    (CreateKey then fails with MalformedPolicyDocumentException).
cat > /tmp/tfstate-key-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRootAccount",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::${ACCT}:root" },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
EOF

# 2. Create the CMK with the root-delegation policy (enables IAM delegation).
#    Root delegation satisfies KMS's policy-lockout safety check, so no
#    --bypass-policy-lockout-safety-check is needed (and must not be added).
KEY_ID=$(aws kms create-key \
  --region "$REGION" --profile "$PROFILE" \
  --description "Terraform state bucket encryption (layerv-terraform-state-$ACCT)" \
  --tags TagKey=Name,TagValue=terraform-state TagKey=ManagedBy,TagValue=runbook-tfstate-kms-migration \
  --policy file:///tmp/tfstate-key-policy.json \
  --query KeyMetadata.KeyId --output text)
echo "Created key: $KEY_ID"

# 3. Enable annual key rotation.
aws kms enable-key-rotation --key-id "$KEY_ID" --region "$REGION" --profile "$PROFILE"

# 4. Create a stable alias — Phase C's backend block references this alias.
#    KMS aliases are regional + per-account: this MUST be created in us-east-2
#    (the backend's region) in each account, or the Phase C `init` can't
#    resolve it.
aws kms create-alias \
  --alias-name alias/terraform-state \
  --target-key-id "$KEY_ID" \
  --region "$REGION" --profile "$PROFILE"
```

Validate (`get-key-rotation-status` rejects an alias — resolve the key id
first):

```bash
aws kms describe-key --key-id alias/terraform-state \
  --region "$REGION" --profile "$PROFILE" \
  --query 'KeyMetadata.{State:KeyState,Mgr:KeyManager,Arn:Arn}'

KEY_ID=$(aws kms describe-key --key-id alias/terraform-state \
  --region "$REGION" --profile "$PROFILE" --query KeyMetadata.KeyId --output text)
aws kms get-key-rotation-status --key-id "$KEY_ID" \
  --region "$REGION" --profile "$PROFILE"
```

Expect `State = Enabled`, `Mgr = CUSTOMER`, `KeyRotationEnabled = true`.

> **Do not schedule this key for deletion** while any state object/version is
> encrypted with it — that makes state unreadable after the deletion window.
> See Rollback below.

## Phase B — Bucket default encryption (required to clear the Config finding)

Sets the bucket-level default to `aws:kms`. **This — not Phase C — is what
clears the `s3-default-encryption-kms` AWS Config rule** (the live finding
SECURITY.md cites), because that rule evaluates the bucket's *default encryption
configuration*, not individual objects. Phase C encrypts the state *objects*
(the audit-trail goal); Phase B flips the bucket default. **Both are required to
fully close #1128** — Phase C alone leaves the Config rule red. (It's still
listed after Phase C here only because it's an independent operator step; run
order between B and C doesn't matter, both just need Phase A's CMK.)

It sets the default so *future* objects written without an explicit SSE header
use the CMK. It does **not** re-encrypt existing objects and does **not** by
itself change TF *state*-object encryption (see the `encrypt = true` gotcha).
Blast radius is minimal: `deploy_etcd = false` in both envs, so the
lambda-layer-on-state-bucket path (`modules/data/main.tf`) is inactive, and
existing AES256/SSE-S3 objects need no KMS to read. (Forward-looking:
`modules/data/main.tf` defaults `lambda_layer_bucket` to the **sandbox** state
bucket; if prod ever sets `deploy_etcd = true` without overriding it, prod would
read the crypto layer cross-account from sandbox and need sandbox-side KMS
decrypt — revisit this bucket-default change then.) (If `put-bucket-encryption`
rejects the bare alias in `KMSMasterKeyID`, use the key ARN or alias ARN
instead — S3 default-encryption alias support has historically been finicky.)

```bash
# Set these for the target env first (Phase A exports them, but sandbox skips
# Phase A, so re-set them here):
#   sandbox: PROFILE=layerv       ACCT=767397897469  REGION=us-east-2
#   prod:    PROFILE=layerv-prod  ACCT=235500187906  REGION=us-east-2

# Use file:// (heredoc) rather than inline escaped JSON — same foot-gun class
# as Phase A's key policy.
cat > /tmp/tfstate-bucket-sse.json <<'JSON'
{
  "Rules": [
    {
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "alias/terraform-state"
      },
      "BucketKeyEnabled": false
    }
  ]
}
JSON
aws s3api put-bucket-encryption \
  --bucket "layerv-terraform-state-$ACCT" \
  --region "$REGION" --profile "$PROFILE" \
  --server-side-encryption-configuration file:///tmp/tfstate-bucket-sse.json
```

> **`BucketKeyEnabled` is deliberately `false`.** S3 Bucket Keys cache a
> bucket-level data key and suppress most per-object KMS calls — which would
> also suppress the per-decrypt CloudTrail events with caller identity that are
> the entire point of #1128. Keeping it off preserves full decrypt-audit
> granularity. The state bucket is low-volume, so the extra KMS request cost is
> negligible. (The Phase C backend writes also do not enable a bucket key.)

## Phase C — Backend cutover (code change, separate PR, after Phase A in BOTH accounts)

This is the load-bearing change that makes the **state objects** KMS-encrypted.
Land it as its own PR **after** the CMK + alias exist in both accounts — the
backend uses `kms_key_id` at state read/write (`PutObject`) time, not at `init`
(init doesn't validate the alias against KMS), so the alias must exist before
any apply runs in that account.

0. **Gate — verify the CI role can use the CMK in each account before that
   account's cutover.** Per "Lockout risk", a same-account CMK needs no new IAM
   grant — but confirm rather than assume: a missing grant surfaces as
   `KMSAccessDeniedException` on the *first apply's state write*,
   mid-`promote-to-prod`. Run the full `simulate-principal-policy` command in
   "Lockout risk" above for `nhp-<env>-github-actions`; the four matched
   action/resource pairs must all return `allowed`. (KMS is the only *new*
   dependency — the role already uses `s3:PutObject`/`GetObject` on this bucket
   daily — but the gate checks the whole write path.) The identity-policy half
   was simulated for both roles as of this PR against a *hypothetical* key ARN;
   still **re-run this against the real CMK once prod Phase A creates it** —
   that's the load-bearing check (it's the prod pre-rollout box in the ledger
   entry).
1. Add `kms_key_id = "alias/terraform-state"` to the `backend "s3"` block in
   **both** `terraform/environments/sandbox/backend.tf` and
   `terraform/environments/prod/backend.tf`. The S3 backend accepts a bare
   alias name here (also key id / key ARN / alias ARN); sandbox Phase D
   confirms it resolved to the CMK before prod. If a future provider version
   tightens `kms_key_id` validation and rejects the bare alias, switch the
   value to the alias ARN or key ARN (per-account).
2. Add `-reconfigure` to the env-stack `terraform init` calls in the workflows.
   **Find them with `grep -n 'terraform init' .github/workflows/build-and-push.yml
   .github/workflows/promote-to-prod.yml` rather than trusting line numbers —
   these large workflows shift constantly.** Change only the bare
   `terraform init` calls (sandbox plan + apply in `build-and-push.yml`; prod
   plan + apply in `promote-to-prod.yml`, four total). **Leave the lint-only
   `terraform init -backend=false` in `build-and-push.yml` unchanged** — it
   never touches backend config. Why `-reconfigure`: it is strictly required
   for a **local operator** with a stale `.terraform/` (a plain `init` there
   fails with *"Backend configuration changed"*); CI checks out fresh and
   caches only the plugin dir, so a plain `init` would also succeed there, but
   `-reconfigure` is harmless/idempotent and keeps the two paths consistent.
   State does **not** move, so `-reconfigure`, **not** `-migrate-state`.
3. Local operators run `terraform -chdir=terraform/environments/<env> init -reconfigure`
   once after pulling.

**Sequencing.** The sandbox apply is the un-gated side — merging the cutover PR
triggers `build-and-push` to apply sandbox automatically, whereas prod is a
manual `promote-to-prod` trigger. Safest order: finish **prod** Phase A → merge
the cutover PR → sandbox applies and is validated (Phase D) → trigger prod.
Doing prod Phase A before merge keeps the prod `backend.tf` alias reference
resolvable even though prod won't apply until triggered (per the step-0 gate).
The prod alias is only resolved at prod **apply** time (`promote-to-prod` is
manual-dispatch — there's no PR-time prod `init`/plan), so the draft cutover PR
can exist before prod Phase A; just ensure prod Phase A precedes the prod apply,
not merely the PR.

## Phase D — Validation (per env, after the first apply that writes state post-cutover)

```bash
# Set PROFILE / ACCT / REGION for the target env first (Phase A exports them,
# but you may jump straight here to validate):
#   sandbox: PROFILE=layerv       ACCT=767397897469  REGION=us-east-2  STATE_KEY=nhp/sandbox/terraform.tfstate
#   prod:    PROFILE=layerv-prod  ACCT=235500187906  REGION=us-east-2  STATE_KEY=nhp/prod/terraform.tfstate
STATE_KEY=nhp/sandbox/terraform.tfstate

aws s3api head-object \
  --bucket "layerv-terraform-state-$ACCT" \
  --key "$STATE_KEY" \
  --region "$REGION" --profile "$PROFILE" \
  --query '{SSE:ServerSideEncryption, Key:SSEKMSKeyId}'
```

Expect `SSE = aws:kms` and **`Key` = the intended CMK ARN** (check the ARN, not
merely that `SSE` is `aws:kms` — a wrong-region/wrong-account alias would either
fail the write or resolve elsewhere). Before cutover this reports `AES256` with
no key.

> **Inspect the state object, not the lock.** `kms_key_id` only changes
> encryption on the next `PutObject`. The S3-native lock object
> (`nhp/<env>/terraform.tfstate.tflock`, `use_lockfile = true`) is written on
> every run by the same backend/key/principals, so it flips to `aws:kms`
> immediately — but `terraform.tfstate` is rewritten only when Terraform
> persists *new* state. So a true no-op apply (empty plan) flips the lock while
> leaving the state object SSE-S3, and a Phase D check that inspected the lock
> would look green falsely. Always check `$STATE_KEY` above. If it still reports
> `AES256` after cutover because applies have been no-ops, force a
> state-mutating apply — anything that persists new state. (A clean
> `-refresh-only` or empty-plan run writes nothing, so it won't flip the state
> object; only a run that detects drift / applies a change does.)

**Confirm the decrypt audit trail (#1128's actual goal).** After a state read
(any plan/apply, or `aws s3api get-object` on the state key), confirm a
`Decrypt` event referencing the CMK appears in CloudTrail. KMS records
`Decrypt`/`GenerateDataKey` as **management** events, so no CloudTrail
data-event logging needs to be configured for this to work — `lookup-events`
finds them directly:

```bash
KEY_ARN=$(aws kms describe-key --key-id alias/terraform-state \
  --region "$REGION" --profile "$PROFILE" --query KeyMetadata.Arn --output text)
# Scope to a tight window AFTER your state read. lookup-events returns the most
# recent Decrypt events account-wide and only then filters by key ARN, so in a
# busy account an unscoped --max-results window can scroll past yours and look
# empty. (GNU date shown; on macOS the `|| date -v` fallback applies.)
SINCE=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-15M +%Y-%m-%dT%H:%M:%SZ)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \
  --start-time "$SINCE" \
  --region "$REGION" --profile "$PROFILE" --max-results 50 \
  --query "Events[?contains(Resources[].ResourceName, '$KEY_ARN')].{Time:EventTime,User:Username}" \
  --output table
```

Expect at least one recent `Decrypt` row referencing the CMK after the read.
`Username` is often blank for an assumed-role (CI) caller — the identity lives
in the event's `userIdentity` — so confirm via the resource match rather than
the `User` column. CloudTrail KMS management events can lag a few minutes; if
the table is empty, widen the `--start-time` window before concluding the audit
trail is missing (`--max-results 50` is already the AWS CLI cap, so it can't go
higher — page with `--next-token` if needed).

> Only objects written **after** cutover are KMS-encrypted. Older state
> versions stay AES256 forever (bucket versioning is on). This is acceptable —
> the finding is forward-looking; the live state object is what matters.

## Rollback

- **Phase C:** revert the backend.tf + workflow PR and run `init -reconfigure`.
  The next state write reverts to the explicit-AES256 path. No data migration.
- **Phase B:** `aws s3api put-bucket-encryption ... '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'`.
- **Phase A:** leave the CMK in place. Disabling or scheduling deletion of the
  key while any state object/version is encrypted with it bricks state. Only
  schedule deletion after confirming **no** state object or version is
  encrypted with the CMK.

## Lockout recovery

If a principal cannot read state after cutover (`AccessDenied` / KMS error),
grant it `kms:Decrypt` + `kms:GenerateDataKey` (via its IAM policy for a
same-account key, or via the key policy). Because the CMK uses root delegation,
an account admin can always recover access.

## Related cleanup

`terraform/bootstrap/main.tf` is an **orphaned** module: it declares a bucket
named `layerv-terraform-state` (no account suffix) that does not exist and is
not the live state bucket. It is not the source of truth for the buckets above
and applying it would create the wrong resources. It also still hardcodes
`sse_algorithm = "AES256"` — so whoever reconciles the module (rather than
deleting it) should switch that to `aws:kms` with this CMK, so the dead module
doesn't re-enshrine the #1128 finding. Reconciling or removing it is tracked in
[#2359](https://github.com/layervai/nhp/issues/2359); this runbook is the
source of truth for state-bucket encryption.

## Disposition

**Keep this runbook after cutover** — the lockout analysis and the AES256-override
/ `.tflock` / `BucketKeyEnabled` gotchas are reusable for any future SSE-S3→KMS
work. On #1128 close, the *transient* artifacts are removed: the ledger entry
(`prod-rollout-ledger/2026-06-06-pr-2342-…`) is deleted when its tasks complete,
and the `docs/SECURITY.md` exception bullet is removed (per its marker). The
durable invariants already live in `terraform/CLAUDE.md`.
