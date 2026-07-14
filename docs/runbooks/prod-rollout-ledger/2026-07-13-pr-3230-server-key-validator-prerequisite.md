# 2026-07-13 · PR #3230 · Server-key validator prerequisite

- **Owner:** prod rollout coordinator
- **Source:** [#3230](https://github.com/layervai/nhp/pull/3230), [cell-assignment PR #3229](https://github.com/layervai/nhp/pull/3229), [tracking issue #3227](https://github.com/layervai/nhp/issues/3227)

Deploy the read-only server-identity validator before #3229 makes Terraform
consume it at plan time. This prerequisite deliberately keeps the current
Secrets Manager data source and plan-known output until the validator exists in
both environments.

- [ ] Pre-rollout: keep #3229 draft and blocked. Restack this PR onto the targeted AC readiness graph fix merged by [#3234](https://github.com/layervai/nhp/pull/3234) at `9f901b747d5971304df71ab018e716af4b846155` (issue #3232), and review a sandbox plan for that exact commit. The plan may update the shared keygen artifact/handler and create the validator role, encrypted log group, function, IAM propagation wait, and exact plan-role invoke grant, but it must not replace `aws_lambda_invocation.keygen`, invoke Seed, rotate the server secret, make relay/server launch-template values unknown, or replace/destroy any Route53 record. Abort if either AC apex/wildcard record has a replace/destroy action or if the merged #3234 graph is absent.
- [ ] Sandbox rollout: apply this exact commit, then invoke only `${name_prefix}-key-validator:$LATEST` with the expected server secret id, hostname, and `Environment=sandbox`. Record the commit, apply run, validator function configuration, encrypted log-group KMS ARN, exact execution-role actions, response shape (`PhysicalResourceId` and `PublicKey` only), and a one-way digest of the public key; never record `SecretString` or private-key material.
- [ ] Sandbox no-write proof: record the server secret's `AWSCURRENT` version id and creation timestamp before and after the validator invocation and confirm they are unchanged. Confirm the invocation read `AWSCURRENT`, the keygen invocation was not replaced, and a second plan is no-op for these resources.
- [ ] Prod rollout: after sandbox proof passes, apply the same exact commit in prod and repeat the validate-only `$LATEST`, encrypted-log, exact-role, response-shape, public-digest, unchanged-`AWSCURRENT`, no-Seed, and second-plan checks with `Environment=prod`.
- [ ] Handoff and cleanup: add durable sandbox and prod evidence links to this PR or #3227, update #3229's body and rollout ledger to link that exact proof, then delete this ledger entry only after both environments are on the recorded commit and #3229 can plan against the already-existing validator.
- [ ] Rollback: before #3229 deploys, revert this PR and apply normally; the validator is read-only and safe to leave during rollback. After #3229 deploys, roll back its validator consumer first. In either order, confirm rollback does not replace `aws_lambda_invocation.keygen` or change the server secret's `AWSCURRENT` version.

If a future taint or replacement of `aws_lambda_invocation.keygen` fails because
Seed detects malformed key material, a keypair mismatch, or hostname/environment
drift, investigate and explicitly migrate the existing secret. Seed is
intentionally fail-closed and must never self-heal or rotate that identity.
Before changing `domain_name` or `environment`, or tainting the keygen invocation,
rerun Validate against the current `AWSCURRENT` value and resolve any metadata
drift explicitly.
The pre-existing keygen log groups require an explicit import/adoption rollout
before Terraform can encrypt and manage them; that separate work is tracked in
[#3231](https://github.com/layervai/nhp/issues/3231) to avoid an existing-resource
collision in this prerequisite.
