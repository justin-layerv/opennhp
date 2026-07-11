# 2026-06-11 · PR #2464 · Terraform plan PR gate

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2464, https://github.com/layervai/nhp/issues/2463

This PR adds a non-mutating sandbox Terraform plan identity and a new PR check.
The check should only become a required merge gate after the role exists, the
secret is configured, and the first run proves the sandbox tfstate is clean
enough to produce useful PR feedback. "Non-mutating" does not mean
low-sensitivity: the role can read sandbox state, SSM SecureStrings, Secrets
Manager values, and KMS-decrypted material. Prod-only Terraform PRs are
reported as skipped so unrelated sandbox state does not block prod-only changes.

- [x] Pre-rollout: confirm the latest sandbox apply has converged successfully
      after the failures linked from issue #2463. _Done/current 2026-06-18:
      Build and Deploy NHP run
      [27734080658](https://github.com/layervai/nhp/actions/runs/27734080658)
      succeeded, including sandbox infrastructure apply, deploy validate, and
      NHP smoke._
- [ ] Pre-rollout: get security-owner sign-off that same-repo PR authors are
      inside the accepted trust boundary for long-lived Auth0 Terraform client
      credentials, short-lived Auth0 API tokens, PR-head Terraform HCL execution
      with the short-lived token and sandbox read role, full sandbox Terraform
      state reads, SSM SecureString reads, Secrets Manager reads, KMS decrypts,
      account-wide IAM, CloudTrail, GuardDuty, Security Hub, Config, and S3
      metadata/list enumeration used by Terraform
      refresh, and the sandbox plan role. The plan role uses a dedicated read policy separate
      from normal CI `terraform_read`; SSM value reads are scoped to NHP
      environment paths, the shared registration public-key path, and the public
      Canonical AMI path, EC2 `Get*` is an explicit refresh allowlist that
      excludes console output, console screenshots, launch-template data, and
      password data, S3 object-content reads are scoped to Terraform state plus
      NHP-managed/plugin bucket
      patterns, and those bucket-prefix patterns intentionally cover every
      current or future matching bucket in the sandbox account via the
      `aws:ResourceAccount` gate. DynamoDB reads are
      limited to table metadata (`Describe*`/`List*`) with no item-data reads,
      Secrets Manager reads are limited to `Describe*`/`Get*` on NHP secrets
      with no account-wide `ListSecrets`. KMS decrypt is constrained to
      `alias/terraform-state` plus the NHP KMS aliases via
      `kms:ResourceAliases`. The sole non-read-verb exception is
      `lambda:InvokeFunction` on the exact `${name_prefix}-relay-status`
      function. Its distinct handler accepts only `confirmed-status`; its
      execution role can read the exact relay secret and public parameter and
      write only its own scoped CloudWatch log stream. It cannot invoke the
      multi-action identity/keygen handler or mutate relay identity state.
      Sign-off must explicitly accept both this semantic-read invocation and
      its bounded log side effect. Each Terraform-touching PR plan therefore
      decrypts the full relay private key inside the scoped status Lambda long
      enough to derive and validate its public half; the response and Terraform
      state contain only version IDs and public keys, with code-only errors and
      redaction tests guarding the boundary. Sign-off must accept that cadence
      and must also accept that an `AWSCURRENT`/public-parameter divergence
      intentionally blocks every unrelated Terraform PR until `promote` repair
      or `sync-current` restores equality. KMS metadata reads intentionally
      use `StringEqualsIfExists` because some KMS list APIs do not carry
      `aws:ResourceAccount`; sign-off must explicitly accept that metadata/list
      exposure can be broader than a strict sandbox-account-only boundary. Only
      decrypt uses the strict account check plus alias allowlist.
      Treat the read-only policy linter as a scoped-Sid tripwire: before adding
      any new value-bearing read Sid, extend the exact resource/condition
      assertions in `.github/scripts/check-terraform-plan-pr-policy-readonly.py`.
      That lint must also keep the relay-status Invoke Sid, action, exact ARN,
      and duplicate-Sid rejection pinned.
      The workflow fetches the Auth0 token using a base-commit copy of sandbox
      `terraform.tfvars` so PR-head `auth0_domain` edits cannot redirect the
      long-lived client secret to another host, but the actual plan still
      evaluates PR-head tfvars and HCL. AWS cannot scope the trust to this
      workflow, so sign-off must accept that any same-repo `pull_request`
      workflow with the role ARN can assume the sandbox read role; push access
      to `layervai/nhp` is inside this sandbox-secret-read boundary.
      Treat base-restored helper paths as a review guard for helper changes,
      not as a hard control against same-repo PR authors who can edit the
      workflow YAML itself.
      Explicitly include plan-time exfil paths such as `data.http`, the
      `external` provider, and provider endpoint overrides in the sign-off.
      Confirm the Auth0 Terraform client grant is read-only; if it is
      write-capable, pause enabling the gate and replace it with an
      environment-approval, trusted-author, or narrower-policy design. Treat
      this Auth0 grant check as the highest-priority required-check enablement
      item because PR-head HCL runs with the short-lived Auth0 token. If a
      tighter OIDC trust boundary is needed, prefer a GitHub Environment because
      AWS can match its environment-scoped `sub`. Also confirm reviewers
      understand that both workflow jobs run on every PR to preserve
      required-check semantics, that prod-only Terraform PRs skip the sandbox
      plan, and that detailed redacted failure excerpts are kept out of the PR
      comment but remain available in the private workflow run summary and
      7-day artifact.
      Before making the check required, confirm the external-contributor path is
      acceptable: forked Terraform PRs cannot read the secret-backed sandbox
      role, get a hard-red required check, and must be re-pushed by a maintainer
      inside `layervai/nhp`.
- [ ] Rollout: configure the repository secret
      `AWS_TERRAFORM_PLAN_PR_ROLE_ARN` from the sandbox Terraform output
      `github_actions_terraform_plan_pr_role_arn`.
- [ ] Rollout: add `Terraform Plan (PR)` (not `Comment Terraform Plan (PR)`)
      to the required PR status checks once the workflow has reported at least
      one successful Terraform-touching run that exercises the scoped sandbox
      SSM, Secrets Manager, S3, and KMS reads plus the exact read-only relay
      status invocation behind the plan role, not just a skip/no-op path.
- [ ] Post-rollout: verify a Terraform-touching PR receives the structured plan
      comment and a passing `Terraform Plan (PR)` check.
- [ ] Rollback: remove the required check and repository secret, then revert PR
      #2464 if the plan gate blocks unrelated PR flow or reports unusable
      sandbox drift.
