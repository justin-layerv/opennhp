# 2026-07-26 · Issue #3284 · Retire Auth0 from Terraform

- **Owner:** prod rollout coordinator
- **Source:** [nhp #3284](https://github.com/layervai/nhp/issues/3284),
  [docs/design/AUTH0_IDENTITY_POLICY.md](../../design/AUTH0_IDENTITY_POLICY.md)

This apply removes ~25 `auth0_*` resources plus 3 credential secret *versions*
from prod state without destroying anything (`removed` + `destroy = false`), and
deletes the Auth0 credential from every CI path. The live tenant is untouched.
Verified by plan against real state: prod forgets 29 objects, sandbox 21, with no
Auth0 object created, changed, or destroyed in either.

- [ ] Pre-rollout: in the prod plan, confirm every `module.auth0.auth0_*` line
      reads "will no longer be managed by Terraform, but will not be destroyed"
      and that **no** Auth0 object is destroyed or replaced. A destroy here
      deletes real clients, the API, or user-bearing connections in the shared
      tenant. Abort on any `must be replaced` / `will be destroyed` under
      `module.auth0`.
- [ ] Pre-rollout: confirm the three `aws_secretsmanager_secret_version` forgets
      (`auth0_backend`, `smoke_test`, `dev_portal_mgmt`) are forgets, not
      destroys. The *containers* stay managed; only Terraform's tracking of the
      values is dropped, and the live secret values are unchanged.
- [ ] Pre-rollout: confirm the client IDs in `terraform.tfvars` match the live
      tenant, so the SSM parameters show no diff. Read them with
      `GET https://layerv.us.auth0.com/api/v2/clients?fields=client_id,name`, or
      confirm the plan shows no change to `aws_ssm_parameter.spa_client_id`.
- [ ] Rollout: apply sandbox, then prod. Order does not matter functionally —
      the two states are independent — but sandbox first keeps the usual blast
      ordering.
- [ ] Post-rollout: `terraform state list | grep auth0_` in **both**
      environments must print nothing.
- [ ] Post-rollout: log in to the prod dashboard with email/password and with
      Google. Forgetting state changes no tenant behaviour, so both must still
      work exactly as before; if either breaks, something was destroyed rather
      than forgotten.
- [ ] Post-rollout: confirm transactional email still sends (password reset).
      The SES email provider config now lives only in the dashboard.
- [ ] **Follow-up PR, only after both states are clean:** delete
      `terraform/modules/auth0/removed.tf`, the `provider "auth0"` stub, and the
      `auth0` entry in `required_providers` in both `environments/*/backend.tf`.
      Terraform needs an explicit provider configuration to decode `auth0_*`
      state entries even for a forget-only plan, so removing them earlier
      strands those entries and breaks the plan.
- [ ] **Follow-up, after the above:** delete the now-unused repository secrets
      `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `PROD_AUTH0_CLIENT_ID`,
      `PROD_AUTH0_CLIENT_SECRET`. Keep `AUTH0_SMOKE_TEST_CLIENT_ID` /
      `AUTH0_SMOKE_TEST_CLIENT_SECRET` — those are smoke-test runtime
      credentials, unrelated to the Terraform provider. Consider also reducing
      the `Terraform` M2M client's 37 Management API scopes in the Auth0
      dashboard, or deleting the client outright; nothing consumes it now.
- [ ] Dashboard (not Terraform — see the identity-policy doc for the full
      runbook): enable `Username-Password-Authentication` on
      `qurl-bot-slack (sandbox)`; disable passwordless `email` on
      `qurl-bot-slack (sandbox)` and `qURL Desktop (Staging)`; enable native
      Account Linking matched on **verified** email only. Do not delete the
      passwordless connection — `email|…` identities own live qURL resources.
- [ ] **Approval-gated, NOT part of this apply:** consolidating the 4 existing
      duplicate identity groups (3 prod, 1 sandbox) catalogued in the
      identity-policy doc. Identity linking and deletion are destructive and
      user-visible. The three prod shadows own nothing and are safe to leave
      alone; the sandbox group would need 18 resources, 8 API keys, and 6 agent
      keys re-pointed.
- [ ] Rollback: re-adding the resource blocks and `terraform import`-ing each
      object by its Auth0 ID. There is no automatic reverse of a forget, so
      **capture the pre-apply state list** (`terraform state list | grep auth0_`)
      and the plan output before applying. Rolling back also means restoring the
      Auth0 credential to CI, which re-opens the PR-time tenant-write exposure
      this change closed — treat that as a security decision, not a routine
      revert.
- [ ] Operational note: rotating `aws_iam_access_key.auth0_ses` now requires
      re-entering the new SMTP credentials in the Auth0 dashboard (Branding >
      Email Provider). Terraform can no longer push that value, so a silent
      rotation breaks transactional email.
- [ ] Cross-repo: qurl-integrations verifies the Slack `/qurl setup <email>`
      flow against the database connection in sandbox once the dashboard
      connection change lands.
