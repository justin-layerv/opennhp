# ==============================================================================
# Auth0 tenant retirement from Terraform (#3284)
# ==============================================================================
# Every `auth0_*` resource this module used to manage now leaves Terraform state
# WITHOUT being destroyed (`lifecycle { destroy = false }` — a declarative
# `terraform state rm`). The live tenant is untouched: clients keep their IDs and
# secrets, the API keeps its identifier and scopes, the Action keeps running.
# Terraform simply stops tracking them, and the Auth0 dashboard becomes the sole
# owner of tenant configuration.
#
# Why retire rather than deepen IaC:
#
#   1. **It removes a tenant-write credential from PR-time code execution.**
#      `terraform-plan-pr.yml` fetched a short-lived Management API token and
#      exposed it to PR-head HCL, which executes on any same-repo pull request.
#      That token belongs to an M2M client holding 37 scopes — audited
#      2026-07-26 — including `create:connections`, `update:connections`,
#      `create`/`update`/`delete:clients`, `update:branding`, `create:actions`,
#      and `read:client_keys` (every client secret in the tenant, prod
#      included). `terraform/CLAUDE.md` required that grant to be read-only or
#      explicitly accepted; it was neither. Retiring the provider deletes the
#      exposure instead of documenting an acceptance for it.
#
#   2. **Terraform could never own the tenant completely anyway.** Writing a
#      connection's `options` needs the Management API
#      `update:connections_options` scope the CI M2M does not hold. The attempt
#      in #2305 left read-after-create drift that failed EVERY subsequent
#      apply — including changes with nothing to do with Auth0 — until #2309
#      and then a full un-management. Partial ownership of a shared tenant was
#      a standing outage risk on unrelated work.
#
#   3. **The provider cannot read back what it writes.** Without
#      `read:client_keys` the provider returns an empty `client_secret`, which
#      is why every credential secret in this module already carries
#      `ignore_changes = [secret_string]` and an operator `put-secret-value`
#      step. Those values were operator-owned in practice long before this
#      change.
#
# What is still Terraform's: the AWS-side plumbing in `main.tf` — Secrets
# Manager secrets, SSM parameters, the SES IAM user, and the (currently
# disabled) rotation Lambda. Those are AWS resources. They now take Auth0
# client IDs from variables instead of from `auth0_*` attributes. Client IDs are
# public identifiers, not secrets.
#
# ── Apply sequencing ──────────────────────────────────────────────────────────
# The `provider "auth0"` block in `environments/*/backend.tf` is deliberately
# still present, reduced to a stub with a placeholder token. Terraform requires
# an explicit provider configuration to decode state entries even for a
# forget-only plan (verified: without it, `Error: Invalid provider
# configuration`), but it makes NO API calls to forget, so the stub needs no
# real credentials — which is why the CI token fetch is deleted in this same
# change rather than a later one.
#
# Once BOTH environments have applied and neither state contains an `auth0_*`
# entry, a follow-up removes this file, the stub provider block, and the
# `required_providers` entry. That follow-up is tracked in the rollout-ledger
# entry for this change. Deleting them before both states are clean strands the
# entries and breaks the plan.

# ── Credential secret VERSIONS (AWS, but Auth0-valued) ───────────────────────
# The secret *containers* stay Terraform-managed — their ARNs are consumed by
# outputs and IAM policies. The *versions* cannot: their entire payload is an
# Auth0 client secret the provider was never able to read back (no
# `read:client_keys` on the CI M2M), which is why each already carried
# `ignore_changes = [secret_string]` plus a documented operator
# `put-secret-value` step. The live values in Secrets Manager are untouched and
# consumers keep reading them; only Terraform's tracking is dropped.
#
# Retiring them rather than re-pointing them at a placeholder is deliberate. A
# placeholder expression under `ignore_changes` looks inert but would be written
# for real if the version were ever recreated (these use
# `create_before_destroy`), silently replacing a working credential with a
# non-functional one. Forgetting the resource cannot fail that way.
#
# Provisioning a NEW environment now means creating the Auth0 clients in the
# dashboard and seeding these secrets with `aws secretsmanager put-secret-value`.
# That is the intended consequence of tenant configuration living in the
# dashboard, and it matches how these values were already maintained.
removed {
  from = aws_secretsmanager_secret_version.auth0_backend
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_secretsmanager_secret_version.auth0_backend_initial
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_secretsmanager_secret_version.smoke_test
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_secretsmanager_secret_version.dev_portal_mgmt
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_secretsmanager_secret_version.slack_oauth
  lifecycle {
    destroy = false
  }
}

# ── API (resource server) + scopes ───────────────────────────────────────────
removed {
  from = auth0_resource_server.qurl_api
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_resource_server_scopes.qurl_scopes
  lifecycle {
    destroy = false
  }
}

# ── RBAC role + permissions ──────────────────────────────────────────────────
removed {
  from = auth0_role.user
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_role_permissions.user
  lifecycle {
    destroy = false
  }
}

# ── Post-login Action + its trigger binding ──────────────────────────────────
# The "Post-Login Security Gates" Action keeps running in the tenant. Its source
# is preserved for review history in
# `../../../docs/design/AUTH0_IDENTITY_POLICY.md`; the dashboard is now where it
# is edited.
removed {
  from = auth0_action.default_permissions
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_trigger_actions.post_login
  lifecycle {
    destroy = false
  }
}

# ── Clients, their credentials, and their API grants ─────────────────────────
# Website Playground M2M (legacy resource name `backend_service`).
removed {
  from = auth0_client.backend_service
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_credentials.backend_service
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_grant.backend_qurl_api
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client.smoke_test
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_credentials.smoke_test
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_grant.smoke_test_qurl_api
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client.dev_portal_mgmt
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_credentials.dev_portal_mgmt
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_grant.dev_portal_mgmt_api
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client.spa_dashboard
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_credentials.spa_dashboard
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_grant.spa_qurl_api
  lifecycle {
    destroy = false
  }
}

# qurl-bot-slack workspace-install client (sandbox only in practice).
removed {
  from = auth0_client.slack_oauth
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_credentials.slack_oauth
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_client_grant.slack_oauth_qurl_api
  lifecycle {
    destroy = false
  }
}

# ── Social connections ───────────────────────────────────────────────────────
# These never existed in either state: both were gated on
# `<provider>_oauth_client_id != null`, no workflow ever exported the matching
# `TF_VAR_*`, and the GitHub Actions secrets their tfvars comments referenced
# were never created — so `count` was permanently 0. Verified against
# `nhp/sandbox/terraform.tfstate` and `nhp/prod/terraform.tfstate`, neither of
# which contains any `auth0_connection*` entry. The blocks are declared anyway
# so a state carrying them from some path not audited here is forgotten rather
# than destroyed.
removed {
  from = auth0_connection.google
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_connection_clients.google
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_connection.github
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_connection_clients.github
  lifecycle {
    destroy = false
  }
}

# Passwordless `email` connection — already un-managed by #2309/#2305 (the
# `update:connections_options` wall described above). Carried forward here so
# the retirement declares one complete list.
removed {
  from = auth0_connection.slack_email
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_connection_clients.slack_email
  lifecycle {
    destroy = false
  }
}

# ── Tenant-wide branding, security, and email ────────────────────────────────
removed {
  from = auth0_branding.layerv
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_branding_theme.layerv
  lifecycle {
    destroy = false
  }
}

# Attack protection (brute force, suspicious IP throttling, breached passwords)
# stays ENABLED in the tenant — forgetting a resource does not disable it. Do
# not confuse this retirement with a reduction in authentication hardening; the
# dashboard settings are unchanged and are now the source of truth.
removed {
  from = auth0_attack_protection.protection
  lifecycle {
    destroy = false
  }
}

# The SES email provider keeps the SMTP credentials it already holds. The IAM
# user and access key that issued them remain Terraform-managed on the AWS side
# (see `main.tf`), so rotating that key now requires a manual re-entry in the
# Auth0 dashboard — called out in the rollout-ledger entry.
removed {
  from = auth0_email_provider.ses
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_email_template.verify_email
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_email_template.welcome_email
  lifecycle {
    destroy = false
  }
}

removed {
  from = auth0_email_template.reset_email
  lifecycle {
    destroy = false
  }
}
