# 2026-07-11 · PR #3181 · qurl-service sandbox-premerge CI OIDC trust

- **Owner:** prod rollout coordinator
- **Source:** nhp PR #3181 · qurl-service PR #1204

Adds the `:environment:sandbox-premerge` sub for qurl-service to the
`nhp-sandbox-github-actions` OIDC trust policy. The claim is gated on
`var.environment == "sandbox"`, so it lands **only on the sandbox role** — the
prod role (`nhp-prod-github-actions`) intentionally does not trust this
PR-code environment. The grant only takes effect after `terraform apply`;
qurl-service's gated pre-merge qv2 smoke fails OIDC until it lands in sandbox.

- [ ] Pre-rollout (gate-before-trust): confirm qurl-service's `sandbox-premerge`
      GitHub Environment already has its `required_reviewers` rule set **before
      merging this PR** (merge auto-applies the trust to sandbox). Once the sub is
      trusted, AWS OIDC mints creds the moment GitHub asserts it — so if the
      Environment's code-trust gate were not yet enforced there would be a window
      where PR code could assume the role unapproved. (The Environment was created
      with the reviewer in qurl-service PR #1204, so this should already hold —
      verify, don't assume.)
- [ ] Rollout: **merge to `main`** — the sandbox apply is automatic. A push to
      `main` touching `terraform/**` runs `build-and-push.yml`'s
      `deploy-sandbox-infra` job (`terraform apply -auto-approve`, no approval:
      the nhp `sandbox` Environment has no protection rules), which lands the new
      trust sub. No manual apply. Merge this **before** qurl-service PR #1204
      leaves draft, since #1204's own PR CI needs the sub to authenticate the
      same-repo `docker-build` / pre-merge qv2 smoke jobs. (Prod is separate and
      operator-driven via `scripts/trigger-prod-deploy.sh`; the sandbox gate on
      this sub means prod stays a no-op regardless — see the Prod line below.)
- [ ] Post-rollout: confirm a same-repo qurl-service PR's `Pre-merge qv2 Smoke
      (Sandbox)` job passes `Configure AWS credentials` after the reviewer
      approves the `sandbox-premerge` deployment.
- [ ] Prod: no prod trust-policy change — the `var.environment == "sandbox"`
      gate makes an `environments/prod` apply produce **no** diff on
      `nhp-prod-github-actions` from this PR (the arm evaluates to `[]` when
      `environment = "prod"`; deterministic, no live state needed). Deliberate:
      least-privilege for untrusted PR code. Belt-and-suspenders: a
      `terraform plan` on `environments/prod` at the next prod planning cycle
      should show zero change to the `github_actions` role.
- [ ] Rollback: if qurl-service reverts the Environment split, this additive,
      sandbox-only sub is harmless if left in place, or can be removed in a
      follow-up sandbox apply.
- [ ] Cross-repo: keep in lockstep with qurl-service PR #1204; do not delete this
      entry until the sandbox apply is done and the qurl-service PR is green.
- [ ] Follow-up (survives this entry's deletion): nhp#3182 — narrow the qurl PR
      smoke to an ECR/ECS-scoped role, and constrain the `sandbox-premerge`
      reviewer set to the small prod-approver group (approval == apply-equivalent
      sandbox creds to untrusted code). Also tracks an optional terraform-prod-
      drift fixture asserting the rendered prod trust policy excludes the
      `sandbox-premerge` sub.
