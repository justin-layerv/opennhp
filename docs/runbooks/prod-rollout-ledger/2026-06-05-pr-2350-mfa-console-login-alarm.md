# 2026-06-05 · PR #2350 · MFA console-login alarm, require-MFA policy, IAM audit

- **Owner:** prod rollout coordinator
- **Source:** [#2350](https://github.com/layervai/nhp/pull/2350) · [issue #1138](https://github.com/layervai/nhp/issues/1138)

Adds (in `terraform/modules/security`) a prod console-login-no-MFA metric filter
+ alarm, a created-but-unattached `require_mfa` IAM policy, an opt-in account
password policy, and a weekly IAM MFA-audit Lambda. Not yet applied to prod;
full resource detail is in the PR.

- [ ] Pre-rollout: the account password policy is an account SINGLETON, opt-in (`enable_account_password_policy` defaults false). Before flipping it true, capture the current policy (`aws iam get-account-password-policy --profile <prod>`; `NoSuchEntity` = the rollback target) — enabling OVERWRITES any existing account policy and tighter `max_password_age`/`reuse_prevention` can force console users to reset at next sign-in.
- [ ] Pre-rollout: confirm `guardduty_alert_emails` is non-empty in the env tfvars (gates both the alarm and the audit Lambda via `enable_guardduty_alerts`); empty = the metric filter still accrues but the alarm/audit silently don't deploy and the #1138 gap reopens.
- [ ] Pre-rollout: validate `console_login_mfa_filter_pattern` at a desk before the prod promote (prod-only — sandbox has `enable_cloudtrail=false`): `aws logs test-metric-filter` matches a no-MFA Success sample and NOT `MFAUsed:Yes` / `ConsoleLogin:Failure`.
- [ ] Rollout: sandbox apply first (creates only the `require-mfa` policy + audit Lambda; no console-login filter, no password policy). Prod apply via the promote path creates the `<prefix>-console-login-no-mfa` filter + alarm. The password policy is a separate, deliberate apply after the capture above.
- [ ] Post-rollout (prod only): `<prefix>-console-login-no-mfa` alarm exists + OK and `LayerV/NHP/Security` `ConsoleLoginWithoutMFA` publishes; the `<prefix>-iam-mfa-audit` Lambda's first weekly run succeeds (no `-errors` alarm); review `IAMUsersWithoutMFA`.
- [ ] Post-rollout: attach `require_mfa` to the human IAM console users/groups (enforcement leg of #1138; ships unattached because those principals live outside this repo) — tracked in [#2351](https://github.com/layervai/nhp/issues/2351).
- [ ] Rollback: set the relevant `enable_*` flags false and re-apply; for the password policy restore from the capture (or `delete-account-password-policy` for the no-policy target); detaching `require_mfa` is a console/CLI action on out-of-repo principals.
- [ ] Follow-ups: [#2351](https://github.com/layervai/nhp/issues/2351) (attach require_mfa); [#2369](https://github.com/layervai/nhp/issues/2369) (alarm on CloudTrail→CWLogs delivery liveness so a blind pipe isn't read as "no MFA-less logins").
