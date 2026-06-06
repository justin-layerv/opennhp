# 2026-06-05 · PR #2344 · CloudTrail CIS metric-filter alarms

- **Owner:** prod rollout coordinator
- **Source:** [#2344](https://github.com/layervai/nhp/pull/2344) · [issue #1140](https://github.com/layervai/nhp/issues/1140)

Adds 12 CIS CloudWatch metric filters + alarms. Not yet in prod: NOT validatable in sandbox (`enable_cloudtrail = false`) — first creation is the prod apply.

- [ ] Pre-rollout: confirm the prod monitoring `alerts` SNS topic (`module.monitoring.sns_topic_arn`) has at least one CONFIRMED subscriber (a CIS CloudWatch.x control only PASSES when its alarm notifies a topic with a subscriber).
- [ ] Pre-rollout: review the plan diff carefully (12 filters + 12 alarms, all additive) — sandbox cannot pre-validate. Decide the [#2353](https://github.com/layervai/nhp/issues/2353) routing sequencing: recommended to land the ticket/page SNS split first or same-window so apply-driven `ticket` noise never hits the `page` audience; record the choice.
- [ ] Rollout: applied by the normal prod promote terraform apply (additive, no replacements/deletions). The apply itself emits IAM/SG/route-table change events from the CI role that trip the `ticket` change-detection alarms — expected, not a failure.
- [ ] Post-rollout (HARD GATE): in Security Hub (prod) filter CIS AWS Foundations v1.4.0 and confirm CloudWatch.1/4/5/6/7/8/9/10/11/12/13/14 report PASSED (allow ~18h for first eval). A still-FAILED control = filter-pattern divergence or unconfirmed subscriber — release-blocking.
- [ ] Post-rollout: confirm delivery end-to-end (apply-driven `*-cis-iam_policy_changes` / `*-cis-security_group_changes` went ALARM and notified email + Slack; `ticket`-severity, no OK notification, self-clear after 5 min); confirm `page` alarms (`*-cis-root_account_usage`, `*-cis-cloudtrail_config_changes`, `*-cis-cmk_disable_or_delete`) are OK/INSUFFICIENT_DATA and didn't fire spuriously (a real trail-tamper pages twice, by design).
- [ ] Rollback: revert this PR (or delete `terraform/modules/security/cloudtrail_metric_filters.tf`) and apply — removes filters + alarms only. Do NOT roll back via `enable_cloudtrail = false` (disables the trail itself).
- [ ] Follow-ups: [#1140](https://github.com/layervai/nhp/issues/1140) stays open (4 app-level metrics, prod-⊇-sandbox parity test, manual CloudWatch.2/.3); [#2353](https://github.com/layervai/nhp/issues/2353) severity-based SNS routing; sandbox-CloudTrail-enablement decision deferred. Excessive `ticket` apply noise → filter by the `Severity` tag, NOT by editing the Security-Hub-frozen patterns.
