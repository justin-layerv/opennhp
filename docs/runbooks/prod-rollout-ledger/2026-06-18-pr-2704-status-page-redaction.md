# 2026-06-18 · PR #2704 · Status page redaction

- **Owner:** prod rollout coordinator
- **Source:** [PR #2704](https://github.com/layervai/nhp/pull/2704) · [issue #2702](https://github.com/layervai/nhp/issues/2702)

Redacts the public status API response and narrows the status Lambda IAM policy. Rollout uses the normal prod promote path; verify the public endpoint after prod apply because the disclosure was externally reachable.

Public `environment`, `timestamp`, component status, and coarse alarm counts are intentionally retained as the minimal status-page contract. Alarm names, reasons, resource identifiers, deployment metadata, and operational details must remain private.

- [ ] Rollout: promote the status-page Lambda and IAM policy through the normal prod promote path.
- [ ] Post-rollout: `curl` the public `/status` endpoint and confirm the response contains only `environment`, `timestamp`, redacted component statuses, and redacted alarm counts; confirm it does not include account IDs, regions, ARNs, instance IDs, ASG details, table names, alarm names/descriptions/reasons, runbook references, image tags, or commit hashes.
- [ ] Post-rollout: confirm the scoped `elasticloadbalancing:DescribeTargetHealth` permission is working by verifying the component statuses are not both stuck on `unknown` when the underlying target groups are registered and healthy.
- [ ] Rollback: revert this PR or redeploy the previous status Lambda only if the redacted endpoint cannot serve a valid coarse status response; keep the endpoint blocked from exposing rich infrastructure metadata during rollback triage.
