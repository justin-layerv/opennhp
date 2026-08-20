# 2026-08-14 · qURL Desktop feedback delivery

- **Owner:** prod rollout coordinator
- **Source:** this nhp PR and its companion qurl-service and qurl-desktop PRs

The infrastructure change creates a dedicated, KMS-encrypted secret with a
`DISABLED` value. Delivery remains off until the service change is deployed and
the rollout coordinator installs a Slack incoming webhook for the existing
company feedback channel.

- [ ] Pre-rollout: merge and deploy the companion qurl-service feedback endpoint before enabling the credential.
- [ ] Rollout: write the dedicated Slack incoming webhook directly to the `qurl-feedback-slack-webhook` Secrets Manager secret in each target environment; never pass the webhook through Terraform inputs, plans, state, logs, or PRs. Keep an `AWSCURRENT` version present because ECS resolves this secret when each qurl-service task launches.
- [ ] Rollout: force a qurl-service ECS deployment so new tasks resolve the updated secret value.
- [ ] Post-rollout: submit one authenticated qURL Desktop feedback item in sandbox, then production, and verify the expected sanitized message arrives in the company feedback channel.
- [ ] Maintenance: if Terraform ever replaces the feedback secret, its replacement is seeded back to `DISABLED`; reinstall the webhook and force a qurl-service ECS deployment before expecting delivery to resume.
- [ ] Rollback: write the literal `DISABLED` to the feedback secret and force a qurl-service ECS deployment; never blank or delete the secret as a disable shortcut. The endpoint will return a retryable unavailable response without sending to Slack.
