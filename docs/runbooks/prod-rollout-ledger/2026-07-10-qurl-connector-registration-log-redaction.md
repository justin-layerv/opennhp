# 2026-07-10 · qURL Connector registration log redaction

- **Owner:** NHP / qURL production rollout coordinator
- **Source:** [qurl-connector#408](https://github.com/layervai/qurl-connector/pull/408), [compatibility policy issue #3153](https://github.com/layervai/nhp/issues/3153)

NHP server images must contain the protocol-body redaction before direct UDP
agent registration is enabled; otherwise a REG credential can be persisted in
server debug/evaluate logs. Relay registration does not use the asynchronous
body-log path, but is not a substitute for deploying the core fix.

- [ ] Pre-rollout: confirm the NHP core redaction canary test and the connector version-compatibility matrix are green for the exact server and connector commits selected for sandbox.
- [ ] Rollout: deploy the redacted NHP server image to sandbox, then production, before allowing connectors to fall back from HTTPS relay registration to direct UDP registration.
- [ ] Post-rollout: exercise representative OTP and REG flows in sandbox and confirm server general/evaluate logs contain only header type and byte length, with no `raw message:` or plaintext `complete decrypting ... message:` records.
- [ ] Rollback: do not roll the server below this fix while direct UDP registration is available; if rollback is required, keep registration relay-only until the redacted image is restored.
- [ ] Cross-repo: remove this ledger entry only after the connector compatibility PR records the deployed NHP commit and direct/relay registration checks are both green.
