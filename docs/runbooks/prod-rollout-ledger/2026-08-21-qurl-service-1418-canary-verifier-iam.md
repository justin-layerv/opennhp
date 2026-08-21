# 2026-08-21 · qurl-service #1418 · sandbox canary verifier IAM

- **Owner:** sandbox rollout coordinator
- **Source:** [qurl-service #1418](https://github.com/layervai/qurl-service/pull/1418)

The governed pre-reader schema-v2 canary verifier needs one additional read of
the sandbox Control connector-authority table. This grant is sandbox-only and
must be live before the verifier is approved; it does not alter the production
role or any runtime principal.

- [ ] Rollout: merge the NHP IAM PR and require the normal current-main sandbox
      deployment's IAM delta to contain exactly one in-place update to the
      `qurl-agent-key-inventory` inline policy on
      `nhp-sandbox-github-actions`. The only added permission in that policy is
      `dynamodb:Scan` on
      `arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority`.
      Review any independent full-stack runtime churn on its own merits. The
      narrow targeted plan is proof of this policy delta only; never apply it or
      substitute it for the workflow's full saved plan.
- [ ] Post-rollout: simulate the live role and record that `dynamodb:Scan` is
      allowed on the exact connector-authority table, remains allowed on the
      existing sandbox Control qurl agent/API tables, and remains implicitly
      denied on an unrelated DynamoDB table. Confirm the policy has no write,
      Lambda invoke, wildcard action, or wildcard connector-authority resource.
- [ ] Cross-repo: approve qurl-service #1418's governed canary verifier only
      after the exact NHP deployment receipt and live IAM simulation pass. Keep
      the NHP connector-resource reader rollout held until that verifier and the
      strict schema-v2 inventory both report `PASS`.
- [ ] Rollback: if the verifier cannot complete safely, remove only the
      `DynamoDBQurlCanaryBindingVerifier` statement and re-apply sandbox before
      abandoning the canary; do not change the pre-existing agent/API inventory
      grant.
