# 2026-08-21 · Connector resource DynamoDB SSE authorization

- **Owner:** Connector resource rollout coordinator
- **Source:** qurl-integrations sandbox proof

The first live `connector_resource` request reached cell0 and invoked `creso`,
but DynamoDB's first strong replay `GetItem` required caller-side
`kms:Decrypt` on the cell table CMK. The role lacked that grant, so the
Authority correctly returned authenticated `unavailable` and NHP sealed public
error `52500`. The same operation subsequently reads three Control tables under
the Control data CMK. Both permissions are DynamoDB-mediated, exact-key and
exact-table grants; neither permits direct KMS use or envelope-key decryption.

- [ ] Pre-rollout: require the Control plan to update only the two sandbox
      `creso` inline execution policies for this fix. Each policy must contain
      exactly two `kms:Decrypt` statements: one on the Control data CMK scoped
      to the agent-keys, connector-authority, and customers table encryption
      contexts, and one on that function's own cell data CMK scoped to its
      qurl-resources and qurl-resource-key-material table contexts. Both must
      require `kms:ViaService=dynamodb.us-east-2.amazonaws.com` and the sandbox
      account subscriber context. No envelope-key decrypt, direct decrypt,
      cross-cell key, wildcard resource, or non-DynamoDB service is allowed.
- [ ] Rollout: merge through the normal current-main NHP workflow and retain
      the terminal Control/cell/runtime/validation receipt. Do not use an ad hoc
      IAM write or a targeted apply; the reviewed saved Control plan remains the
      deployment authority.
- [ ] Post-rollout: simulate and record `allowed` for each `creso` role on its
      exact Control and own-cell CMKs with the matching DynamoDB service and
      table/subscriber contexts. Record `implicitDeny` for direct/no-context,
      wrong-service, envelope-key, unrelated-key, and cross-cell-key decrypts.
      Then rerun the protected qurl-integrations Connector resource proof and
      require cold create, exact replay, warm continuity, terminal conflict,
      KNK/ACK/Login, and zero runtime management HTTP evidence.
- [ ] Prod: before enabling `connector_resource` in production, require the
      equivalent two exact per-function grants in the reviewed production plan
      and the same IAM-simulation matrix against production-owned table names,
      account context, and CMKs.
- [ ] Rollback: if the grants cannot remain live, disable the Connector resource
      operation before removing them. Removing either grant while `creso`
      remains selected intentionally restores authenticated `52500`, not a
      functioning degraded mode.
