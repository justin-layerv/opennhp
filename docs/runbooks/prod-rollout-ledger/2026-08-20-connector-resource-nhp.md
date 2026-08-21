# 2026-08-20 · Connector resource provisioning over assigned-cell NHP

- **Owner:** prod rollout coordinator
- **Source:** NHP, qurl-service, qurl-conformance, and connector-resource client PRs

Roll out the post-registration `connector_resource` v1 LST/LRT path in lockstep.
It replaces the unused HTTP provisioning format; no compatibility bridge or
HTTP fallback is permitted.

- [x] Cross-repo: merge and pin the final qurl-conformance connector-resource
      contract, then merge the qurl-service `ResolveConnectorResource` (`creso`)
      implementation before enabling an NHP cell server that can invoke it.
- [x] Pre-reader schema gate: after the qurl-service producer publishes, resolve
      the immutable API image digest built from that same main commit as
      `767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl@sha256:<manifest-digest>`.
      Do not use the Connector Authority image: its scratch image contains only
      `/var/runtime/bootstrap`; `/app/qurl-agent-key-inventory` is shipped in
      the API image. From a governed GitHub Actions job, assume only
      `arn:aws:iam::767397897469:role/nhp-sandbox-github-actions`, log in to
      sandbox ECR, and verify the qurl-service `build-and-deploy.yml` main-push
      run identified by `RUN_ID` is a successful push to `main`. Read the exact
      source SHA and run attempt from GitHub rather than operator input. That
      workflow publishes the API image under the first seven characters of its
      source SHA. Require both its `Docker Build` and `Publish Connector
      Authority (sandbox)` jobs to have succeeded; require the Authority tag
      `${SOURCE_SHA}-${RUN_ID}-${ATTEMPT}` to exist and its ECR digest to equal
      `/sandbox/nhp/control/connector-authority/image-digest`. Then resolve the
      API manifest digest from ECR, construct the immutable ref, pull it, and
      run the inventory against the one table both sandbox NHP cells read for
      registered-agent first knocks:

      ```sh
      set -euo pipefail
      run="$(gh api "repos/layervai/qurl-service/actions/runs/$RUN_ID")"
      SOURCE_SHA="$(jq -r .head_sha <<<"$run")"
      ATTEMPT="$(jq -r .run_attempt <<<"$run")"
      test "$(jq -r .event <<<"$run")" = push
      test "$(jq -r .head_branch <<<"$run")" = main
      test "$(jq -r .conclusion <<<"$run")" = success
      [[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]
      QURL_API_IMAGE_TAG="${SOURCE_SHA:0:7}"
      QURL_API_IMAGE_DIGEST="$(aws ecr describe-images \
        --region us-east-2 \
        --registry-id 767397897469 \
        --repository-name layerv/nhp-qurl \
        --image-ids imageTag="$QURL_API_IMAGE_TAG" \
        --query 'imageDetails[0].imageDigest' \
        --output text)"
      [[ "$QURL_API_IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]
      QURL_API_IMAGE_BY_DIGEST="767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl@$QURL_API_IMAGE_DIGEST"
      docker pull "$QURL_API_IMAGE_BY_DIGEST"
      docker run --rm \
        -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
        -e AWS_REGION=us-east-2 \
        --entrypoint /app/qurl-agent-key-inventory \
        "$QURL_API_IMAGE_BY_DIGEST" \
        --table-prefix layerv-nhp-sandbox-control \
        --expect-account 767397897469 \
        --json > agent-key-inventory.json
      ```

      The role's `qurl-agent-key-inventory` inline policy grants
      `dynamodb:Scan` on sandbox `*-qurl-{api,agent}-keys` and the exact
      `layerv-nhp-sandbox-control-connector-authority` table needed by the
      post-canary binding verifier; it grants no writes. Do not mount or forward
      a long-lived local profile. Retain `agent-key-inventory.json` as rollout
      evidence. Require exit 0 and JSON `result: PASS`, which means
      zero v0, v1, absent, or otherwise invalid schema rows and a valid
      schema-v2 enrollment-kind / connector-claim relation for every row. Exit
      1, 2, or 130 blocks the NHP reader rollout. Do not infer a credential kind
      or backfill an old row:
      deliberately reset and re-enroll each affected disposable sandbox agent,
      then rerun the inventory. Until this gate passes, the schema-v2-only
      first-knock reader would fail closed for ordinary knocks, registration
      completion, and credential recovery, not only `connector_resource`.
      This gate passed after the governed reset and normal-writer OTP canary.
      NHP main run `32485353259` converged the source-bound Connector Authority
      digest
      `sha256:406bafadedc45c24dcc68233af34b87dde06cedb09bad1647ae97724722ff8b9`
      through Control, both cells, relay, validation, and smoke; independent
      readback found all 11 selected aliases exact and provisioned concurrency
      `READY` at 2/2/2. Protected qurl-service verifier run `32491453997` at
      main `908d0c9cef3e2f7f45f14c2029c334e91edfdd83` retained an inventory PASS:
      735 rows scanned, two registration rows, both schema v2, 733 claim rows,
      and zero blockers, unsupported rows, unclaimed rows, malformed rows, or
      cross-owner rows. Its canary binding verifier found exactly one match for
      the approved binding and returned `result: PASS`.
- [ ] Pre-rollout: produce refresh-enabled preview plans for sandbox Control,
      cell0, and cell1, but do not retain either cell plan as an apply artifact.
      Confirm the complete Control graph is 13 functions and 26 closed aliases;
      only the two new `creso` functions and their exact IAM, alarms, and
      dependency-endpoint grants may be added. Confirm cell0 retains
      `layerv-nhp-sandbox-cell0` and cell1 retains the live doubled
      `layerv-nhp-sandbox-cell1-cell1` table prefix, with raw CMK ARNs (never
      aliases) and no table/key replacement.
- [ ] Rollout: deploy the two `creso` functions and aliases first, verify all
      five cold-start table SSE checks. The same workflow run must emit the
      positive `consumer_rollout_ready` receipt only after Control is exact and
      verified; a superseded run, rejected plan, failed/partial apply, or failed
      promotion emits no receipt. Only after that receipt may cell0 and cell1
      create fresh plans and deploy NHP servers with the five-operation alias
      set atomically. Before the Control apply, preview plans deliberately
      retain the exact four-operation predecessor (no `creso` env or invoke
      grant); never apply or reuse that predecessor plan for the new runtime.
      If Control partially applies, do not rerun the failed job: review a fresh
      current-state plan whose checker admits only the closed partial-retry set,
      complete and verify Control, then allow a new workflow run to plan cells.
      Do not enable production in this rollout; bind its independently verified
      table prefixes and raw CMKs in a separate reviewed production plan. If a
      production cell selects hardware custody, extend the exact Control plan
      checker and fixtures for the reviewed CreateKey/key-lifecycle IAM and KMS
      endpoint SIDs first; the sandbox checker intentionally fails that shape
      closed today.
- [ ] Immediately after the first sandbox Control apply creates both `creso`
      aliases, land the separately reviewable retirement that removes
      `resolve_connector_resource` from
      `authority_alias_hold_bootstrap_operations`, and prove a refresh-enabled
      no-op plus normal selected/standby reads over both cells. This retirement
      must merge before any later Connector Authority image publication; the
      bootstrap exemption makes both new aliases follow newest and is safe only
      for their first creation.
- [ ] Post-rollout: run the authenticated UDP smoke lane in both sandbox cells.
      Prove create, exact replay (`found_existing=true`), expected-resource
      match, expected-resource conflict without creation, every frozen error,
      and absence of generic-plugin or HTTP fallback. Record the real sealed
      maximum success/error datagram sizes and require every packet to remain
      at or below 1232 bytes.
- [ ] Post-rollout: confirm `ResolveConnectorResource` invocation/error/
      throttle/duration/spillover and terminal-outcome alarms have the exact
      function and cell dimensions, then record a refresh-enabled no-op for all
      three sandbox roots after the burn-in window.
- [ ] Rollback: roll cell servers back first so they stop emitting the new LST,
      then roll back the Control image/functions and cross-repo client release.
      Once the five-operation cell convergence gate is live, `creso` is not
      independently reversible: removing its Control alias first deliberately
      fails the cell gate closed, so never attempt a Control-only `creso`
      rollback while a selected server still declares the five-operation graph.
      Do not delete resource or key-material rows created by successful
      sandbox smoke exchanges; they are durable idempotency evidence and the
      old unused HTTP format has no compatible recovery role.
