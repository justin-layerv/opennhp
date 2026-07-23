# 2026-07-23 · PR #3403 · Secure Hub config delivery

- **Owner:** prod rollout coordinator
- **Source:** [#3403](https://github.com/layervai/nhp/pull/3403),
  Hub foundation [#3227](https://github.com/layervai/nhp/issues/3227)

The Hub image remains dark and unpublished in this source slice. Before any
task or UDP listener is reachable, render one validated secret-bearing config
on a fresh encrypted task volume, keep every secret out of the long-lived
worker environment, and make ECS monitor the same config-driven binary health
command that the image proves.

- [ ] Pre-rollout (one-shot config delivery): render the strict public JSON and
      inject the three key values only into a short-lived, nonessential
      `nhp-hubd materialize-config` init container running as root. Make the
      worker depend on that container's `SUCCESS`; ECS does not permit the
      `SUCCESS` dependency condition on an essential container. The init must
      use the same immutable Hub image digest as the worker and a fresh
      task-scoped, encrypted volume mounted writable at `/nhp-hub/etc`. Present
      that volume empty without copying the image's fail-closed placeholder
      `hub.toml`; Docker-managed volumes require the equivalent of `nocopy`.
      Verify the init exits successfully after writing only canonical
      `hub.toml` as mode `0400`, owner `65532:65532`, and record its
      `config_sha256=sha256:<hex>` output. Fargate task definitions do not
      expose a supported tmpfs contract, so do not claim this volume is tmpfs.
- [ ] Pre-rollout (secret isolation): mount the completed `/nhp-hub/etc` volume
      read-only into the long-lived worker, retain `USER 65532:65532`, a
      read-only root filesystem, and dropped capabilities, and provide none of
      `NHP_HUB_PUBLIC_CONFIG_JSON`, `NHP_HUB_PRIVATE_KEY_B64`,
      `NHP_HUB_ACTIVE_COOKIE_KEY_B64`, or
      `NHP_HUB_PREVIOUS_COOKIE_KEY_B64` to that worker. Do not share process
      namespaces, pass secrets through argv/logs/errors, or hot-rewrite the
      file; rotation requires a replacement task with a fresh volume.
      Fargate does not support ECS `dockerSecurityOptions`, so do not claim or
      render `no-new-privileges`; require it only if the runtime substrate is
      explicitly changed to ECS EC2.
- [ ] Pre-rollout (health lockstep): derive `health_listen_addr` in the public
      config JSON and the target group's private TCP port from one reviewed
      Terraform local. ECS ignores an image-embedded Docker healthcheck unless
      the container definition also declares it, so render and source-lock
      `healthCheck.command = ["CMD", "/nhp-hub/nhp-hubd", "healthcheck"]`
      with `interval=30`, `timeout=3`, `retries=3`, and `startPeriod=10`.
      Add a task-definition contract test for those exact values and keep the
      private NLB TCP target-health check as an independent signal.
- [ ] Pre-rollout (rendered task proof): assert the materializer is
      nonessential and root, the worker depends on its `SUCCESS`, both use the
      same immutable digest, the init mount is writable, the worker mount and
      root filesystem are read-only, and only the init container receives the
      four materialization environment inputs.
- [ ] Rollout: deploy a replacement sandbox task on a fresh volume, record the
      materialized config digest, and require both ECS container `HEALTHY` and
      private NLB target health before any Hub security-group or UDP listener
      activation.
- [ ] Rollback: stop the replacement task and restore the prior dark task
      definition/image pin. Never reuse or mutate its task volume; no data
      migration or Authority state rollback is required.
- [ ] Follow-up: delete this ledger entry only after the rendered task proof,
      sandbox replacement-task proof, and rollback evidence are recorded.
