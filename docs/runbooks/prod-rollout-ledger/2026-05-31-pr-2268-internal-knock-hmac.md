# 2026-05-31 · PR #2268 · Internal knock HMAC prod tasks

- **Owner:** prod rollout coordinator
- **Source:** [#2268](https://github.com/layervai/nhp/pull/2268) · [issue #1311](https://github.com/layervai/nhp/issues/1311) (closed by merge; entry stays open until prod verification)

Flips NHP internal-knock auth to strict (`NHP_INTERNAL_AUTH_REQUIRE=true`) via the server launch template. Not yet in prod: rollout runs the prod promote path and refreshes the server ASG.

- [ ] Pre-rollout: confirm prod qurl-service ECS tasks and prod NHP server instances read the same `NHP_INTERNAL_AUTH_SECRET` parameter.
- [ ] Pre-rollout: run a prod qurl-service headless resolve smoke and capture `InternalAuthSuccess` + `InternalAuthFailPermit=0` before the strict flip.
- [ ] Pre-rollout: confirm follow-ups [#2269](https://github.com/layervai/nhp/issues/2269), [#2271](https://github.com/layervai/nhp/issues/2271), [#2274](https://github.com/layervai/nhp/issues/2274) are non-blocking.
- [ ] Rollout: run the prod promote path including the NHP server launch-template/user-data change; if apply updates only the launch template, explicitly refresh the `layerv-nhp-prod-server` ASG so instances pick up `NHP_INTERNAL_AUTH_REQUIRE=true`.
- [ ] Post-rollout: confirm refreshed instances run the expected environment, re-run the headless resolve smoke, and confirm `InternalAuthFailStrict=0`, `InternalAuthFailPermit=0`, `InternalAuthSuccess>0`.
- [ ] Rollback: set prod `NHP_INTERNAL_AUTH_REQUIRE=false`, apply, and refresh the prod server ASG if strict-mode failures appear.
- [ ] Follow-ups: [#2269](https://github.com/layervai/nhp/issues/2269) (plan-time strict-secret guard), [#2271](https://github.com/layervai/nhp/issues/2271) (sandbox strict-mode eval), [#2274](https://github.com/layervai/nhp/issues/2274) (per-endpoint metric dimensions).
