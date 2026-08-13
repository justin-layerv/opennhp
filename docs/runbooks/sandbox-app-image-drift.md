# Sandbox app-image drift gate

`build-and-push.yml` uses the `sandbox-app-image-drift` job to prove that the
live sandbox server, AC, and relay image tags contain the workflow SHA's app
tree before `/sandbox/nhp/deploy/deployed-commit` is advanced. This prevents a
failed app rollout followed by an infra-only deploy from recording a commit that
is not actually live.

## When It Runs

The gate runs on workflow-triggering `main` pushes and explicit sandbox deploy
dispatches. Pushes that do not match `build-and-push.yml`'s `on.push.paths`, such
as docs-only pushes, do not start the workflow by themselves. A manual sandbox
workflow dispatch re-runs this gate and can heal drift when the target app tree
is healthy.

## Expected Fail-Closed Cases

- An active server or AC image-tag SSM read fails.
- The relay image-tag SSM read fails with anything other than
  `ParameterNotFound`.
- A live tag is empty, `unknown`, `None`, malformed, or not fetchable as a commit.
- A live tag does not contain the workflow SHA's app tree for that component.

These failures are intentional. Do not manually advance
`/sandbox/nhp/deploy/deployed-commit` while live tags cannot prove the workflow
SHA.

Because the gate is on the qualifying `main` push path, a broad AWS SSM or OIDC
incident can make unrelated app, infra, workflow, or test pushes fail red. Treat
that as an environment/control-plane incident and rerun after recovery; do not
interpret the failure as proof that the pushed code is broken until the logs show
real tag drift.

## Triage

1. Confirm whether the failure is an AWS/SSM/OIDC read failure or a real live-tag
   drift notice in the `sandbox-app-image-drift` or `Update Deployment Tracking`
   logs.
2. For transient AWS/SSM/OIDC failures, rerun the workflow after AWS recovers.
   The scripts deliberately do not retry or guess clean.
   If the server, AC, relay, or qURL rollout steps already succeeded and only
   `Update Deployment Tracking` failed on the post-switch SSM/git proof, leave
   `/sandbox/nhp/deploy/deployed-commit` stale and rerun the workflow after the
   control-plane issue clears.
3. If the resolver cannot fetch a live tag's commit from GitHub, it treats the
   tag as unproven and forces a rebuild/roll instead of failing red. If a
   surprising full app roll happens without app-path drift, check GitHub/network
   reachability and whether the active tag was force-pushed away.
4. For real drift, inspect which component tag is stale. A fresh app image build
   and roll should heal drift when the target app tree builds and deploys
   cleanly.
5. If the target app tree is broken, land the app fix or revert the breaking
   change. `force_build=true` is not a bypass; it still builds and rolls the
   target tree.
6. There is deliberately no infra-only sandbox deploy bypass while `main`'s app
   tree is broken. For an urgent unrelated Terraform fix, repair or revert the
   app break first so sandbox can prove the app bytes it records.
7. If an active tag points at an unreachable commit, recover by rolling a
   fetchable target image and let the post-switch gate stamp deployed-commit
   only after live tags converge.

## Relay Note

Relay is single-slot today, so the live relay tag is
`/sandbox/nhp/relay/image-tag`. If relay moves to blue/green, update the drift
gate before that rollout so relay tag reads use active-slot resolution. That
future migration is tracked in
[layervai/nhp#3105](https://github.com/layervai/nhp/issues/3105).
