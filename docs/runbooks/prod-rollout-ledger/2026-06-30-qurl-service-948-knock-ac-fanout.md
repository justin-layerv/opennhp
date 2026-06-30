# 2026-06-30 · qurl-service#948 · Cell-wide knock AC fan-out

- **Owner:** prod rollout coordinator
- **Source:** [qurl-service#948](https://github.com/layervai/qurl-service/issues/948), this PR

Closes the NHP knock→AC firewall-coverage race: an origin knock now waits for all
its local ACs AND fans the knock out to all assigned peer servers
(`Config.EnableKnockACFanout`). The flag is gated on `var.environment == "sandbox"`
in `terraform/main.tf` (module `compute`), so it is **on in sandbox, off in prod**
until the prod flip below. Behavior change lands on the hottest path (every
qURL/native knock), so it is per-environment toggleable and instantly revertable.

- [ ] Post-rollout (sandbox): after the sandbox server fleet refreshes onto this
      build, confirm `config.toml` shows `EnableKnockACFanout = true` on a server
      instance, then confirm the `example.com` session-anchoring smoke
      (`TestSessionAnchoring_RefreshPastExpiry_ReturnsNon200`,
      `TestSessionAnchoring_FirstAuthorizeAnchors/no_sleep_positive_control`) stops
      recurring across several Build-and-Deploy runs (the #948 verdict criterion).
- [ ] Post-rollout (sandbox): watch the new `KnockFanout` / `KnockFanoutPeerSuccess`
      / `KnockFanoutPeerFail` counters and confirm `BroadcastDurationMs` p99 has not
      regressed meaningfully (wait-for-all moves it from fastest-AC to slowest-AC),
      and that `KnockForwardFailure` / `KnockNoAC` / qURL-5xx alarms stay flat.
- [ ] Rollout (prod): to enable in prod, widen the gate in `terraform/main.tf`
      (`enable_knock_ac_fanout = ...`) to include prod and apply; re-run the same
      post-rollout smoke + metric checks against prod before declaring done.
- [ ] Rollback: set the per-environment gate to `false` (or revert this PR) and
      apply — the server returns to the legacy first-success, local-only path with
      no data migration. No cross-repo coordination required.
- [ ] Cross-repo: none. The fix is NHP-internal; qurl-service/traefik-plugins are
      unchanged (qurl-service#948 is the originating bug report only).
