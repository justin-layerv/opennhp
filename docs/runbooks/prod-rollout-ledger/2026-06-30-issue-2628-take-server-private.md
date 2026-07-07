# 2026-06-30 · Issue #2628 · Take nhp-server private (drop public knock surface)

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/issues/2628 (epic #2208 phase #8);
  depends on #6 (#2680) + #7. Architecture:
  `docs/design/NHP_RELAY_TOPOLOGY.md`; relay active-color follow-up:
  `docs/design/RELAY_ACTIVE_CELL_ROUTING.md`.

Adds a `take_server_private` flag (default false) that removes the public server
knock NLB (UDP 62206 + 0.0.0.0/0 ingress) and repoints the in-VPC AC +
qurl-service to the **internal** relay NLB. **Sandbox is flipped true now (soak);
prod stays false** until a dedicated prod-cutover PR after the relay carries real
browser traffic in prod (#6/#2680) and the resolve plugin is retired (#7).

## Sandbox (this PR)

- [ ] Post-apply: **instance-refresh the AC** so the new `ServerEndpoint` (internal
      NLB) renders, then confirm AC registration succeeds (NHP_AOL → NHP_ARD/AAK).
      Both NLBs run `preserve_client_ip`, so the server replies from its **instance
      IP, not the NLB IP** — this smoke proves the AC accepts that reply. **Fallback
      if it fails:** point the AC at CloudMap `server.<namespace>:62206` instead of
      the internal NLB.
- [ ] Post-apply: confirm a server blue/green deploy still works with the public UDP
      listener gone — `blue-green-switch.sh` switches the
      `/<env>/nhp/server/internal-udp-listener-arn` listener to the target color
      before it records active-color. The fallback is allowed **only because the
      `/<env>/nhp/server/take-server-private` marker is `true`**; a missing public
      listener without that marker, or a missing internal listener/TG contract with
      the marker true, hard-fails before active-color can drift (covered by
      `tests/scripts/blue-green-switch_test.sh`; verify a real dispatch).
- [ ] Post-apply: verify from OUTSIDE the VPC that UDP 62206 to the (now-removed)
      public NLB is unreachable, and that browser qURL via the relay still works.
- [ ] Post-apply: confirm `internal_tg_no_healthy_targets` is the live blue-side
      server-health alarm and `green_internal_tg_no_healthy_targets` is the green
      sibling (the public-NLB `unhealthy_hosts`/`no_healthy_hosts`/`tcp_resets`
      alarms are now gated off in sandbox).
- [ ] Post-apply: explicitly accept the internal per-color target-health alarm
      semantics: warm standby keeps strict missing-data pages because a color with
      zero healthy internal relay targets is unsafe to flip active; cold standby
      suppresses missing-data pages until green is intentionally warmed. These
      alarms are not active-color-gated by design.
- [ ] HARD GATE: for the active-color internal relay migration, apply while
      `/<env>/nhp/server/active-color` is `blue`; if the apply happens while
      green is active, immediately run a server blue/green switch and the
      active-listener smoke before accepting qURL browser traffic so
      `internal-udp-listener-arn` points at
      `/<env>/nhp/server/{active}-internal-udp-tg-arn`. This PR retains the
      existing internal TG as the blue TG to avoid replacing the live relay TG; a
      green-active first apply would otherwise leave the listener on blue after
      green re-homes to its new TG.
- [ ] Post-apply: confirm the two public-NLB-dependent sandbox CI checks **skip
      cleanly** (not fail) on the first private deploy — `build-and-push.yml` "Run
      Integration Tests" is `if: nlb_dns != ''` (skips), and
      `scripts/validate-deployment.sh` notes "server is private … skipping public-NLB
      reachability checks" instead of failing. The CI runner is outside the VPC, so
      real end-to-end coverage now lives in the relay path (#6/#2680) + the smokes above.
- [ ] **Interim e2e-coverage gap:** skipping the integration tests means sandbox has NO
      automated end-to-end knock coverage from the merge of this PR until the relay-path
      e2e lands. Treat the relay-path e2e (under #6/#2680) as a **blocker** for that
      window — not a nice-to-have — and lean on the manual activation smokes above until
      it exists. If the window is long, weigh a minimal in-VPC knock smoke (self-hosted
      runner or a one-shot Lambda hitting the internal NLB) so the soak isn't fully blind
      on the knock path — "skip cleanly" trades a red signal for no signal.

## Prod cutover (FUTURE, separate PR — do NOT do in this PR)

- [ ] Pre: relay carries real browser traffic in prod (#6/#2680) and resolve plugin
      retired (#7); relay fleet instance-refreshed onto the internal-NLB host.
- [ ] Pre: confirm **no external/standalone AC or raw-UDP agent** still depends on the
      public knock NLB (QURL-only end-state) — migrate any to the relay first.
- [ ] Rollout: the prod public NLB has `enable_deletion_protection=true` — **flip it
      off before** `take_server_private=true` can destroy it, else the apply fails.
- [ ] Rollout: relay re-resolve smoke (relay re-resolves the internal NLB DNS if its
      chosen node changes) + ACK unconnected-socket smoke (relay accepts the server
      ACK from the instance IP, source ≠ dialed NLB) — issue #2628 review addenda.
- [ ] **Reduced canary fence:** when private, the server canary sets
      `disable_nlb_health_checks=true` (`nlb_intentionally_absent`) and advances on
      **CPU + ASG-instance health only**. The internal relay NLB now has per-color
      TGs and per-color health alarms, but the canary module still does not consume
      those internal TG health signals as rollout gates. Track wiring that signal
      into private canary health in #3125; until then, confirm CPU/ASG checkpoints
      are tuned tightly enough before the first private prod canary, or accept the
      reduced fence explicitly.
- [ ] Rollback: revert `take_server_private` to false (re-creates the public NLB via
      the `moved {}` blocks); AC + qurl-service repoint back to the public NLB.

_Delete this file once the prod cutover completes and the above is verified._
