# 2026-06-28 · Issue #2861 · eBPF required check

- **Owner:** qURL v2 rollout coordinator
- **Source:** https://github.com/layervai/nhp/issues/2861,
  https://github.com/layervai/nhp/pull/2860,
  https://github.com/layervai/nhp/pull/2753

PR #2860 made `eBPF datapath and object freshness proof` safe to require by
removing the `pull_request.paths` trigger filter and moving the expensive proof
behind the `Detect eBPF proof inputs` job. The qURL v2 epic (PR #2753) then
merged that workflow to `main` and `qurl-v2` was deleted, so the required check
targets **`main`** — `qurl-v2` is moot. The ruleset is config-as-code in
`.github/rulesets/ebpf-datapath-proof-required.json`, applied/verified with
`.github/scripts/require-ebpf-datapath-check.sh`.

- [x] Current-state check (2026-06-30): `qurl-v2` is deleted (merged via #2753);
      the only active ruleset was `Require signed commits` (~ALL); `main` uses
      classic branch protection whose required contexts are `Test`,
      `Build server`, `Build ac`, `age-check ×3` — no eBPF context, and no stale
      `surgical-kill`/`#2779` binding present anywhere.
- [x] Pre-rollout (2026-06-30): `.github/workflows/ebpf-datapath-test.yml` on
      `main` has no `pull_request.paths` filter and emits the job context
      `eBPF datapath and object freshness proof`. The proof `if:` fails closed —
      `!cancelled() && (needs.changes.result != 'success' || needs.changes.outputs.ebpf == 'true')`
      — so a failed `Detect eBPF proof inputs` runs the proof rather than
      skip-passing the required check.
- [x] Pre-rollout (2026-06-30): the proof has passed green on a clean
      `ubuntu-24.04` runner with the pinned snapshot/packages (e.g. Actions run
      28426196670). The #2870 snapshot-resolvability canary is tracked
      separately; the proof's own install retries + fail-closed install gate the
      snapshot in the meantime.
- [x] Rollout (2026-06-30): added `eBPF datapath and object freshness proof`
      (integration_id 15368 = GitHub Actions) to `main` via the additive branch
      ruleset `eBPF datapath proof required` — ruleset **id 18322648**,
      enforcement `active`, `refs/heads/main`. Existing classic branch-protection
      contexts on `main` are preserved (the ruleset is additive). No stale
      `surgical-kill`/`#2779` context existed to replace. Applied and verified
      with `require-ebpf-datapath-check.sh --apply` / `--check`.
- [x] Post-rollout (2026-06-30): an unrelated PR reports a terminal status, not
      Expected/missing — PR #2877: `Detect eBPF proof inputs` success,
      `eBPF datapath and object freshness proof` skipped.
- [x] Post-rollout (2026-06-30): detector failure cannot silently satisfy the
      proof — the proof `if:` treats a non-success detector result as
      proof-required (see pre-rollout entry); enforced by the workflow shape.
- [x] Post-rollout (2026-06-30): an eBPF/object PR runs the *real* proof — the
      proof job executes (not skips) on eBPF-input PRs (Actions run 28426196670).
      Stale committed-object bytes fail the proof via
      `scripts/check-ebpf-committed-object-drift.sh`, unit-proven in PR #2860
      (committed full-DWARF / stale-object rejection in
      `tests/scripts/check-ebpf-committed-object-drift_test.sh`).
- [ ] Post-rollout watch: confirm the next real eBPF-input PR to `main` shows the
      proof executing green and the next unrelated PR shows it skipped, then
      delete this entry. Open PRs cut before #2753 lack the workflow and must
      rebase onto current `main` to pick it up (dependabot rebases triggered
      2026-06-30).
- [ ] Rollback (contingency): `require-ebpf-datapath-check.sh --remove` (deletes
      ruleset 18322648), or remove only this context from the ruleset, if
      unrelated PRs report the check as Expected/missing or the pinned Ubuntu
      snapshot is unavailable long enough to block urgent eBPF fixes. Keep the
      workflow; it remains the source/object safety proof. A manually cancelled
      latest-head run must be rerun (`!cancelled()` intentionally leaves the
      required context cancelled rather than compiling a cancelled run).
