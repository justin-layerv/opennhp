# 2026-06-28 · Issue #2861 · eBPF required check

- **Owner:** qURL v2 rollout coordinator
- **Source:** https://github.com/layervai/nhp/issues/2861, https://github.com/layervai/nhp/pull/2860

PR #2860 makes `eBPF datapath and object freshness proof` safe to require by
removing the `pull_request.paths` trigger filter and moving the expensive proof
behind the `Detect eBPF proof inputs` job. Do not enable the required check
against the older path-filtered qURL v2 workflow; that would strand unrelated
PRs on an Expected/missing status.

- [x] Current-state check (2026-06-28): `qurl-v2` is not using legacy branch
      protection, the active branch rulesets only returned `Require signed
      commits`, and effective branch rules for `qurl-v2`/`main` returned no
      `required_status_checks`. The old `eBPF surgical-kill datapath proof`
      context is not required before this PR lands.

- [ ] Pre-rollout: after PR #2860 lands on `qurl-v2`, confirm
      `.github/workflows/ebpf-datapath-test.yml` on `origin/qurl-v2` has no
      `pull_request.paths` filter and emits the job context
      `eBPF datapath and object freshness proof`. Also confirm that the proof
      job condition fails closed when `Detect eBPF proof inputs` fails by
      running on `needs.changes.result != 'success'` instead of skip-passing the
      required check.
- [ ] Pre-rollout: confirm the latest `qurl-v2` eBPF proof passed on a clean
      `ubuntu-24.04` GitHub-hosted runner with the pinned
      `EBPF_APT_SNAPSHOT`/package values, and land or explicitly waive the
      #2870 snapshot-resolvability canary before making this proof required.
- [ ] Rollout: add `eBPF datapath and object freshness proof` to the
      `qurl-v2` required status checks. Prefer a branch ruleset if the repo has
      migrated by then; otherwise preserve the existing branch-protection
      policy and add only this context. Replace any stale required context named
      `eBPF surgical-kill datapath proof`; the job was renamed in PR #2860 and
      the old name will not match. `main` is not applicable until this workflow
      lands on `main`; adding the context there before the workflow exists would
      block every main-bound PR on a missing check.
- [ ] Post-rollout: verify an unrelated PR to `qurl-v2` reports
      `Detect eBPF proof inputs` as success and
      `eBPF datapath and object freshness proof` as skipped/success, not
      Expected/missing.
- [ ] Post-rollout: verify detector failure cannot silently satisfy the
      required proof context. The workflow should either show
      `Detect eBPF proof inputs` as failed or run
      `eBPF datapath and object freshness proof` because its `if:` condition
      treats a non-success detector result as proof-required.
- [ ] Post-rollout: verify an eBPF/object PR runs the real proof and fails on
      stale committed object bytes. Use a temporary PR that changes
      `nhp/ebpf/**` without updating
      `endpoints/ac/main/etc/nhp_ebpf_xdp.o`, confirm the drift diagnostic, then
      close and delete the probe branch.
- [ ] Rollback: remove only the `eBPF datapath and object freshness proof`
      required context from `qurl-v2` branch protection/rulesets if unrelated
      PRs report the check as Expected/missing or the pinned Ubuntu snapshot
      becomes unavailable long enough to block urgent eBPF fixes. Keep the
      workflow in place; it remains the source/object safety proof.
      If a latest-head workflow run is manually cancelled, rerun it; the
      `!cancelled()` guard intentionally leaves the required proof context
      cancelled instead of compiling a cancelled run.
