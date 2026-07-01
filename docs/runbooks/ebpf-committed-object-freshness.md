# Runbook: eBPF committed-object freshness

## What fired

One of:

- **`eBPF datapath and object freshness proof` failed** on a PR. The required
  load-relevant comparison failed.
- **Pinned apt snapshot/toolchain install failed** in the proof workflow.

PR #2860 introduced this proof so the native AC object at
`endpoints/ac/main/etc/nhp_ebpf_xdp.o` cannot silently lag the eBPF source used
by `make test-ebpf`. The committed object is DWARF-stripped while retaining BTF
sections; runtime loading uses the BTF-bearing object bytes, not DWARF.

## Triage order

1. If the required comparison failed on a PR that did not touch eBPF source,
   the committed native AC object, or the workflow toolchain pins,
   remember that clang builtin headers and transitive system headers are
   byte-sensitive. Check snapshot.ubuntu.com availability and the apt
   snapshot/package pins in `.github/workflows/ebpf-datapath-test.yml` plus
   `scripts/check-ebpf-committed-object-drift.sh`.
2. If those pins match, check whether an unpinned transitive header reached the
   compile through the clang or libbpf packages.
3. If the committed object contains DWARF/debug sections, regenerate it with
   `--update`; do not hand-commit full-DWARF objects.

## Rebaseline

A real clang/llvm/libbpf pin bump requires regenerating and committing the
DWARF-stripped native AC object with the canonical Linux eBPF toolchain:

```bash
CLANG=clang-18 LLVM_STRIP=llvm-strip-18 bash scripts/check-ebpf-committed-object-drift.sh --update
```

`--update` strips DWARF/debug sections before writing
`endpoints/ac/main/etc/nhp_ebpf_xdp.o`, and refuses to overwrite the committed
object when the local clang, llvm-strip, package, or apt snapshot provenance
does not match the pinned CI toolchain. `EBPF_ALLOW_NONCANONICAL_UPDATE=1`
exists only for an intentional emergency rebaseline; include the reason and
resulting object SHA in the PR if you use it.

## Snapshot outage

For a sustained snapshot.ubuntu.com outage, do not silently skip the freshness
check. The maintainer escape hatch is an explicit PR/workflow change that either
moves `EBPF_APT_SNAPSHOT` to a reachable snapshot plus object rebaseline, or
temporarily removes `--snapshot` with the resulting object SHA called out in the
PR and a follow-up issue to restore snapshot-pinned installs.

After a future Ubuntu or apt major-version bump, re-run
`tests/scripts/install-ebpf-toolchain_test.sh` and a clean-container
`scripts/install-ebpf-toolchain.sh` probe before trusting the terminal/retry
classifier; it intentionally matches `LC_ALL=C` apt/dpkg diagnostic text.

## Required-check rollout

`eBPF datapath and object freshness proof` is a **required status check on
`main`**, enforced by the additive branch ruleset `eBPF datapath proof required`
(config-as-code: `.github/rulesets/ebpf-datapath-proof-required.json`). The
context is bound to integration_id 15368 (GitHub Actions) so only the
Actions-produced check satisfies it. PR #2860 made the proof require-safe (no
`pull_request.paths` filter; conditional `changes` job); the qURL v2 epic (#2753)
landed it on `main` and `qurl-v2` was deleted, so `main` is the target.

Apply, verify, or roll back with:

```bash
.github/scripts/require-ebpf-datapath-check.sh --check    # read-only drift check
.github/scripts/require-ebpf-datapath-check.sh --apply    # idempotent create/update
.github/scripts/require-ebpf-datapath-check.sh --remove   # rollback (delete ruleset)
```

The check is satisfiable for every PR: the workflow runs on every PR to `main`
(no path filter) and the proof job reports a terminal `skipped`/`success`/
`failure` via the #2860 conditional-job pattern, so an unrelated PR reports
`skipped`, never Expected/missing. `--apply` refuses to create the rule unless
the workflow is present on the target branch, so the context cannot be required
before it can report. A PR branch cut before #2753 lacks the workflow and must
rebase onto current `main` to pick it up.

Follow the rollout entry
`docs/runbooks/prod-rollout-ledger/2026-06-28-issue-2861-ebpf-required-check.md`
for the pre-rollout, rollout, post-rollout, and rollback checklist.

### Operational notes

- **Reconciliation is manual.** CI runs only the fixture suite + `shellcheck`,
  not `--check` against the live repo, so an out-of-band weakening of the ruleset
  (added bypass actor, an `exclude` of `refs/heads/main`, enforcement flipped to
  `evaluate`) is not auto-detected. Run `--check` after any suspected change.
  Scheduled drift detection is tracked in issue #2898.
- **Skipped-required-check dependency.** Satisfiability relies on GitHub treating
  a job skipped via job-level `if:` as a passing required check (verified live on
  PR #2877). If GitHub ever changes that, unrelated PRs would hang as Expected —
  roll back with `--remove` and keep the post-rollout-watch ledger item open
  until the next unrelated and next real eBPF PR both confirm the behavior.
- **No bypass actors (fail-closed).** The ruleset grants no bypass, so an
  emergency eBPF hotfix blocked by an unresolvable pinned apt snapshot is
  unblocked via `--remove` (needs repo-admin scope), not a per-actor bypass —
  ensure the on-call has that scope.
