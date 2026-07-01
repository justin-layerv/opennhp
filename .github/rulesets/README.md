# Repository rulesets (config-as-code)

GitHub repository rulesets are stored as live repo settings, not in this repo.
The JSON files here are the **reviewable source of truth** for the rulesets this
project manages deliberately, so a ruleset change is proposed and reviewed in a
PR before it is applied to the live repository.

These files are *not* auto-synced by GitHub. They are applied (and verified)
with the matching script under `.github/scripts/`.

## `ebpf-datapath-proof-required.json`

Makes the eBPF datapath/object-freshness proof a **required status check** on
`main`. Binds the required context to the check identity that actually produces
it:

- workflow: `eBPF Datapath and Object Freshness Test`
  (`.github/workflows/ebpf-datapath-test.yml`)
- check / job name (the required `context`): `eBPF datapath and object freshness proof`
- `integration_id: 15368` — the **GitHub Actions** app (github.com-specific; GHES
  would differ), so only the Actions-produced check can satisfy the rule (a
  same-named status from another app cannot).

`strict_required_status_checks_policy` is `false` to match `main`'s existing
status-check posture (branches are not forced up to date before merge).

Apply / verify / roll back:

```bash
# read-only compliance check (exit non-zero on drift). Verifies enforcement,
# target, the ref condition (includes AND excludes — an added exclude can neuter
# the rule), the required contexts + integration_id, bypass_actors (catches an
# added bypass), and the strict / do-not-enforce-on-create rule params.
.github/scripts/require-ebpf-datapath-check.sh --check

# create or update the ruleset to match this file (idempotent)
.github/scripts/require-ebpf-datapath-check.sh --apply

# rollback: delete the ruleset
.github/scripts/require-ebpf-datapath-check.sh --remove
```

The required check is **satisfiable for every PR** because
`ebpf-datapath-test.yml` runs on every PR to `main` (no workflow-level path
filter) and its proof job reports a terminal `skipped`/`success`/`failure`
status via the conditional-job pattern from PR #2860 — an unrelated PR reports
`skipped`, never a missing/hung check. `--apply` refuses to create the rule
unless that workflow is present on the target branch, so the rule cannot be made
required before the context can report.

**Reconciliation is manual:** CI runs the fixture suite + `shellcheck`, not
`--check` against the live repo, so an out-of-band change to the live ruleset is
not auto-detected — run `--check` after any suspected change. Scheduled drift
detection is tracked in [#2898](https://github.com/layervai/nhp/issues/2898).

See `docs/runbooks/ebpf-committed-object-freshness.md` and the rollout entry
`docs/runbooks/prod-rollout-ledger/2026-06-28-issue-2861-ebpf-required-check.md`.
Tracked in https://github.com/layervai/nhp/issues/2861.
