# lockdown-body-drift fixtures

Regression fixtures for [`scripts/check-lockdown-body-drift.sh`](../../../scripts/check-lockdown-body-drift.sh) (#1645).

That lint fences the qurl-service public-ALB `/internal/*` lockdown body
contract: the served body and the smoke fence's expected body must both derive
from one shared Terraform `local`, and Terraform + the smoke resolver must name
the same SSM parameter. The production lint runs against the three real source
files and self-validates in the happy path — but a regression in one of its
greps (a future anchor change, or the count-gate `awk` extractor drifting after
a `terraform fmt` rule change) wouldn't surface until a real drift coincides
with the bug. These fixtures pre-flush every failure mode on every CI run, and
exercise the otherwise-unused 3-arg override interface
(`check-lockdown-body-drift.sh TF_FILE GO_RESOLVER_FILE GO_FENCE_FILE`).

## Layout

Each fixture is a synthetic trio under `fixtures/<name>/`:

| File          | Lint argument      | Role                                            |
|---------------|--------------------|-------------------------------------------------|
| `main.tf`     | `TF_FILE`          | `local` + lockdown rule + SSM parameter         |
| `resolver.go` | `GO_RESOLVER_FILE` | smoke resolver — carries the SSM parameter name |
| `fence.go`    | `GO_FENCE_FILE`    | smoke fence — `publicALBLockdownExpectedCT` + a body var with no map literal |

The files are **not** compiled or applied (`//go:build ignore` on the Go side,
never an input to `terraform`); only the patterns the lint greps for matter.

## Fixtures

Each broken fixture isolates exactly one of the lint's six invariants. Keep
this table in lockstep with the `FIXTURES` array in `run-fixtures.sh` (the
runner fails if the array and the on-disk dirs disagree).

| Fixture                      | Exit | Invariant exercised                                              |
|------------------------------|------|------------------------------------------------------------------|
| `in-sync`                    | 0    | all six invariants satisfied                                    |
| `missing-local`              | 1    | check 1 — `local.public_internal_lockdown_body = jsonencode(...)` is gone |
| `message-body-inlined`       | 1    | check 2 — rule `message_body` re-inlined instead of the local    |
| `value-inlined`              | 1    | check 3 — SSM param `value` re-inlined instead of the local      |
| `fence-literal-reintroduced` | 1    | check 4a — a `publicALBLockdownExpectedBody` map literal returned |
| `tf-param-name-drift`        | 1    | check 4b — TF param name lost the `/nhp/qurl/internal-lockdown-body` suffix |
| `resolver-name-drift`        | 1    | check 4b — resolver names a different parameter                  |
| `resolver-comment-only`      | 1    | check 4b — suffix survives only in a resolver doc comment, code renamed |
| `count-gate-drift`           | 1    | check 5 — rule and param `count` gates differ                    |
| `count-missing`              | 1    | check 5 — rule lost its `count` line (extractor must not grab a later resource) |
| `ct-drift`                   | 1    | check 6 — TF `content_type` ≠ the fence's `publicALBLockdownExpectedCT` |
| `unrelated-content-type`     | 0    | check 6 is block-scoped — an unrelated `content_type` elsewhere must not trip it |

## Running

```bash
./tests/lints/lockdown-body-drift/run-fixtures.sh
```

Runs in CI via `.github/workflows/validate-workflows.yml` (alongside the
production lint), which also `shellcheck`s both scripts.

## Adding a fixture

1. Create `fixtures/<name>/` with `main.tf`, `resolver.go`, `fence.go` — start
   by copying `in-sync/` and mutating the one file that breaks the invariant.
2. Add a `"<name>|<expected-exit>"` row to the `FIXTURES` array in
   `run-fixtures.sh` and a row to the table above.
3. Run the suite locally; the lockstep check fails loudly if the array and the
   directories disagree.
