# nhp-server restart-evidence corpus

The shared decision table for "a non-zero systemd `NRestarts` counter on an
nhp-server instance — crash, or infrastructure blip that already healed?"

Two implementations answer that question and **must not drift**:

| Implementation | Consumer |
|---|---|
| `.github/scripts/classify-nhp-server-restart-evidence.sh` | the blue/green post-switch deploy gate (`verify-knock-ready.sh`) |
| `classifyRestartEvidence` in `tests/smoke/restart_evidence.go` | the smoke suite's Tier 1 deploy-stability fence |

They cannot share code — one runs on a GitHub runner mid-deploy, the other
inside a Go test binary whose SSM probes must stay single named commands (see
`tests/smoke/CLAUDE.md` rule 8, and the `rejectPatterns` tripwire that bars the
pipes and command substitution the shell probe uses). So they share this corpus
instead, and both are driven over it:

- `tests/lints/blue-green-restart-classification/run-fixtures.sh` (Part D)
- `tests/smoke/restart_evidence_test.go` (`TestRestartEvidenceCorpus`)

## Layout

One directory per case:

```
<case-name>/report    the evidence report, exactly as the on-instance probe emits it
<case-name>/verdict   the single verdict token both implementations must return
```

Verdict tokens: `clean`, `infra_selfhealed` (both pass the gate), `app_crash`,
`infra_unstable`, `indeterminate` (all fail it).

## Adding a case

Add the directory, then run both suites. A case that only one side satisfies is
exactly the drift this corpus exists to catch — fix the implementation, do not
soften the expectation.

Cases are chosen to isolate one branch each. `crash-oom-outranks-container-start`
is deliberately an OOM *alongside* an exit-125, because an OOM case whose exit
status is already abnormal (137) is decided by the exit-status branch and leaves
the OOM branch untested — which is how it originally shipped untested.

Background: the gate used to read `NRestarts >= 1` as an application crash and
name the PR #1096 panic class unconditionally. Sandbox deploy 31340465407
(2026-08-09) tripped it on docker's own exit 125 — the awslogs driver failing to
create a CloudWatch log stream, container never started, healthy six seconds
later — and the resulting retained lock cost four hours of blocked deploys.
