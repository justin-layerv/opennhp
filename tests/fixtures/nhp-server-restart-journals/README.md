# nhp-server restart-journal corpus

The shared **collector** corpus: given this systemd journal and this unit state,
here is the one evidence report both collectors must produce.

`../nhp-server-restart-evidence/` is the sibling corpus for the **decision** —
report in, verdict out. This one sits one step earlier, because there are two
collectors as well as two decision tables:

| Collector | Consumer |
|---|---|
| `RESTART_EVIDENCE_SCRIPT` in `.github/scripts/verify-knock-ready.sh` | the blue/green post-switch deploy gate |
| the `--grep` probes + parsers in `tests/smoke/restart_evidence.go` | the smoke suite's Tier 1 deploy-stability fence |

Agreeing on the decision while disagreeing on the evidence reproduces the
original outage with matching verdicts: a verdict is only as good as the lines it
was built from. Both are driven over this corpus:

- `tests/lints/blue-green-restart-classification/run-fixtures.sh` (Part E)
- `tests/smoke/restart_evidence_test.go` (`TestRestartEvidenceJournalCorpus`)

Two divergences were found by adding it, which is the argument for its existence:

- the Go side counted only `^panic: ` where the shell script also counts
  `fatal error: ` and `goroutine N [running]:`. A `fatal error: concurrent map
  writes` produced `PANICS=0` on one side and `PANICS=2` on the other. Both still
  fail the deploy — the exit status carries that — but `PANICS` is what selects
  the "#1096 panic class" wording, so the two callers diagnosed the same crash
  differently. `crash-fatal-error-no-panic-line` pins it.
- the shell script's `tr "\n" " "` left a trailing space on `DAEMONERR` that the
  Go side trimmed. Cosmetic, invisible in any rendered message, and it made the
  reports differ byte for byte. Only Part E can see this class — see the table
  below.

## What each side actually guards

The two suites do **not** assert the same thing about a case, and it matters
when reading a failure:

| Suite | Runs | Compares | So it catches |
|---|---|---|---|
| Part E (shell) | the real on-instance script | its stdout against `report`, **byte for byte** | anything the script does, including whitespace — the only side that can see the trailing-space class |
| `TestRestartEvidenceJournalCorpus` (Go) | the Go collector only | `restartEvidence` structs, field by field | field-level divergence: a missed exit line, a miscounted marker, the wrong daemon error |

**Part E is the only guard against a shell-collector regression, and the reason
is structural rather than a matter of normalisation.** The Go test never
executes that script: its two inputs are the committed `report` and the Go
collector's output, neither of which changes when `verify-knock-ready.sh` does.
So do not weaken Part E's raw comparison on the assumption that the Go test
would also catch it — it cannot, whatever the comparison.

It is *not* that the Go side trims the difference away.
`parseRestartEvidenceReport` stores `DAEMONERR` verbatim (unlike the numeric
fields, which it trims), while the `got` side comes from
`lastMeaningfulDaemonError`, which trims — so a `report` authored **with** a
stray trailing space fails the Go test. Verified: adding one to
`selfhealed-cloudwatch-log-stream/report` reds both suites. What cannot reach
the Go test is the shell script growing that space.

The report is the shared anchor either way: the shell side pins its exact bytes,
the Go side pins its meaning.

### What "agreement" is scoped to

These cases hold journal text that docker and systemd actually emit, and that is
the scope of the guarantee: **the two collectors agree on journals that occur.**
They are not equivalent on constructed input — `lastMeaningfulDaemonError`
documents three ways the `DAEMONERR` extractors diverge (filter scope, the
required colon-space, trailing whitespace), none reachable from real docker
output.

That is a deliberate boundary, not an oversight. `DAEMONERR` only sharpens the
operator message — no branch of the classifier reads it — and reproducing a grep
pipeline byte-for-byte in Go would mean also reproducing `grep -o`'s
multiple-matches-per-line and `cut -c`'s locale-dependent counting. Adding a
fixture with unrealistic text to pin which side wins would trade this corpus's
main property, that every case is real journal output, for coverage of an input
that cannot arrive.

## Layout

One directory per case:

```
<case-name>/journal   systemd journal text, as `journalctl -u nhp-server -o cat` prints it
<case-name>/unit      NRESTARTS / ACTIVESTATE / SUBSTATE — what the systemctl reads return
<case-name>/report    the evidence report both collectors must build from the two above
```

`unit` uses the report's own `key=value` shape so both sides parse it with the
code they already have.

## Adding a case

Write `journal` and `unit`, then generate `report` from the deploy gate's
on-instance script rather than by hand — it is the older of the two collectors
and the one whose output format the classifier's contract is written against.
Part E replays exactly that, so a hand-written report that differs in whitespace
fails there first.

Then run both suites. A case only one side satisfies is the drift this corpus
exists to catch: fix the collector, do not soften the expectation.

**Keep the daemon-error line ASCII.** `selfhealed-daemon-error-over-200-chars`
pins the `cut -c1-200` truncation boundary, and `cut -c` counts *characters*
under a UTF-8 locale (macOS/BSD) but *bytes* under GNU coreutils, while the Go
collector slices 200 bytes. A multi-byte daemon error at or over that boundary
would therefore pass on Linux CI and fail on a macOS developer's `make
lint-workflows`. Production is unaffected — the probe runs on Amazon Linux, where
`cut -c` is byte-based and agrees with `found[:200]` — but a fixture must not
depend on which side of that split it runs.

Part E **enforces** this rather than relying on you to read it. It is scoped to
the daemon-error line because that is the only text `cut -c` touches: `EXITS`
goes through a line-wise `sed`, and `PANICS`/`OOM` through `grep -c` on ASCII
patterns, none of it locale-sensitive. So the rest of a journal may keep real
non-ASCII — `selfhealed-cloudwatch-log-stream` retains the unit's own
`✅ Server stopped gracefully`, because a fixture edited to satisfy a blanket
ASCII rule would be less faithful to what the journal actually holds, for no
gain.
