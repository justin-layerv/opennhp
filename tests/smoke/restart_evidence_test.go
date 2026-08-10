//go:build smoke

package smoke

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// restart_evidence_test.go runs entirely offline — no AWS, no deployed
// environment, no SSM. It is wired into nhp-smoke-pr.yml's smoke-build job so
// it executes at PR time; `go build`/`go vet` alone would not run it.

// corpusDir is the decision table shared with the blue/green deploy gate's
// shell classifier. See its README for why the two implementations exist.
const corpusDir = "../fixtures/nhp-server-restart-evidence"

// TestRestartEvidenceCorpus drives every corpus case through the Go
// classifier. Its counterpart — Part D of
// tests/lints/blue-green-restart-classification/run-fixtures.sh — drives the
// same cases through .github/scripts/classify-nhp-server-restart-evidence.sh.
// The two implementations cannot share code (see restart_evidence.go), so
// this corpus is what keeps them from drifting.
func TestRestartEvidenceCorpus(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("read corpus %s: %v", corpusDir, err)
	}

	cases := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		cases++

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			report, err := os.ReadFile(filepath.Join(corpusDir, name, "report"))
			if err != nil {
				t.Fatalf("read report: %v", err)
			}
			wantRaw, err := os.ReadFile(filepath.Join(corpusDir, name, "verdict"))
			if err != nil {
				t.Fatalf("read verdict: %v", err)
			}
			want := restartVerdict(strings.TrimSpace(string(wantRaw)))

			got, detail := classifyRestartEvidence(parseRestartEvidenceReport(string(report)))
			if got != want {
				t.Fatalf("verdict = %q, want %q (the shell classifier in "+
					".github/scripts/classify-nhp-server-restart-evidence.sh agrees with the "+
					"corpus; this implementation has drifted from it)\ndetail: %s", got, want, detail)
			}
			if detail == "" {
				t.Fatal("detail is empty — the operator-facing message is the other half of the fix")
			}

			// Optional per-case message assertions, shared with Part D of the
			// shell runner. Without them the corpus pins verdicts only, so a
			// message-only behaviour had to be asserted once per language.
			for _, needle := range corpusNeedles(t, name, "detail-contains") {
				if !strings.Contains(detail, needle) {
					t.Errorf("detail is missing %q\ndetail: %s", needle, detail)
				}
			}
			for _, needle := range corpusNeedles(t, name, "detail-excludes") {
				if strings.Contains(detail, needle) {
					t.Errorf("detail must not contain %q\ndetail: %s", needle, detail)
				}
			}
		})
	}

	// A corpus that silently emptied would otherwise report success.
	if cases < 10 {
		t.Fatalf("only %d corpus case(s) found in %s — the shared decision table lost cases",
			cases, corpusDir)
	}
}

// corpusNeedles reads an optional per-case assertion file (one substring per
// line). Absent file means no assertion.
func corpusNeedles(t *testing.T, caseName, file string) []string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(corpusDir, caseName, file))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read %s/%s: %v", caseName, file, err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// TestRestartEvidenceMessagesStateObservations covers message behaviour the
// shared corpus cannot: cases built from a restartEvidence struct rather than
// a parsed report. The corpus owns the rest via detail-contains/-excludes.
func TestRestartEvidenceMessagesStateObservations(t *testing.T) {
	t.Parallel()

	// Panic text is corroboration, not the verdict. With a non-125 exit the
	// verdict is already app_crash; the panic only sharpens the wording.
	verdict, withPanic := classifyRestartEvidence(restartEvidence{
		NRestarts: 1, ActiveState: "active", SubState: "running",
		Exits: []string{"exited:2"}, Panics: 3,
	})
	if verdict != verdictAppCrash {
		t.Fatalf("verdict = %q, want %q", verdict, verdictAppCrash)
	}
	if !strings.Contains(withPanic, "#1096") {
		t.Errorf("an observed panic must name #1096: %s", withPanic)
	}

	verdict, withoutPanic := classifyRestartEvidence(restartEvidence{
		NRestarts: 1, ActiveState: "active", SubState: "running",
		Exits: []string{"exited:2"},
	})
	if verdict != verdictAppCrash {
		t.Fatalf("verdict = %q, want %q — the exit status alone must carry it", verdict, verdictAppCrash)
	}
	if strings.Contains(withoutPanic, "#1096") {
		t.Errorf("a panic-less crash must not assert the #1096 class: %s", withoutPanic)
	}
	if withPanic == withoutPanic {
		t.Error("panic evidence should still change the wording")
	}
	if strings.Contains(withPanic, "line(s)") {
		t.Errorf("panic presence must not be rendered as a line count: %s", withPanic)
	}
}

// TestRestartEvidenceProbesPassRejectList proves the new probes are accepted
// by ssm_probe.go's tripwire. They are read-only single commands with no shell
// metacharacters — deliberately using journalctl's own --grep rather than a
// pipe, which the reject-list would (correctly) refuse.
func TestRestartEvidenceProbesPassRejectList(t *testing.T) {
	t.Parallel()

	probes := append([]string{
		cmdSystemdActiveStateNhpServer,
		cmdSystemdSubStateNhpServer,
	}, journalEvidenceProbes...)
	for _, cmd := range probes {
		if err := sendShellScriptRaw(cmd); err != nil {
			t.Errorf("probe rejected by the reject-list: %q: %v", cmd, err)
		}
	}
}

// TestRestartEvidenceProbeArgsSurviveTheShell fences the quoting of every
// journal probe.
//
// SSM hands these strings to a shell, so an unquoted --grep pattern containing
// a space is word-split before journalctl ever sees it:
//
//	--grep=Main process exited
//	  → argv: [--grep=Main] [process] [exited]
//
// journalctl then treats `process` and `exited` as matches, which must be
// FIELD=VALUE, and errors. probeServerRestartEvidence returns that error and
// the Tier 1 fence reports "cannot confirm whether this was an application
// crash" — on every instance that actually restarted, which is the only time
// these probes run at all. The healthy path never issues them, so nothing else
// in this suite would notice.
//
// Checked by running each command through `sh` against a stub journalctl that
// echoes its argv, not by pattern-matching the constants: the property under
// test is what the shell does to them.
func TestRestartEvidenceProbeArgsSurviveTheShell(t *testing.T) {
	t.Parallel()

	stubDir := t.TempDir()
	stub := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"
	if err := os.WriteFile(filepath.Join(stubDir, "journalctl"), []byte(stub), 0o755); err != nil {
		t.Fatalf("write journalctl stub: %v", err)
	}

	for _, cmd := range journalEvidenceProbes {
		t.Run(probeGrepPattern(cmd), func(t *testing.T) {
			t.Parallel()

			run := exec.Command("sh", "-c", cmd)
			run.Env = append(os.Environ(), "PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := run.Output()
			if err != nil {
				t.Fatalf("run %q: %v", cmd, err)
			}
			args := strings.Split(strings.TrimRight(string(out), "\n"), "\n")

			// Exactly one --grep, carrying the whole pattern.
			greps := 0
			for _, a := range args {
				if strings.HasPrefix(a, "--grep=") {
					greps++
				}
			}
			if greps != 1 {
				t.Fatalf("journalctl received %d --grep args, want 1 — the pattern was word-split by the shell; single-quote it\nargv: %q\ncmd:  %s",
					greps, args, cmd)
			}

			// No stray positional args. Checked structurally rather than
			// against a list of permitted values: a bare word is legitimate
			// only as the value of a flag that takes one separately, so the
			// test is "is the previous token such a flag?" — which needs no
			// updating when a probe changes its unit, output format or line
			// bound. A whitelist of {"nhp-server","cat","400"} would have to
			// grow every time one of those values changed, and a stale entry
			// there weakens the tripwire silently.
			//
			// `--grep=X` is the attached `--flag=value` form and so takes no
			// separate value, which is why a word-split pattern fragment is
			// caught: `process` follows `--grep=Main`, not a value-taking flag.
			takesSeparateValue := map[string]bool{"-u": true, "-o": true, "-n": true}
			for i, a := range args {
				if strings.HasPrefix(a, "-") {
					continue
				}
				if i > 0 && takesSeparateValue[args[i-1]] {
					continue
				}
				t.Fatalf("journalctl received unexpected positional arg %q at index %d — matches must be FIELD=VALUE, so journalctl errors on this\nargv: %q\ncmd:  %s",
					a, i, args, cmd)
			}
		})
	}
}

// journalCorpusDir is the shared COLLECTOR corpus, one level earlier in the
// pipeline than corpusDir above.
//
// corpusDir starts from an already-built report, so it fences the two decision
// tables and nothing else. But there are two COLLECTORS as well — the deploy
// gate's piped on-instance script, and the --grep probes plus parsers in
// restart_evidence.go — and two collectors reading the same journal can build
// different reports. That is the same failure the classification exists to stop,
// one step upstream: a verdict is only as good as the lines it was built from.
//
// So each case here holds real systemd journal text plus the unit state, and the
// one report both collectors must produce from it.
const journalCorpusDir = "../fixtures/nhp-server-restart-journals"

// TestRestartEvidenceJournalCorpus drives the Go collector over every journal
// case. Its counterpart — Part E of
// tests/lints/blue-green-restart-classification/run-fixtures.sh — drives the
// deploy gate's on-instance script over the same journals and asserts the same
// reports.
//
// The two halves assert different things about a case, deliberately. Part E
// compares the script's stdout to the report byte for byte; this compares
// parsed restartEvidence structs field by field, which is the right shape for
// probes that return one field each.
//
// So a regression in the SHELL collector is invisible here, and Part E is what
// guards it. The reason is structural, not a matter of normalisation: this test
// never executes that script. Its two inputs are the committed report and the
// Go collector's output, neither of which changes when verify-knock-ready.sh
// does. Do not read a green run here as "the bytes agree".
//
// Note it is not that whitespace gets normalised away —
// parseRestartEvidenceReport stores DAEMONERR verbatim (unlike the numeric
// fields, which it trims), while the got side comes from
// lastMeaningfulDaemonError, which trims. So a report authored WITH a stray
// trailing space fails this test. What cannot reach it is the shell script
// growing one.
//
// The --grep patterns are taken from the production command constants rather
// than written out again here, so a probe whose pattern changes is exercised
// with its new pattern.
func TestRestartEvidenceJournalCorpus(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(journalCorpusDir)
	if err != nil {
		t.Fatalf("read journal corpus %s: %v", journalCorpusDir, err)
	}

	cases := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		cases++

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			read := func(file string) string {
				b, err := os.ReadFile(filepath.Join(journalCorpusDir, name, file))
				if err != nil {
					t.Fatalf("read %s: %v", file, err)
				}
				return string(b)
			}

			want := parseRestartEvidenceReport(read("report"))
			// `unit` carries only the three systemctl reads; pad it with the
			// journal-derived keys parseRestartEvidenceReport requires, so it
			// parses as a well-formed report rather than a malformed one.
			//
			// DAEMONERR is deliberately absent: it is not in that parser's
			// required set, and only NRestarts/ActiveState/SubState are read
			// back from the result below. If the required set ever grows to
			// include it, this padding needs the key too — the failure would be
			// every case turning `malformed`, which is loud rather than subtle.
			unit := parseRestartEvidenceReport(read("unit") + "\nEXITS=\nPANICS=0\nOOM=0")

			got := collectEvidenceFromJournal(t, unit, read("journal"))

			if diff := describeEvidenceDiff(want, got); diff != "" {
				t.Fatalf("the Go collector and the deploy gate's on-instance script disagree about this journal:\n%s\n"+
					"Part E of tests/lints/blue-green-restart-classification/run-fixtures.sh asserts the shell "+
					"collector produces the corpus report; this side has drifted from it.", diff)
			}
		})
	}
}

// collectEvidenceFromJournal mirrors probeServerRestartEvidence's assembly with
// journalctl replaced by a local grep over fixture text. Keep it in the same
// shape as that function: same probe constants, same parsers, same summing of
// the three panic markers.
func collectEvidenceFromJournal(t *testing.T, unit restartEvidence, journal string) restartEvidence {
	t.Helper()

	ev := restartEvidence{
		NRestarts:   unit.NRestarts,
		ActiveState: unit.ActiveState,
		SubState:    unit.SubState,
	}
	ev.Exits = parseSystemdExitLines(journalGrep(t, cmdJournalNhpServerExits, journal))
	for _, cmd := range panicMarkerProbes {
		ev.Panics += countNonEmptyLines(journalGrep(t, cmd, journal))
	}
	ev.OOM = countNonEmptyLines(journalGrep(t, cmdJournalNhpServerOOM, journal))
	ev.DaemonErr = lastMeaningfulDaemonError(journalGrep(t, cmdJournalNhpServerDaemonErrors, journal))
	return ev
}

// journalGrep applies a probe's --grep pattern to journal text, standing in for
// what journalctl does on the instance.
//
// Matched line by line, which is what `-o cat --grep` yields: journalctl tests
// the pattern against each entry's MESSAGE, so a leading `^` anchors to the
// start of a line rather than the start of the journal.
//
// Being an emulation, it cannot see two things, both bounded:
//
//   - Dialect. journalctl's --grep is PCRE; this is Go's RE2. Every current
//     pattern means the same in both, and a PCRE-only construct would fail
//     regexp.Compile below rather than pass quietly — the good failure mode.
//     What is unreachable is a construct both engines accept and read
//     differently.
//   - Case. journalctl's --grep is smart-case, so the three lowercase panic
//     patterns match case-insensitively there and case-sensitively here. See
//     the marker constants in restart_evidence.go for why that is recorded
//     rather than emulated.
//   - Entry boundaries. journalctl applies --grep to a whole MESSAGE, so an
//     entry containing embedded newlines is one unit there and several lines
//     here. Irrelevant for these markers — each is anchored to the start of a
//     line systemd or the Go runtime emits on its own — but it matters if a
//     fixture ever carries a genuinely multi-line MESSAGE.
//
// Neither is a reason to distrust the corpus for what it does pin: that the two
// collectors extract the same evidence from the same lines. What closes the gap
// between either collector and real journalctl is a live run, not a fixture.
func journalGrep(t *testing.T, cmd, journal string) string {
	t.Helper()

	pattern := probeGrepPattern(cmd)
	if pattern == cmd {
		t.Fatalf("probe has no --grep pattern: %q", cmd)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("probe --grep pattern %q does not compile: %v", pattern, err)
	}

	var out []string
	for _, line := range strings.Split(journal, "\n") {
		if re.MatchString(line) {
			out = append(out, line)
		}
	}

	// Apply the probe's own -n, which journalctl applies to the MATCHING
	// entries when --grep is present: `-n 400` means the last 400 matches, not
	// the last 400 journal lines. Honouring it keeps the emulation faithful and
	// leaves the bound exercisable by a future fixture; ignoring it would make
	// this a third dialect, on top of RE2-for-PCRE.
	//
	// No corpus case comes near 400 matches, so this changes nothing today. It
	// is here so the emulation does not quietly diverge from the thing it
	// stands in for.
	if n := probeLineBound(t, cmd); n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return strings.Join(out, "\n")
}

// probeLineBound returns a probe's `-n N` value, or 0 if it has none.
func probeLineBound(t *testing.T, cmd string) int {
	t.Helper()

	fields := strings.Fields(cmd)
	for i, f := range fields {
		if f != "-n" || i+1 >= len(fields) {
			continue
		}
		n, err := strconv.Atoi(fields[i+1])
		if err != nil {
			t.Fatalf("probe has a non-numeric -n value %q: %s", fields[i+1], cmd)
		}
		return n
	}
	return 0
}

// probeGrepPattern returns a probe's --grep pattern with its shell quoting
// removed — the only part that differs between the journal probes, so it
// doubles as a subtest name.
//
// Strips exactly one balanced pair of single quotes, not every quote at either
// end. A single-quoted shell token cannot contain a literal `'`: there is no
// escape inside single quotes, so embedding one means closing and reopening,
//
//	'a'\''b'
//
// which is why a pattern needing one arrives here in a shape this deliberately
// does not try to unquote. Better that it fail to compile, or fail to match
// visibly, than be silently mangled by a greedy trim.
//
// That example is an indented block on purpose. In doc-comment PROSE gofmt
// rewrites two adjacent single quotes into a right double quote (godoc's
// typographic convention), so the escape cannot be written inline there without
// being silently mangled into a different, wrong sequence. Indented blocks are
// preserved verbatim. Do not unindent it.
func probeGrepPattern(cmd string) string {
	_, pattern, ok := strings.Cut(cmd, "--grep=")
	if !ok {
		return cmd
	}
	if len(pattern) >= 2 && pattern[0] == '\'' && pattern[len(pattern)-1] == '\'' {
		pattern = pattern[1 : len(pattern)-1]
	}
	return pattern
}

// describeEvidenceDiff renders only the fields that differ, so a failure names
// the disagreement instead of dumping two structs at the reader.
//
// The want side is labelled `report=`, not `shell=`: it is the committed
// fixture, and this test never executes the shell collector. Calling it `shell=`
// would suggest the script had just run and disagreed, which is the one thing a
// reader of this failure must not conclude — Part E is where the script's actual
// output is checked.
func describeEvidenceDiff(want, got restartEvidence) string {
	var diffs []string
	report := func(field string, w, g any) {
		diffs = append(diffs, fmt.Sprintf("  %-12s report=%v  go=%v", field, w, g))
	}
	// Scalars only: fmt.Sprint is an exact comparison for strings and ints.
	add := func(field string, w, g any) {
		if fmt.Sprint(w) != fmt.Sprint(g) {
			report(field, w, g)
		}
	}
	add("NRestarts", want.NRestarts, got.NRestarts)
	add("ActiveState", want.ActiveState, got.ActiveState)
	add("SubState", want.SubState, got.SubState)
	// Exits is compared element-wise, not stringified: fmt.Sprint renders
	// []string{"a b"} and []string{"a","b"} identically as "[a b]", so a
	// stringify comparison would call two structurally different slices equal.
	// Unreachable for tokens shaped like `exited:125`, which contain no spaces —
	// but a comparison that is only correct because of its inputs is the wrong
	// thing to have inside a drift fence.
	if !slices.Equal(want.Exits, got.Exits) {
		report("Exits", want.Exits, got.Exits)
	}
	add("Panics", want.Panics, got.Panics)
	add("OOM", want.OOM, got.OOM)
	add("DaemonErr", want.DaemonErr, got.DaemonErr)
	return strings.Join(diffs, "\n")
}

// TestParseSystemdExitLines fences the journal parser against the real line
// shapes systemd emits. A parser that silently stopped matching would leave
// every restart unexplained and fail healthy deploys closed — the same outage
// wearing a different message.
func TestParseSystemdExitLines(t *testing.T) {
	t.Parallel()

	journal := strings.Join([]string{
		"nhp-server.service: Main process exited, code=exited, status=125/n/a",
		"nhp-server.service: Main process exited, code=exited, status=0/SUCCESS",
		"nhp-server.service: Main process exited, code=exited, status=2/INVALIDARGUMENT",
		"nhp-server.service: Main process exited, code=killed, status=9/KILL",
		"nhp-server.service: Scheduled restart job, restart counter is at 1.",
		"",
	}, "\n")

	got := parseSystemdExitLines(journal)
	want := []string{"exited:125", "exited:0", "exited:2", "killed:9"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed %v, want %v", got, want)
		}
	}
}

// TestLastMeaningfulDaemonError pins the ExecStartPre filter. The unit's own
// `ExecStartPre=-/usr/bin/docker stop|rm nhp-server` emits "No such container"
// on every clean start, INCLUDING the successful retry after a failed start —
// so it is the last daemon error in the journal, and taking the last line
// naively reports the harmless one and hides the real cause.
func TestLastMeaningfulDaemonError(t *testing.T) {
	t.Parallel()

	journal := strings.Join([]string{
		"Error response from daemon: No such container: nhp-server",
		"docker: Error response from daemon: failed to create task for container: " +
			"failed to initialize logging driver: failed to create Cloudwatch log stream.",
		"nhp-server.service: Main process exited, code=exited, status=125/n/a",
		"Error response from daemon: No such container: nhp-server",
		"Started nhp-server.service.",
	}, "\n")

	got := lastMeaningfulDaemonError(journal)
	if !strings.Contains(got, "failed to create Cloudwatch log stream") {
		t.Fatalf("expected the real cause, got %q", got)
	}
	if strings.Contains(got, "No such container") {
		t.Fatalf("reported the benign ExecStartPre noise: %q", got)
	}

	// A journal with only the benign noise yields nothing worth showing.
	if got := lastMeaningfulDaemonError("Error response from daemon: No such container: nhp-server"); got != "" {
		t.Fatalf("expected no reportable daemon error, got %q", got)
	}
}
