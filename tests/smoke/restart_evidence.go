//go:build smoke

package smoke

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// restart_evidence.go answers one question: when systemd's NRestarts counter
// on an nhp-server instance is non-zero, did the SERVER crash, or did docker
// fail to start the container at all?
//
// The smoke suite used to conclude "crash" from the counter alone and name the
// PR #1096 panic class in its failure message. That is not something NRestarts
// can support. Sandbox deploy 31340465407 (2026-08-09) produced:
//
//	Main process exited, code=exited, status=125/n/a
//	docker: Error response from daemon: failed to create task for container:
//	failed to initialize logging driver: failed to create Cloudwatch log stream
//
// 125 is docker's own exit code for "the run command itself failed" — here the
// awslogs driver could not create its CloudWatch log stream. The container
// never started, no Go code ran, and systemd's Restart=always/RestartSec=5
// recovered it in six seconds. The blue/green deploy gate made the same
// mistake and paid four hours of blocked deploys for it; this file keeps the
// smoke suite from repeating it.
//
// The load-bearing signal is the unit's EXIT STATUS, not the restart count. A
// Go panic terminates the process with status 2 and any signal death reports a
// non-125 status, so a real crash is caught even when its stack trace never
// reaches the journal — which matters, because the unit runs `docker run
// --log-driver=awslogs` and container output goes to CloudWatch. Panic and OOM
// evidence sharpen the message; the exit status is what keeps the verdict safe.
//
// `systemctl show -p ExecMainStatus` is deliberately NOT used: it reports the
// SURVIVING process's status, so it reads 0 on exactly the instance whose
// previous start attempt failed.
//
// ---------------------------------------------------------------------------
// Relationship to the deploy gate
// ---------------------------------------------------------------------------
// .github/scripts/classify-nhp-server-restart-evidence.sh implements the same
// decision for the blue/green post-switch gate. The two cannot share code: that
// one runs as shell on a GitHub runner and collects its evidence with a piped
// on-instance script, which this suite may not do (CLAUDE.md rule 8 — every
// probe is a named constant — plus the rejectPatterns tripwire that bars pipes
// and command substitution outright).
//
// They share a corpus instead: tests/fixtures/nhp-server-restart-evidence/.
// Both are driven over it, so a change to one decision table that is not made
// in the other turns red. Do not edit this table without editing that script.

// Evidence-gathering probes. Each is a single read-only command with no shell
// metacharacters, so it satisfies both the named-helper rule and the
// reject-list. They are issued ONLY when NRestarts is non-zero — the healthy
// path stays exactly one SSM round-trip per instance.
//
// Scoped to `-b` (this boot) to match NRestarts' own per-boot semantics, which
// is sound because this fence runs against a freshly-deployed fleet.
//
// journalctl's own --grep does the filtering. That is not a stylistic choice:
// piping to grep would trip rejectPatterns, and shipping the whole journal
// back would risk SSM's 24,000-character output truncation silently dropping
// the very lines the verdict depends on.
//
// EVERY --grep pattern is single-quoted. SSM runs these through a shell, so an
// unquoted pattern containing a space is word-split: `--grep=Main process
// exited` arrives as `--grep=Main` plus two positional args, journalctl rejects
// `process` as a match (matches must be FIELD=VALUE), and the probe errors —
// which this fence reports as "cannot confirm whether this was an application
// crash" on every instance that actually restarted. Single quotes also protect
// `[0-9]` from glob expansion. Fenced by
// TestRestartEvidenceProbeArgsSurviveTheShell.
//
// The -n bound means something different here than in the deploy gate's probe.
// With --grep, journalctl applies --lines to the MATCHING entries, so 400 is
// "the last 400 exit lines". The gate's on-instance script greps within the
// last 20000 RAW journal lines instead. The two agree whenever the evidence
// sits inside both windows, which on a freshly-deployed instance it does; they
// could differ on an instance chatty enough to push an early restart past
// 20000 lines, where this side is the more complete of the two. Do not
// "align" these numbers — they are not the same quantity.
const (
	// cmdSystemdActiveStateNhpServer and cmdSystemdSubStateNhpServer prove
	// the unit actually converged. "Self-healed" has to mean healed.
	cmdSystemdActiveStateNhpServer = "systemctl show nhp-server --property=ActiveState --value"
	cmdSystemdSubStateNhpServer    = "systemctl show nhp-server --property=SubState --value"

	// cmdJournalNhpServerExits returns systemd's own "Main process exited,
	// code=<c>, status=<n>/..." lines — the exit statuses that separate a
	// container-start failure (125) from the server process dying.
	cmdJournalNhpServerExits = "journalctl -u nhp-server -b --no-pager -o cat -n 400 --grep='Main process exited'"

	// The three Go panic/fatal markers, counted as LINES and summed into
	// restartEvidence.Panics. Corroboration for the message, not the safety
	// property (see the file header).
	//
	// Three probes rather than one alternation because the reject-list bars
	// `|` from a probe string outright. They must stay in lockstep with the
	// single `grep -cE "^(panic: |fatal error: |goroutine [0-9]+
	// \[running\]:)"` in the deploy gate's on-instance script: PANICS is what
	// selects the "#1096 panic class" wording, so a marker matched on one
	// side only means the two callers diagnose the same crash differently.
	// A `fatal error:` (concurrent map write, out of memory) is a runtime
	// abort with no `panic:` line at all, and one panic emits both its
	// `panic:` header and a `goroutine N [running]:` line — the gate counts
	// both, so summing three probes reproduces its count exactly.
	// Fenced by the shared journal corpus.
	//
	// One residual the corpus cannot see: journalctl's --grep is smart-case,
	// so an all-lowercase pattern matches case-INSENSITIVELY. These three
	// patterns are all lowercase, while the gate's `grep -cE` is
	// case-sensitive — so a MESSAGE beginning `Panic: ` would be counted here
	// and not there. The other three probes below contain uppercase, which
	// keeps journalctl case-sensitive and leaves them aligned. The Go runtime
	// only ever emits these markers lowercase, so no real crash diverges, and
	// neither fence can reach it: the corpus replays canonical text, and Go's
	// regexp stand-in for --grep is case-sensitive either way. Left as a
	// documented residual rather than papered over with a (?i) that would
	// make the emulation lie about the gate.
	cmdJournalNhpServerPanics        = "journalctl -u nhp-server -b --no-pager -o cat -n 400 --grep='^panic: '"
	cmdJournalNhpServerFatalErrors   = "journalctl -u nhp-server -b --no-pager -o cat -n 400 --grep='^fatal error: '"
	cmdJournalNhpServerGoroutineDump = "journalctl -u nhp-server -b --no-pager -o cat -n 400 --grep='^goroutine [0-9]+ \\[running\\]:'"

	// cmdJournalNhpServerOOM matches systemd's own unit-scoped OOM message.
	// The kernel's "Out of memory: Killed process" line is NOT visible here:
	// kernel records carry no _SYSTEMD_UNIT, so `journalctl -u` excludes
	// them. A container OOM also surfaces as exit 137 (128+SIGKILL), which
	// the exit-status branch already fails on.
	//
	// -n was 50 where every other probe used 400; harmonized deliberately, so
	// the shared bound documented above is one number rather than a special
	// case a reader has to explain. Strictly a wider window on a line that is
	// rare to begin with, so it cannot lose evidence — but it is a behaviour
	// change, not a consequence of the quoting fix.
	cmdJournalNhpServerOOM = "journalctl -u nhp-server -b --no-pager -o cat -n 400 --grep='killed by the OOM killer'"

	// cmdJournalNhpServerDaemonErrors returns docker daemon refusals so the
	// failure message can name the actual cause. Filtered in Go, not here:
	// the unit's own `ExecStartPre=-/usr/bin/docker stop|rm nhp-server`
	// emits "No such container" on every clean start, so it is the LAST
	// daemon error after a failed start that systemd then retried
	// successfully. Reporting it would name the harmless line and hide the
	// real one.
	cmdJournalNhpServerDaemonErrors = "journalctl -u nhp-server -b --no-pager -o cat -n 400 --grep='Error response from daemon:'"
)

// panicMarkerProbes are the three probes whose line counts SUM into
// restartEvidence.Panics, reproducing the gate's single alternation.
//
// One list, not a loop body repeated per caller: the production collector and
// the journal-corpus fence both range over this, so adding a fourth marker is
// one edit. Hand-copying the subset is the seam journalEvidenceProbes was
// introduced to close, and a marker added to production but not to the fence
// would only be caught if some fixture happened to exercise it alone.
var panicMarkerProbes = []string{
	cmdJournalNhpServerPanics,
	cmdJournalNhpServerFatalErrors,
	cmdJournalNhpServerGoroutineDump,
}

// journalEvidenceProbes is every journal probe the collector issues, in the
// order it issues them. Named so the shell-safety fence and the corpus fence
// enumerate exactly what production sends rather than a hand-copied list that
// can fall behind.
var journalEvidenceProbes = slices.Concat(
	[]string{cmdJournalNhpServerExits},
	panicMarkerProbes,
	[]string{cmdJournalNhpServerOOM, cmdJournalNhpServerDaemonErrors},
)

// maxSelfHealedRestarts bounds how much container-start flapping still counts
// as "self-healed". A transient CloudWatch Logs or daemon blip costs one or
// two attempts; a dozen is an infrastructure fault an operator should see even
// though the fleet happens to be up.
//
// MUST match MAX_SELF_HEALED_RESTARTS's default in
// .github/scripts/classify-nhp-server-restart-evidence.sh. The shared corpus
// pins it from both sides.
const maxSelfHealedRestarts = 2

// restartVerdict is the classification of a non-zero NRestarts counter.
type restartVerdict string

const (
	verdictClean           restartVerdict = "clean"
	verdictInfraSelfHealed restartVerdict = "infra_selfhealed"
	verdictAppCrash        restartVerdict = "app_crash"
	verdictInfraUnstable   restartVerdict = "infra_unstable"
	verdictIndeterminate   restartVerdict = "indeterminate"
)

// passes reports whether this verdict lets the deploy-stability fence pass.
// Only "nothing restarted" and "docker could not start the container and
// systemd already fixed it" do.
func (v restartVerdict) passes() bool {
	return v == verdictClean || v == verdictInfraSelfHealed
}

// restartEvidence is what the probes collect. Field names mirror the keys in
// the shell probe's report so the shared corpus reads the same on both sides.
type restartEvidence struct {
	NRestarts   int
	ActiveState string
	SubState    string
	// Exits holds "code:status" pairs in journal order, e.g. "exited:125".
	Exits     []string
	Panics    int
	OOM       int
	DaemonErr string

	// malformed records why the evidence could not be trusted. Non-empty
	// forces verdictIndeterminate — we fail closed rather than guess.
	malformed string
}

// classifyRestartEvidence renders the verdict and a human-readable detail that
// states what was OBSERVED. The detail names PR #1096 only when a panic was
// actually seen; asserting it unconditionally is the bug this replaces.
//
// Mirror of .github/scripts/classify-nhp-server-restart-evidence.sh. Keep the
// branch ORDER identical — the corpus pins the outcomes, not the sequence, so
// a reordering that changes precedence would only show up as a corpus failure
// if a case happens to straddle the two branches.
func classifyRestartEvidence(ev restartEvidence) (restartVerdict, string) {
	if ev.malformed != "" {
		return verdictIndeterminate, fmt.Sprintf(
			"%s — cannot classify the restart", ev.malformed)
	}
	if ev.NRestarts == 0 {
		return verdictClean, "NRestarts=0"
	}

	// A status=0 exit is the deploy's own stop path, not a failed start.
	var nonzero []string
	for _, e := range ev.Exits {
		if idx := strings.LastIndex(e, ":"); idx >= 0 && e[idx+1:] != "0" {
			nonzero = append(nonzero, e)
		}
	}

	observed := fmt.Sprintf("NRestarts=%d", ev.NRestarts)
	if len(nonzero) > 0 {
		observed += "; abnormal unit exits: " + strings.Join(nonzero, " ")
	} else {
		observed += "; no abnormal unit exit recorded in the journal"
	}
	if ev.Panics == 0 {
		observed += "; Go panic in journal: absent"
	} else {
		observed += "; Go panic in journal: PRESENT"
	}
	if ev.OOM == 0 {
		observed += "; OOM kill: absent"
	} else {
		observed += "; OOM kill: PRESENT"
	}
	observed += fmt.Sprintf("; unit now: %s/%s", ev.ActiveState, ev.SubState)

	// Panic evidence is CORROBORATION, not its own decision branch. The verdict
	// is carried by the exit status — a panicking process exits 2, so the
	// non-125 branch below catches a real panic whether or not its stack trace
	// reached the journal. Pre-empting that with `Panics != 0` made the panic
	// grep decisive, which is how an application log line beginning at column 0
	// with `panic: ` could turn an unrelated container-start self-heal into a
	// claimed #1096 regression.
	//
	// OOM stays decisive, unlike panic text, because it is systemd's own
	// unit-scoped statement that it killed the process — not a string that
	// application output can forge.
	if ev.OOM != 0 {
		return verdictAppCrash, observed + " — the server process was killed by the OOM killer during this deploy. " +
			"Check the instance's memory headroom and the server's allocation profile before re-deploying."
	}

	const investigate = "Investigate journalctl -u nhp-server on this instance before re-deploying."

	containerStartFailures := 0
	for _, e := range nonzero {
		if e == "exited:125" {
			containerStartFailures++
			continue
		}
		if ev.Panics != 0 {
			return verdictAppCrash, observed + fmt.Sprintf(
				" — exit %s with a Go panic in the journal: the server process panicked during "+
					"this deploy. This is the regression class fixed by PR #1096 (panic: send on "+
					"closed channel). %s", e, investigate)
		}
		return verdictAppCrash, observed + fmt.Sprintf(
			" — exit %s is the server process terminating abnormally, not a container-start "+
				"failure (docker reports its own failures as exit 125). %s", e, investigate)
	}

	if ev.DaemonErr != "" {
		observed += "; last docker daemon error: " + ev.DaemonErr
	}

	// Restarts nothing accounts for. With a panic marker also present this is
	// the likely shape of a real panic whose exit line never reached the
	// scanned journal, so say so rather than reporting a bare accounting gap.
	if containerStartFailures < ev.NRestarts {
		if ev.Panics != 0 {
			return verdictIndeterminate, observed + fmt.Sprintf(
				" — only %d of %d restart(s) are explained by a container-start failure, and a "+
					"Go panic marker is present without a matching exit line. Most likely a real "+
					"panic whose exit line was dropped from the journal. %s",
				containerStartFailures, ev.NRestarts, investigate)
		}
		return verdictIndeterminate, observed + fmt.Sprintf(
			" — only %d of %d restart(s) are explained by a container-start failure; the "+
				"remainder has no recorded cause. %s",
			containerStartFailures, ev.NRestarts, investigate)
	}

	if ev.ActiveState != "active" || ev.SubState != "running" {
		return verdictInfraUnstable, observed + " — every restart is a docker container-start failure " +
			"(exit 125), so no nhp-server code ran, but the unit has not converged to active/running."
	}

	if ev.NRestarts > maxSelfHealedRestarts {
		return verdictInfraUnstable, observed + fmt.Sprintf(
			" — every restart is a docker container-start failure (exit 125) and the unit is "+
				"running now, but %d restarts exceeds the self-heal budget of %d. Treat this as an "+
				"infrastructure fault (container runtime, log driver, or registry), not an "+
				"nhp-server defect.", ev.NRestarts, maxSelfHealedRestarts)
	}

	detail := observed + " — docker failed to start the container (exit 125), " +
		"so no nhp-server code ran; systemd's Restart=always policy recovered it and the unit is " +
		"healthy. Not an application crash."

	// A panic marker here caused NONE of the restarts: every one is accounted
	// for by an exit 125, which a panicking process cannot produce. So it is a
	// recovered panic, or a log line beginning at column 0 with a panic marker.
	// Surfaced loudly, but NOT made the verdict — failing here would make panic
	// text decisive exactly where the exit-status accounting is complete and
	// says the deploy is fine.
	if ev.Panics != 0 {
		detail += " NOTE: a Go panic marker appears in this boot's journal but caused none of " +
			"the restarts — most likely a recovered panic or a log line beginning with a panic " +
			"marker. Worth a look; not a reason to block the deploy."
	}

	return verdictInfraSelfHealed, detail
}

// maxCounterDigits bounds a counter to what the shell classifier's
// `^[0-9]{1,9}$` guard accepts. The bound is load-bearing on BOTH sides: an
// all-digit value that overflows bash's signed 64-bit arithmetic WRAPS rather
// than erroring, and a wrapped NRestarts passed the accounting and budget
// comparisons all the way to infra_selfhealed — the gate going green on a
// corrupted counter.
const maxCounterDigits = 9

// parseCounter accepts exactly what the shell's `^[0-9]{1,9}$` accepts, on the
// UNTRIMMED value. Stricter than strconv.Atoi, which takes a sign and which —
// with a TrimSpace — let " 1", "+1" and "-1" through here while the shell
// rejected all three. On "-1" that difference was not cosmetic: Go reached
// infra_selfhealed and PASSED the gate where the shell failed closed.
func parseCounter(value string) (int, bool) {
	if value == "" || len(value) > maxCounterDigits {
		return 0, false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	// Cannot fail: at most 9 digits fits int on every supported platform.
	n, _ := strconv.Atoi(value)
	return n, true
}

// counterMalformed is the single wording for a rejected counter, so a reworded
// message cannot land on some counters and not others.
func counterMalformed(label, value string) string {
	return fmt.Sprintf("evidence report carries a non-numeric or implausibly large %s (\"%s\")",
		label, value)
}

// parseRestartEvidenceReport reads the key=value report emitted by the deploy
// gate's on-instance probe. It exists so the smoke suite can be driven over the
// SAME corpus as that gate — the probes below build a restartEvidence directly.
func parseRestartEvidenceReport(report string) restartEvidence {
	var ev restartEvidence
	seen := map[string]bool{}

	for _, line := range strings.Split(report, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// An empty value is indistinguishable from an absent key to the shell
		// classifier, which initialises every field to "" and tests -z. Treat it
		// the same here, or `PANICS=` yields "missing PANICS" there and
		// "non-numeric" here for one identical report. DAEMONERR is optional and
		// legitimately empty, and is not in the required set below.
		if value == "" {
			continue
		}
		seen[key] = true
		switch key {
		case "NRESTARTS":
			n, ok := parseCounter(value)
			if !ok {
				ev.malformed = counterMalformed("NRestarts", value)
				return ev
			}
			ev.NRestarts = n
		case "ACTIVESTATE":
			ev.ActiveState = value
		case "SUBSTATE":
			ev.SubState = value
		case "EXITS":
			ev.Exits = splitExits(value)
		case "PANICS":
			n, ok := parseCounter(value)
			if !ok {
				ev.malformed = counterMalformed("panic-line count", value)
				return ev
			}
			ev.Panics = n
		case "OOM":
			n, ok := parseCounter(value)
			if !ok {
				ev.malformed = counterMalformed("OOM-line count", value)
				return ev
			}
			ev.OOM = n
		case "DAEMONERR":
			ev.DaemonErr = value
		}
	}

	for _, required := range []string{"NRESTARTS", "ACTIVESTATE", "SUBSTATE", "PANICS", "OOM"} {
		if !seen[required] {
			ev.malformed = "evidence report is missing " + required
			return ev
		}
	}
	return ev
}

// splitExits parses "exited:125,exited:0," into its entries.
func splitExits(raw string) []string {
	var out []string
	// Deliberately does NOT trim: the shell compares each entry exactly with
	// `[[ "$entry" == "exited:125" ]]`, so trimming here made `exited:125 ,` a
	// container-start failure (pass) in Go and an abnormal exit (fail) in the
	// shell — a verdict-level divergence with Go on the permissive side.
	for _, e := range strings.Split(raw, ",") {
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

// parseSystemdExitLines extracts "code:status" from systemd's
//
//	nhp-server.service: Main process exited, code=exited, status=125/n/a
//
// lines. Anything that does not match that shape is ignored rather than
// guessed at; an unparsed exit line simply leaves a restart unexplained, which
// the classifier fails closed on.
func parseSystemdExitLines(journal string) []string {
	var out []string
	for _, line := range strings.Split(journal, "\n") {
		idx := strings.Index(line, "Main process exited, code=")
		if idx < 0 {
			continue
		}
		rest := line[idx+len("Main process exited, code="):]
		code, rest, ok := strings.Cut(rest, ", status=")
		if !ok {
			continue
		}
		status := rest
		// "125/n/a" -> "125"; also handles a bare "125".
		if cut, _, found := strings.Cut(status, "/"); found {
			status = cut
		}
		status = strings.TrimSpace(status)
		if _, err := strconv.Atoi(status); err != nil {
			continue
		}
		out = append(out, strings.TrimSpace(code)+":"+status)
	}
	return out
}

// lastMeaningfulDaemonError returns the last docker daemon refusal worth
// showing an operator, skipping the "No such container" noise the unit's own
// ExecStartPre emits on every clean start (including the successful retry
// after a failed one, which is why "last line wins" alone reports the wrong
// thing).
//
// Equivalent to the gate's
//
//	grep -oE "Error response from daemon: .*" | grep -v "No such container" |
//	  tail -n 1 | tr -d "\r" | cut -c1-200 | tr -d "\n"
//
// for canonical docker output — which always emits `Error response from
// daemon: <msg>`, with "No such container" appearing only AS the message body —
// and the journal corpus pins that. It is NOT equivalent for constructed input,
// in at least three ways, all verified:
//
//   - Filter scope. The shell re-extracts marker-to-EOL and filters that
//     substring; this tests the whole line. On `No such container … : Error
//     response from daemon: <real error>` the shell keeps the real error and
//     this drops the line.
//   - Required separator. The shell regex requires the colon-space; the marker
//     here does not. On `…daemon:<msg>` with no space this reports the message
//     and the shell reports nothing.
//   - Trailing whitespace. `grep -o` preserves it; TrimSpace here removes it.
//
// Deliberately not chased into exact equivalence. DAEMONERR only sharpens the
// operator message — no branch of classifyRestartEvidence reads it — so a
// divergence on input docker cannot produce costs nothing, while matching a
// grep pipeline byte-for-byte in Go means also reproducing `grep -o`'s
// multiple-matches-per-line and `cut -c`'s locale-dependent character
// counting. That is a larger surface than the thing it would protect. The
// corpus is what guarantees agreement on journals that actually occur.
func lastMeaningfulDaemonError(journal string) string {
	const marker = "Error response from daemon:"
	found := ""
	for _, line := range strings.Split(journal, "\n") {
		idx := strings.Index(line, marker)
		if idx < 0 || strings.Contains(line, "No such container") {
			continue
		}
		found = strings.TrimSpace(line[idx:])
	}
	if len(found) > 200 {
		found = found[:200]
	}
	return found
}

// countNonEmptyLines counts the lines journalctl --grep returned. journalctl
// prints "-- No entries --" on stderr and nothing on stdout when a pattern
// matches nothing, so an empty result is a clean zero.
func countNonEmptyLines(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// probeServerRestartEvidence collects everything needed to classify a
// non-zero NRestarts counter. Callers MUST have already established that the
// counter is non-zero (via probeServerNRestarts) — this issues eight extra SSM
// round-trips (ActiveState, SubState, exits, three panic markers, OOM, daemon
// errors) and there is nothing to explain on a healthy instance.
//
// Fails closed: any probe error is returned, and the caller treats an error as
// "cannot confirm the deploy was clean".
// isJournalNoMatch reports whether err is EXACTLY journalctl's no-matches
// shape: a Failed invocation whose command exited 1 with nothing on stderr.
// Status is checked because sendShellScript returns the typed error for
// Cancelled and TimedOut too; those must propagate even if they ever carried
// ResponseCode 1 (SSM normally reports -1 there, but the guard should not
// rest on that).
func isJournalNoMatch(err error) bool {
	var failed *ssmCommandFailed
	if !errors.As(err, &failed) ||
		failed.Status != "Failed" ||
		failed.ResponseCode != 1 {
		return false
	}
	// SSM's shell wrapper synthesizes this exact stderr for a non-zero exit
	// whose command wrote nothing to stderr -- measured live on the dispatched
	// smoke run (i-0209b63d922e839b0): journalctl --grep with no matches
	// surfaces as Failed / code 1 / this string, never as an empty stderr. A
	// command that produced its OWN stderr still propagates.
	switch strings.TrimSpace(failed.Stderr) {
	case "", "failed to run commands: exit status 1":
		return true
	}
	return false
}

// sendJournalGrep issues a journalctl --grep probe and maps its documented
// no-matches outcome to an empty result: journalctl exits 1 when no entries
// match the pattern, which SSM reports as a Failed invocation. That is the
// INNOCENT outcome for every probe below -- a restarted unit with no panic,
// no fatal error, no OOM line -- and treating it as a probe failure made the
// evidence collector fail closed on precisely the restarts it exists to
// clear (measured live on i-0209b63d922e839b0: a docker exit-125 blip failed
// the deploy-stability smoke twice because '^panic: ' matched nothing).
// Exit codes above 1, and every other failure shape, still propagate.
func sendJournalGrep(ctx context.Context, instanceID, cmd string) (string, error) {
	out, err := sendShellScript(ctx, instanceID, cmd)
	if err != nil {
		if isJournalNoMatch(err) {
			return "", nil
		}
		return "", err
	}
	return out, nil
}

// probeServerRestartEvidence collects everything needed to classify a
// non-zero NRestarts counter; see the doc block above sendJournalGrep for why
// the journal probes tolerate the no-matches exit.
func probeServerRestartEvidence(ctx context.Context, instanceID string, nRestarts int) (restartEvidence, error) {
	ev := restartEvidence{NRestarts: nRestarts}

	activeState, err := sendShellScript(ctx, instanceID, cmdSystemdActiveStateNhpServer)
	if err != nil {
		return ev, fmt.Errorf("probe ActiveState: %w", err)
	}
	ev.ActiveState = strings.TrimSpace(activeState)

	subState, err := sendShellScript(ctx, instanceID, cmdSystemdSubStateNhpServer)
	if err != nil {
		return ev, fmt.Errorf("probe SubState: %w", err)
	}
	ev.SubState = strings.TrimSpace(subState)

	exitLines, err := sendJournalGrep(ctx, instanceID, cmdJournalNhpServerExits)
	if err != nil {
		return ev, fmt.Errorf("probe journal exit lines: %w", err)
	}
	ev.Exits = parseSystemdExitLines(exitLines)

	// Summed, not one probe: see panicMarkerProbes. The gate's single
	// alternation counts all three marker kinds as panic lines, and PANICS
	// only ever selects wording, so partial coverage here would make the two
	// callers describe the same crash differently.
	for _, cmd := range panicMarkerProbes {
		lines, err := sendJournalGrep(ctx, instanceID, cmd)
		if err != nil {
			return ev, fmt.Errorf("probe journal panic lines: %w", err)
		}
		ev.Panics += countNonEmptyLines(lines)
	}

	oomLines, err := sendJournalGrep(ctx, instanceID, cmdJournalNhpServerOOM)
	if err != nil {
		return ev, fmt.Errorf("probe journal OOM lines: %w", err)
	}
	ev.OOM = countNonEmptyLines(oomLines)

	// Best-effort: the daemon error only sharpens the message, so a failure
	// here must not turn an otherwise-classifiable restart into a red deploy.
	if daemonLines, derr := sendJournalGrep(ctx, instanceID, cmdJournalNhpServerDaemonErrors); derr == nil {
		ev.DaemonErr = lastMeaningfulDaemonError(daemonLines)
	}

	return ev, nil
}
