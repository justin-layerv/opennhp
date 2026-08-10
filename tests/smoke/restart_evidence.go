//go:build smoke

package smoke

import (
	"context"
	"fmt"
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
const (
	// cmdSystemdActiveStateNhpServer and cmdSystemdSubStateNhpServer prove
	// the unit actually converged. "Self-healed" has to mean healed.
	cmdSystemdActiveStateNhpServer = "systemctl show nhp-server --property=ActiveState --value"
	cmdSystemdSubStateNhpServer    = "systemctl show nhp-server --property=SubState --value"

	// cmdJournalNhpServerExits returns systemd's own "Main process exited,
	// code=<c>, status=<n>/..." lines — the exit statuses that separate a
	// container-start failure (125) from the server process dying.
	cmdJournalNhpServerExits = "journalctl -u nhp-server -b --no-pager -o cat -n 400 --grep=Main process exited"

	// cmdJournalNhpServerPanics counts Go panic headers. Corroboration for
	// the message, not the safety property (see the file header).
	cmdJournalNhpServerPanics = "journalctl -u nhp-server -b --no-pager -o cat -n 400 --grep=^panic:"

	// cmdJournalNhpServerOOM matches systemd's own unit-scoped OOM message.
	// The kernel's "Out of memory: Killed process" line is NOT visible here:
	// kernel records carry no _SYSTEMD_UNIT, so `journalctl -u` excludes
	// them. A container OOM also surfaces as exit 137 (128+SIGKILL), which
	// the exit-status branch already fails on.
	cmdJournalNhpServerOOM = "journalctl -u nhp-server -b --no-pager -o cat -n 50 --grep=killed by the OOM killer"

	// cmdJournalNhpServerDaemonErrors returns docker daemon refusals so the
	// failure message can name the actual cause. Filtered in Go, not here:
	// the unit's own `ExecStartPre=-/usr/bin/docker stop|rm nhp-server`
	// emits "No such container" on every clean start, so it is the LAST
	// daemon error after a failed start that systemd then retried
	// successfully. Reporting it would name the harmless line and hide the
	// real one.
	cmdJournalNhpServerDaemonErrors = "journalctl -u nhp-server -b --no-pager -o cat -n 400 --grep=Error response from daemon:"
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
		observed += fmt.Sprintf("; Go panic in journal: PRESENT (%d line(s))", ev.Panics)
	}
	if ev.OOM == 0 {
		observed += "; OOM kill: absent"
	} else {
		observed += "; OOM kill: PRESENT"
	}
	observed += fmt.Sprintf("; unit now: %s/%s", ev.ActiveState, ev.SubState)

	if ev.Panics != 0 {
		return verdictAppCrash, observed + " — the server process panicked during this deploy. " +
			"This is the regression class fixed by PR #1096 (panic: send on closed channel). " +
			"Investigate journalctl -u nhp-server on this instance before re-deploying."
	}
	if ev.OOM != 0 {
		return verdictAppCrash, observed + " — the server process was killed by the OOM killer during this deploy. " +
			"Check the instance's memory headroom and the server's allocation profile before re-deploying."
	}

	containerStartFailures := 0
	for _, e := range nonzero {
		if e != "exited:125" {
			return verdictAppCrash, observed + fmt.Sprintf(
				" — exit %s is the server process terminating abnormally, not a container-start "+
					"failure (docker reports its own failures as exit 125). Investigate "+
					"journalctl -u nhp-server on this instance before re-deploying.", e)
		}
		containerStartFailures++
	}

	if ev.DaemonErr != "" {
		observed += "; last docker daemon error: " + ev.DaemonErr
	}

	if containerStartFailures < ev.NRestarts {
		return verdictIndeterminate, observed + fmt.Sprintf(
			" — only %d of %d restart(s) are explained by a container-start failure; the "+
				"remainder has no recorded cause. Investigate journalctl -u nhp-server on this "+
				"instance before re-deploying.", containerStartFailures, ev.NRestarts)
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

	return verdictInfraSelfHealed, observed + " — docker failed to start the container (exit 125), " +
		"so no nhp-server code ran; systemd's Restart=always policy recovered it and the unit is " +
		"healthy. Not an application crash."
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
		seen[key] = true
		switch key {
		case "NRESTARTS":
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				ev.malformed = fmt.Sprintf("evidence report carries a non-numeric NRestarts (%q)", value)
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
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				ev.malformed = fmt.Sprintf("evidence report carries a non-numeric panic-line count (%q)", value)
				return ev
			}
			ev.Panics = n
		case "OOM":
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				ev.malformed = fmt.Sprintf("evidence report carries a non-numeric OOM-line count (%q)", value)
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
	for _, e := range strings.Split(raw, ",") {
		if e = strings.TrimSpace(e); e != "" {
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
// counter is non-zero (via probeServerNRestarts) — this issues five extra SSM
// round-trips and there is nothing to explain on a healthy instance.
//
// Fails closed: any probe error is returned, and the caller treats an error as
// "cannot confirm the deploy was clean".
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

	exitLines, err := sendShellScript(ctx, instanceID, cmdJournalNhpServerExits)
	if err != nil {
		return ev, fmt.Errorf("probe journal exit lines: %w", err)
	}
	ev.Exits = parseSystemdExitLines(exitLines)

	panicLines, err := sendShellScript(ctx, instanceID, cmdJournalNhpServerPanics)
	if err != nil {
		return ev, fmt.Errorf("probe journal panic lines: %w", err)
	}
	ev.Panics = countNonEmptyLines(panicLines)

	oomLines, err := sendShellScript(ctx, instanceID, cmdJournalNhpServerOOM)
	if err != nil {
		return ev, fmt.Errorf("probe journal OOM lines: %w", err)
	}
	ev.OOM = countNonEmptyLines(oomLines)

	// Best-effort: the daemon error only sharpens the message, so a failure
	// here must not turn an otherwise-classifiable restart into a red deploy.
	if daemonLines, derr := sendShellScript(ctx, instanceID, cmdJournalNhpServerDaemonErrors); derr == nil {
		ev.DaemonErr = lastMeaningfulDaemonError(daemonLines)
	}

	return ev, nil
}
