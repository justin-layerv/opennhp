//go:build smoke

package smoke

import (
	"os"
	"path/filepath"
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
		})
	}

	// A corpus that silently emptied would otherwise report success.
	if cases < 10 {
		t.Fatalf("only %d corpus case(s) found in %s — the shared decision table lost cases",
			cases, corpusDir)
	}
}

// TestRestartEvidenceMessagesStateObservations pins the message contract: the
// #1096 panic class is named only when a panic was actually observed. The
// original bug was not just the wrong verdict, it was a failure message that
// sent whoever read it hunting a panic that did not exist.
func TestRestartEvidenceMessagesStateObservations(t *testing.T) {
	t.Parallel()

	selfHealed := restartEvidence{
		NRestarts: 1, ActiveState: "active", SubState: "running",
		Exits: []string{"exited:0", "exited:125"},
		DaemonErr: "Error response from daemon: failed to create task for container: " +
			"failed to initialize logging driver: failed to create Cloudwatch log stream",
	}
	verdict, detail := classifyRestartEvidence(selfHealed)
	if verdict != verdictInfraSelfHealed {
		t.Fatalf("verdict = %q, want %q", verdict, verdictInfraSelfHealed)
	}
	if strings.Contains(detail, "#1096") {
		t.Errorf("self-heal message must not assert the #1096 panic class: %s", detail)
	}
	for _, want := range []string{
		"Go panic in journal: absent",
		"docker failed to start the container (exit 125)",
		"failed to create Cloudwatch log stream",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("self-heal message is missing %q: %s", want, detail)
		}
	}

	// A crash proven only by its exit status must report that status and
	// must NOT borrow the panic wording.
	_, detail = classifyRestartEvidence(restartEvidence{
		NRestarts: 1, ActiveState: "active", SubState: "running",
		Exits: []string{"exited:2"},
	})
	if strings.Contains(detail, "#1096") {
		t.Errorf("a panic-less crash must not assert the #1096 panic class: %s", detail)
	}
	if !strings.Contains(detail, "exit exited:2") {
		t.Errorf("a panic-less crash must report its exit status: %s", detail)
	}

	// ...while an observed panic still names it.
	_, detail = classifyRestartEvidence(restartEvidence{
		NRestarts: 1, ActiveState: "active", SubState: "running",
		Exits: []string{"exited:2"}, Panics: 3,
	})
	if !strings.Contains(detail, "#1096") {
		t.Errorf("an observed panic must still name #1096: %s", detail)
	}
}

// TestRestartEvidenceProbesPassRejectList proves the new probes are accepted
// by ssm_probe.go's tripwire. They are read-only single commands with no shell
// metacharacters — deliberately using journalctl's own --grep rather than a
// pipe, which the reject-list would (correctly) refuse.
func TestRestartEvidenceProbesPassRejectList(t *testing.T) {
	t.Parallel()

	for _, cmd := range []string{
		cmdSystemdActiveStateNhpServer,
		cmdSystemdSubStateNhpServer,
		cmdJournalNhpServerExits,
		cmdJournalNhpServerPanics,
		cmdJournalNhpServerOOM,
		cmdJournalNhpServerDaemonErrors,
	} {
		if err := sendShellScriptRaw(cmd); err != nil {
			t.Errorf("probe rejected by the reject-list: %q: %v", cmd, err)
		}
	}
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
