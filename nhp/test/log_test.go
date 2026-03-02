package test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/OpenNHP/opennhp/nhp/log"
)

func TestLog(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nhp-log-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tlog := log.NewLogger("NHP-LogTest", log.LogLevelDebug, tmpDir, "logtest")
	log.SetGlobalLogger(tlog)

	log.Info("Info log test")
	log.Debug("Debug log test")
	log.Close()
}

// readLogFile reads the log file for today's date from the given directory.
func readLogFile(t *testing.T, dir, name string) string {
	t.Helper()
	date := time.Now().Format("2006-01-02")
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.log", name, date))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read log file %s: %v", path, err)
	}
	return string(data)
}

// logEntry represents a single JSON log line for test assertions.
type logEntry struct {
	Time      string `json:"time"`
	Level     string `json:"level"`
	Msg       string `json:"msg"`
	Component string `json:"component"`
	Source    struct {
		Function string `json:"function"`
		File     string `json:"file"`
		Line     int    `json:"line"`
	} `json:"source"`
}

// parseLogLines parses newline-delimited JSON log output into entries.
func parseLogLines(t *testing.T, raw string) []logEntry {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	entries := make([]logEntry, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry logEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON log line: %v\nline: %s", err, line)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestLog_JSONFormat(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nhp-json-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	l := log.NewLogger("NHP-Test", log.LogLevelTrace, tmpDir, "jsontest")
	l.Info("hello %s", "world")
	l.Error("something failed: %d", 42)
	l.Warning("low memory: %d%%", 90)
	l.Debug("debug detail")
	l.Trace("trace detail")

	time.Sleep(200 * time.Millisecond)
	l.Close()

	raw := readLogFile(t, tmpDir, "jsontest")
	entries := parseLogLines(t, raw)

	if len(entries) != 5 {
		t.Fatalf("expected 5 log entries, got %d", len(entries))
	}

	tests := []struct {
		idx       int
		level     string
		msg       string
		component string
	}{
		{0, "INFO", "hello world", "NHP-Test"},
		{1, "ERROR", "something failed: 42", "NHP-Test"},
		{2, "WARNING", "low memory: 90%", "NHP-Test"},
		{3, "DEBUG", "debug detail", "NHP-Test"},
		{4, "TRACE", "trace detail", "NHP-Test"},
	}

	for _, tc := range tests {
		e := entries[tc.idx]
		if e.Level != tc.level {
			t.Errorf("entry[%d]: expected level=%q, got %q", tc.idx, tc.level, e.Level)
		}
		if e.Msg != tc.msg {
			t.Errorf("entry[%d]: expected msg=%q, got %q", tc.idx, tc.msg, e.Msg)
		}
		if e.Component != tc.component {
			t.Errorf("entry[%d]: expected component=%q, got %q", tc.idx, tc.component, e.Component)
		}
		if e.Time == "" {
			t.Errorf("entry[%d]: time field is empty", tc.idx)
		}
		if e.Source.File == "" {
			t.Errorf("entry[%d]: source.file is empty", tc.idx)
		}
	}
}

func TestLog_AuditSeparateFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nhp-audit-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	l := log.NewLogger("NHP-Audit", log.LogLevelAudit, tmpDir, "auditlog")
	l.Info("info message")
	l.Audit("security event: %s", "login")
	l.Transaction("tx: %s", "commit")

	time.Sleep(200 * time.Millisecond)
	l.Close()

	// Main log should have info only (audit/transaction go to audit writer)
	mainEntries := parseLogLines(t, readLogFile(t, tmpDir, "auditlog"))
	auditEntries := parseLogLines(t, readLogFile(t, tmpDir, "auditlog-audit"))

	hasInfo := false
	for _, e := range mainEntries {
		if e.Msg == "info message" {
			hasInfo = true
		}
	}
	if !hasInfo {
		t.Error("expected info message in main log file")
	}

	if len(auditEntries) != 2 {
		t.Fatalf("expected 2 entries in audit log, got %d", len(auditEntries))
	}
	if auditEntries[0].Level != "AUDIT" {
		t.Errorf("expected AUDIT level, got %q", auditEntries[0].Level)
	}
	if auditEntries[1].Level != "TRANSACTION" {
		t.Errorf("expected TRANSACTION level, got %q", auditEntries[1].Level)
	}
}

func TestLog_LevelFiltering(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nhp-level-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// LogLevelError only allows Error, Warning, Critical
	l := log.NewLogger("NHP-Level", log.LogLevelError, tmpDir, "leveltest")
	l.Error("error msg")
	l.Warning("warning msg")
	l.Info("should not appear")
	l.Debug("should not appear")

	time.Sleep(200 * time.Millisecond)
	l.Close()

	entries := parseLogLines(t, readLogFile(t, tmpDir, "leveltest"))
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (error+warning), got %d", len(entries))
	}
	if entries[0].Level != "ERROR" {
		t.Errorf("expected ERROR, got %q", entries[0].Level)
	}
	if entries[1].Level != "WARNING" {
		t.Errorf("expected WARNING, got %q", entries[1].Level)
	}
}

func TestLog_GlobalLogger(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nhp-global-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	l := log.NewLogger("NHP-Global", log.LogLevelInfo, tmpDir, "globaltest")
	log.SetGlobalLogger(l)

	// Global functions should write to the same file
	log.Info("global info")
	log.Error("global error")

	time.Sleep(200 * time.Millisecond)
	log.Close()

	entries := parseLogLines(t, readLogFile(t, tmpDir, "globaltest"))
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 global log entries, got %d", len(entries))
	}

	// Source should point to this test file, not globalLog.go
	for _, e := range entries {
		if strings.Contains(e.Source.File, "globalLog.go") {
			t.Errorf("source should point to caller, not globalLog.go: %s:%d", e.Source.File, e.Source.Line)
		}
	}
}

func TestLog_SubLogger(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nhp-sub-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	parent := log.NewLogger("Parent", log.LogLevelInfo, tmpDir, "subtest")
	child := parent.NewSubLogger("Child", log.LogLevelInfo)

	parent.Info("parent message")
	child.Info("child message")

	time.Sleep(200 * time.Millisecond)
	parent.Close()

	// Both should write to the same file
	entries := parseLogLines(t, readLogFile(t, tmpDir, "subtest"))
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Component != "Parent" {
		t.Errorf("expected component=Parent, got %q", entries[0].Component)
	}
	if entries[1].Component != "Child" {
		t.Errorf("expected component=Child, got %q", entries[1].Component)
	}
}

func TestLog_NewLoggerDefine_AllMethodsSafe(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nhp-define-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// NewLoggerDefine should have all methods initialized (no nil panics)
	l := log.NewLoggerDefine("", log.LogLevelTrace, tmpDir, "definetest")

	// None of these should panic
	l.Info("info")
	l.Warning("warning")
	l.Error("error")
	l.Critical("critical")
	l.Debug("debug")
	l.Trace("trace")
	l.Verbose("verbose")
	l.Stats("stats")
	l.Audit("audit")
	l.Transaction("transaction")
	l.Evaluate("evaluate")

	time.Sleep(200 * time.Millisecond)
	l.Close()

	// Verify main log has the expected entries
	entries := parseLogLines(t, readLogFile(t, tmpDir, "definetest"))
	if len(entries) < 7 {
		t.Errorf("expected at least 7 entries in main log, got %d", len(entries))
	}
}

func TestLog_StdoutFallback(t *testing.T) {
	// Logger with empty dir and name should write to stdout without panic
	l := log.NewLogger("Stdout", log.LogLevelInfo, "", "")
	l.Info("stdout test")
	l.Close()
}

func TestLog_CloseTwice(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nhp-close-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	l := log.NewLogger("NHP-Close", log.LogLevelInfo, tmpDir, "closetest")
	l.Info("before close")

	// Double close should not panic
	l.Close()
	l.Close()
}
