package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunReturnsSetupErrorInsteadOfPanicking(t *testing.T) {
	missingTempRoot := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missingTempRoot)

	_, err := run(config{StartAt: time.Now()})
	if err == nil {
		t.Fatal("run returned nil error with an unusable temporary root")
	}
	if !strings.Contains(err.Error(), "create temporary SDK root") {
		t.Fatalf("run error = %q, want clean temporary-root context", err)
	}
}
