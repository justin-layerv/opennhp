//go:build linux

package ac

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

// TestIsConntrackNoEntries fences the no-match exit-code +
// stderr-text inspection that distinguishes "no flows matched"
// (idempotent success) from real failures. Uses real subprocess
// invocations to produce authentic *exec.ExitError values rather
// than synthesizing them (os.ProcessState has unexported fields
// no test fixture can populate honestly).
func TestIsConntrackNoEntries(t *testing.T) {
	noMatchOutput := "0 flow entries have been deleted.\n"
	realErrOutput := "conntrack v1.4.6: Operation failed: invalid parameters\n"

	tests := []struct {
		name     string
		exitCode int
		output   string
		want     bool
	}{
		{"exit-1-with-noentries-text", 1, noMatchOutput, true},
		{"exit-1-with-real-error-text", 1, realErrOutput, false},
		{"exit-2-rejects", 2, noMatchOutput, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := exitErrForCode(t, tt.exitCode)
			if got := isConntrackNoEntries(err, tt.output); got != tt.want {
				t.Errorf("isConntrackNoEntries(exit %d, %q): got %v want %v",
					tt.exitCode, tt.output, got, tt.want)
			}
		})
	}

	t.Run("nil-err", func(t *testing.T) {
		if isConntrackNoEntries(nil, "anything") {
			t.Error("nil err must not be treated as no-entries")
		}
	})

	t.Run("non-exit-err", func(t *testing.T) {
		if isConntrackNoEntries(errors.New("context canceled"), "anything") {
			t.Error("non-ExitError must not be treated as no-entries")
		}
	})
}

func exitErrForCode(t *testing.T, code int) error {
	t.Helper()
	cmd := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code))
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError for exit %d, got %T: %v", code, err, err)
	}
	return exitErr
}
