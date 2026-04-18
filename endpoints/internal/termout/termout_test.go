package termout

import (
	"os"
	"testing"
)

// TestIsTerminal verifies the TTY detector correctly identifies
// non-terminal file descriptors. Under production (docker awslogs,
// systemd journal) stdout is always a pipe or non-character-device
// file, so the banner and server-info output must drop ANSI codes.
// This test pins that contract so nobody reintroduces a change that
// makes isTerminal return true for a pipe.
//
// Fences the regression class described in the review of PR #1098:
// ANSI escapes mid-line break CloudWatch Logs metric-filter string
// matching.
func TestIsTerminal(t *testing.T) {
	t.Run("pipe is not a terminal", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		defer r.Close()
		defer w.Close()
		if isTerminal(r) {
			t.Errorf("isTerminal(pipe-read) = true, want false")
		}
		if isTerminal(w) {
			t.Errorf("isTerminal(pipe-write) = true, want false")
		}
	})

	t.Run("regular file is not a terminal", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "tty-detect-")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		defer f.Close()
		if isTerminal(f) {
			t.Errorf("isTerminal(regular-file) = true, want false")
		}
	})

	t.Run("nil file returns false without panicking", func(t *testing.T) {
		// Guards against a future refactor that wires a user-supplied
		// file handle through the API without a nil check. Today the
		// only caller is init() with os.Stdout (never nil), but cheap
		// insurance is cheap.
		if isTerminal(nil) {
			t.Errorf("isTerminal(nil) = true, want false")
		}
	})

	// Note: /dev/null is intentionally not tested. On Linux and macOS
	// it is a character device (ModeCharDevice set), so isTerminal
	// returns true for it. That is not a bug in production (nothing
	// reads /dev/null output) and matching it more precisely would
	// require platform-specific termios syscalls.
}

// TestShouldEnableColor pins the precedence matrix documented on
// ShouldEnableColor:
//
//  1. NO_COLOR disables regardless of everything else.
//  2. FORCE_COLOR / CLICOLOR_FORCE enables regardless of TTY state.
//  3. Otherwise, follow isTerminal(f).
//
// The TTY-positive path (f is a real terminal) cannot be synthesized
// from a test without a pty library. The ForceColor branch covers
// the "enable when not a TTY" case, which is the only production-
// relevant non-TTY-positive outcome.
func TestShouldEnableColor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	tests := []struct {
		name string
		env  ColorEnv
		want bool
	}{
		{"pipe + no env vars -> off (docker/systemd path)", ColorEnv{}, false},
		{"pipe + NO_COLOR -> off", ColorEnv{NoColor: true}, false},
		{"pipe + FORCE_COLOR -> on (CI-with-pipe-wants-color)", ColorEnv{ForceColor: true}, true},
		{"pipe + both set: NO_COLOR wins", ColorEnv{NoColor: true, ForceColor: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldEnableColor(r, tt.env); got != tt.want {
				t.Errorf("ShouldEnableColor(pipe, %+v) = %v, want %v", tt.env, got, tt.want)
			}
		})
	}
}

// TestParseForceColor pins the value interpretation for FORCE_COLOR
// and CLICOLOR_FORCE. Matches the de-facto convention used by widely
// adopted CLI color libraries: "0" / "false" / "" are explicit
// disables; anything else enables.
func TestParseForceColor(t *testing.T) {
	tests := []struct {
		label string
		in    string
		want  bool
	}{
		{"empty/unset", "", false},
		{"disable-zero", "0", false},
		{"disable-false-lower", "false", false},
		{"disable-false-upper", "FALSE", false},
		{"disable-false-mixed", "False", false},
		{"enable-one", "1", true},
		{"enable-two-supports-color-level", "2", true},
		{"enable-true", "true", true},
		{"enable-yes", "yes", true},
		{"enable-on", "on", true},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			if got := parseForceColor(tt.in); got != tt.want {
				t.Errorf("parseForceColor(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
