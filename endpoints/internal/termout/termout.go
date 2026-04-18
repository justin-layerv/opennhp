// Package termout centralizes terminal-aware ANSI color constants used
// by the nhp-server, nhp-ac, and nhp-agent startup banners and info
// blocks. Colors are emitted only when all of the following hold:
//
//   - NO_COLOR is unset (https://no-color.org/)
//   - stdout is an interactive terminal, OR FORCE_COLOR / CLICOLOR_FORCE
//     is set to a non-"0"/non-"false" value
//
// Under docker (any log driver), systemd, or a redirected pipe, the
// exported color variables are empty strings, so
//
//	fmt.Printf("%s%s%s", termout.Bold, "hi", termout.Reset)
//
// writes the payload only. This keeps CloudWatch Logs and journald
// output free of escape sequences — specifically, CloudWatch Logs
// metric filters that match on substrings of the startup banner do
// not need to account for ANSI bytes sitting mid-line.
//
// Env var precedence:
//   - NO_COLOR (any presence, even empty) disables colors unconditionally.
//   - FORCE_COLOR / CLICOLOR_FORCE (non-"0", non-"false") enables colors
//     even when stdout is not a TTY. Useful for CI runners that pipe
//     stdout but want colored diagnostics.
//   - Otherwise, colors track isTerminal(stdout).
package termout

import (
	"os"
	"strings"
)

// Exported color codes. Populated by init() based on the env + TTY
// decision matrix; empty strings when color is disabled.
var (
	Reset  string
	Cyan   string
	Green  string
	Yellow string
	Blue   string
	Purple string
	Bold   string
	Dim    string
)

func init() {
	if !ShouldEnableColor(os.Stdout, readColorEnv()) {
		return
	}
	Reset = "\033[0m"
	Cyan = "\033[36m"
	Green = "\033[32m"
	Yellow = "\033[33m"
	Blue = "\033[34m"
	Purple = "\033[35m"
	Bold = "\033[1m"
	Dim = "\033[2m"
}

// ColorEnv captures the color-related environment variables that
// influence the ShouldEnableColor decision. Separated from the live
// env so tests can synthesize arbitrary combinations without mutating
// process state.
type ColorEnv struct {
	// NoColor is true when NO_COLOR is present in the environment,
	// regardless of value (per https://no-color.org/).
	NoColor bool
	// ForceColor is true when either FORCE_COLOR or CLICOLOR_FORCE
	// is set to any value other than "", "0", or "false" (case-
	// insensitive). Matches the de-facto convention used by
	// chalk / supports-color and most Node / Rust CLIs.
	ForceColor bool
}

// ShouldEnableColor reports whether ANSI color codes should be emitted
// for output written to f. Exported as a seam so the decision matrix
// is directly testable without relying on package-init side effects.
//
// Precedence:
//  1. NO_COLOR wins absolutely — false regardless of TTY or FORCE_COLOR.
//  2. FORCE_COLOR / CLICOLOR_FORCE — true regardless of TTY.
//  3. Fall through to isTerminal(f).
func ShouldEnableColor(f *os.File, env ColorEnv) bool {
	if env.NoColor {
		return false
	}
	if env.ForceColor {
		return true
	}
	return isTerminal(f)
}

// readColorEnv snapshots the color-related env vars for the current
// process. Used by init(); tests call ShouldEnableColor directly with
// a synthesized ColorEnv.
func readColorEnv() ColorEnv {
	_, noColor := os.LookupEnv("NO_COLOR")
	return ColorEnv{
		NoColor:    noColor,
		ForceColor: parseForceColor(os.Getenv("FORCE_COLOR")) || parseForceColor(os.Getenv("CLICOLOR_FORCE")),
	}
}

// parseForceColor interprets a FORCE_COLOR / CLICOLOR_FORCE value.
// Empty string means unset (false); "0" and "false" (case-insensitive)
// are explicit disables; everything else enables.
func parseForceColor(v string) bool {
	switch strings.ToLower(v) {
	case "", "0", "false":
		return false
	default:
		return true
	}
}

// isTerminal reports whether f is attached to an interactive terminal.
// Pure-stdlib: a TTY's file mode has ModeCharDevice set; pipes,
// redirects, systemd-journaled stdout, and docker-captured stdout do
// not. Works on Linux (production target) and macOS (dev).
//
// Nil-safe: returns false when f is nil rather than panicking on
// f.Stat(). The only production caller passes os.Stdout (never nil
// during process lifetime), so this guard is cheap insurance for
// future callers that may not check before invoking.
//
// Not exhaustive — a character device that isn't a terminal (e.g.
// /dev/null) also matches, but that is acceptable: nothing reads
// /dev/null output, so color emission is harmless, and the alternative
// syscall.IoctlGetTermios pulls in a platform-specific dependency for
// no observable gain.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
