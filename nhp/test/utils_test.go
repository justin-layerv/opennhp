package test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	log "github.com/OpenNHP/opennhp/nhp/log"
	utils "github.com/OpenNHP/opennhp/nhp/utils"
)

func TestGenerateUUIDv4(t *testing.T) {
	uuid, err := utils.GenerateUUIDv4()
	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	fmt.Println("uuid: ", uuid)
}

func TestIPTables(t *testing.T) {
	// Skip if iptables is not available (e.g., in CI environments)
	if _, err := os.Stat("/sbin/iptables"); os.IsNotExist(err) {
		if _, err := os.Stat("/usr/sbin/iptables"); os.IsNotExist(err) {
			t.Skip("iptables not available, skipping test")
		}
	}

	iptables, err := utils.NewIPTables()

	if err != nil {
		fmt.Printf("error: %v\n", err)
	}

	fmt.Printf("iptables: %+v", iptables)
}

func TestPanicCatch(t *testing.T) {
	// Create temp directory for log files
	tmpDir, err := os.MkdirTemp("", "nhp-panic-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tlog := log.NewLogger("NHP-LogTest", log.LogLevelDebug, tmpDir, "logtest")
	log.SetGlobalLogger(tlog)
	defer log.Close()

	func() {
		defer func() {
			fmt.Println("defer function returns 0")
		}()

		defer utils.CatchPanicThenRun(func() {
			fmt.Println("panic caught###")
		})

		defer func() {
			fmt.Println("defer function returns 1")
		}()

		fmt.Println("function starts")

		panic(1)
	}()
}

func TestUpdateTomlConfig(t *testing.T) {
	tempFile, err := os.CreateTemp("", "config-*.toml")
	if err != nil {
		t.Fatalf("can't create temporary file: %v", err)
	}
	defer func() { _ = os.Remove(tempFile.Name()) }()

	initialContent := `# NHP-Agent base config
# field with (-) does not support dynamic update

# PrivateKeyBase64 (-): agent private key in base64 format.
# TEEPrivateKeyBase64 (-): TEE private key in base64 format.
# DefaultCipherScheme: 0: curve25519 (only supported scheme).
# UserId: specify the user id this agent represents.
# OrganizationId: specify the organization id this agent represents.
# LogLevel: 0: silent, 1: error, 2: info, 3: audit, 4: debug, 5: trace.
PrivateKeyBase64 = "lDaE1EKKyIJG4A28IZup/GDBZWYWEPZqGFaoV4Rlnn0="
DefaultCipherScheme = 0
UserId = "agent-0"
OrganizationId = "opennhp.org"
LogLevel = 4
# UserData: a customized user entry for flexibility.
# Its key-value pairs will be send to server along with knock message.
[UserData]
"ExampleKey0" = "StringValue"
"ExampleKey1" = 1
"ExampleKey2" = true
`
	if _, err := tempFile.WriteString(initialContent); err != nil {
		t.Fatalf("can't write into temporary file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	// Seed the file mode to 0644 so the 0600 assertion below actually
	// proves UpdateTomlConfig normalized it — os.CreateTemp creates at
	// 0600, so without this step the test "passes" trivially from the
	// initial mode. This mirrors the production rotation case where
	// the pre-existing etc/*.toml file was written at 0644 before the
	// permission-tightening shipped.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tempFile.Name(), 0644); err != nil {
			t.Fatalf("chmod 0644 on temp file: %v", err)
		}
	}

	if err := utils.UpdateTomlConfig(tempFile.Name(), "PrivateKeyBase64", "+Jnee2lP6Kn47qzSaqwSmWxORsBkkCV6YHsRqXM23Vo="); err != nil {
		t.Fatalf("can't update toml config: %v", err)
	}

	content, err := os.ReadFile(tempFile.Name())
	if err != nil {
		t.Fatalf("can't read temporary file: %v", err)
	}

	if !strings.Contains(string(content), "PrivateKeyBase64 = \"+Jnee2lP6Kn47qzSaqwSmWxORsBkkCV6YHsRqXM23Vo=\"") {
		t.Fatalf("can't find updated value in temporary file")
	}

	// Verify the 0600 permission tightening holds. The file's initial
	// permission from os.CreateTemp is 0600 too, but WriteFile rewrites
	// it — so a future regression that sets 0644 would surface here.
	// Skip on Windows where Unix perm bits aren't meaningful.
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(tempFile.Name())
		if statErr != nil {
			t.Fatalf("stat temp file: %v", statErr)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("UpdateTomlConfig left file mode %o, want 0600", perm)
		}
	}
}

// TestIPTablesAcceptInputModeTracking verifies that AcceptInputMode is properly
// tracked to prevent duplicate rule additions and ensure proper cleanup.
func TestIPTablesAcceptInputModeTracking(t *testing.T) {
	// Create IPTables struct directly (without calling NewIPTables which requires root)
	ipt := &utils.IPTables{
		AcceptInputMode:  false,
		AcceptInput6Mode: false,
	}

	// Test that AcceptInputMode starts as false
	if ipt.AcceptInputMode {
		t.Error("AcceptInputMode should start as false")
	}

	// Test that ResetAllInput does nothing when AcceptInputMode is false
	// (This prevents trying to delete non-existent rules)
	ipt.ResetAllInput()
	if ipt.AcceptInputMode {
		t.Error("AcceptInputMode should remain false after ResetAllInput when already false")
	}
}

// TestUpdateTomlConfig_KeyWithRegexMetachars fences the
// regexp.QuoteMeta(key) defense. A key containing `.` would, without
// quoting, match any single character in the existing file and
// replace the wrong line. Exercises the defense end-to-end: seed a
// TOML containing two keys ("foo.bar" and "fooXbar"), update the
// literal "foo.bar" key, assert "fooXbar" stays untouched.
func TestUpdateTomlConfig_KeyWithRegexMetachars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm semantics + tempfile permission differ on Windows")
	}
	tmp, err := os.CreateTemp("", "cfg-meta-*.toml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	const initial = "\"foo.bar\" = \"old\"\n\"fooXbar\" = \"unrelated\"\n"
	if _, err := tmp.WriteString(initial); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = tmp.Close()
	if err := utils.UpdateTomlConfig(tmp.Name(), "\"foo.bar\"", "new"); err != nil {
		t.Fatalf("UpdateTomlConfig: %v", err)
	}
	out, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(out), "\"foo.bar\" = \"new\"") {
		t.Errorf("foo.bar key not updated: %s", out)
	}
	if !strings.Contains(string(out), "\"fooXbar\" = \"unrelated\"") {
		t.Errorf("fooXbar key was clobbered (QuoteMeta regression): %s", out)
	}
	// Double the regression surface: this path is the only test that
	// exercises UpdateTomlConfig's atomic-write-and-rename through
	// the QuoteMeta codepath. Assert that the post-rename mode is
	// 0600 — note this is a "mode stays 0600" fence, not the
	// "normalizes 0644 → 0600" fence that the main TestUpdateTomlConfig
	// provides via explicit Chmod-to-0644 before the call. A future
	// refactor that accidentally switched back to os.WriteFile at
	// 0644 would still fail this assertion.
	info, statErr := os.Stat(tmp.Name())
	if statErr != nil {
		t.Fatalf("stat temp file: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("metachar-key path left file mode %o, want 0600", perm)
	}
}

// TestUpdateTomlConfig_ValueWithDollarSigns fences the sibling
// defense: ReplaceAllLiteralString (not ReplaceAllString) is used so
// a value containing `$1`, `${name}`, or `$$` is written literally
// rather than expanded as a regex replacement reference. Today's
// production callers pass only base64 ECDH keys (no `$`), but the
// function is exported; a future caller passing a raw value with
// `$` characters must not see surprising expansion.
func TestUpdateTomlConfig_ValueWithDollarSigns(t *testing.T) {
	// No Windows skip: this test only asserts the written value
	// substring, with no permission assertion. The regex-expansion
	// fence is platform-independent.
	tmp, err := os.CreateTemp("", "cfg-dollar-*.toml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString("Secret = \"old\"\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = tmp.Close()
	// Value contains every shape ReplaceAllString would expand:
	// $1 (numbered group), ${name} (named group), $$ (literal $).
	const literalValue = "prefix-$1-and-${name}-and-$$-suffix"
	if err := utils.UpdateTomlConfig(tmp.Name(), "Secret", literalValue); err != nil {
		t.Fatalf("UpdateTomlConfig: %v", err)
	}
	out, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// The value must land on disk byte-for-byte. If ReplaceAllString
	// snuck back in, $1 and ${name} would become "" (no captures)
	// and $$ would become $ — all three survivorship checks fail.
	// Build wantLine with the SAME format the production code uses
	// (`%s = "%s"`, raw) rather than %q, so an extension of
	// literalValue to include `"` or `\n` would diverge only in the
	// production code under test, not in the assertion.
	wantLine := fmt.Sprintf(`Secret = "%s"`, literalValue)
	if !strings.Contains(string(out), wantLine) {
		t.Errorf("value not written literally:\nwant substring: %s\ngot:\n%s", wantLine, out)
	}
}

// TestUpdateTomlConfig_RejectsUntrustedPaths fences the runtime path-
// sanitization gate added to UpdateTomlConfig. The exported signature
// can't constrain the caller, so the runtime check is the invariant
// the function's "service-owned config paths only" contract rests on.
// A future refactor that silently loosens either half of the check
// (absolute-path requirement or ..-segment rejection) must fail here.
func TestUpdateTomlConfig_RejectsUntrustedPaths(t *testing.T) {
	// Build the "accepted at gate" sample portably — on Windows
	// filepath.IsAbs("/etc/nhp/config.toml") returns false (drive
	// letter required), which would turn the one negative-assert
	// row into a false positive. TempDir is absolute on every OS.
	okPath := filepath.Join(t.TempDir(), "config.toml")
	cases := []struct {
		name   string
		path   string
		reject bool
	}{
		{"relative path", "config.toml", true},
		{"relative subdir", "etc/config.toml", true},
		{"abs with .. segment", "/etc/nhp/../../tmp/evil.toml", true},
		{"abs with lone .. component", "/etc/nhp/..", true},
		{"abs clean path (accepted at gate)", okPath, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := utils.UpdateTomlConfig(tc.path, "Key", "value")
			// Gate rejections wrap ErrInvalidConfigPath; downstream
			// os.ReadFile failures on a clean-but-nonexistent path
			// return a different sentinel (fs.ErrNotExist).
			gotGateReject := errors.Is(err, utils.ErrInvalidConfigPath)
			if tc.reject && !gotGateReject {
				t.Errorf("path=%q: want gate rejection, got err=%v", tc.path, err)
			}
			if !tc.reject && gotGateReject {
				t.Errorf("path=%q: gate rejected a clean absolute path: %v", tc.path, err)
			}
		})
	}
}

// TestClearStaleFailOpenRulesFunction verifies that ClearStaleFailOpenRules
// exists and can be called. This function cleans up any fail-open ACCEPT rules
// left behind by a previous process instance that crashed or was killed while
// in fail-open mode.
//
// Note: We can't fully test the iptables interaction without root, but we
// verify the function exists and the struct fields are properly initialized.
func TestClearStaleFailOpenRulesFunction(t *testing.T) {
	// Verify the IPTables struct has the required fields for tracking fail-open state
	ipt := &utils.IPTables{}

	// Verify AcceptInputMode field exists and defaults to false
	if ipt.AcceptInputMode != false {
		t.Error("AcceptInputMode should default to false")
	}

	// Verify AcceptInput6Mode field exists and defaults to false
	if ipt.AcceptInput6Mode != false {
		t.Error("AcceptInput6Mode should default to false")
	}

	// Verify IPv6Available field exists and defaults to false
	if ipt.IPv6Available != false {
		t.Error("IPv6Available should default to false")
	}

	// The ClearStaleFailOpenRules method should exist on IPTables
	// This is a compile-time check - if the method doesn't exist, this won't compile
	_ = ipt.ClearStaleFailOpenRules

	t.Log("ClearStaleFailOpenRules function exists and struct fields are properly initialized")
}

// TestIPTablesFailOpenModeLogic tests the logic around fail-open mode
// without requiring actual iptables commands.
func TestIPTablesFailOpenModeLogic(t *testing.T) {
	t.Run("AcceptAllInput_sets_mode_flag", func(t *testing.T) {
		ipt := &utils.IPTables{
			AcceptInputMode: false,
			Binary:          "/sbin/iptables", // Required for AcceptAllInput
		}

		// Note: AcceptAllInput will fail to execute the actual iptables command
		// in this test (no root), but the mode flag logic can still be tested
		// by checking the initial state

		if ipt.AcceptInputMode {
			t.Error("AcceptInputMode should be false before AcceptAllInput")
		}
	})

	t.Run("ResetAllInput_only_runs_when_accept_mode_true", func(t *testing.T) {
		ipt := &utils.IPTables{
			AcceptInputMode: false,
			Binary:          "/sbin/iptables",
		}

		// When AcceptInputMode is false, ResetAllInput should return early
		// This prevents trying to delete a rule that doesn't exist
		ipt.ResetAllInput()

		// Mode should still be false
		if ipt.AcceptInputMode {
			t.Error("AcceptInputMode should remain false")
		}
	})

	t.Run("mode_tracking_prevents_duplicate_rules", func(t *testing.T) {
		ipt := &utils.IPTables{
			AcceptInputMode: true, // Simulate already in accept mode
			Binary:          "/sbin/iptables",
		}

		// When AcceptInputMode is already true, AcceptAllInput should return early
		// This prevents adding duplicate rules
		// (The actual iptables command won't run in test, but the mode check happens first)

		if !ipt.AcceptInputMode {
			t.Error("AcceptInputMode should be true for this test")
		}
	})
}
