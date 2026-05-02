//go:build smoke

package smoke

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// TestSSMProbeRejectList verifies that every synthetic "bad" command
// strings is rejected by the reject-list. This is a unit-level test
// — no network, no SSM client — but lives under the smoke build tag so
// it runs alongside the rest of the suite whenever we check probe
// invariants.
//
// Adding a probe that trips the reject-list means either (a) the
// reject-list is overreaching and needs tuning, or (b) the probe
// should not exist. Both are good conversations.
func TestSSMProbeRejectList(t *testing.T) {
	bad := []string{
		// state mutation
		"rm -rf /tmp/x",
		"mv /etc/passwd /tmp/p",
		"cp /etc/shadow /tmp/s",
		"dd if=/dev/zero of=/tmp/z",
		"echo hi | tee /tmp/x",
		"chmod 777 /etc/shadow",
		"chown root /tmp/x",
		"echo hi > /tmp/x",
		"echo hi >> /tmp/x",
		// firewall mutation
		"iptables -L",
		"ipset -A defaultset 1.2.3.4,80,5.6.7.8",
		"sysctl -w net.ipv4.ip_forward=1",
		// service mutation
		"systemctl restart nhp-ac",
		"systemctl stop nhp-server",
		"service docker restart",
		// docker mutation
		"docker restart nhp-server",
		"docker stop nhp-server",
		"docker run --rm alpine",
		"docker pull nginx",
		// package install
		"apt-get install curl",
		"apt install wget",
		"yum install httpd",
		"dpkg -i pkg.deb",
		// shell control: chaining and substitution
		"true; rm /tmp/x",
		"echo $(whoami)",
		"echo `whoami`",
		"true && echo bad",
	}

	for _, cmd := range bad {
		t.Run(cmd, func(t *testing.T) {
			err := sendShellScriptRaw(cmd)
			if err == nil {
				t.Fatalf("expected reject for %q, got nil", cmd)
			}
			if !errors.Is(err, errCommandRejected) {
				t.Fatalf("expected errCommandRejected for %q, got %v", cmd, err)
			}
		})
	}
}

// TestClassifyQurlAPIURLError pins the contract that the
// QURL_API_URL probe's diagnostic dispatcher fires on the two
// grep-failure shapes that come out of sendShellScript today.
// If sendShellScript's `status=%s stderr=%q` format is reworded,
// or if the AWS SSM agent ever changes the stderr text for a
// missing-file grep, this test catches the silent regression to the
// generic catch-all path. Pure unit test — no SSM, no network.
func TestClassifyQurlAPIURLError(t *testing.T) {
	tests := []struct {
		name      string
		input     error
		wantHint  string
		wantWraps bool
	}{
		{
			name:      "missing_file_via_grep_exit_2",
			input:     fmt.Errorf(`ssm command abc-123 status=Failed stderr="grep: %s: No such file or directory\n"`, nhpServerEnvFilePath),
			wantHint:  "nhp-server env file missing",
			wantWraps: true,
		},
		{
			name:      "missing_line_via_grep_exit_1",
			input:     errors.New(`ssm command def-456 status=Failed stderr=""`),
			wantHint:  "QURL_API_URL line missing",
			wantWraps: true,
		},
		{
			name:      "passthrough_unrelated_error",
			input:     errors.New("ssm get-command-invocation: throttled"),
			wantHint:  "throttled",
			wantWraps: false, // returned as-is, no extra wrap
		},
		{
			// Pin that an SSM-side cancel (status != Failed) with empty
			// stderr does NOT trip the missing-line branch. Builds the
			// literal at runtime via the SDK enum so the misspell
			// linter doesn't flag the source — the actual on-wire
			// status name is whatever the SDK formats.
			name:      "passthrough_canceled_status_does_not_match_failed_branch",
			input:     fmt.Errorf(`ssm command xyz-789 status=%s stderr=""`, ssmtypes.CommandInvocationStatusCancelled),
			wantHint:  fmt.Sprintf("status=%s", ssmtypes.CommandInvocationStatusCancelled),
			wantWraps: false,
		},
		{
			name:     "nil_returns_nil",
			input:    nil,
			wantHint: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyQurlAPIURLError(tc.input)
			if tc.input == nil {
				if got != nil {
					t.Fatalf("nil input: want nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("non-nil input %v: got nil", tc.input)
			}
			if !strings.Contains(got.Error(), tc.wantHint) {
				t.Errorf("error message %q missing hint %q", got.Error(), tc.wantHint)
			}
			// Distinguish "wrapped with extra context" from "returned
			// unchanged" via errors.Unwrap: %w-wrapped errors return
			// non-nil from Unwrap; a plain `return err` returns nil
			// from Unwrap. errors.Is alone can't tell these apart
			// (any err satisfies errors.Is itself), so a future
			// refactor that adds context to the passthrough path
			// would silently slip past Is-only assertions.
			unwrapped := errors.Unwrap(got)
			if tc.wantWraps {
				if unwrapped == nil {
					t.Errorf("expected the classifier to wrap the original error with extra context; got an unwrapped error %v", got)
				} else if !errors.Is(got, tc.input) {
					t.Errorf("wrapped error does not chain back to original via errors.Is")
				}
			} else if unwrapped != nil {
				t.Errorf("expected passthrough (no wrap), but errors.Unwrap returned %v", unwrapped)
			}
		})
	}
}

// TestSSMFailedErrorFmtLockMatchesClassifier locks the coupling
// between sendShellScript's error format and the substring
// classifyQurlAPIURLError matches on. classifyQurlAPIURLError treats
// `status=Failed stderr=""` as the "QURL_API_URL line missing"
// diagnostic; that string is produced by the ssmFailedErrorFmt
// constant. Without this lock, a refactor of ssmFailedErrorFmt would
// silently regress every classifier in the package to the catch-all
// path. #1597 tracks the typed-error refactor that removes the
// substring-match entirely.
func TestSSMFailedErrorFmtLockMatchesClassifier(t *testing.T) {
	got := fmt.Errorf(ssmFailedErrorFmt,
		"command-id-fixture",
		ssmtypes.CommandInvocationStatusFailed,
		"")
	const want = `status=Failed stderr=""`
	if !strings.Contains(got.Error(), want) {
		t.Fatalf("ssmFailedErrorFmt produced %q which does not contain classifier match string %q",
			got.Error(), want)
	}
}

// TestParseQurlAPIURLValue pins the malformed-line branch of
// parseQurlAPIURLValue. Production probe path is anchored at
// `^QURL_API_URL=` so the unexpected-shape branch is unreachable
// today, but a future probe that bypasses the anchor — or a
// transient SSM agent bug returning Success with empty stdout —
// would exercise it.
func TestParseQurlAPIURLValue(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    string
		wantErr bool
	}{
		{
			name: "happy_path",
			line: "QURL_API_URL=https://internal-api.qurl.layerv.xyz",
			want: "https://internal-api.qurl.layerv.xyz",
		},
		{
			name: "trim_surrounding_whitespace",
			line: "  QURL_API_URL=foo  ",
			want: "foo",
		},
		{
			name:    "empty_input",
			line:    "",
			wantErr: true,
		},
		{
			name:    "no_prefix",
			line:    "FOO=bar",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseQurlAPIURLValue(tc.line)
			switch {
			case tc.wantErr && err == nil:
				t.Errorf("expected error for line %q, got nil (got=%q)", tc.line, got)
			case !tc.wantErr && err != nil:
				t.Errorf("unexpected error for line %q: %v", tc.line, err)
			case got != tc.want:
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSSMProbeNamedCommandsPassRejectList verifies that every named
// probe's command string clears the reject-list. This catches the
// regression where someone tightens the reject-list and accidentally
// breaks an existing probe.
func TestSSMProbeNamedCommandsPassRejectList(t *testing.T) {
	const benignHostname = "internal-api.qurl.layerv.xyz"
	allowed := []string{
		cmdHealthLiveFromHost,
		cmdHealthKnockReadyFromHost,
		cmdDockerNhpServerRunning,
		cmdDockerImageTag,
		cmdSystemdNRestartsNhpServer,
		cmdGrepQurlAPIURL,
		fmt.Sprintf(cmdDigInternalQurlAPIFmt, benignHostname),
		fmt.Sprintf(cmdCurlInternalQurlAPIFmt, benignHostname),
		fmt.Sprintf(cmdCurlInternalQurlResolveFmt, benignHostname),
	}
	for _, cmd := range allowed {
		t.Run(cmd, func(t *testing.T) {
			if err := sendShellScriptRaw(cmd); err != nil {
				t.Fatalf("named probe command rejected unexpectedly: %q: %v", cmd, err)
			}
		})
	}
}
