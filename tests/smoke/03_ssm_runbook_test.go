//go:build smoke

package smoke

// Tier 1: SSM RunShellScript deploy runbook invariants.
//
// Capability: the SSM-based health gates the blue/green deploy uses
// to certify standby instances before flipping the NLB listener.
//
// Regression fences:
//
//	PR #1005 — `aws ssm send-command --timeout-seconds 15` was rejected
//	           by the API (minimum is 30); the deploy silently retried
//	           and timed out without ever probing the new instances.
//
//	          — the embedded shell command for `aws ssm send-command
//	           --parameters commands=["..."]` has no way to escape
//	           internal double quotes, so verify-asg-instances-healthy.sh
//	           guards against them at runtime. This file adds a Go-side
//	           static check so the guard can't rot silently.
//
// Every test here is sandbox-only because it either sends an actual
// SSM command (requires NHP_SMOKE_ALLOW_SSM_PROBES=true) or reads a
// shell script whose path is relative to the nhp repo checkout, which
// only exists in the smoke-test job's workspace.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"
)

// TestSSMRunbook_TimeoutMeetsAPIMinimum fences PR #1005 directly.
// Sends an SSM command with --timeout-seconds 29 and asserts the
// AWS API returns ValidationException. Pins the API minimum so no
// future shell script drifts below 30 and silently fails gating.
//
// We deliberately do NOT also send a positive-case command with
// timeout=30. A successful SendCommand would actually execute a
// shell command on a production instance for no test value (the
// ValidationException alone proves the boundary), and AWS CLI-side
// parameter validation already catches obviously-invalid values.
// The negative case is the fence; the positive case is noise.
//
// Regression fence for PR #1005.
func TestSSMRunbook_TimeoutMeetsAPIMinimum(t *testing.T) {
	skipIfNoSSMProbes(t)
	asgName := requireActiveServerASG(t)

	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s", asgName)
	}
	instance := instances[0]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := testConfig.SSMClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:    []string{instance},
		DocumentName:   aws.String("AWS-RunShellScript"),
		TimeoutSeconds: aws.Int32(29),
		Parameters: map[string][]string{
			"commands": {"true"},
		},
	})
	if err == nil {
		t.Fatal("--timeout-seconds 29 was accepted — the API minimum is no longer 30, update deploy runbook")
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "ValidationException" {
		t.Fatalf("--timeout-seconds 29 failed with unexpected error shape: %v", err)
	}
}

// TestSSMRunbook_VerifyASGInstancesShellCmdExits0 executes the
// post-#1005 verify-asg-instances shell command (host-side curl via
// --net=host loopback) against every InService server instance.
// This is an executable form of the deploy-time runbook: if this
// test passes, the next blue/green deploy's health gate will pass
// against the same fleet, because it runs the same command.
func TestSSMRunbook_VerifyASGInstancesShellCmdExits0(t *testing.T) {
	skipIfNoSSMProbes(t)
	asgName := requireActiveServerASG(t)

	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s", asgName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Every instance must probe healthy. Iterate here (unlike the
	// single-instance probe in 02_docker_image_test.go) because the
	// deploy gate iterates, and we want to fence the same guarantee
	// the deploy relies on.
	for _, instance := range instances {
		if err := probeHealthLiveFromHost(ctx, instance); err != nil {
			t.Errorf("instance %s: verify-asg-instances shell cmd failed: %v", instance, err)
		}
	}
}

// TestSSMRunbook_ShellCmdHasNoDoubleQuotes is a belt-and-suspenders
// Go-side static check on verify-asg-instances-healthy.sh. The shell
// script has its own runtime guard; this test catches the
// class at a different layer — if a future edit adds a double-quoted
// command literal, the shell guard would reject it at deploy time.
// This Go test rejects it at PR time instead, which is cheaper.
func TestSSMRunbook_ShellCmdHasNoDoubleQuotes(t *testing.T) {
	scriptPath, err := findVerifyASGScript()
	if err != nil {
		t.Skipf("script not found in workspace: %v", err)
	}

	content, err := os.ReadFile(scriptPath) // #nosec G304 — path is under the repo, not user input
	if err != nil {
		t.Fatalf("read %s: %v", scriptPath, err)
	}

	// Find the line that runs the sample `docker exec ... wget` probe.
	// The script's usage comment at line 38-41 documents the default
	// command form. Any code change that introduces an embedded "
	// inside a `commands=[...]` parameter is a regression.
	//
	// We scan the whole file for the forbidden pattern `commands=["`
	// followed by anything containing another `"` before `]"`. In
	// practice, the shell script either uses single quotes for the
	// command or uses `$SHELL_CMD` variable expansion — both are fine.
	s := string(content)
	if strings.Contains(s, "commands=[\"") {
		// Check each occurrence: if the segment between the opening
		// `commands=["` and the closing `"]` contains another `"`,
		// that's a bug.
		start := 0
		for {
			idx := strings.Index(s[start:], "commands=[\"")
			if idx < 0 {
				break
			}
			segStart := start + idx + len(`commands=["`)
			segEnd := strings.Index(s[segStart:], `"]`)
			if segEnd < 0 {
				// Unclosed — shellcheck would catch this too, but we
				// don't want to silently pass.
				t.Fatalf("unclosed commands=[\" at offset %d in %s", segStart, scriptPath)
			}
			segment := s[segStart : segStart+segEnd]
			if strings.Contains(segment, `"`) {
				t.Fatalf("embedded double-quote inside commands=[...] in %s:\n  segment: %q", scriptPath, segment)
			}
			start = segStart + segEnd + len(`"]`)
		}
	}
}

// findVerifyASGScript walks up from the current test directory to
// locate verify-asg-instances-healthy.sh. Returns an error if the
// script is not found within 6 levels up, which means either the
// working directory is unusual or the script has been renamed.
func findVerifyASGScript() (string, error) {
	return findRepoScript("verify-asg-instances-healthy.sh")
}

// findRepoScript resolves a .github/scripts/<name> path by walking up from the
// working directory. Shared so probes/tests that need to read a repo script
// use one idiom rather than each inventing its own relative path.
func findRepoScript(name string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, ".github", "scripts", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New(name + " not found within 6 parent directories")
}
