//go:build smoke

package smoke

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// ssm_probe.go is the single place in the smoke suite that sends SSM
// RunShellScript commands. It exists to enforce two invariants:
//
//  1. Tests cannot express an arbitrary command. Every probe is a
//     named Go function with the command baked in as a string constant.
//     There is no exported API that accepts a command string as a
//     parameter. Adding a probe means adding a new named function
//     reviewed under CODEOWNERS.
//
//  2. Defense in depth: the private sendShellScript function regex-checks
//     every command string against a reject-list before sending it to
//     SSM. This catches refactoring mistakes (someone bypasses the
//     named-helper API) and stops the smoke suite from being the thing
//     that ever mutates a production instance.
//
// Probes are read-only. None of them install packages, modify files,
// start/stop services, or change iptables/ipset. If you need a new
// capability that involves writing state, it is almost certainly not a
// smoke test — it is an integration test, and it belongs in
// tests/integration with an ephemeral harness.

// Baked-in command strings. Every probe is a constant. No dynamic
// construction of command text is allowed.
//
// IMPORTANT: nhp-server runs in a Docker container with --net=host
// and the container image intentionally has NO curl, NO wget, and no
// other health-probe binaries (MEMORY gotcha "nhp-server container
// has no curl or wget"). Every health probe runs on the INSTANCE
// (the host), which reaches the container at 127.0.0.1:8888 thanks
// to --net=host.
//
// PR #1005's regression class was: the deploy gate tried
// `docker exec nhp-server wget ...`, the image had no wget, every
// standby instance was declared unhealthy, and the blue/green flip
// never happened. The correct fence is to run the deploy gate's
// actual post-#1005 shell command — host-side curl — against real
// instances and assert exit 0.
const (
	// cmdHealthLiveFromHost is the exact shape the post-#1005 deploy
	// gate uses: curl the nhp-server container's /health/live from
	// the host via --net=host loopback. If this returns non-zero,
	// either curl is missing from the AMI (which would be a new
	// regression class) or the server isn't responding — either way,
	// the blue/green deploy would not flip.
	cmdHealthLiveFromHost = "curl -sf -m 5 http://127.0.0.1:8888/health/live"

	cmdDockerNhpServerRunning = "docker ps --filter name=nhp-server --format '{{.Status}}'"
	cmdDockerImageTag         = "docker inspect --format '{{.Config.Image}}' nhp-server"
)

// rejectPatterns are command substrings that must never appear in any
// probe, even if someone bypasses the named-helper API. This list fires
// only as a safety net — it should never be the only thing catching a
// bad command.
//
// The list is deliberately broad; the cost of a false-positive
// (rejecting a harmless probe) is that someone has to rewrite the
// probe, which is a good conversation to have.
var rejectPatterns = []*regexp.Regexp{
	// State mutation
	regexp.MustCompile(`\brm\b`),
	regexp.MustCompile(`\bmv\b`),
	regexp.MustCompile(`\bcp\b`),
	regexp.MustCompile(`\bdd\b`),
	regexp.MustCompile(`\btee\b`),
	regexp.MustCompile(`\bchmod\b`),
	regexp.MustCompile(`\bchown\b`),
	regexp.MustCompile(`>`),
	regexp.MustCompile(`>>`),

	// Firewall/routing mutation (reads are allowed via explicit commands)
	regexp.MustCompile(`\biptables\b`),
	regexp.MustCompile(`\bipset\s+-(A|D|F|X|N)\b`),
	regexp.MustCompile(`\bsysctl\s+-w\b`),

	// Service mutation
	regexp.MustCompile(`\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|unmask)\b`),
	regexp.MustCompile(`\bservice\s+\S+\s+(start|stop|restart|reload)\b`),

	// Docker mutation
	regexp.MustCompile(`\bdocker\s+(start|stop|restart|kill|rm|rmi|run|pull|push|build|commit|tag)\b`),

	// Package install
	regexp.MustCompile(`\bapt(-get)?\s+(install|remove|purge|upgrade)\b`),
	regexp.MustCompile(`\byum\s+(install|remove|update)\b`),
	regexp.MustCompile(`\bdpkg\s+-i\b`),
}

// errCommandRejected is returned by sendShellScript when a probe string
// trips the reject-list. Tests surface this as a clear failure: either
// the reject-list is overreaching, or a new probe was added that should
// not exist.
var errCommandRejected = errors.New("ssm_probe: command rejected by reject-list")

// sendShellScript is the ONLY function in this package that actually
// calls SSM. It is unexported; callers are the named probe functions
// below. Tests must not call it directly.
//
// Behavior:
//   - Returns errCommandRejected if cmd matches any rejectPatterns regex.
//     The rejected command is logged for diagnosis.
//   - Sends AWS-RunShellScript with --timeout-seconds 30 (API minimum).
//   - Polls get-command-invocation until a terminal status; max wait ~45s.
//   - Returns stdout on Success, an error containing stderr otherwise.
func sendShellScript(ctx context.Context, instanceID, cmd string) (string, error) {
	for _, pat := range rejectPatterns {
		if pat.MatchString(cmd) {
			return "", fmt.Errorf("%w: pattern %q matched in %q", errCommandRejected, pat.String(), cmd)
		}
	}

	if testConfig.SSMClient == nil {
		return "", errors.New("ssm client not configured")
	}

	sendResp, err := testConfig.SSMClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:    []string{instanceID},
		DocumentName:   aws.String("AWS-RunShellScript"),
		TimeoutSeconds: aws.Int32(30),
		Parameters: map[string][]string{
			"commands": {cmd},
		},
	})
	if err != nil {
		return "", fmt.Errorf("ssm send-command %s: %w", instanceID, err)
	}
	if sendResp.Command == nil || sendResp.Command.CommandId == nil {
		return "", errors.New("ssm send-command returned nil command id")
	}
	cmdID := *sendResp.Command.CommandId

	// Poll GetCommandInvocation with exponential backoff. Most probes
	// complete in well under a second once the command is scheduled,
	// so starting with 250ms saves ~2s per probe vs. a fixed 2s
	// pre-poll sleep. Cap backoff at 2s so worst-case eventual
	// consistency is still handled without runaway latency.
	deadline := time.Now().Add(45 * time.Second)
	wait := 250 * time.Millisecond
	const maxWait = 2 * time.Second

	for {
		time.Sleep(wait)

		getResp, err := testConfig.SSMClient.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(cmdID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			// Eventual consistency: the invocation may not be visible
			// immediately after send-command. Retry until deadline.
			if time.Now().After(deadline) {
				return "", fmt.Errorf("ssm get-command-invocation %s: %w", cmdID, err)
			}
			if wait < maxWait {
				wait *= 2
			}
			continue
		}

		status := string(getResp.Status)
		switch status {
		case "Success":
			return strings.TrimSpace(aws.ToString(getResp.StandardOutputContent)), nil
		case "Failed", "Cancelled", "TimedOut":
			return "", fmt.Errorf("ssm command %s status=%s stderr=%q",
				cmdID, status, aws.ToString(getResp.StandardErrorContent))
		}

		if time.Now().After(deadline) {
			return "", fmt.Errorf("ssm command %s timed out in status=%s", cmdID, status)
		}
		if wait < maxWait {
			wait *= 2
		}
	}
}

// probeHealthLiveFromHost runs the post-#1005 deploy gate shell
// command on the host and returns nil on exit 0. This is the exact
// shape verify-asg-instances-healthy.sh uses when called by the
// blue/green deploy, so passing this probe means the deploy gate
// would also pass against the same instance.
//
// Fences PR #1005 (deploy gate shell command must actually work
// against the deployed image).
func probeHealthLiveFromHost(ctx context.Context, instanceID string) error {
	_, err := sendShellScript(ctx, instanceID, cmdHealthLiveFromHost)
	return err
}

// probeDockerNhpServerRunning returns the nhp-server container's
// `docker ps --format '{{.Status}}'` line (e.g. "Up 3 hours"). Empty
// string + nil error means no such container, which is itself a bug
// class worth fencing.
func probeDockerNhpServerRunning(ctx context.Context, instanceID string) (string, error) {
	return sendShellScript(ctx, instanceID, cmdDockerNhpServerRunning)
}

// probeDockerImageTag returns the image reference the nhp-server
// container was launched from (e.g. "layerv/nhp-server:abc123...").
func probeDockerImageTag(ctx context.Context, instanceID string) (string, error) {
	return sendShellScript(ctx, instanceID, cmdDockerImageTag)
}

// sendShellScriptRaw is an UNEXPORTED test-only helper that lets
// ssm_probe_test.go exercise the reject-list directly without needing
// an actual SSM client. It short-circuits: returns errCommandRejected
// for rejected commands, nil otherwise. Production code paths (tests in
// other files) must not call this.
func sendShellScriptRaw(cmd string) error {
	for _, pat := range rejectPatterns {
		if pat.MatchString(cmd) {
			return fmt.Errorf("%w: pattern %q matched in %q", errCommandRejected, pat.String(), cmd)
		}
	}
	return nil
}
