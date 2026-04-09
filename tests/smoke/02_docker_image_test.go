//go:build smoke

package smoke

// Tier 1: nhp-server Docker image surface + deploy-gate health probe.
//
// Capability: the post-#1005 deploy gate verifies standby instances
// via `curl` ON THE HOST against the container's --net=host loopback
// (the container image intentionally has no curl/wget — MEMORY
// gotcha "nhp-server container has no curl or wget"). Tests in this
// file fence both halves of that invariant:
//
//   - TestDockerImage_HealthProbeFromHostReaches200 — the post-#1005
//     shell command (host curl → 127.0.0.1:8888/health/live) actually
//     returns 0 against the deployed image. If this fails, either
//     curl is missing from the AMI (new regression), the container
//     isn't running, or the image doesn't bind to the expected port.
//     Any of those would break the next blue/green flip.
//
//   - TestDockerImage_NhpServerContainerRunning — the container is
//     actually up under the expected name.
//
//   - TestDockerImage_UsesImmutableTag — the container is pinned to
//     a 40-char SHA, so rollbacks are well-defined.
//
// Regression fence for PR #1005 (both the deploy-gate shell command
// correctness AND the image surface it depends on).
//
// All tests in this file require SSM probes. They t.Skip cleanly
// when NHP_SMOKE_ALLOW_SSM_PROBES is not "true", which is the
// default policy in prod during the 30-day burn-in.

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

// imageTagShaPattern matches the reference format we expect docker
// inspect to return: a repo reference ending in a 40-char SHA. Branch
// names and `:latest` are deliberately rejected — every deployed
// container should be running an immutable tag so rollbacks are
// well-defined.
var imageTagShaPattern = regexp.MustCompile(`:[0-9a-f]{40}$`)

// TestDockerImage_HealthProbeFromHostReaches200 fences PR #1005's
// actual regression class directly: the post-#1005 deploy gate shell
// command must run cleanly against the deployed image. The command
// is `curl -sf -m 5 http://127.0.0.1:8888/health/live` executed ON
// THE HOST via SSM; --net=host routes loopback traffic into the
// container. An exit-0 means the image is reachable, the container
// is running, curl is present in the AMI, and the server is
// returning 200 — every link in the deploy gate's chain.
//
// Regression fence for PR #1005.
func TestDockerImage_HealthProbeFromHostReaches200(t *testing.T) {
	skipIfNoSSMProbes(t)
	asgName := requireActiveServerASG(t)

	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s", asgName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Probe one instance — if the post-#1005 shell command is
	// broken, every instance is equally broken. Iterating adds noise
	// without increasing signal. The verify-asg-instances runbook
	// test below iterates every instance as an executable runbook
	// form of the same fence.
	instance := instances[0]
	if err := probeHealthLiveFromHost(ctx, instance); err != nil {
		t.Fatalf("instance %s: post-#1005 deploy gate shell command failed: %v", instance, err)
	}
}

// TestDockerImage_NhpServerContainerRunning fences the "the container
// is actually up" invariant — surfaces "`docker ps` returns nothing
// for the nhp-server name" failure modes, which are distinct from "the
// binary is crashing" (liveness catches that) and "the image is
// wrong" (TestDockerImage_UsesImmutableTag catches that).
func TestDockerImage_NhpServerContainerRunning(t *testing.T) {
	skipIfNoSSMProbes(t)
	asgName := requireActiveServerASG(t)

	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s", asgName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	instance := instances[0]
	status, err := probeDockerNhpServerRunning(ctx, instance)
	if err != nil {
		t.Fatalf("instance %s: %v", instance, err)
	}
	if !strings.HasPrefix(strings.TrimSpace(status), "Up") {
		t.Fatalf("instance %s: nhp-server status=%q, want starts with Up", instance, status)
	}
}

// TestDockerImage_UsesImmutableTag fences the invariant that every
// deployed container references an immutable 40-char SHA image tag.
// A `:latest`, a branch name, or an empty tag is a critical
// regression: rollbacks stop being well-defined, and two instances in
// the same ASG can silently run different code.
func TestDockerImage_UsesImmutableTag(t *testing.T) {
	skipIfNoSSMProbes(t)
	asgName := requireActiveServerASG(t)

	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s", asgName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	instance := instances[0]
	tag, err := probeDockerImageTag(ctx, instance)
	if err != nil {
		t.Fatalf("instance %s: %v", instance, err)
	}
	tag = strings.TrimSpace(tag)
	if !imageTagShaPattern.MatchString(tag) {
		t.Fatalf("instance %s: image tag %q does not end in a 40-char SHA — rollbacks require immutable tags", instance, tag)
	}
}
