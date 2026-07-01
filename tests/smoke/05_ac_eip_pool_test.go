//go:build smoke

package smoke

// Tier 1: AC Elastic IP pool sizing and coverage.
//
// Capability: the pool of EIPs the AC ASG draws from on instance
// launch. The pool is sized per terraform/modules/ac/eip.tf:33 —
// `2 * max_capacity + 1` in blue/green envs (the +1 prevents an
// instance refresh from deadlocking on the EIP-disassociation
// eventual-consistency window) and `max_capacity` in canary envs
// (single ASG, no parallel-color scenario).
//
// In blue/green mode the post-#1006 minimum is what's being fenced
// (pre-#1006 the pool was sized to max_capacity, which deadlocked
// every refresh). In canary mode there's no equivalent regression
// PR — the assertion just fences that the formula keeps matching
// the TF source of truth. #1454 tracks whether canary actually needs
// the +1 slack too (suspect yes, but the test mirrors TF either way).

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
)

// acEIPPoolTag mirrors terraform/modules/ac/main.tf's local.eip_pool_tag
// ("${name_prefix}-ac") and terraform/modules/ac/eip.tf's EIPPool tag key.
// The sandbox/prod modules set name_prefix to "layerv-nhp-{env}"; update
// this helper if that module contract changes.
func acEIPPoolTag() (key, value string) {
	return "EIPPool", fmt.Sprintf("layerv-nhp-%s-ac", testConfig.Environment)
}

// TestACEIPPool_AllActiveACsHaveEIP enumerates the active AC ASG's
// InService instances and confirms each has an associated managed
// EIP from the AC EIP pool. Any instance with only an auto-assigned
// EC2 public IP is an acute bug: customer origins and internal WAFs
// allowlist the managed pool, not arbitrary instance public IPs.
//
// Regression fence for PR #2911 (EIP reassociation during concurrent
// AC boots displaced a healthy instance onto an auto-assigned public IP).
func TestACEIPPool_AllActiveACsHaveEIP(t *testing.T) {
	requireRemote(t) // AC Elastic IP pool is AWS-only; no equivalent in the local stack.
	asgName := requireActiveACASG(t)

	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService AC instances in ASG %s", asgName)
	}

	poolTagKey, poolTagValue := acEIPPoolTag()
	ips := describeInstanceElasticIPs(t, instances, poolTagKey, poolTagValue)
	for _, id := range instances {
		if ip, ok := ips[id]; !ok || ip == "" {
			t.Errorf("AC instance %s has no managed EIP tagged %s=%s", id, poolTagKey, poolTagValue)
		}
	}
}

// TestACEIPPool_PoolSizeMeetsMinimum fences PR #1006. Reads the pool
// size via tag filter and asserts it meets the deploy-mode-specific
// minimum from terraform/modules/ac/eip.tf:
//
//	enable_blue_green ? max_capacity * 2 + 1 : max_capacity
//
// In blue/green envs the +1 slack is what keeps an instance refresh
// from deadlocking on EIP claim during the AWS-side EIP-disassociation
// eventual-consistency window (PR #1006). In canary envs there's a
// single ASG and no parallel-color scenario, so max_capacity is the
// floor.
//
// Tag key and value are load-bearing and come from the terraform
// source at terraform/modules/ac/eip.tf:
//
//	tags = merge(var.tags, {
//	  EIPPool = local.eip_pool_tag  // "${name_prefix}-ac"
//	})
//
// If the pool has zero matching EIPs, the test FAILS (does not skip)
// because a typo in the tag key/value would otherwise silently
// neuter this regression guard — exactly the thing a fence test
// must not do.
//
// Regression fence for PR #1006.
func TestACEIPPool_PoolSizeMeetsMinimum(t *testing.T) {
	requireRemote(t) // AC Elastic IP pool is AWS-only; no equivalent in the local stack.
	asgName := requireActiveACASG(t)

	// The EIP pool is tagged EIPPool=layerv-nhp-{env}-ac. Tag key and
	// value are asserted here against the TF source of truth. DO NOT
	// relax this to a substring match or softer skip path without
	// also updating the terraform comment + this test.
	poolTagKey, poolTagValue := acEIPPoolTag()
	poolSize := describeElasticIPPool(t, poolTagKey, poolTagValue)
	if poolSize == 0 {
		t.Fatalf("no EIPs tagged %s=%s — tag shape drifted from terraform/modules/ac/eip.tf; PR #1006 fence is broken, update the test",
			poolTagKey, poolTagValue)
	}

	// Find max_capacity for the AC ASG.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	asgResp, err := testConfig.ASGClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{asgName},
	})
	if err != nil {
		t.Fatalf("describe AC ASG %s: %v", asgName, err)
	}
	if len(asgResp.AutoScalingGroups) == 0 {
		t.Fatalf("AC ASG %s not found", asgName)
	}
	maxCap := aws.ToInt32(asgResp.AutoScalingGroups[0].MaxSize)
	if maxCap <= 0 {
		t.Fatalf("AC ASG %s has max_size=%d", asgName, maxCap)
	}

	// Formula must mirror terraform/modules/ac/eip.tf:33 exactly,
	// paired with the regression-class reference for the right
	// deploy mode. #1006 is the blue/green parallel-color refresh
	// deadlock; canary has no historical bug class for this
	// assertion yet (see #1454 for whether the +1 slack should mirror).
	//
	// Branching on testConfig.DeployMode (server-side regime) is
	// safe even though the TF formula keys on var.enable_ac_blue_green
	// because the second precondition on aws_ssm_parameter.deploy_mode
	// asserts var.enable_blue_green == var.enable_ac_blue_green at
	// plan time. A half-flip would fail terraform plan, not silently
	// mis-fence here.
	//
	// Single switch (not two) so the {minRequired, ref} pair stays in
	// lockstep — adding a future mode requires one edit, not two.
	var (
		minRequired int
		ref         string
	)
	switch testConfig.DeployMode {
	case DeployModeBlueGreen:
		minRequired = int(2*maxCap + 1)
		ref = "PR #1006 regression"
	case DeployModeCanary:
		minRequired = int(maxCap)
		ref = "TF formula drift (eip.tf:33 vs smoke; see #1454 for whether canary should mirror #1006's +1)"
	default:
		t.Fatalf("unexpected DeployMode %q (want %s or %s)", testConfig.DeployMode, DeployModeBlueGreen, DeployModeCanary)
	}
	if poolSize < minRequired {
		t.Fatalf("EIP pool %s=%s has %d EIPs, minimum is %d (deploy_mode=%s, max_cap=%d) — %s",
			poolTagKey, poolTagValue, poolSize, minRequired, testConfig.DeployMode, maxCap, ref)
	}
	t.Logf("EIP pool %s=%s: size=%d, minimum=%d (deploy_mode=%s, max_cap=%d)", poolTagKey, poolTagValue, poolSize, minRequired, testConfig.DeployMode, maxCap)
}

// TestACEIPPool_AlarmEvaluationPeriodsAtLeast3 reads the CloudWatch
// alarm that watches EIP pool utilization and confirms its
// evaluation_periods is at least 3. The pre-#1006 alarm fired on a
// single breach, which cry-wolfed during every normal instance
// refresh. PR #1006 tuned it to require 3 consecutive breaches.
//
// Regression fence for PR #1006.
func TestACEIPPool_AlarmEvaluationPeriodsAtLeast3(t *testing.T) {
	requireRemote(t) // CloudWatch alarm config is AWS-only; no equivalent in the local stack.
	alarmName := fmt.Sprintf("layerv-nhp-%s-ac-eip-pool-utilization-high", testConfig.Environment)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := testConfig.CWClient.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []string{alarmName},
	})
	if err != nil {
		t.Fatalf("describe alarm %s: %v", alarmName, err)
	}
	if len(resp.MetricAlarms) == 0 {
		// Alarm may be named differently in a future TF rename. Skip
		// rather than fail so the test can be updated deliberately.
		t.Skipf("alarm %s not found — name may have changed, update this test", alarmName)
	}
	a := resp.MetricAlarms[0]
	periods := aws.ToInt32(a.EvaluationPeriods)
	if periods < 3 {
		t.Fatalf("alarm %s: evaluation_periods=%d, want >= 3 (PR #1006 regression)", alarmName, periods)
	}
	t.Logf("alarm %s: evaluation_periods=%d (OK)", alarmName, periods)
}

// NOTE: if PR #1006 is ever structurally obsoleted (EIP claim is
// decoupled from user_data per follow-up #1007), delete this file
// and replace with a new capability test for the new EIP allocation
// mechanism. "Deletion is a valid PR" — see maintenance rule 5 in
// tests/smoke/CLAUDE.md.
