//go:build smoke

package smoke

// Tier 1: AC Elastic IP pool sizing and coverage.
//
// Capability: the pool of EIPs the AC ASG draws from on instance
// launch. The pool is sized to `2 * max_capacity + 1` so that an
// instance refresh that launches a new instance before terminating an
// old one (the default refresh strategy) always has a free EIP to
// claim, avoiding the refresh deadlock.
//
// Regression fence for PR #1006: pre-#1006 the pool was sized to
// max_capacity, which meant every instance refresh deadlocked on a
// tight pool. The test asserts the post-#1006 minimum so no future
// size edit re-introduces the deadlock.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
)

// TestACEIPPool_AllActiveACsHaveEIP enumerates the active AC ASG's
// InService instances and confirms each has an associated public IP
// (EIP). Any instance without an EIP is an acute bug: it either
// can't be reached by the NHP server for AOP messages, or it can't
// egress to AWS APIs, depending on how the missing EIP manifests.
func TestACEIPPool_AllActiveACsHaveEIP(t *testing.T) {
	asgName := requireActiveACASG(t)

	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService AC instances in ASG %s", asgName)
	}

	ips := describeInstancePublicIPs(t, instances)
	for _, id := range instances {
		if ip, ok := ips[id]; !ok || ip == "" {
			t.Errorf("AC instance %s has no public IP (EIP)", id)
		}
	}
}

// TestACEIPPool_PoolSizeMeetsMinimum fences PR #1006. Reads the pool
// size via tag filter and asserts it is at least `2 * max_capacity + 1`
// when blue/green is enabled (which is the only configuration we
// currently run).
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
	asgName := requireActiveACASG(t)

	// The EIP pool is tagged EIPPool=layerv-nhp-{env}-ac. Tag key and
	// value are asserted here against the TF source of truth. DO NOT
	// relax this to a substring match or softer skip path without
	// also updating the terraform comment + this test.
	poolTagKey := "EIPPool"
	poolTagValue := fmt.Sprintf("layerv-nhp-%s-ac", testConfig.Environment)
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

	// Formula from terraform/modules/ac/eip.tf:
	//   enable_blue_green ? max_capacity * 2 + 1 : max_capacity
	// Sandbox and prod both have blue/green enabled. If the count
	// ever drops below max*2+1, the refresh deadlock #1006 fenced is
	// back. If blue/green is ever disabled this test needs to be
	// updated to branch on an env-var signal.
	minRequired := int(2*maxCap + 1)
	if poolSize < minRequired {
		t.Fatalf("EIP pool %s=%s has %d EIPs, minimum is %d (2*max_cap+1 where max_cap=%d) — PR #1006 regression",
			poolTagKey, poolTagValue, poolSize, minRequired, maxCap)
	}
	t.Logf("EIP pool %s=%s: size=%d, minimum=%d (max_cap=%d)", poolTagKey, poolTagValue, poolSize, minRequired, maxCap)
}

// TestACEIPPool_AlarmEvaluationPeriodsAtLeast3 reads the CloudWatch
// alarm that watches EIP pool utilization and confirms its
// evaluation_periods is at least 3. The pre-#1006 alarm fired on a
// single breach, which cry-wolfed during every normal instance
// refresh. PR #1006 tuned it to require 3 consecutive breaches.
//
// Regression fence for PR #1006.
func TestACEIPPool_AlarmEvaluationPeriodsAtLeast3(t *testing.T) {
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
// nhp/CLAUDE.md.
