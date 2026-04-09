//go:build smoke

package smoke

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	astypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// aws_helpers.go collects the read-only AWS API calls used across
// tests. All helpers fail the test on error; they never silently skip
// or return empty slices as a "not available" signal.

// inServiceCache memoizes DescribeAutoScalingGroups results per ASG
// name for the lifetime of a test process. The InService instance
// set doesn't change during a smoke run, and five Tier 1 tests
// read it for the same ASG — we'd otherwise burn 5× DescribeASG
// API calls for identical results.
//
// Concurrency: Tier 1 tests run serially (no t.Parallel()), so
// the check-then-act pattern below is not a real race today. When
// #1014 lands t.Parallel() on independent tests, two goroutines
// may both hit the cache-miss path and both call the API; the
// second write clobbers the first, both goroutines return their
// own results, and the cost is at most one redundant API call per
// ASG per process start. Acceptable — no need to convert to
// sync.Once or keyed-Once until measurements say otherwise.
var (
	inServiceCacheMu sync.Mutex
	inServiceCache   = map[string][]string{}
)

// describeInServiceInstances returns the instance IDs of every
// InService member of the named ASG. Results are cached per ASG
// name for the process lifetime.
//
// Empty slice on success is possible (ASG has zero desired) and
// callers must handle it. A cache hit never fails; a cache miss
// calls DescribeAutoScalingGroups and t.Fatalf's on error.
func describeInServiceInstances(t *testing.T, asgName string) []string {
	t.Helper()

	inServiceCacheMu.Lock()
	if cached, ok := inServiceCache[asgName]; ok {
		inServiceCacheMu.Unlock()
		return cached
	}
	inServiceCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := testConfig.ASGClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{asgName},
	})
	if err != nil {
		t.Fatalf("describe ASG %s: %v", asgName, err)
	}
	if len(resp.AutoScalingGroups) == 0 {
		t.Fatalf("ASG %s not found", asgName)
	}

	var ids []string
	for _, inst := range resp.AutoScalingGroups[0].Instances {
		if inst.LifecycleState == astypes.LifecycleStateInService && inst.InstanceId != nil {
			ids = append(ids, *inst.InstanceId)
		}
	}

	inServiceCacheMu.Lock()
	inServiceCache[asgName] = ids
	inServiceCacheMu.Unlock()
	return ids
}

// describeASGCapacity returns the desired and min capacity of the
// named ASG. Used by blue/green tests to assert that the inactive
// color is scaled to zero.
func describeASGCapacity(t *testing.T, asgName string) (desired, minSize int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := testConfig.ASGClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{asgName},
	})
	if err != nil {
		t.Fatalf("describe ASG %s: %v", asgName, err)
	}
	if len(resp.AutoScalingGroups) == 0 {
		t.Fatalf("ASG %s not found", asgName)
	}
	g := resp.AutoScalingGroups[0]
	return aws.ToInt32(g.DesiredCapacity), aws.ToInt32(g.MinSize)
}

// describeInstancePublicIPs returns a map from instance ID to the
// public IP (EIP) currently associated with that instance. Instances
// without an EIP are omitted from the map — the caller decides if
// that's a failure.
func describeInstancePublicIPs(t *testing.T, instanceIDs []string) map[string]string {
	t.Helper()
	if len(instanceIDs) == 0 {
		return map[string]string{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := testConfig.EC2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: instanceIDs,
	})
	if err != nil {
		t.Fatalf("describe instances %v: %v", instanceIDs, err)
	}

	out := make(map[string]string)
	for _, r := range resp.Reservations {
		for _, inst := range r.Instances {
			if inst.InstanceId == nil || inst.PublicIpAddress == nil {
				continue
			}
			out[*inst.InstanceId] = *inst.PublicIpAddress
		}
	}
	return out
}

// describeElasticIPPool returns the total number of allocated EIPs
// tagged with the given tag key+value. Used to size-check the AC EIP
// pool against the `2*max_capacity + 1` minimum fenced by PR #1006.
func describeElasticIPPool(t *testing.T, tagKey, tagValue string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := testConfig.EC2Client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("tag:" + tagKey),
				Values: []string{tagValue},
			},
		},
	})
	if err != nil {
		t.Fatalf("describe addresses tag:%s=%s: %v", tagKey, tagValue, err)
	}
	return len(resp.Addresses)
}

// getSSMParameter reads a single plain-text SSM parameter. Returns
// (value, true) on success, ("", false) if the parameter is missing.
// Any OTHER AWS error (permissions, network) fails the test — those
// are bugs in the smoke-suite setup, not missing-data conditions.
//
// This helper intentionally does NOT decrypt SecureStrings — tests
// that need to read secrets should fail loudly rather than silently
// dragging them into test output.
func getSSMParameter(t *testing.T, name string) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := testConfig.SSMClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var notFound *ssmtypes.ParameterNotFound
		if errors.As(err, &notFound) {
			return "", false
		}
		t.Fatalf("ssm get-parameter %s: %v", name, err)
	}
	if resp.Parameter == nil || resp.Parameter.Value == nil {
		return "", false
	}
	return *resp.Parameter.Value, true
}
