//go:build smoke

package smoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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

// cellIDPattern mirrors the validation block on var.cell_id in
// terraform/variables.tf — lowercase alphanumeric with optional
// internal single dashes, leading/trailing/double dashes rejected.
// TF enforces this at apply time; we re-check here as defense in
// depth against an out-of-band `aws ssm put-parameter` overwrite,
// since CellID gets concatenated into SSM paths in the canary tests
// and a "../foo" value would produce surprising lookups.
//
// cellIDMaxLen mirrors `length(var.cell_id) <= 32` in
// terraform/variables.tf. Drift-prevention cross-link is tracked in
// #1452 (TF↔smoke duplicated-constant cross-references).
var cellIDPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

const cellIDMaxLen = 32

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
// callers must handle it. Empty results are intentionally not cached
// because they can also be a transient refresh race. A non-empty cache
// hit never fails; a cache miss calls DescribeAutoScalingGroups and
// t.Fatalf's on error.
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

	// Empty InService lists can be a refresh race; do not cache them
	// or callers with a local retry loop will keep seeing the transient.
	if len(ids) > 0 {
		inServiceCacheMu.Lock()
		inServiceCache[asgName] = ids
		inServiceCacheMu.Unlock()
	}
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

// describeInstanceElasticIPs returns a map from instance ID to the
// public EIP currently associated with that instance from the tagged
// AC EIP pool. Instances with only an EC2 auto-assigned public IP are
// omitted from the map because they are not safe stable egress IPs.
func describeInstanceElasticIPs(t *testing.T, instanceIDs []string, tagKey, tagValue string) map[string]string {
	t.Helper()
	if len(instanceIDs) == 0 {
		return map[string]string{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := testConfig.EC2Client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("instance-id"),
				Values: instanceIDs,
			},
			{
				Name:   aws.String("tag:" + tagKey),
				Values: []string{tagValue},
			},
		},
	})
	if err != nil {
		t.Fatalf("describe addresses for instances %v tag:%s=%s: %v", instanceIDs, tagKey, tagValue, err)
	}

	out := make(map[string]string)
	for _, addr := range resp.Addresses {
		if addr.InstanceId == nil || addr.PublicIp == nil {
			continue
		}
		out[*addr.InstanceId] = *addr.PublicIp
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

// deployDiscovery is the pair of values smoke needs to read at
// startup before any test runs. Both keys are Terraform-owned (see
// terraform/main.tf::aws_ssm_parameter.deploy_mode and ::cell_id);
// shape validation lives in terraform/variables.tf::cell_id.
type deployDiscovery struct {
	Mode   string
	CellID string
}

// fetchDeployDiscovery reads /{env}/nhp/deploy/{mode,cell-id} in a
// single GetParameters round-trip. Called from TestMain — failure
// here (missing param, unknown value, infra error) means smoke is
// pointed at a non-deployed env or one whose terraform is out of
// date, and a hard error is the right signal.
//
// One batch call instead of two serial GetParameter calls keeps
// suite startup snappy when the SSM endpoint is slow, and it
// consolidates the "missing — env not deployed or terraform out of
// date" error path so the message can't drift between callers.
func fetchDeployDiscovery(ctx context.Context, client *ssm.Client, env string) (deployDiscovery, error) {
	modeName := "/" + env + "/nhp/deploy/mode"
	cellName := "/" + env + "/nhp/deploy/cell-id"

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := client.GetParameters(cctx, &ssm.GetParametersInput{
		Names:          []string{modeName, cellName},
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return deployDiscovery{}, fmt.Errorf("ssm get-parameters %v: %w", []string{modeName, cellName}, err)
	}
	if len(resp.InvalidParameters) > 0 {
		return deployDiscovery{}, fmt.Errorf("SSM parameters missing %v — env not deployed or terraform out of date", resp.InvalidParameters)
	}

	out := deployDiscovery{}
	for _, p := range resp.Parameters {
		if p.Name == nil || p.Value == nil {
			continue
		}
		switch *p.Name {
		case modeName:
			out.Mode = *p.Value
		case cellName:
			out.CellID = *p.Value
		}
	}
	// Distinguish absent-from-response from value-validation failures.
	// InvalidParameters above catches names AWS rejected; this catches
	// the residual case where a parameter was returned with a nil
	// Name/Value (or, defensively, didn't match either expected key)
	// so operators don't chase a confusing "want blue_green or canary"
	// when the real issue is an empty response slot.
	if out.Mode == "" {
		return deployDiscovery{}, fmt.Errorf("SSM parameter %s absent from response", modeName)
	}
	if out.CellID == "" {
		return deployDiscovery{}, fmt.Errorf("SSM parameter %s absent from response", cellName)
	}
	switch out.Mode {
	case DeployModeBlueGreen, DeployModeCanary:
	default:
		return deployDiscovery{}, fmt.Errorf("SSM parameter %s = %q, want %s or %s", modeName, out.Mode, DeployModeBlueGreen, DeployModeCanary)
	}
	if len(out.CellID) > cellIDMaxLen || !cellIDPattern.MatchString(out.CellID) {
		return deployDiscovery{}, fmt.Errorf("SSM parameter %s = %q does not match terraform/variables.tf::cell_id shape (lowercase alphanumeric, optional internal single dashes, 1..%d chars) — out-of-band overwrite?", cellName, out.CellID, cellIDMaxLen)
	}
	return out, nil
}

// readSSMParameterWithContext reads a single plain-text SSM parameter. Returns
// (value, true, nil) on success and ("", false, nil) only for
// ParameterNotFound. Malformed AWS responses, including a nil Parameter or nil
// Parameter.Value, are returned as errors so skip-gate callers fail loud instead
// of treating corrupt payloads as "environment not deployed".
//
// Intentionally does NOT decrypt SecureStrings — tests that need to
// read secrets should fail loudly rather than silently dragging them
// into test output.
func readSSMParameterWithContext(ctx context.Context, name string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := testConfig.SSMClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var notFound *ssmtypes.ParameterNotFound
		if errors.As(err, &notFound) {
			return "", false, nil
		}
		return "", false, err
	}
	if resp.Parameter == nil {
		return "", false, fmt.Errorf("SSM GetParameter %s returned nil Parameter", name)
	}
	if resp.Parameter.Value == nil {
		return "", false, fmt.Errorf("SSM GetParameter %s returned nil Parameter.Value", name)
	}
	return *resp.Parameter.Value, true, nil
}

// resolvePublicALBLockdownExpectedBody reads the qurl-service public-ALB
// /internal/* lockdown fixed-response body from the SSM parameter Terraform
// publishes at /{env}/nhp/qurl/internal-lockdown-body, and parses it into the
// expected-shape map the 09_public_alb_internal_lockdown_test.go wire
// assertions compare against.
//
// #1645, Path B. Terraform sets that parameter from the SAME local that drives
// the listener rule's fixed_response.message_body
// (terraform/modules/qurl-service/main.tf::local.public_internal_lockdown_body),
// so the served body and this expected body cannot drift across an apply. The
// fence then compares the live wire response against THIS IaC-pinned value —
// not against a DescribeRules read of the rule it probes — which is what makes
// it flip red on an out-of-band rule edit (acceptance criterion #5): the edit
// moves the wire response but not this parameter. A DescribeRules-sourced
// expected value (Path A) would read the edited rule and move both sides
// together, so it could never fail on a body edit.
//
// Called from TestMain only when QURLInternalALBEnabled is set; on envs where
// the lockdown rule isn't wired the parameter doesn't exist and the read is
// skipped. When it IS enabled the read MUST succeed — a missing/unparseable
// parameter is a hard error (Terraform out of date, env mis-gated, or the body
// shape changed without updating this resolver). TestMain records that error
// rather than os.Exit-ing, and the 09_* lockdown fences surface it via
// requirePublicALBLockdownExpectedBody, so the failure stays scoped to the
// fences that depend on the body instead of aborting the whole suite (mode/cell
// in fetchDeployDiscovery is universal, so that one is fatal; this is not).
func resolvePublicALBLockdownExpectedBody(ctx context.Context, env string) (map[string]string, error) {
	name := "/" + env + "/nhp/qurl/internal-lockdown-body"

	value, ok, err := readSSMParameterWithContext(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("ssm get-parameter %s: %w", name, err)
	}
	if !ok {
		return nil, fmt.Errorf("SSM parameter %s missing — qurl-service terraform out of date (the module publishes it whenever domain_name+internal_alb_enabled), or this env is mis-gated as internal-ALB-enabled", name)
	}

	var body map[string]string
	if err := json.Unmarshal([]byte(value), &body); err != nil {
		return nil, fmt.Errorf("SSM parameter %s value %q does not decode into map[string]string — if #1642 switched the lockdown body to text/plain, this resolver and publicALBLockdownExpectedBody's type must change in the same PR: %w", name, value, err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("SSM parameter %s decoded to an empty object — expected the lockdown body shape", name)
	}
	return body, nil
}

// getSSMParameter wraps readSSMParameterWithContext for callers where any AWS
// error other than ParameterNotFound is a smoke-suite setup bug.
func getSSMParameter(t *testing.T, name string) (string, bool) {
	t.Helper()
	requireRemote(t)

	value, ok, err := readSSMParameterWithContext(context.Background(), name)
	if err != nil {
		t.Fatalf("ssm get-parameter %s: %v", name, err)
	}
	return value, ok
}
