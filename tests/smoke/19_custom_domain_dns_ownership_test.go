//go:build smoke

package smoke

// Tier 2: custom-domain cert ownership contract.
//
// Capability: every deployed cert under /nhp/certs/<domain>/meta must not have
// public _layerv-verify DNS pointing at a different Layerv verification token.
// This catches stale cross-environment state before the 30-day renewal window
// turns it into scheduled RenewalDnsOwnershipFailures alarm state.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"
)

const (
	customDomainCertPrefix              = "/nhp/certs"
	customDomainCertMetaSuffix          = "/meta"
	customDomainRunbook                 = "docs/runbooks/custom-domain-cert-dns-ownership.md"
	customDomainVerificationTokenPrefix = "lv_verify_"
	dnsLookupAttempts                   = 3
	metaRecheckAttempts                 = 3
	metaRecheckDelay                    = 2 * time.Second
	ownershipSweepWorkers               = 32
	ownershipSweepTimeout               = 4 * time.Minute
	ownershipSweepAllReadsFailedFloor   = 3
)

type customDomainCertRow struct {
	status string
	token  string
}

type customDomainOwnershipFinding struct {
	failed                    bool
	rowReadError              bool
	deterministicRowReadError bool
	message                   string
}

// TestCustomDomainCertDNSOwnership_MatchesManagedRows checks the
// cross-environment ownership shape that caused prod renewal alarms: public
// _layerv-verify TXT contains a Layerv verification token, but it is not this
// environment's qurl-domains token. Missing or arbitrary non-Layerv TXT still
// breaks renewal, but it is customer-controlled DNS drift; keep that visible in
// smoke logs without making unrelated deploys depend on customer DNS.
// Harness read failures, orphaned cert state, token-format drift, and
// bounded-sweep exhaustion are log-only at smoke time. Additionally,
// deterministic qurl-domains table/IAM drift blocks immediately, and
// all-attempted-row-read failure blocks after the minimum-attempt floor because
// a sustained DDB outage may have disabled the cross-environment fence; the
// scheduled renewal aggregate alarms own other fleet-state signals without
// turning customer volume into a promotion blocker.
func TestCustomDomainCertDNSOwnership_MatchesManagedRows(t *testing.T) {
	// Skip cleanly in envs without the custom-domain cert Lambda. Keep this
	// gate in lockstep with the paired cleanup smoke test.
	if _, ok := getSSMParameter(t, "/"+testConfig.Environment+"/nhp/custom-domain-cert/cleanup-topic-arn"); !ok {
		t.Skipf("skipped: env %q has not deployed the custom-domain cert lambda", testConfig.Environment)
	}
	// Deployment-completeness gate only. The cleanup topic can exist while a
	// hand-edit or partial apply dropped the Lambda/log wiring this smoke fence
	// relies on.
	if _, ok := getSSMParameter(t, "/"+testConfig.Environment+"/nhp/custom-domain-cert/lambda-log-group"); !ok {
		t.Fatalf("cleanup topic ARN is present but lambda-log-group SSM param is missing -- terraform drift or hand-edit")
	}

	domains := listCustomDomainCertMetaDomains(t)
	if len(domains) == 0 {
		t.Skipf("skipped: no custom-domain cert metadata under %s", customDomainCertPrefix)
	}

	tableName := customDomainQurlDomainsTableName()
	workerCount := min(ownershipSweepWorkers, len(domains))
	t.Logf("checking %d custom-domain cert DNS ownership row(s) with %d worker(s)", len(domains), workerCount)

	ctx, cancel, deadlineSource := ownershipSweepContext(t)
	defer cancel()

	jobs := make(chan string)
	findings := make(chan customDomainOwnershipFinding, len(domains))
	var checked int64
	var rowReadAttempts int64
	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for domain := range jobs {
				finding, ok, rowReadAttempted := checkCustomDomainCertDNSOwnership(ctx, tableName, domain)
				if rowReadAttempted {
					atomic.AddInt64(&rowReadAttempts, 1)
				}
				if ok {
					findings <- finding
				}
				if ok || rowReadAttempted {
					atomic.AddInt64(&checked, 1)
				}
			}
		}()
	}

enqueue:
	for _, domain := range domains {
		select {
		case jobs <- domain:
		case <-ctx.Done():
			break enqueue
		}
	}
	close(jobs)
	workers.Wait()
	close(findings)

	var rowReadErrors int
	var deterministicRowReadErrors int
	for finding := range findings {
		if finding.rowReadError {
			rowReadErrors++
		}
		if finding.deterministicRowReadError {
			deterministicRowReadErrors++
		}
		if finding.failed {
			t.Error(finding.message)
		} else {
			t.Log(finding.message)
		}
	}

	checkedCount := atomic.LoadInt64(&checked)
	if err := ctx.Err(); err != nil {
		t.Logf("custom-domain ownership sweep exceeded %s after checking %d/%d domain(s): %v; leaving incomplete coverage as a smoke signal only at fleet scale; raise ownershipSweepTimeout only after measuring actual fleet runtime",
			deadlineSource, checkedCount, len(domains), err)
	} else if checkedCount < int64(len(domains)) {
		t.Logf("custom-domain ownership sweep checked %d/%d domain(s) before worker completion; leaving incomplete coverage as a smoke signal only at fleet scale; raise ownershipSweepTimeout only after measuring actual fleet runtime",
			checkedCount, len(domains))
	}
	rowReadAttemptCount := atomic.LoadInt64(&rowReadAttempts)
	if shouldBlockQurlDomainsReadFailures(deterministicRowReadErrors, rowReadErrors, rowReadAttemptCount) {
		if deterministicRowReadErrors == 0 {
			t.Errorf("custom-domain ownership sweep could not read any %s row across %d attempted row read(s); "+
				"this likely means cell/table/IAM drift or a sustained DDB outage, so the blocking cross-environment fence is disabled",
				tableName, rowReadAttemptCount)
			return
		}
		t.Errorf("custom-domain ownership sweep hit %d deterministic %s read error(s) across %d attempted row read(s); "+
			"this likely means qurl-domains table/cell/IAM drift, so the blocking cross-environment fence is disabled",
			deterministicRowReadErrors, tableName, rowReadAttemptCount)
	} else if rowReadAttemptCount > 0 && rowReadErrors == int(rowReadAttemptCount) {
		// Deadline-cancelled reads count as attempts but emit no row-read
		// finding, so a timed-out sweep cannot masquerade as cell/table/IAM
		// drift. Require a small attempt floor before blocking so a one-domain
		// env is not held by one persistent DDB retry window. Deterministic
		// table/cell/IAM errors bypass the floor above.
		if rowReadAttemptCount < ownershipSweepAllReadsFailedFloor {
			t.Logf("custom-domain ownership sweep could not read any %s row across %d attempted row read(s), below the %d-attempt blocking floor; "+
				"leaving as log-only to avoid blocking on a low-fleet transient, but rerun if this persists",
				tableName, rowReadAttemptCount, ownershipSweepAllReadsFailedFloor)
		}
	}
}

func customDomainQurlDomainsTableName() string {
	// Intentionally duplicates terraform/main.tf::local.name_prefix plus
	// terraform/modules/dynamodb/main.tf::aws_dynamodb_table.qurl_domains.name
	// rather than discovering by prefix. If Terraform renames the table or
	// testConfig.CellID drifts from the deployed cell, every read fails against
	// the IAM-granted table ARN and the sweep fails loud instead of silently
	// disabling the blocking fence.
	return fmt.Sprintf("layerv-nhp-%s-%s-qurl-domains", testConfig.Environment, testConfig.CellID)
}

func ownershipSweepContext(t *testing.T) (context.Context, context.CancelFunc, string) {
	deadline := time.Now().Add(ownershipSweepTimeout)
	deadlineSource := fmt.Sprintf("ownershipSweepTimeout (%s)", ownershipSweepTimeout)
	if testDeadline, ok := t.Deadline(); ok {
		testBudgetDeadline := testDeadline.Add(-30 * time.Second)
		if testBudgetDeadline.Before(deadline) {
			deadline = testBudgetDeadline
			deadlineSource = "test deadline minus 30s"
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	return ctx, cancel, deadlineSource
}

func checkCustomDomainCertDNSOwnership(
	ctx context.Context,
	tableName, domain string,
) (finding customDomainOwnershipFinding, hasFinding bool, rowReadAttempted bool) {
	if ctx.Err() != nil {
		return customDomainOwnershipFinding{}, false, false
	}
	row, ok, err := getCustomDomainCertRow(ctx, tableName, domain)
	rowReadAttempted = true
	if err != nil {
		if isSweepContextError(ctx, err) {
			return customDomainOwnershipFinding{}, false, rowReadAttempted
		}
		deterministic := isDeterministicQurlDomainsReadError(err)
		resolution := "leaving as log-only because renewal aggregate alarms own fleet-state failures"
		if deterministic {
			resolution = "blocking because deterministic table/cell/IAM drift disables the cross-environment fence"
		}
		return customDomainOwnershipFinding{
			rowReadError:              true,
			deterministicRowReadError: deterministic,
			message: fmt.Sprintf(
				"smoke harness could not read %s qurl-domains row for %s: %v; "+
					"%s; rerun after AWS recovers, then see %s if this persists",
				tableName, domain, err, resolution, customDomainRunbook,
			),
		}, true, rowReadAttempted
	}
	if ctx.Err() != nil {
		return customDomainOwnershipFinding{}, false, rowReadAttempted
	}
	if !ok || row.token == "" {
		stillPresent, err := customDomainCertMetaStillPresentAfterRetry(ctx, domain)
		if err != nil {
			if isSweepContextError(ctx, err) {
				return customDomainOwnershipFinding{}, false, rowReadAttempted
			}
			return customDomainOwnershipFinding{
				message: fmt.Sprintf(
					"%s has no managed %s row with verification_token, and SSM meta recheck failed: %v; "+
						"leaving as log-only because renewal aggregate alarms own orphan detection; see %s",
					domain, tableName, err, customDomainRunbook,
				),
			}, true, rowReadAttempted
		}
		if ctx.Err() != nil {
			return customDomainOwnershipFinding{}, false, rowReadAttempted
		}
		if !stillPresent {
			return customDomainOwnershipFinding{
				message: fmt.Sprintf("%s cert metadata disappeared while checking ownership; treating as in-flight offboard cleanup", domain),
			}, true, rowReadAttempted
		}
		return customDomainOwnershipFinding{
			message: fmt.Sprintf(
				"%s has cert material in SSM but no managed %s row with verification_token; "+
					"renewal will report RenewalOrphanedCerts until stale cert state is offboarded/deleted (see %s)",
				domain, tableName, customDomainRunbook,
			),
		}, true, rowReadAttempted
	}
	if !strings.HasPrefix(row.token, customDomainVerificationTokenPrefix) {
		return customDomainOwnershipFinding{
			message: fmt.Sprintf(
				"%s managed verification_token %q does not start with %q; "+
					"cannot classify cross-environment TXT safely, leaving as log-only; update this smoke fence before relying on cross-env token classification (see %s)",
				domain, row.token, customDomainVerificationTokenPrefix, customDomainRunbook,
			),
		}, true, rowReadAttempted
	}

	verifyName := "_layerv-verify." + domain
	txtValues, err := lookupTXTValues(ctx, verifyName)
	if err != nil {
		if isSweepContextError(ctx, err) {
			return customDomainOwnershipFinding{}, false, rowReadAttempted
		}
		return customDomainOwnershipFinding{
			message: fmt.Sprintf(
				"%s has cert material in SSM but %s TXT lookup did not return values: %v; "+
					"renewal will fail until DNS is restored or stale cert state is offboarded (status=%q; see %s)",
				domain, verifyName, err, row.status, customDomainRunbook,
			),
		}, true, rowReadAttempted
	}
	if ctx.Err() != nil {
		return customDomainOwnershipFinding{}, false, rowReadAttempted
	}
	if slices.Contains(txtValues, row.token) {
		return customDomainOwnershipFinding{}, false, rowReadAttempted
	}

	otherLayervTokens := layervVerificationTokens(txtValues)
	if len(otherLayervTokens) > 0 {
		return customDomainOwnershipFinding{
			failed: true,
			message: fmt.Sprintf(
				"%s has cert material in SSM but public %s TXT contains other Layerv verification token(s) %q "+
					"(status=%q). If DNS now belongs to another env, offboard/delete this domain from %s; "+
					"if it should remain in %s, restore this env's verification TXT. See %s",
				domain, verifyName, otherLayervTokens, row.status,
				testConfig.Environment, testConfig.Environment, customDomainRunbook,
			),
		}, true, rowReadAttempted
	}

	return customDomainOwnershipFinding{
		message: fmt.Sprintf(
			"%s has cert material in SSM but public %s TXT values %q do not contain this environment's verification token; "+
				"renewal will fail until DNS is restored or stale cert state is offboarded (status=%q; see %s)",
			domain, verifyName, txtValues, row.status, customDomainRunbook,
		),
	}, true, rowReadAttempted
}

func isSweepContextError(ctx context.Context, err error) bool {
	return ctx.Err() != nil &&
		(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
}

func isDeterministicQurlDomainsReadError(err error) bool {
	var notFound *ddbtypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return true
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDenied", "AccessDeniedException", "ResourceNotFoundException":
		return true
	}
	return false
}

func shouldBlockQurlDomainsReadFailures(
	deterministicRowReadErrors int,
	rowReadErrors int,
	rowReadAttemptCount int64,
) bool {
	if deterministicRowReadErrors > 0 {
		return true
	}
	return rowReadAttemptCount >= ownershipSweepAllReadsFailedFloor &&
		rowReadErrors == int(rowReadAttemptCount)
}

func TestCustomDomainCertDNSOwnership_DeterministicQurlDomainsReadError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "modeled resource not found",
			err:  &ddbtypes.ResourceNotFoundException{Message: aws.String("table missing")},
			want: true,
		},
		{
			name: "generic resource not found",
			err:  &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "table missing"},
			want: true,
		},
		{
			name: "generic access denied exception",
			err:  &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"},
			want: true,
		},
		{
			name: "generic access denied",
			err:  &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"},
			want: true,
		},
		{
			name: "throttling stays transient",
			err:  &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "throttled"},
			want: false,
		},
		{
			name: "context deadline stays timeout-shaped",
			err:  context.DeadlineExceeded,
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isDeterministicQurlDomainsReadError(tt.err); got != tt.want {
				t.Fatalf("isDeterministicQurlDomainsReadError(%T) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestCustomDomainCertDNSOwnership_ShouldBlockQurlDomainsReadFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                       string
		deterministicRowReadErrors int
		rowReadErrors              int
		rowReadAttemptCount        int64
		want                       bool
	}{
		{
			name:                       "deterministic drift blocks below floor",
			deterministicRowReadErrors: 1,
			rowReadErrors:              1,
			rowReadAttemptCount:        1,
			want:                       true,
		},
		{
			name:                "all transient errors below floor stay log only",
			rowReadErrors:       2,
			rowReadAttemptCount: 2,
			want:                false,
		},
		{
			name:                "all transient errors at floor block",
			rowReadErrors:       ownershipSweepAllReadsFailedFloor,
			rowReadAttemptCount: ownershipSweepAllReadsFailedFloor,
			want:                true,
		},
		{
			name:                "timeout attempts without row-read findings do not block",
			rowReadErrors:       1,
			rowReadAttemptCount: 2,
			want:                false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := shouldBlockQurlDomainsReadFailures(
				tt.deterministicRowReadErrors,
				tt.rowReadErrors,
				tt.rowReadAttemptCount,
			)
			if got != tt.want {
				t.Fatalf("shouldBlockQurlDomainsReadFailures(%d, %d, %d) = %v, want %v",
					tt.deterministicRowReadErrors, tt.rowReadErrors, tt.rowReadAttemptCount, got, tt.want)
			}
		})
	}
}

func customDomainCertMetaStillPresentAfterRetry(ctx context.Context, domain string) (bool, error) {
	name := customDomainCertPrefix + "/" + domain + customDomainCertMetaSuffix
	var lastErr error
	sawPresent := false
	for attempt := 1; attempt <= metaRecheckAttempts; attempt++ {
		_, present, err := readSSMParameterWithContext(ctx, name)
		if err == nil {
			if !present {
				return false, nil
			}
			sawPresent = true
			lastErr = nil
		} else {
			lastErr = err
		}
		if attempt < metaRecheckAttempts {
			select {
			case <-time.After(metaRecheckDelay):
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}
	}
	if sawPresent {
		return true, nil
	}
	return false, lastErr
}

func listCustomDomainCertMetaDomains(t *testing.T) []string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	p := ssm.NewGetParametersByPathPaginator(testConfig.SSMClient, &ssm.GetParametersByPathInput{
		Path:           aws.String(customDomainCertPrefix),
		Recursive:      aws.Bool(true),
		WithDecryption: aws.Bool(false),
	})

	seen := map[string]struct{}{}
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			t.Fatalf("list %s parameters: %v", customDomainCertPrefix, err)
		}
		for _, param := range page.Parameters {
			name := aws.ToString(param.Name)
			if !strings.HasSuffix(name, customDomainCertMetaSuffix) {
				continue
			}
			domain := strings.TrimSuffix(strings.TrimPrefix(name, customDomainCertPrefix+"/"), customDomainCertMetaSuffix)
			if domain == "" || strings.Contains(domain, "/") {
				t.Fatalf("unexpected custom-domain cert meta path %q under %s", name, customDomainCertPrefix)
			}
			seen[domain] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for domain := range seen {
		out = append(out, domain)
	}
	slices.Sort(out)
	return out
}

func getCustomDomainCertRow(ctx context.Context, tableName, domain string) (customDomainCertRow, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// aws-sdk-go-v2's default retryer covers transient DDB throttling; avoid a
	// local retry loop so the sweep-wide deadline remains the fleet cap. Use a
	// strongly consistent read because a cross-environment token finding blocks
	// deploys; a just-rotated verification_token should not hard-fail on a stale
	// DDB replica.
	resp, err := testConfig.DDBClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"domain": &ddbtypes.AttributeValueMemberS{Value: domain},
		},
		ConsistentRead:       aws.Bool(true),
		ProjectionExpression: aws.String("#s, verification_token"),
		ExpressionAttributeNames: map[string]string{
			"#s": "status",
		},
	})
	if err != nil {
		return customDomainCertRow{}, false, err
	}
	if len(resp.Item) == 0 {
		return customDomainCertRow{}, false, nil
	}
	return customDomainCertRow{
		status: attrString(resp.Item["status"]),
		token:  attrString(resp.Item["verification_token"]),
	}, true, nil
}

func attrString(v ddbtypes.AttributeValue) string {
	if s, ok := v.(*ddbtypes.AttributeValueMemberS); ok {
		return s.Value
	}
	return ""
}

func lookupTXTValues(ctx context.Context, name string) ([]string, error) {
	var lastErr error
	for attempt := 1; attempt <= dnsLookupAttempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		values, err := net.DefaultResolver.LookupTXT(attemptCtx, name)
		cancel()
		if err == nil {
			slices.Sort(values)
			return values, nil
		}
		lastErr = err
		if isDefinitiveDNSNotFound(err) {
			break
		}
		if attempt < dnsLookupAttempts {
			backoff := time.Duration(attempt) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return nil, fmt.Errorf("TXT lookup did not return values: %w", lastErr)
}

func isDefinitiveDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

func layervVerificationTokens(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, customDomainVerificationTokenPrefix) {
			out = append(out, value)
		}
	}
	return out
}
