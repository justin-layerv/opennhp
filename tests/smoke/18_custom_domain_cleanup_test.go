//go:build smoke

package smoke

// Tier 2: custom-domain cleanup consumer contract.
//
// Capability added in PR #1993. Closes #2000.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/google/uuid"
)

// smokeCleanupDomainPrefix is in lockstep with the `/nhp/certs/smoke-cleanup-*`
// SSM resource pattern in terraform/main.tf::smoke_custom_domain_cleanup —
// any drift breaks PutParameter with AccessDenied.
const smokeCleanupDomainPrefix = "smoke-cleanup-"

// cleanupEventType is the SNS message-attribute value the lambda dispatcher
// matches in handler() to route to handle_domain_cleanup. Wire-contract
// owned by qurl-service/internal/events/domain_event_publisher.go and
// mirrored in custom_domain_cert_manager.py::EVENT_DOMAIN_CLEANUP — three
// places stay in lockstep; the publisher repo is the canonical source.
//
// No CI lint enforces this cross-repo lockstep — the three constants live
// in two different repositories and a Go module/Python module/Go module
// split, so a structural grep is awkward. If any of the three drift, this
// smoke test catches it at the 90s log-line poll timeout, not at lint
// time. Future readers: don't go looking for the lint that doesn't exist
// (the log-line-prefix lockstep IS lint-fenced via
// scripts/check-cert-cleanup-log-gate-unique.sh — but only inside this
// repo).
const cleanupEventType = "domain.cleanup"

// cleanupLogLinePrefix is the literal substring the lambda emits at the
// tail of handle_domain_cleanup (see the back-pointer comment near
// `logger.info` in custom_domain_cert_manager.py). Combined with the
// per-run UUID in `domain` it gives a per-event-unique match. SSM-side
// regressions (e.g. SSM_CERT_PREFIX drift) are fenced by
// assertSSMParamsAbsent, not by log-line shape matching — keeping this
// substring narrow keeps the test resilient to log-format refactors.
const cleanupLogLinePrefix = "Domain cleanup complete for"

// smokeCleanupLogTimeout caps the FilterLogEvents wait. SNS→Lambda delivery
// is typically <5s; log ingestion can lag 5–15s. If runs flake on the
// timeout (e.g. cold-start drift), this is the first knob to reach for —
// not the polling cadence. Effective scan window is wider:
// publishedAt = time.Now() - cwlIngestionClockPad (5s), so the
// FilterLogEvents StartTime covers ~95s of log group activity. Cost
// is one extra scan-window second per smoke run.
const smokeCleanupLogTimeout = 90 * time.Second

// TestCustomDomainCleanup_LambdaProcessesPublishedEvent publishes a
// synthetic domain.cleanup event, waits for the cert lambda's
// "Domain cleanup complete for {domain}" log line, then asserts the
// pre-staged SSM cert params are gone.
//
// Headline regression this fences: the `alias/aws/sns` AWS-managed-key
// implicit grant. SNS encrypts the topic with that key and authorises
// in-account kms:GenerateDataKey for any sns:Publish caller via a built-in
// policy. The smoke role's IAM policy
// (terraform/main.tf::aws_iam_role_policy.smoke_custom_domain_cleanup)
// grants sns:Publish ONLY — no explicit kms:* — so a regression in that
// implicit grant returns AccessDenied on Publish and trips this test.
//
// Skip semantics:
//   - topic-arn SSM param absent → env hasn't deployed the cert lambda → skip.
//   - log-group param absent while topic-arn present → terraform drift → fatal.
//
// "Absent" here is strictly ParameterNotFound — getSSMParameter t.Fatalfs
// on any other SSM error (throttle / IAM / network), so a degraded
// harness fails loud rather than skipping silently as a feature-disabled
// env.
//
// Not gated on AllowSSMProbes: the cleanup tail's SSM SendCommand fires
// from the lambda role, not the smoke role, matching a real customer
// offboard. The lambda deletes the smoke cert params before dispatching
// the AC SendCommand, so the AC's --delete branch finds nothing to act on.
//
// Scope-outs (deliberate):
//   - Route53 TXT cleanup: acme_cname_target omitted in the payload, so
//     delete_acme_txt_record is a no-op.
//   - AC fan-out: when the lambda's AC_INSTANCE_TAG env var is unset
//     (e.g. envs without an AC fleet), trigger_cert_delete returns early
//     and the cleanup-complete log line still fires. The smoke pass
//     condition is "lambda processed the event," not "AC fleet evicted."
//
// Leak surface: a runner crash between PutParameter and t.Cleanup
// (panic / OOM / runner-termination) leaks pre-staged params. The IAM
// scope bounds them to `/nhp/certs/smoke-cleanup-*` and values are the
// literal string "smoke-test-synthetic-not-a-real-cert" — no real cert
// material exposed.
func TestCustomDomainCleanup_LambdaProcessesPublishedEvent(t *testing.T) {
	requireCWLogs(t)
	t.Parallel()

	topicArn, ok := getSSMParameter(t, "/"+testConfig.Environment+"/nhp/custom-domain-cert/cleanup-topic-arn")
	if !ok {
		t.Skipf("skipped: env %q has not deployed the custom-domain cert lambda (no cleanup topic ARN in SSM)", testConfig.Environment)
	}
	// getSSMParameter returns ("", false) on a nil Parameter/Value
	// and ("", true) only when a literal empty string is the param
	// value. AWS SSM PutParameter rejects empty strings at the API,
	// so this branch is unreachable through normal terraform — but
	// fail loud rather than letting sns.Publish see "" if it ever is.
	if topicArn == "" {
		t.Fatalf("cleanup topic ARN SSM param exists but is empty — terraform drift")
	}
	logGroup, ok := getSSMParameter(t, "/"+testConfig.Environment+"/nhp/custom-domain-cert/lambda-log-group")
	if !ok {
		// The two SSM params share the same `var.deploy_custom_domain_cert`
		// count gate, so divergence only happens via a hand-edit (operator
		// running `aws ssm delete-parameter` against one and not the other).
		// That's itself a useful signal — fail loud rather than skip.
		t.Fatalf("cleanup topic ARN is present but lambda-log-group SSM param is missing — terraform drift or hand-edit")
	}

	domain := smokeCleanupDomainPrefix + uuid.NewString() + ".example.invalid"
	prefix := "/nhp/certs/" + domain
	names := []string{prefix + "/key", prefix + "/chain", prefix + "/meta"}

	// Cleanup registered BEFORE pre-stage: a partial PutParameter run
	// (throttle / IAM eval lag) would otherwise leak the first success.
	// ParameterNotFound is the expected post-success path (the lambda
	// already deleted the param) and is suppressed; any other error is
	// surfaced via t.Logf so a degraded cleanup branch — IAM tightening,
	// role rotation — stays visible in CI. The "LEAK:" prefix is grep-
	// anchored: CI log dashboards scan for it across the smoke matrix.
	t.Cleanup(func() {
		// Per-call 5s context so a slow first delete can't squeeze the
		// remaining two — under SSM throttling, sharing one budget would
		// risk leaking the later names when the API would have succeeded
		// with its own budget. Pre-stage uses 10s per call (PutParameter
		// validates schema); cleanup is best-effort so 5s is enough.
		del := func(name string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := testConfig.SSMClient.DeleteParameter(ctx, &ssm.DeleteParameterInput{Name: aws.String(name)})
			return err
		}
		for _, n := range names {
			err := del(n)
			if err == nil {
				continue
			}
			var notFound *ssmtypes.ParameterNotFound
			if errors.As(err, &notFound) {
				continue
			}
			t.Logf("LEAK: cleanup DeleteParameter %s failed: %v — possible leak under /nhp/certs/smoke-cleanup-*", n, err)
		}
	})

	prestageSSMSmokeCertParams(t, names)

	// publishedAt is deliberately the lower bound on the lambda's log
	// timestamp — captured before publishCleanupEvent (which under SDK
	// retry can take several seconds), so the FilterLogEvents StartTime
	// window is guaranteed to include any log line the lambda emits for
	// this invocation.
	publishedAt := time.Now().Add(-cwlIngestionClockPad)
	publishCleanupEvent(t, topicArn, domain)

	expectedLog := cleanupLogLinePrefix + " " + domain
	if found := pollCWLogsForMessage(t, logGroup, expectedLog, publishedAt, smokeCleanupLogTimeout); !found {
		t.Fatalf("did not see %q in %s within %s after publish — cert lambda did not process the cleanup event", expectedLog, logGroup, smokeCleanupLogTimeout)
	}

	// The log line is emitted AFTER _delete_ssm_cert_params returns in
	// handle_domain_cleanup (custom_domain_cert_manager.py — back-pointer
	// comment near the logger.info call). Observing the log line is a safe
	// synchronous gate for this SSM-side assertion.
	assertSSMParamsAbsent(t, names)
}

// prestageSSMSmokeCertParams writes the three /key, /chain, /meta SSM
// params with synthetic values. All three params share the same opaque
// literal — the cert lambda's cleanup path does not parse or validate
// the values today (it only deletes). If a future lambda change adds
// a content-shape check on `/meta` (e.g. JSON-validate before delete),
// this helper would need to write a value matching the meta schema.
func prestageSSMSmokeCertParams(t *testing.T, names []string) {
	t.Helper()
	put := func(name string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := testConfig.SSMClient.PutParameter(ctx, &ssm.PutParameterInput{
			Name: aws.String(name),
			// Synthetic, not a real cert; safe even if it ever leaks past t.Cleanup.
			Value: aws.String("smoke-test-synthetic-not-a-real-cert"),
			// Plain String: SecureString would force a kms:GenerateDataKey
			// grant on the smoke role unrelated to the alias/aws/sns path
			// this test fences. Lambda's bulk delete_parameters ignores type.
			Type:        ssmtypes.ParameterTypeString,
			Overwrite:   aws.Bool(true),
			Description: aws.String("Synthetic cert material pre-staged by tests/smoke/18_custom_domain_cleanup_test.go. Safe to delete."),
		})
		return err
	}
	for _, name := range names {
		if err := put(name); err != nil {
			t.Fatalf("ssm put-parameter %s: %v", name, err)
		}
	}
}

// publishCleanupEvent publishes a domain.cleanup payload to the cleanup
// topic. Wire-shape owned by qurl-service/internal/events/domain_event_publisher.go.
//
// cert_param_prefix is omitted so the lambda derives it from domain_name —
// proves the fall-back path in handle_domain_cleanup. The derivation rule
// is inline at `cert_prefix = SSM_CERT_PREFIX.rstrip('/') + '/' + domain`
// (custom_domain_cert_manager.py, in handle_domain_cleanup); if that rule
// ever changes (URL-encoding, lowercasing, etc.) this test will leak
// pre-staged params at the old path and the assertion below will trip —
// grep there first when this test goes red on a clean env.
//
// acme_cname_target is omitted so the Route53 sweep is a no-op (this test
// does not fence Route53). MessageAttributes.event_type is required —
// see the inline comment on the body shape below for the dispatcher
// contract.
func publishCleanupEvent(t *testing.T, topicArn, domain string) {
	t.Helper()

	// INVARIANT: the body MUST NOT carry an `event_type` field. The
	// lambda's dispatcher in _handle_sns_records reads `event_type` from
	// MessageAttributes only — so an attribute-routed flow that flipped
	// to body-field routing would silently still match if we also wrote
	// event_type into the body here. Keeping the body attribute-free for
	// that field is what makes the regression LOUD (poll times out at
	// 90s with a clear "did not see" fatal). If a future refactor wants
	// to mirror event_type into the body for downstream consumers (e.g.
	// a DDB record), do it at the consumer site, not here.
	bodyBytes, err := json.Marshal(map[string]any{
		"domain_name": domain,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := testConfig.SNSClient.Publish(ctx, &sns.PublishInput{
		TopicArn: aws.String(topicArn),
		Message:  aws.String(string(bodyBytes)),
		MessageAttributes: map[string]snstypes.MessageAttributeValue{
			"event_type": {
				DataType:    aws.String("String"),
				StringValue: aws.String(cleanupEventType),
			},
		},
	})
	if err != nil {
		t.Fatalf("sns publish to %s: %v", topicArn, err)
	}
	// MessageId correlates with SNS delivery metrics + lambda CW logs;
	// emit alongside the per-run UUID domain so triage doesn't depend
	// solely on log-line shape matching. SDK guarantees a non-nil response
	// on err == nil, but MessageId is *string so still nil-check that.
	if resp.MessageId != nil {
		t.Logf("published cleanup event: domain=%s sns_message_id=%s", domain, *resp.MessageId)
	}
}

// assertSSMParamsAbsent t.Errorf's (not fatals) once per name still in
// SSM so all three names get checked and t.Cleanup still runs. Uses a
// raw GetParameter rather than getSSMParameter so a transient AWS error
// (throttle / IAM eval lag / network) does not halt the loop after the
// first name — broken-harness signals are t.Errorf'd too, never t.Fatalf'd
// here.
func assertSSMParamsAbsent(t *testing.T, names []string) {
	t.Helper()
	get := func(name string) (*ssm.GetParameterOutput, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return testConfig.SSMClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(name),
			WithDecryption: aws.Bool(false),
		})
	}
	for _, n := range names {
		_, err := get(n)
		if err != nil {
			var notFound *ssmtypes.ParameterNotFound
			if errors.As(err, &notFound) {
				continue // expected — lambda cleaned it up
			}
			// "harness:" prefix vs "regression:" lets CI triage tell at
			// a glance whether the cert lambda actually regressed or
			// AWS is throttling SSM under us.
			t.Errorf("harness: ssm get-parameter %s during absent-check: %v", n, err)
			continue
		}
		// Deliberately don't echo the value: the existence claim IS the
		// failure, and a future IAM-scope broadening shouldn't make this
		// helper leak whatever lives at the broader path.
		t.Errorf("regression: expected SSM param %s to be gone after cleanup, still present", n)
	}
}
