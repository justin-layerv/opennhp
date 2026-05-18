//go:build smoke

package smoke

// CloudWatch Logs FilterLogEvents helpers shared across smoke tests
// that wait for specific log lines to appear after triggering an
// event. The NextToken-vs-match-set semantics in scanCWLogsForMatch
// are the non-obvious bit — CW pages the scan window, not the match
// set, so a busy log group can return empty pages before the matching
// event surfaces.
//
// Sole caller today: tests/smoke/18_custom_domain_cleanup_test.go
// (the Tier 2 fence for the custom-domain cleanup consumer). The
// helpers are extracted here in anticipation of additional Tier 2
// fences on lambda or ECS service log groups where the same poll-
// for-log-line shape applies — the page-budget + transient-error +
// case-sensitivity invariants are non-trivial to re-derive.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/smithy-go"
)

// cwlPollIntervalInitial / cwlPollIntervalMax bound the FilterLogEvents
// backoff for pollCWLogsForMessage. Exponential 1s → 5s keeps the
// early-hit case fast and easy on the CloudWatch Logs FilterLogEvents
// quota (5 TPS / 10 concurrent per account) when concurrent smoke tests
// scan log groups in the same account.
const (
	cwlPollIntervalInitial = 1 * time.Second
	cwlPollIntervalMax     = 5 * time.Second
)

// cwlIngestionClockPad is the StartTime lead-back applied to
// FilterLogEvents queries. Absorbs both directions of drift: clock skew
// between the smoke runner and CloudWatch, and log-ingestion lag if the
// observed system emits before the smoke runner's wall clock advances
// past the trigger call. Shrinking below ~1s would risk dropping the
// observed log line off the query window on fast paths.
const cwlIngestionClockPad = 5 * time.Second

// cwlScanPageBudget caps the per-tick NextToken pagination chain.
// 10 pages × default 10k events/page ≈ 100k events of scan window per
// tick — well past any realistic smoke run while keeping the per-tick
// worst-case FilterLogEvents calls bounded under the account-wide 5 TPS
// / 10 concurrent quota when many smoke tests poll in parallel.
// Hitting the bound is non-fatal: the outer deadline retries from the
// start, the test only fails if the full timeout elapses without
// finding the message.
const cwlScanPageBudget = 10

// dumpCWLogsPageBudget caps the diagnostic dump pagination. 3 pages ×
// Limit=20 = ~60 events max — `Limit` is also a 1MB per-page scan hint,
// so on a very busy log group pagination matters more than the literal
// event count. Smaller than cwlScanPageBudget because the dump is
// best-effort triage on a failed run, not the fence itself.
const dumpCWLogsPageBudget = 3

// pollCWLogsForMessage scans a log group via FilterLogEvents until
// `wantMsg` appears or `timeout` elapses. Returns false ONLY on
// deadline; non-transient SDK errors fatal directly. The CW-unsafe
// character check enforces an invariant the quoted-substring filter
// syntax we emit (`"<wantMsg>"`) silently breaks on: CW's quoting
// does not share Go's strconv escaping, so backslashes / quotes /
// newlines in `wantMsg` would never match. CW Logs quoted-substring
// matching is case-sensitive — desirable for the typical per-run UUID
// caller, but callers using a non-UUID `wantMsg` should normalize
// case at the source rather than in the filter. `wantMsg` should be
// unique enough (e.g. a per-run UUID) that the matching set is 0 or 1
// events across the StartTime window — see scanCWLogsForMatch for why
// a FilterPattern still paginates.
func pollCWLogsForMessage(t *testing.T, logGroup, wantMsg string, startTime time.Time, timeout time.Duration) bool {
	t.Helper()
	if strings.ContainsAny(wantMsg, "\"\\\n\r") {
		t.Fatalf("pollCWLogsForMessage: wantMsg %q contains CW-unsafe characters (\\ \" \\n \\r) — use a CW-filter-safe substring", wantMsg)
	}

	deadline := time.Now().Add(timeout)
	startMillis := startTime.UnixMilli()
	wait := cwlPollIntervalInitial

	for time.Now().Before(deadline) {
		if found := scanCWLogsForMatch(t, logGroup, startMillis, wantMsg, deadline); found {
			return true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		time.Sleep(min(wait, remaining))
		wait = min(wait*2, cwlPollIntervalMax)
	}

	dumpRecentCWLogEvents(t, logGroup, startTime, wantMsg)
	return false
}

// scanCWLogsForMatch walks a single pass of FilterLogEvents pages for
// the given StartTime window, following NextToken until either a match
// is found, the window is exhausted, or cwlScanPageBudget pages have
// been read. CW pages the scan window (not the match set) even with a
// FilterPattern, so following the token inside one tick — instead of
// re-scanning from the start on every poll — bounds the inner loop by
// the FilterLogEvents quota rather than by polling cadence. The
// `deadline` is the outer poll's wall-clock deadline; the per-page
// context timeout is clamped to the remaining budget so a runaway scan
// can't run ~100s past the documented timeout. Transient SDK errors
// (RNFE / throttle) end the scan early and return false so the caller
// can backoff; non-transient errors fatal directly. Hitting the page
// budget is non-fatal so the outer deadline can retry.
func scanCWLogsForMatch(t *testing.T, logGroup string, startMillis int64, wantMsg string, deadline time.Time) bool {
	t.Helper()
	filterPattern := `"` + wantMsg + `"`
	var nextToken *string
	for page := 0; page < cwlScanPageBudget; page++ {
		if time.Now().After(deadline) {
			return false
		}
		// 100ms throttle on subsequent pages spreads the account-wide
		// 5 TPS FilterLogEvents quota — without it, a 10-page tick can
		// drain the quota in under 2s and slow parallel CWL-scanning
		// smoke tests. First page has nothing to spread from. Clamp
		// to remaining so a sub-100ms remaining budget can't overrun.
		if page > 0 {
			time.Sleep(min(100*time.Millisecond, time.Until(deadline)))
			// Re-check the deadline after the sleep. A clamped-to-zero
			// sleep that still consumed the residual budget would leave
			// us building a non-positive perCallTimeout below and
			// making a doomed-context SDK call. Bail before the call.
			if time.Now().After(deadline) {
				return false
			}
		}
		perCallTimeout := min(10*time.Second, time.Until(deadline))
		// Page-0 covers the race where time elapsed between the line-115
		// deadline check and here is enough to push perCallTimeout
		// non-positive. Pages > 0 already bailed after the sleep above;
		// this is the symmetric guard for the first iteration.
		if perCallTimeout <= 0 {
			return false
		}
		out, err := func() (*cloudwatchlogs.FilterLogEventsOutput, error) {
			ctx, cancel := context.WithTimeout(context.Background(), perCallTimeout)
			defer cancel()
			return testConfig.CWLogsClient.FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{
				LogGroupName:  aws.String(logGroup),
				StartTime:     aws.Int64(startMillis),
				FilterPattern: aws.String(filterPattern),
				NextToken:     nextToken,
			})
		}()
		if err != nil {
			if !isTransientCWLError(err) {
				t.Fatalf("cwl filter %s for %q: %v", logGroup, wantMsg, err)
			}
			t.Logf("transient CWL error, will retry: %v", err)
			return false
		}
		for _, ev := range out.Events {
			// Belt-and-suspenders: CWL's server-side quoted-substring
			// filter already matched, but a Go-side strings.Contains
			// re-check defends against future CW filter-syntax surprises
			// (e.g. a wantMsg containing a token CW treats specially).
			if ev.Message != nil && strings.Contains(*ev.Message, wantMsg) {
				return true
			}
		}
		if out.NextToken == nil {
			return false
		}
		nextToken = out.NextToken
	}
	t.Logf("scanCWLogsForMatch: exhausted %d pages this tick without finding %q — log group is very busy; outer deadline will retry", cwlScanPageBudget, wantMsg)
	return false
}

// isTransientCWLError returns true for CWL errors that should NOT halt
// the caller — the SDK should be retried after backoff. ResourceNotFound
// is expected on fresh envs (log group is created lazily on first
// invocation). The upstream filter for "env doesn't have the lambda at
// all" is the caller's own SSM-skip-gate (e.g. an absent topic-arn
// discovery param triggers t.Skipf); a wholly-undeployed env never
// reaches this helper. Throttling/LimitExceeded comes from the 5 TPS /
// 10 concurrent account-wide FilterLogEvents quota under parallel
// smoke. context.DeadlineExceeded / context.Canceled cover the
// near-deadline path where scanCWLogsForMatch clamps the per-call
// timeout below ~1s: the SDK can return a wrapped context error rather
// than a modeled smithy.APIError, and we don't want a tail-end clamp
// to fatal the test instead of letting the outer deadline return false.
//
// Tail-end retry storm: when the outer deadline is within ~1-2s, a
// transient classification → outer backoff sleep → re-clamped scan →
// near-immediate context-expiry loop can iterate several times before
// the outer for-deadline check fires. Bounded by the deadline, so not
// a correctness bug — don't "fix" this without preserving the
// transient-as-non-fatal property the round-18 fix established.
func isTransientCWLError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "ResourceNotFoundException", "ThrottlingException", "LimitExceededException":
		return true
	}
	return false
}

// dumpRecentCWLogEvents writes recent log lines from a log group (no
// FilterPattern) into the test output on a poll miss. The failure
// message names the missing substring; this trailing dump tells the
// operator whether the observed system was invoked at all, whether
// earlier records errored, etc., so the CI artifact carries triage
// signal.
//
// Suppressed on prod. The unfiltered dump can surface lines from
// concurrent real customer offboards (cert-lambda log groups process
// real domains in parallel with the smoke event), and the CI artifact
// goes to GitHub Actions output. Prod operators with IAM access can
// re-pull the same window from the AWS console; sandbox keeps the
// inline triage signal.
//
// `startTime` is the same anchor the failing poll used. After a long
// poll timeout the missed event is well in the past — a fixed lookback
// from now wouldn't include it at all. Anchoring on `startTime` lines
// the dump up with exactly the window the missed event should have
// been in. Up to dumpCWLogsPageBudget pages × Limit=20 / page = ~60
// events max; on a busy log group `Limit` is also a per-page 1MB scan
// hint, so pagination raises diagnostic hit rate without unbounded
// cost.
func dumpRecentCWLogEvents(t *testing.T, logGroup string, startTime time.Time, wantMsg string) {
	t.Helper()
	if testConfig.Environment == "prod" {
		// Surface the exact FilterPattern that would have matched so an
		// operator can copy-paste the targeted query into the AWS
		// console rather than re-deriving it from the test source.
		t.Logf("triage dump suppressed on prod: log group %s, FilterPattern %q, StartTime %s (RFC3339)",
			logGroup, `"`+wantMsg+`"`, startTime.UTC().Format(time.RFC3339))
		return
	}
	startMillis := startTime.UnixMilli()
	startStr := startTime.UTC().Format(time.RFC3339)
	var (
		nextToken *string
		total     int
	)
	for page := 0; page < dumpCWLogsPageBudget; page++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := testConfig.CWLogsClient.FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{
			LogGroupName: aws.String(logGroup),
			StartTime:    aws.Int64(startMillis),
			Limit:        aws.Int32(20),
			NextToken:    nextToken,
		})
		cancel()
		if err != nil {
			t.Logf("triage dump: FilterLogEvents (unfiltered) page %d failed: %v", page, err)
			return
		}
		if page == 0 && len(out.Events) == 0 {
			t.Logf("triage dump: no events in %s since %s (target likely never invoked)", logGroup, startStr)
			return
		}
		if page == 0 {
			t.Logf("triage dump: events in %s since %s (up to %d pages):", logGroup, startStr, dumpCWLogsPageBudget)
		}
		for _, ev := range out.Events {
			msg := ""
			if ev.Message != nil {
				msg = strings.TrimRight(*ev.Message, "\n")
			}
			t.Logf("  %s", msg)
			total++
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	t.Logf("triage dump: emitted %d events", total)
}
