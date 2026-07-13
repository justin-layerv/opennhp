package server

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

var (
	dimNameCallerIP   = aws.String("CallerIP")
	dimNameReason     = aws.String("Reason")
	dimNameSource     = aws.String("Source")
	dimNameOutcome    = aws.String("Outcome")
	dimNameFanoutMode = aws.String("FanoutMode")
)

const revocationFanoutUnknown = "unknown"

// recordKnockForwardOutcome emits the outcome of a single ForwardHttpKnock call
// (qurl-service#976 Phase 0A) on BOTH success and failure, so the Outcome
// dimension yields a success/fail ratio and a cause-split of failures. Only the
// dimensioned series is emitted — the undimensioned total is already covered by
// KnockForwardSuccess + KnockForwardFailure, so a base counter here would be a
// redundant third overlapping series (dashboards should sum the Outcome
// dimension, not add a base to KnockForwardFailure). nil-safe.
//
// Cardinality note for dashboards: this fires once per no-local-AC resource in
// the handleHttpOpenResource loop (per-forward), whereas KnockFailReason fires
// once per knock. They're 1:1 on the single-resource qURL path (the target
// scenario) but diverge for a multi-resource knock, so sum(KnockForwardOutcome)
// is NOT directly comparable to KnockFailReason there.
func (s *UdpServer) recordKnockForwardOutcome(outcome ForwardOutcome) {
	if s == nil {
		return
	}
	s.metrics.IncrCounterWithDims(MetricKnockForwardOutcome, []types.Dimension{
		{Name: dimNameOutcome, Value: aws.String(string(outcome))},
	})
}

// recordKnockFailReason emits the top-level cause of a failed qURL knock
// (qurl-service#976 Phase 0B). The "Reason" dimension is the bounded
// KnockFailReason enum. nil-safe (Publisher guards a nil receiver).
func (s *UdpServer) recordKnockFailReason(reason KnockFailReason) {
	if s == nil {
		return
	}
	// Base + dimensioned (mirrors recordInternalKnockRequest): base is the
	// alarmable "total failed knocks" series, the Reason breakdown is attribution.
	s.metrics.IncrCounter(MetricKnockFailReason)
	s.metrics.IncrCounterWithDims(MetricKnockFailReason, []types.Dimension{
		{Name: dimNameReason, Value: aws.String(string(reason))},
	})
}

// The CallerIP breakdown stream assumes a bounded internal caller set
// (qurl-service plus fleet members). Alarmable streams should use the base
// counters below; the CallerIP dimensions are for attribution, not broad
// internet-facing cardinality.
func (hs *HttpServer) recordInternalKnockRequest(source, callerIP string) {
	if hs == nil || hs.udpServer == nil {
		return
	}
	hs.udpServer.metrics.IncrCounter(MetricInternalKnockRequest)
	hs.udpServer.metrics.IncrCounterWithDims(MetricInternalKnockRequest, []types.Dimension{
		{Name: dimNameSource, Value: aws.String(normalizeInternalKnockMetricSource(source))},
		{Name: dimNameCallerIP, Value: aws.String(callerIP)},
	})
}

func normalizeInternalKnockMetricSource(source string) string {
	switch source {
	case SourceAPI:
		return SourceAPI
	case "":
		// Forwarded server-to-server hops and legacy internal callers both omit
		// Source; keep them in one bounded fleet-origin bucket for attribution.
		return "server"
	default:
		return "unknown"
	}
}

// recordRevocationFanoutSent emits the existing base RevocationFanoutSent stream
// plus a bounded FanoutMode breakdown. The base stream preserves the rollout
// smoke/runbook contract; the targeted-only stream lets the #2790 drift alarm
// distinguish targeted fanout collapse from unrelated cell-wide revokes.
// The handler fanout-mode gate accepts only the two known modes; normalize anyway
// so a future caller cannot create unbounded CloudWatch dimensions by bypassing
// that gate. Dashboards graphing this metric should pin either the base
// {Environment, Cell} stream or a specific FanoutMode stream so base + breakdown
// series are not double-counted. Publisher drops zero-valued counters at flush,
// so sent=0 makes the targeted FanoutMode series absent rather than explicitly
// zero; the #2790 alarm's FILL expression and rollout breach-path proof are
// load-bearing for pure zero-match buckets.
func (s *UdpServer) recordRevocationFanoutSent(fanoutMode string, sent int) {
	if s == nil {
		return
	}
	fanoutMode = normalizeRevocationFanoutMetricMode(fanoutMode)
	value := float64(sent)
	s.metrics.AddCounterWithDims(MetricRevocationFanoutSent, value, nil)
	s.metrics.AddCounterWithDims(MetricRevocationFanoutSent, value, []types.Dimension{
		{Name: dimNameFanoutMode, Value: aws.String(fanoutMode)},
	})
}

func normalizeRevocationFanoutMetricMode(fanoutMode string) string {
	switch fanoutMode {
	case revocationFanoutCellWide, revocationFanoutTargeted:
		return fanoutMode
	default:
		return revocationFanoutUnknown
	}
}

// See recordInternalKnockRequest for the CallerIP cardinality contract.
func (hs *HttpServer) recordInternalTokenValidateFailure(callerIP, reason string) {
	if hs == nil || hs.udpServer == nil {
		return
	}
	// Publish three exact dimension sets:
	//   - base: aggregate failure alarm,
	//   - Reason: bounded reason-specific detection (including the RunID alarm),
	//   - CallerIP/Reason: attribution.
	hs.udpServer.metrics.IncrCounter(MetricInternalTokenValidateFailure)
	hs.udpServer.metrics.IncrCounterWithDims(MetricInternalTokenValidateFailure, []types.Dimension{
		{Name: dimNameReason, Value: aws.String(reason)},
	})
	hs.udpServer.metrics.IncrCounterWithDims(MetricInternalTokenValidateFailure, []types.Dimension{
		{Name: dimNameCallerIP, Value: aws.String(callerIP)},
		{Name: dimNameReason, Value: aws.String(reason)},
	})
}
