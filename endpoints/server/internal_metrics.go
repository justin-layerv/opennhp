package server

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

var (
	dimNameCallerIP = aws.String("CallerIP")
	dimNameReason   = aws.String("Reason")
	dimNameSource   = aws.String("Source")
	dimNameOutcome  = aws.String("Outcome")
)

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

// See recordInternalKnockRequest for the CallerIP cardinality contract.
func (hs *HttpServer) recordInternalTokenValidateFailure(callerIP, reason string) {
	if hs == nil || hs.udpServer == nil {
		return
	}
	hs.udpServer.metrics.IncrCounter(MetricInternalTokenValidateFailure)
	hs.udpServer.metrics.IncrCounterWithDims(MetricInternalTokenValidateFailure, []types.Dimension{
		{Name: dimNameCallerIP, Value: aws.String(callerIP)},
		{Name: dimNameReason, Value: aws.String(reason)},
	})
}
