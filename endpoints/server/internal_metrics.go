package server

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

var (
	dimNameCallerIP = aws.String("CallerIP")
	dimNameReason   = aws.String("Reason")
	dimNameSource   = aws.String("Source")
)

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
