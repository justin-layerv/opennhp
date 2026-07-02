package server

import (
	"strings"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// KnockFailReason is the bounded, top-level classification of a failed qURL
// knock at handleHttpOpenResource (qurl-service#976 Phase 0B). It folds the 0A
// forward outcome together with local-AC / broadcast state into one label per
// knock so a deploy produces a reason histogram instead of an opaque
// KnockNoAC/ErrServerACOpsFailed count. It is a metric-dimension value — keep it
// a small closed set; never fold raw ids/ips/error-strings into it.
type KnockFailReason string

const (
	KnockFailNoResources                    KnockFailReason = "no_resources"
	KnockFailLocalNoACForwardNotAttempted   KnockFailReason = "local_no_ac_forward_not_attempted"
	KnockFailForwardNoAssignment            KnockFailReason = "forward_no_assignment"
	KnockFailForwardAllTargetsUnusable      KnockFailReason = "forward_all_targets_unusable"
	KnockFailForwardRemoteNoAC              KnockFailReason = "forward_remote_no_ac"
	KnockFailForwardRemoteACOpsFailed       KnockFailReason = "forward_remote_ac_ops_failed"
	KnockFailTransactionTimeoutAfterPinhole KnockFailReason = "transaction_timeout_after_pinhole"
	KnockFailTransactionClosedOrShutdown    KnockFailReason = "transaction_closed_or_server_shutdown"
	KnockFailTokenPublishFailed             KnockFailReason = "token_publish_failed"
	KnockFailUnknownAllACOpsFailed          KnockFailReason = "unknown_all_ac_ops_failed"
)

// forwardOutcomeToKnockReason folds the finer 0A ForwardOutcome into the coarser
// 0B knock-reason set.
func forwardOutcomeToKnockReason(o ForwardOutcome) KnockFailReason {
	switch o {
	case ForwardSuccess:
		// A ForwardSuccess reaching this FAILURE classifier is a contradiction:
		// a genuinely successful forward returns early (httpserver.go, the
		// ErrSuccess-ack branch) and never derives a fail reason. We can still
		// land here if a non-conforming peer answers HTTP 200 with a non-success
		// (or nil) ack yet an empty Error field — forwardToServer then returns
		// (ack, nil), ForwardHttpKnock reports ForwardSuccess, and the knock
		// nonetheless fails locally. Bucket it as unknown rather than let it
		// silently inflate forward_all_targets_unusable — keeping that histogram
		// bar trustworthy matters more than the (currently unreachable) edge.
		return KnockFailUnknownAllACOpsFailed
	case ForwardNoAssignment, ForwardAssignmentExpired:
		return KnockFailForwardNoAssignment
	case ForwardAllTargetsFiltered:
		return KnockFailForwardAllTargetsUnusable
	case ForwardRemoteNoAC:
		return KnockFailForwardRemoteNoAC
	case ForwardRemoteACOpsFailed:
		return KnockFailForwardRemoteACOpsFailed
	default:
		// Coarse "no usable forward path" bucket. It spans two shapes: reached
		// targets but got no usable ack (http / decode / request / context) AND
		// never got to try (storage / no-storage / forwarder-stopped — including
		// the forwarder-shutting-down tail during a canary roll, the exact window
		// being studied). 0B stays coarse on purpose; the finer 0A
		// KnockForwardOutcome preserves which of these it was, so split this bar
		// on that dimension rather than reading it as pure target-unreachability.
		return KnockFailForwardAllTargetsUnusable
	}
}

// deriveKnockFailReason classifies a failed knock into one 0B label. When the
// no-local-AC failover forward was attempted, its outcome wins; otherwise the
// per-resource AC-op results are classified (timeout-after-pinhole / closed /
// no-local-AC / unknown). Prefers the typed error code, falling back to the
// message since a broadcast wraps the real cause in ErrServerACOpsFailed's detail.
//
// The artMsgs loop returns on the first failing entry. For the single-resource
// qURL path — the target scenario — artMsgs holds one entry, so the label is
// deterministic. A multi-resource group with two *different* failing AC-ops
// would pick one by Go's randomized map order; that's an accepted bounded
// dominant-cause choice, in the same family as the multi-resource re-resolve
// equivalence tracked in #2452, not a determinism bug to fix here.
func deriveKnockFailReason(artMsgs map[string]*common.ACOpsResultMsg, forwardAttempted bool, lastForwardOutcome ForwardOutcome) KnockFailReason {
	if forwardAttempted {
		return forwardOutcomeToKnockReason(lastForwardOutcome)
	}
	// matches prefers the typed ErrCode but falls back to the detail message,
	// because a broadcast failure wraps the specific cause inside the aggregate
	// ErrServerACOpsFailed and carries the real code only in the message.
	matches := func(m *common.ACOpsResultMsg, code, msg string) bool {
		return m.ErrCode == code || strings.Contains(m.ErrMsg, msg)
	}
	for _, m := range artMsgs {
		if m == nil || m.ErrCode == common.ErrSuccess.ErrorCode() {
			continue
		}
		switch {
		case matches(m, common.ErrTransactionFailedByTimeout.ErrorCode(), common.ErrTransactionFailedByTimeout.Error()):
			return KnockFailTransactionTimeoutAfterPinhole
		case matches(m, common.ErrTransactionFailedByClosedConnection.ErrorCode(), common.ErrTransactionFailedByClosedConnection.Error()),
			matches(m, common.ErrTransactionFailedByClosedDevice.ErrorCode(), common.ErrTransactionFailedByClosedDevice.Error()),
			matches(m, common.ErrPacketToMessageRoutineStopped.ErrorCode(), common.ErrPacketToMessageRoutineStopped.Error()):
			return KnockFailTransactionClosedOrShutdown
		case matches(m, common.ErrACConnectionNotFound.ErrorCode(), common.ErrACConnectionNotFound.Error()):
			return KnockFailLocalNoACForwardNotAttempted
		}
	}
	return KnockFailUnknownAllACOpsFailed
}
