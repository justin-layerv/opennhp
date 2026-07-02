package server

import (
	"fmt"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestForwardOutcomeToKnockReason(t *testing.T) {
	cases := map[ForwardOutcome]KnockFailReason{
		ForwardNoAssignment:       KnockFailForwardNoAssignment,
		ForwardAssignmentExpired:  KnockFailForwardNoAssignment,
		ForwardAllTargetsFiltered: KnockFailForwardAllTargetsUnusable,
		ForwardRemoteNoAC:         KnockFailForwardRemoteNoAC,
		ForwardRemoteACOpsFailed:  KnockFailForwardRemoteACOpsFailed,
		ForwardRequestFailed:      KnockFailForwardAllTargetsUnusable, // catch-all
		ForwardContextCanceled:    KnockFailForwardAllTargetsUnusable, // catch-all
		// A ForwardSuccess reaching the failure classifier is a contradiction
		// (a real success returns early); it must bucket as unknown, NOT default
		// into forward_all_targets_unusable and skew that histogram bar.
		ForwardSuccess: KnockFailUnknownAllACOpsFailed,
	}
	for in, want := range cases {
		if got := forwardOutcomeToKnockReason(in); got != want {
			t.Errorf("forwardOutcomeToKnockReason(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeriveKnockFailReason(t *testing.T) {
	acOps := func(code, msg string) map[string]*common.ACOpsResultMsg {
		return map[string]*common.ACOpsResultMsg{"q_x": {ErrCode: code, ErrMsg: msg}}
	}
	// Broadcast failures wrap the real cause in ErrServerACOpsFailed's detail,
	// so the classifier keys on the message, not just the top-level code.
	aggr := common.ErrServerACOpsFailed.ErrorCode()

	tests := []struct {
		name             string
		artMsgs          map[string]*common.ACOpsResultMsg
		forwardAttempted bool
		lastOutcome      ForwardOutcome
		want             KnockFailReason
	}{
		{"forward wins: remote no-ac", nil, true, ForwardRemoteNoAC, KnockFailForwardRemoteNoAC},
		{"forward wins: no assignment", nil, true, ForwardNoAssignment, KnockFailForwardNoAssignment},
		{"forward reported success but knock still failed -> unknown", nil, true, ForwardSuccess, KnockFailUnknownAllACOpsFailed},
		{"timeout after pinhole", acOps(aggr, fmt.Sprintf("q_x: %s", common.ErrTransactionFailedByTimeout.Error())), false, "", KnockFailTransactionTimeoutAfterPinhole},
		{"closed connection", acOps(aggr, common.ErrTransactionFailedByClosedConnection.Error()), false, "", KnockFailTransactionClosedOrShutdown},
		{"routine stopped", acOps(aggr, common.ErrPacketToMessageRoutineStopped.Error()), false, "", KnockFailTransactionClosedOrShutdown},
		{"local no-ac, forward not attempted", acOps(common.ErrACConnectionNotFound.ErrorCode(), common.ErrACConnectionNotFound.Error()), false, "", KnockFailLocalNoACForwardNotAttempted},
		{"unknown", acOps("59999", "weird"), false, "", KnockFailUnknownAllACOpsFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveKnockFailReason(tt.artMsgs, tt.forwardAttempted, tt.lastOutcome); got != tt.want {
				t.Fatalf("deriveKnockFailReason = %q, want %q", got, tt.want)
			}
		})
	}
}
