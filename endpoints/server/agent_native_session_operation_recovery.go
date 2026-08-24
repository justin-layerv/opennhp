package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func (s *UdpServer) buildAgentNativeSessionOperationRecoveryAck(ppd *core.PacketParserData,
	request common.AgentNativeSessionOperationRecoveryMsg,
) ([]byte, string, error) {
	ack := &common.ServerNativeSessionOperationRecoveryAckMsg{
		ErrCode: common.ErrInvalidInput.ErrorCode(), ErrMsg: common.ErrInvalidInput.Error(),
	}
	deny := func(publicErr *common.Error) ([]byte, string, error) {
		*ack = common.ServerNativeSessionOperationRecoveryAckMsg{ErrCode: publicErr.ErrorCode(), ErrMsg: publicErr.Error()}
		body, err := json.Marshal(ack)
		return body, "", err
	}
	if ppd == nil || ppd.HeaderType != core.NHP_EXT || request.HeaderType != core.NHP_EXT ||
		len(ppd.RemotePubKey) != core.PublicKeySize || !s.nativeSessionOperationEnabled() {
		return deny(common.ErrInvalidInput)
	}
	publicKey := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
	projection := request.KnockProjection()
	projection.NHPAgentPublicKey = publicKey
	serverBinding, err := s.nativeSessionOperationServerBinding()
	if err != nil {
		return deny(common.ErrServerACOpsFailed)
	}
	op, err := sessionControlNativeOperationForKnock(&projection, publicKey, serverBinding)
	if err != nil {
		return deny(common.ErrInvalidInput)
	}
	store, err := s.nativeSessionOperationStore()
	if err != nil {
		return deny(common.ErrServerACOpsFailed)
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionControlNativeOperationAggregateTimeout)
	defer cancel()
	// Recovery is transaction-first. An absent operation is atomically denied
	// by the identity-checked CANCELED tombstone without an eventual lookup or
	// an extra read. If the operation already exists, the conditional write
	// loses and CancelAbsentNativeSessionOperation classifies that exact row;
	// identity rotation after MAPPED therefore cannot invalidate its receipt.
	current, err := store.CancelAbsentNativeSessionOperation(ctx, op, time.Now().UTC())
	if err != nil || current == nil || current.Operation != op {
		return deny(common.ErrServerACOpsFailed)
	}
	if current.State == sessionControlNativeOperationStateMapped || current.State == sessionControlNativeOperationStateClosing {
		if current.Candidate == nil {
			return deny(common.ErrServerACOpsFailed)
		}
		selector := sessionControlExactRetirementSelectorForCandidate(*current.Candidate)
		if _, err = s.ensureAuthenticatedExactSessionClose(ctx, selector); err != nil {
			return deny(common.ErrServerACOpsFailed)
		}
		current, err = store.ResolveNativeSessionOperation(ctx, op.Binding.OperationID)
		if err != nil || current == nil || current.Operation != op {
			return deny(common.ErrServerACOpsFailed)
		}
	}
	if current.State != sessionControlNativeOperationStateCanceled &&
		current.State != sessionControlNativeOperationStateClosing &&
		current.State != sessionControlNativeOperationStateClosed {
		return deny(common.ErrServerACOpsFailed)
	}
	ack.OperationID = op.Binding.OperationID
	ack.BindingSHA256 = op.Binding.BindingSHA256
	ack.State = current.State
	if current.Candidate != nil {
		candidate := *current.Candidate
		ack.CellID = candidate.CellID
		ack.SessionID = candidate.SessionID
		ack.SessionIssuedAtMillis = candidate.IssuedAtMillis
		ack.RunID = candidate.RunID
		ack.RunAttempt = candidate.RunAttempt
		if current.State == sessionControlNativeOperationStateClosing || current.State == sessionControlNativeOperationStateClosed {
			ack.CloseEventID = sessionControlExactCloseEventID(candidate)
		}
	}
	ack.ErrCode = common.ErrSuccess.ErrorCode()
	ack.ErrMsg = ""
	body, err := json.Marshal(ack)
	return body, "", err
}
