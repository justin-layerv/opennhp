package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// buildAgentExactSessionCloseAck handles the body-authenticated NHP 1.1 EXT
// contract. A successful ACK means the exact server-assigned session has
// durably entered (or previously completed) the close lifecycle; AC cleanup is
// intentionally asynchronous and restart-recoverable.
func (s *UdpServer) buildAgentExactSessionCloseAck(ppd *core.PacketParserData) ([]byte, string, error) {
	if ppd == nil || ppd.ConnData == nil || ppd.ConnData.RemoteAddr == nil {
		return nil, "", errors.New("invalid exact session close packet")
	}
	s.incrAgentSessionCloseMetric(MetricAgentSessionCloseRequest)
	ack := &common.ServerExactSessionCloseAckMsg{
		ErrCode: common.ErrInvalidInput.ErrorCode(),
		ErrMsg:  common.ErrInvalidInput.Error(),
	}
	deny := func(publicErr *common.Error) ([]byte, string, error) {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ack.CellID = ""
		ack.SessionID = 0
		ack.SessionIssuedAtMillis = 0
		ack.RunID = ""
		ack.RunAttempt = 0
		ack.CloseEventID = ""
		ack.State = ""
		ack.ErrCode = publicErr.ErrorCode()
		ack.ErrMsg = publicErr.Error()
		body, err := json.Marshal(ack)
		return body, "", err
	}

	var request common.AgentExactSessionCloseMsg
	if err := common.DecodeAgentExactSessionCloseMsg(ppd.BodyMessage, &request); err != nil {
		return deny(common.ErrInvalidInput)
	}
	if request.HeaderType != core.NHP_EXT || ppd.HeaderType != core.NHP_EXT || request.HeaderType != ppd.HeaderType {
		return deny(common.ErrKnockHeaderTypeMismatch)
	}
	if request.CellID != s.sessionControlCellID {
		return deny(common.ErrServerACOpsFailed)
	}
	if len(ppd.RemotePubKey) != core.PublicKeySize {
		return deny(common.ErrInvalidInput)
	}
	agentPublicKey := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
	selector := sessionControlExactRetirementSelector{
		CellID: request.CellID, AgentPublicKey: agentPublicKey, SessionID: request.SessionID,
		IssuedAtMillis: request.SessionIssuedAtMillis, RunID: request.RunID, RunAttempt: request.RunAttempt,
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
	defer cancel()
	result, err := s.ensureAuthenticatedExactSessionClose(closeCtx, selector)
	if err != nil {
		return deny(common.ErrServerACOpsFailed)
	}
	if result == nil || !sessionControlExactRetirementSelectorMatchesCandidate(selector, result.Candidate) ||
		!validSessionControlFenceEventID(result.CloseEventID) ||
		(result.State != sessionControlSessionStateClosing && result.State != sessionControlSessionStateClosed) {
		return deny(common.ErrServerACOpsFailed)
	}
	ack.SessionID = selector.SessionID
	ack.CellID = selector.CellID
	ack.SessionIssuedAtMillis = selector.IssuedAtMillis
	ack.RunID = selector.RunID
	ack.RunAttempt = selector.RunAttempt
	ack.CloseEventID = result.CloseEventID
	ack.State = result.State
	ack.ErrCode = common.ErrSuccess.ErrorCode()
	ack.ErrMsg = ""
	s.incrAgentSessionCloseMetric(MetricAgentSessionCloseLocalSuccess)
	body, err := json.Marshal(ack)
	return body, "", err
}
