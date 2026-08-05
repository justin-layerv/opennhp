package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorauthority"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorcell"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

const (
	ConnectorRegistrationAWSRegionEnvVar       = "NHP_CONNECTOR_REGISTRATION_AWS_REGION"
	ConnectorRegistrationAWSAccountEnvVar      = "NHP_CONNECTOR_REGISTRATION_AWS_ACCOUNT_ID"
	ConnectorRegistrationIssueOTPAliasEnvVar   = "NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN"
	ConnectorRegistrationActivateAliasEnvVar   = "NHP_CONNECTOR_REGISTRATION_ACTIVATE_ALIAS_ARN"
	ConnectorRegistrationCompleteAliasEnvVar   = "NHP_CONNECTOR_REGISTRATION_COMPLETE_ALIAS_ARN"
	ConnectorRegistrationLambdaTimeoutEnvVar   = "NHP_CONNECTOR_REGISTRATION_AUTHORITY_LAMBDA_TIMEOUT"
	ConnectorRegistrationHandlerBudgetEnvVar   = "NHP_CONNECTOR_REGISTRATION_HANDLER_BUDGET"
	ConnectorRegistrationPacketBudgetEnvVar    = "NHP_CONNECTOR_REGISTRATION_PACKET_BUDGET"
	ConnectorRegistrationResponseReserveEnvVar = "NHP_CONNECTOR_REGISTRATION_RESPONSE_RESERVE"
	ConnectorRegistrationWriteBudgetEnvVar     = "NHP_CONNECTOR_REGISTRATION_WRITE_BUDGET"
	connectorRegistrationMinLambdaTimeout      = 3 * time.Second
	connectorRegistrationMaxPacketBudget       = time.Duration(core.RemoteTransactionProcessTimeoutMs) * time.Millisecond
	// connectorRegistrationHandlerAbsentWriteBudget bounds the physical write of
	// the frozen dark-cell denial. A dark cell loads no registration timing (see
	// configureConnectorCellAuthority, which leaves connectorRegistrationTiming
	// zero when the config is absent), so the receipt-anchored packet/write
	// ladder is unavailable and a fixed, generous budget from now() is used
	// instead. The denial body is a tiny constant, so this only ever bounds a
	// blocked writer — never a legitimate slow Authority call, which the dark
	// path does not make.
	connectorRegistrationHandlerAbsentWriteBudget = 500 * time.Millisecond
)

var (
	errInvalidConnectorRegistrationConfiguration = errors.New("connector registration: invalid configuration")
	errConnectorRegistrationDeadline             = errors.New("connector registration: request deadline exhausted")
	errConnectorRegistrationAction               = errors.New("connector registration: invalid handler action")
	errConnectorRegistrationResponseEncode       = errors.New("connector registration: response encryption failed")
	errConnectorRegistrationResponseHandoff      = errors.New("connector registration: transaction handoff failed")
	errConnectorRegistrationResponseWrite        = errors.New("connector registration: response write failed")
	errConnectorRegistrationResponseShortWrite   = errors.New("connector registration: short response write")
)

// Fixed metric names are the complete observer surface for this composition.
// No peer, source, agent, credential, query, or other attacker-derived value is
// used as a dimension or metric name.
const (
	MetricConnectorRegistrationOTPRequest        = "ConnectorRegistrationOTPRequest"
	MetricConnectorRegistrationActivationRequest = "ConnectorRegistrationActivationRequest"
	MetricConnectorRegistrationCompletionRequest = "ConnectorRegistrationCompletionRequest"
	MetricConnectorRegistrationIngressRejected   = "ConnectorRegistrationIngressRejected"
	// MetricConnectorRegistrationHandlerAbsent counts assigned-cell registration
	// intents (OTP, activation, or completion) that were structurally recognized
	// but reached an instance with NO live Authority handler — the capability is
	// dark, or the instance predates its connector-authority activation rollout.
	// A non-zero value is the direct signal that a cell fleet is serving
	// Connector registration from at least one un-activated instance; it is the
	// alarm that turns the "registration reply aspId is invalid" / silent-stall
	// class of incident into an attributable server-side counter.
	MetricConnectorRegistrationHandlerAbsent         = "ConnectorRegistrationHandlerAbsent"
	MetricConnectorRegistrationAuthoritySuccess      = "ConnectorRegistrationAuthoritySuccess"
	MetricConnectorRegistrationRequestRejected       = "ConnectorRegistrationRequestRejected"
	MetricConnectorRegistrationDeadlineRejected      = "ConnectorRegistrationDeadlineRejected"
	MetricConnectorRegistrationInvokeFailed          = "ConnectorRegistrationInvokeFailed"
	MetricConnectorRegistrationResponseRejected      = "ConnectorRegistrationResponseRejected"
	MetricConnectorRegistrationAuthorityRejected     = "ConnectorRegistrationAuthorityRejected"
	MetricConnectorRegistrationOTPAdmissionRejected  = "ConnectorRegistrationOTPAdmissionRejected"
	MetricConnectorRegistrationResponseAttempt       = "ConnectorRegistrationResponseAttempt"
	MetricConnectorRegistrationResponseSent          = "ConnectorRegistrationResponseSent"
	MetricConnectorRegistrationResponseDeadline      = "ConnectorRegistrationResponseDeadline"
	MetricConnectorRegistrationResponseEncodeFailed  = "ConnectorRegistrationResponseEncodeFailed"
	MetricConnectorRegistrationResponseHandoffFailed = "ConnectorRegistrationResponseHandoffFailed"
	MetricConnectorRegistrationResponseWriteFailed   = "ConnectorRegistrationResponseWriteFailed"
	MetricConnectorRegistrationResponseShortWrite    = "ConnectorRegistrationResponseShortWrite"
	MetricConnectorRegistrationInternalFailure       = "ConnectorRegistrationInternalFailure"
)

type connectorRegistrationHandler interface {
	HandleOTP(context.Context, []byte, []byte, string) connectorcell.RegistrationResult
	HandleRegistration(context.Context, []byte, []byte) connectorcell.RegistrationResult
	HandleRegistrationCompletion(context.Context, []byte, []byte) connectorcell.RegistrationResult
}

type connectorRegistrationOperation uint8

const (
	connectorRegistrationOTP connectorRegistrationOperation = iota + 1
	connectorRegistrationActivation
	connectorRegistrationCompletion
)

type connectorRegistrationConfig struct {
	environment      string
	cellID           string
	region           string
	accountID        string
	issueOTPAliasARN string
	activateAliasARN string
	completeAliasARN string
	timing           connectorRegistrationTiming
}

// connectorRegistrationTiming is the complete assigned-cell receipt deadline
// ladder. Every value is explicit so source code cannot accidentally turn a
// measurement candidate into a deployment default.
type connectorRegistrationTiming struct {
	authorityLambdaTimeout time.Duration
	handlerBudget          time.Duration
	packetBudget           time.Duration
	// responseReserve is a validation-only tail bound: it must fit after the
	// handler budget and contain writeBudget. Runtime deadlines use
	// packetBudget and writeBudget directly.
	responseReserve time.Duration
	writeBudget     time.Duration
}

func loadConnectorRegistrationConfig(lookupEnv func(string) (string, bool)) (*connectorRegistrationConfig, error) {
	if lookupEnv == nil {
		return nil, errInvalidConnectorRegistrationConfiguration
	}
	region, regionSet := lookupEnv(ConnectorRegistrationAWSRegionEnvVar)
	accountID, accountSet := lookupEnv(ConnectorRegistrationAWSAccountEnvVar)
	issueOTP, issueOTPSet := lookupEnv(ConnectorRegistrationIssueOTPAliasEnvVar)
	activate, activateSet := lookupEnv(ConnectorRegistrationActivateAliasEnvVar)
	complete, completeSet := lookupEnv(ConnectorRegistrationCompleteAliasEnvVar)
	lambdaTimeout, lambdaTimeoutSet := lookupEnv(ConnectorRegistrationLambdaTimeoutEnvVar)
	handlerBudget, handlerBudgetSet := lookupEnv(ConnectorRegistrationHandlerBudgetEnvVar)
	packetBudget, packetBudgetSet := lookupEnv(ConnectorRegistrationPacketBudgetEnvVar)
	responseReserve, responseReserveSet := lookupEnv(ConnectorRegistrationResponseReserveEnvVar)
	writeBudget, writeBudgetSet := lookupEnv(ConnectorRegistrationWriteBudgetEnvVar)
	if !regionSet && !accountSet && !issueOTPSet && !activateSet && !completeSet &&
		!lambdaTimeoutSet && !handlerBudgetSet && !packetBudgetSet && !responseReserveSet && !writeBudgetSet {
		return nil, nil
	}
	if !regionSet || !accountSet || !issueOTPSet || !activateSet || !completeSet ||
		!lambdaTimeoutSet || !handlerBudgetSet || !packetBudgetSet || !responseReserveSet || !writeBudgetSet ||
		!strictConnectorAuthorityEnvValue(region) ||
		!strictConnectorAuthorityEnvValue(accountID) ||
		!strictConnectorAuthorityEnvValue(issueOTP) ||
		!strictConnectorAuthorityEnvValue(activate) ||
		!strictConnectorAuthorityEnvValue(complete) {
		return nil, errInvalidConnectorRegistrationConfiguration
	}
	timing, err := parseConnectorRegistrationTiming(
		lambdaTimeout, handlerBudget, packetBudget, responseReserve, writeBudget,
	)
	if err != nil {
		return nil, err
	}

	environment, environmentSet := lookupEnv("NHP_ENVIRONMENT")
	cellID, cellSet := lookupEnv("NHP_CELL_ID")
	// Only deployable cell environments own Authority targets. Local and ad-hoc
	// environments must keep this composition dark.
	if !environmentSet || !cellSet {
		return nil, errInvalidConnectorRegistrationConfiguration
	}

	config := &connectorRegistrationConfig{
		environment: environment, cellID: cellID, region: region, accountID: accountID,
		issueOTPAliasARN: issueOTP, activateAliasARN: activate, completeAliasARN: complete, timing: timing,
	}
	boundary := connectorCellBoundary(config)
	targets := connectorauthority.RegistrationCellTargets{
		IssueRegistrationOTPAliasARN: issueOTP,
		ActivateRegistrationAliasARN: activate,
		CompleteRegistrationAliasARN: complete,
	}
	if err := connectorauthority.ValidateRegistrationCellTargets(boundary, targets); err != nil {
		return nil, errInvalidConnectorRegistrationConfiguration
	}
	return config, nil
}

func parseConnectorRegistrationTiming(
	lambdaTimeout string,
	handlerBudget string,
	packetBudget string,
	responseReserve string,
	writeBudget string,
) (connectorRegistrationTiming, error) {
	values := [...]string{
		lambdaTimeout,
		handlerBudget,
		packetBudget,
		responseReserve,
		writeBudget,
	}
	var durations [len(values)]time.Duration
	for index, value := range values {
		if !strictConnectorAuthorityEnvValue(value) {
			return connectorRegistrationTiming{}, errInvalidConnectorRegistrationConfiguration
		}
		duration, err := time.ParseDuration(value)
		if err != nil {
			return connectorRegistrationTiming{}, errInvalidConnectorRegistrationConfiguration
		}
		durations[index] = duration
	}
	timing := connectorRegistrationTiming{
		authorityLambdaTimeout: durations[0],
		handlerBudget:          durations[1],
		packetBudget:           durations[2],
		responseReserve:        durations[3],
		writeBudget:            durations[4],
	}
	responseTail := timing.packetBudget - timing.handlerBudget
	if timing.authorityLambdaTimeout < connectorRegistrationMinLambdaTimeout ||
		timing.authorityLambdaTimeout%time.Second != 0 ||
		timing.handlerBudget <= timing.authorityLambdaTimeout ||
		timing.packetBudget <= timing.handlerBudget ||
		timing.packetBudget >= connectorRegistrationMaxPacketBudget ||
		timing.responseReserve <= 0 || timing.responseReserve > responseTail ||
		timing.writeBudget <= 0 || timing.writeBudget > timing.responseReserve {
		return connectorRegistrationTiming{}, errInvalidConnectorRegistrationConfiguration
	}
	return timing, nil
}

func connectorRegistrationDeadline(receiptNanos int64, budget time.Duration, now time.Time) (time.Time, bool) {
	if receiptNanos <= 0 || budget <= 0 {
		return time.Time{}, false
	}
	receipt := time.Unix(0, receiptNanos)
	if receipt.After(now) {
		return time.Time{}, false
	}
	deadline := receipt.Add(budget)
	return deadline, deadline.After(now)
}

func (s *UdpServer) connectorRegistrationContext(receiptNanos int64) (context.Context, context.CancelFunc) {
	deadline, live := connectorRegistrationDeadline(receiptNanos, s.connectorRegistrationTiming.handlerBudget, time.Now())
	if !live {
		// Give the handler an already-expired context so invalid receipt
		// timestamps and exhausted budgets fail closed.
		deadline = time.Unix(0, 1)
	}
	ctx, cancel := context.WithDeadline(s.LifecycleCtx(), deadline)
	return ctx, cancel
}

func (s *UdpServer) connectorRegistrationWriteDeadline(receiptNanos int64, now time.Time) (time.Time, bool) {
	packetDeadline, live := connectorRegistrationDeadline(
		receiptNanos, s.connectorRegistrationTiming.packetBudget, now,
	)
	if !live || s.connectorRegistrationTiming.writeBudget <= 0 {
		return packetDeadline, false
	}
	writeDeadline := now.Add(s.connectorRegistrationTiming.writeBudget)
	if packetDeadline.Before(writeDeadline) {
		return packetDeadline, true
	}
	return writeDeadline, true
}

// connectorRegistrationResponseWriteDeadline selects the bounded absolute write
// deadline for a registration response. A live Authority response uses the
// receipt-anchored packet/write ladder from config. The dark handler-absent
// denial has no such config (a dark cell never loads it), so it uses a fixed
// budget from now — the frozen body is tiny and idempotent, and the point is to
// deliver a visible denial, not to honor a receipt deadline the request never
// established. Without this the dark path would compute a non-live deadline from
// the zero-value timing and drop the denial, re-creating the client stall.
func (s *UdpServer) connectorRegistrationResponseWriteDeadline(receiptNanos int64, authorityRan bool, now time.Time) (time.Time, bool) {
	if authorityRan {
		return s.connectorRegistrationWriteDeadline(receiptNanos, now)
	}
	return now.Add(connectorRegistrationHandlerAbsentWriteBudget), true
}

// handleConnectorRegistrationOTP intercepts only the exact top-level
// aspId=agent intent. The existing peer-key limiter remains ahead of the email-
// bearing Authority operation. OTP is fire-and-forget for every outcome.
func (s *UdpServer) handleConnectorRegistrationOTP(ppd *core.PacketParserData) (bool, error) {
	// The intent probe is pure and needs no handler; evaluate it before the
	// handler-nil check so a recognized Connector OTP is CLAIMED even on a dark
	// cell and never handed to the generic OTP plugin.
	if ppd == nil || !connectorcell.IsRegistrationOTPIntent(ppd.BodyMessage) {
		return false, nil
	}
	if s.rejectClaimedConnectorRegistrationOutsideDirectUDP(ppd) {
		return true, nil
	}
	if s.connectorRegistrationHandler == nil {
		// Capability dark: claim and drop the recognized Connector OTP intent
		// rather than leaking its secret-bearing body to the generic OTP plugin.
		// NHP_OTP is fire-and-forget, so there is no application reply either way.
		clear(ppd.BodyMessage)
		s.metrics.IncrCounter(MetricConnectorRegistrationHandlerAbsent)
		return true, nil
	}
	defer clear(ppd.BodyMessage)
	s.metrics.IncrCounter(MetricConnectorRegistrationOTPRequest)
	agentPubkey := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
	if !s.allowOTPRequest(ppd, agentPubkey) {
		s.metrics.IncrCounter(MetricConnectorRegistrationOTPAdmissionRejected)
		return true, nil
	}
	ctx, cancel := s.connectorRegistrationContext(ppd.LocalInitTime)
	defer cancel()
	observedSource := ""
	if ppd.ConnData != nil && ppd.ConnData.RemoteAddr != nil {
		observedSource = ppd.ConnData.RemoteAddr.IP.String()
	}
	result := s.connectorRegistrationHandler.HandleOTP(ctx, ppd.BodyMessage, ppd.RemotePubKey, observedSource)
	defer clear(result.Body)
	if result.Action != connectorcell.RegistrationActionNoApplicationReply || result.Body != nil ||
		result.RecoveryAction != connectorcell.RegistrationRecoveryNone {
		return true, s.invalidConnectorRegistrationAction()
	}
	s.recordConnectorRegistrationOutcome(result.Classification)
	return true, nil
}

func (s *UdpServer) buildConnectorRegistrationResult(
	ppd *core.PacketParserData,
	operation connectorRegistrationOperation,
) connectorcell.RegistrationResult {
	defer clear(ppd.BodyMessage)
	ctx, cancel := s.connectorRegistrationContext(ppd.LocalInitTime)
	defer cancel()
	var result connectorcell.RegistrationResult
	switch operation {
	case connectorRegistrationActivation:
		s.metrics.IncrCounter(MetricConnectorRegistrationActivationRequest)
		result = s.connectorRegistrationHandler.HandleRegistration(ctx, ppd.BodyMessage, ppd.RemotePubKey)
	case connectorRegistrationCompletion:
		s.metrics.IncrCounter(MetricConnectorRegistrationCompletionRequest)
		result = s.connectorRegistrationHandler.HandleRegistrationCompletion(ctx, ppd.BodyMessage, ppd.RemotePubKey)
	default:
		result.Classification = connectorcell.ClassificationInternalFailure
	}
	return result
}

func (s *UdpServer) handleDirectConnectorRegistration(
	ppd *core.PacketParserData,
	operation connectorRegistrationOperation,
) (bool, error) {
	// isConnectorRegistrationIntent is a pure, allocation-free structural probe
	// of the body; it needs neither the Authority handler nor its config. It is
	// evaluated BEFORE the handler-nil check so a genuine assigned-cell Connector
	// registration is CLAIMED even when the capability is dark, and answered with
	// the proper authenticated aspId="agent" denial produced below — never leaked
	// to the generic qURL knock handler, whose ServerRegisterAckMsg carries the
	// wrong aspId (empty for the static plugin, "qurl" for the deployed one) and
	// surfaces to qurl-go as "native registration reply aspId is invalid".
	if ppd == nil || !isConnectorRegistrationIntent(ppd.BodyMessage, operation) {
		return false, nil
	}
	transaction := ppd.OwningRemoteTransaction()
	if s.rejectClaimedConnectorRegistrationOutsideDirectUDP(ppd) {
		return true, retireConnectorRegistrationTransaction(transaction)
	}
	if transaction == nil {
		clear(ppd.BodyMessage)
		s.metrics.IncrCounter(MetricConnectorRegistrationInternalFailure)
		return true, common.ErrTransactionIdNotFound
	}
	result, authorityRan := s.connectorRegistrationResult(ppd, operation)
	defer clear(result.Body)
	headerType, emit, err := connectorRegistrationResponse(result, operation)
	if err != nil {
		return true, joinConnectorRegistrationTerminalError(
			s.invalidConnectorRegistrationAction(),
			retireConnectorRegistrationTransaction(transaction),
		)
	}
	// Authority outcome and response delivery are deliberately separate
	// signals: ResponseAttempt/Sent/Failure below records the transport leg. The
	// Authority-outcome metric applies only when the Authority actually ran; the
	// dark path already recorded MetricConnectorRegistrationHandlerAbsent.
	if authorityRan {
		s.recordConnectorRegistrationOutcome(result.Classification)
	}
	if !emit {
		return true, retireConnectorRegistrationTransaction(transaction)
	}
	s.metrics.IncrCounter(MetricConnectorRegistrationResponseAttempt)
	deadline, live := s.connectorRegistrationResponseWriteDeadline(ppd.LocalInitTime, authorityRan, time.Now())
	if !live {
		s.metrics.IncrCounter(MetricConnectorRegistrationResponseDeadline)
		return true, joinConnectorRegistrationTerminalError(
			errConnectorRegistrationDeadline,
			retireConnectorRegistrationTransaction(transaction),
		)
	}
	if err = s.forwardConnectorRegistrationToTransaction(ppd, transaction, headerType, result.Body, deadline); err != nil {
		s.recordConnectorRegistrationResponseFailure(err)
		return true, joinConnectorRegistrationTerminalError(
			err,
			retireConnectorRegistrationTransaction(transaction),
		)
	}
	s.metrics.IncrCounter(MetricConnectorRegistrationResponseSent)
	return true, nil
}

// connectorRegistrationResult produces the RegistrationResult for a claimed
// assigned-cell registration intent. When the Authority handler is live it runs
// it and reports authorityRan=true so the Authority-outcome metric applies.
// When the capability is dark it clears the request body, records only
// MetricConnectorRegistrationHandlerAbsent, and returns the frozen authenticated
// denial (aspId="agent") — a "registration disabled" RAK for activation, the
// retryable "completion temporarily unavailable" LRT for completion — so the
// request is answered visibly instead of falling through to the generic qURL
// knock handler (wrong aspId) or being dropped (client stall).
func (s *UdpServer) connectorRegistrationResult(
	ppd *core.PacketParserData,
	operation connectorRegistrationOperation,
) (result connectorcell.RegistrationResult, authorityRan bool) {
	if s.connectorRegistrationHandler != nil {
		return s.buildConnectorRegistrationResult(ppd, operation), true
	}
	clear(ppd.BodyMessage)
	s.metrics.IncrCounter(MetricConnectorRegistrationHandlerAbsent)
	if operation == connectorRegistrationCompletion {
		return connectorcell.RegistrationCompletionUnavailableLRT(), false
	}
	return connectorcell.RegistrationDisabledRAK(), false
}

func retireConnectorRegistrationTransaction(transaction *core.RemoteTransaction) error {
	if transaction == nil {
		return common.ErrTransactionIdNotFound
	}
	// The owning transaction's Run goroutine is installed before endpoint
	// dispatch. Retirement is local-only and must not inherit an already-expired
	// packet or server-lifecycle context: connection teardown still wins through
	// the transaction's done channel.
	err := transaction.CompleteContext(context.Background())
	if errors.Is(err, common.ErrTransactionClosed) {
		return nil
	}
	return err
}

func joinConnectorRegistrationTerminalError(primary, retirement error) error {
	// errors.Join already drops nil operands and returns nil when both are
	// nil; the joined value is only ever logged (metric classification runs on
	// the pre-join error), so no manual nil-collapsing is needed.
	return errors.Join(primary, retirement)
}

func isConnectorRegistrationIntent(body []byte, operation connectorRegistrationOperation) bool {
	switch operation {
	case connectorRegistrationOTP:
		return connectorcell.IsRegistrationOTPIntent(body)
	case connectorRegistrationActivation:
		return connectorcell.IsRegistrationIntent(body)
	case connectorRegistrationCompletion:
		return connectorcell.IsRegistrationCompletionIntent(body)
	default:
		return false
	}
}

// rejectClaimedConnectorRegistrationOutsideDirectUDP is the transport-only
// counterpart for a caller that has already matched an exact registration
// intent. Browser relay lifecycle traffic is rejected unconditionally by the
// relay boundary and never reaches this handler.
func (s *UdpServer) rejectClaimedConnectorRegistrationOutsideDirectUDP(
	ppd *core.PacketParserData,
) bool {
	if ppd.ConnData != nil && ppd.ConnData.IngressTransport == core.IngressTransportDirectUDP {
		return false
	}
	clear(ppd.BodyMessage)
	s.metrics.IncrCounter(MetricConnectorRegistrationIngressRejected)
	if s.observeConnectorRegistrationRejectedBodyCleared != nil {
		s.observeConnectorRegistrationRejectedBodyCleared(ppd.BodyMessage)
	}
	return true
}

func connectorRegistrationResponse(
	result connectorcell.RegistrationResult,
	operation connectorRegistrationOperation,
) (headerType int, emit bool, err error) {
	// OTP is deliberately absent: it is one-way and is fully handled by
	// handleConnectorRegistrationOTP, so it can never become a response action.
	switch operation {
	case connectorRegistrationActivation:
		switch result.Action {
		case connectorcell.RegistrationActionDropNoReply:
			if result.Body != nil || result.RecoveryAction != connectorcell.RegistrationRecoveryPendingExact {
				return 0, false, errConnectorRegistrationAction
			}
			return 0, false, nil
		case connectorcell.RegistrationActionEmitRAK:
			if len(result.Body) == 0 || result.RecoveryAction != connectorcell.RegistrationRecoveryNone {
				return 0, false, errConnectorRegistrationAction
			}
			return core.NHP_RAK, true, nil
		}
	case connectorRegistrationCompletion:
		// The strict completion codec freezes every success, rejection, and
		// unavailable outcome to EmitLRT. Any other action is a handler/contract
		// violation and must remain an internal failure, not a benign no-reply.
		if result.Action == connectorcell.RegistrationActionEmitLRT && len(result.Body) > 0 &&
			result.RecoveryAction == connectorcell.RegistrationRecoveryNone {
			return core.NHP_LRT, true, nil
		}
	}
	return 0, false, errConnectorRegistrationAction
}

func (s *UdpServer) invalidConnectorRegistrationAction() error {
	s.metrics.IncrCounter(MetricConnectorRegistrationInternalFailure)
	return errConnectorRegistrationAction
}

func (s *UdpServer) forwardConnectorRegistrationToTransaction(
	ppd *core.PacketParserData,
	transaction *core.RemoteTransaction,
	headerType int,
	body []byte,
	deadline time.Time,
) error {
	if ppd == nil || ppd.ConnData == nil || transaction == nil {
		return common.ErrTransactionIdNotFound
	}
	ctx, cancel := context.WithDeadline(s.LifecycleCtx(), deadline)
	defer cancel()
	wire, err := s.buildRelayInnerReplyContext(ctx, ppd, headerType, body)
	if err != nil {
		return classifyConnectorRegistrationEncryptionError(err)
	}
	defer clear(wire)
	// The encrypted wire bytes are an independent clone, and ConnectionData
	// outlives this transaction. Capturing the immutable destination before
	// completion lets Run destroy only the request packet/hash scratch while the
	// bounded physical write proceeds.
	remote := ppd.ConnData.RemoteAddr
	if completeErr := transaction.CompleteContext(ctx); completeErr != nil {
		if errors.Is(completeErr, common.ErrTransactionClosed) {
			s.recordTransactionClosed(completeErr)
		}
		return fmt.Errorf("%w: %w", errConnectorRegistrationResponseHandoff, completeErr)
	}
	_, err = s.writeUDPDatagram(ctx, wire, remote, deadline)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errConnectorRegistrationDeadline
		}
		if errors.Is(err, io.ErrShortWrite) {
			return errConnectorRegistrationResponseShortWrite
		}
		return fmt.Errorf("%w: %w", errConnectorRegistrationResponseWrite, err)
	}
	return nil
}

func classifyConnectorRegistrationEncryptionError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errConnectorRegistrationDeadline
	}
	return fmt.Errorf("%w: %w", errConnectorRegistrationResponseEncode, err)
}

func (s *UdpServer) recordConnectorRegistrationResponseFailure(err error) {
	metric := MetricConnectorRegistrationResponseWriteFailed
	switch {
	case errors.Is(err, errConnectorRegistrationDeadline), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		metric = MetricConnectorRegistrationResponseDeadline
	case errors.Is(err, errConnectorRegistrationResponseEncode):
		metric = MetricConnectorRegistrationResponseEncodeFailed
	case errors.Is(err, errConnectorRegistrationResponseHandoff), errors.Is(err, common.ErrTransactionIdNotFound), errors.Is(err, common.ErrTransactionClosed):
		metric = MetricConnectorRegistrationResponseHandoffFailed
	case errors.Is(err, errConnectorRegistrationResponseShortWrite), errors.Is(err, io.ErrShortWrite):
		metric = MetricConnectorRegistrationResponseShortWrite
	}
	s.metrics.IncrCounter(metric)
}

func (s *UdpServer) recordConnectorRegistrationOutcome(classification connectorcell.Classification) {
	metric := MetricConnectorRegistrationInternalFailure
	switch classification {
	case connectorcell.ClassificationSuccess:
		metric = MetricConnectorRegistrationAuthoritySuccess
	case connectorcell.ClassificationRequestRejected:
		metric = MetricConnectorRegistrationRequestRejected
	case connectorcell.ClassificationDeadlineRejected:
		metric = MetricConnectorRegistrationDeadlineRejected
	case connectorcell.ClassificationAuthorityInvocationFailed:
		metric = MetricConnectorRegistrationInvokeFailed
	case connectorcell.ClassificationAuthorityResponseRejected:
		metric = MetricConnectorRegistrationResponseRejected
	case connectorcell.ClassificationAuthoritySemanticError:
		metric = MetricConnectorRegistrationAuthorityRejected
	}
	s.metrics.IncrCounter(metric)
}
