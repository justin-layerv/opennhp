package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorauthority"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorcell"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

const (
	ConnectorResourceAWSRegionEnvVar  = "NHP_CONNECTOR_RESOURCE_AWS_REGION"
	ConnectorResourceAWSAccountEnvVar = "NHP_CONNECTOR_RESOURCE_AWS_ACCOUNT_ID"
	ConnectorResourceAliasARNEnvVar   = "NHP_CONNECTOR_RESOURCE_ALIAS_ARN"

	// 1280-byte IPv6 minimum MTU - 40-byte IPv6 header - 8-byte UDP header.
	// This is an operational bound beneath NHP's protocol maximum: the complete
	// sealed datagram, not merely plaintext JSON, must fit. The conformance
	// plaintext ceiling is defined as this packet ceiling minus its conservative
	// seal budget; the real Noise-sealed maximum-field test below this seam is
	// the executable proof that the current wire encoder remains inside it.
	connectorResourceMaxDatagramBytes = conformance.ConnectorResourceLSTV1MaxPacketBytes
)

var (
	errInvalidConnectorResourceConfiguration = errors.New("connector resource: invalid configuration")
	errConnectorResourceDeadline             = errors.New("connector resource: request deadline exhausted")
	errConnectorResourceResponse             = errors.New("connector resource: response unavailable")
	errConnectorResourceResponseEncode       = errors.New("connector resource: response encryption failed")
	errConnectorResourceResponseHandoff      = errors.New("connector resource: transaction handoff failed")
	errConnectorResourceResponseWrite        = errors.New("connector resource: response write failed")
	errConnectorResourceResponseShortWrite   = errors.New("connector resource: short response write")
	errConnectorResourceResponseOversize     = errors.New("connector resource: sealed response exceeds unfragmented datagram bound")
)

const (
	MetricConnectorResourceRequest                   = "ConnectorResourceRequest"
	MetricConnectorResourceSuccess                   = "ConnectorResourceSuccess"
	MetricConnectorResourceRequestRejected           = "ConnectorResourceRequestRejected"
	MetricConnectorResourceIngressRejected           = "ConnectorResourceIngressRejected"
	MetricConnectorResourceHandlerAbsent             = "ConnectorResourceHandlerAbsent"
	MetricConnectorResourceDeadlineRejected          = "ConnectorResourceDeadlineRejected"
	MetricConnectorResourceInvokeFailed              = "ConnectorResourceInvokeFailed"
	MetricConnectorResourceAuthorityResponseRejected = "ConnectorResourceAuthorityResponseRejected"
	MetricConnectorResourceAuthorityRejected         = "ConnectorResourceAuthorityRejected"
	MetricConnectorResourceResponseAttempt           = "ConnectorResourceResponseAttempt"
	MetricConnectorResourceResponseSent              = "ConnectorResourceResponseSent"
	MetricConnectorResourceResponseEncodeFailed      = "ConnectorResourceResponseEncodeFailed"
	MetricConnectorResourceResponseHandoffFailed     = "ConnectorResourceResponseHandoffFailed"
	MetricConnectorResourceResponseWriteFailed       = "ConnectorResourceResponseWriteFailed"
	MetricConnectorResourceResponseShortWrite        = "ConnectorResourceResponseShortWrite"
	MetricConnectorResourceResponseOversizeRejected  = "ConnectorResourceResponseOversizeRejected"
	MetricConnectorResourceInternalFailure           = "ConnectorResourceInternalFailure"
)

type connectorResourceDirectHandler interface {
	HandleDirect(context.Context, []byte, []byte) (connectorcell.HandleResult, bool)
}

type connectorResourceConfig struct {
	environment string
	cellID      string
	region      string
	accountID   string
	aliasARN    string
}

func loadConnectorResourceConfig(lookupEnv func(string) (string, bool)) (*connectorResourceConfig, error) {
	if lookupEnv == nil {
		return nil, errInvalidConnectorResourceConfiguration
	}
	region, regionSet := lookupEnv(ConnectorResourceAWSRegionEnvVar)
	accountID, accountSet := lookupEnv(ConnectorResourceAWSAccountEnvVar)
	aliasARN, aliasSet := lookupEnv(ConnectorResourceAliasARNEnvVar)
	if !regionSet && !accountSet && !aliasSet {
		return nil, nil
	}
	if !regionSet || !accountSet || !aliasSet || !strictConnectorAuthorityEnvValue(region) ||
		!strictConnectorAuthorityEnvValue(accountID) || !strictConnectorAuthorityEnvValue(aliasARN) {
		return nil, errInvalidConnectorResourceConfiguration
	}
	environment, environmentSet := lookupEnv("NHP_ENVIRONMENT")
	cellID, cellSet := lookupEnv("NHP_CELL_ID")
	if !environmentSet || !cellSet {
		return nil, errInvalidConnectorResourceConfiguration
	}
	config := &connectorResourceConfig{environment: environment, cellID: cellID, region: region, accountID: accountID, aliasARN: aliasARN}
	boundary := connectorauthority.CellBoundary{Boundary: connectorauthority.Boundary{
		Environment: environment, AccountID: accountID, Region: region,
	}, CellID: cellID}
	if err := connectorauthority.ValidateConnectorResourceCellTarget(boundary, connectorauthority.ConnectorResourceCellTarget{
		ResolveConnectorResourceAliasARN: aliasARN,
	}); err != nil {
		return nil, errInvalidConnectorResourceConfiguration
	}
	return config, nil
}

func (s *UdpServer) handleDirectConnectorResource(ppd *core.PacketParserData) (bool, error) {
	if ppd == nil || !connectorcell.IsConnectorResourceIntent(ppd.BodyMessage) {
		return false, nil
	}
	transaction := ppd.OwningRemoteTransaction()
	if ppd.ConnData == nil || ppd.ConnData.IngressTransport != core.IngressTransportDirectUDP {
		clear(ppd.BodyMessage)
		s.metrics.IncrCounter(MetricConnectorResourceIngressRejected)
		return true, retireConnectorRegistrationTransaction(transaction)
	}
	if transaction == nil {
		clear(ppd.BodyMessage)
		s.metrics.IncrCounter(MetricConnectorResourceInternalFailure)
		return true, common.ErrTransactionIdNotFound
	}

	s.metrics.IncrCounter(MetricConnectorResourceRequest)
	authorityRan := s.connectorResourceHandler != nil
	var result connectorcell.HandleResult
	if authorityRan {
		ctx, cancel := s.connectorRegistrationContext(ppd.LocalInitTime)
		result, _ = s.connectorResourceHandler.HandleDirect(ctx, ppd.BodyMessage, ppd.RemotePubKey)
		cancel()
	} else {
		s.metrics.IncrCounter(MetricConnectorResourceHandlerAbsent)
		result.Body, _ = connectorcell.EncodeConnectorResourceError(connectorcell.ConnectorResourceErrorUnavailable, 0)
	}
	clear(ppd.BodyMessage)
	defer clear(result.Body)
	if len(result.Body) == 0 {
		s.metrics.IncrCounter(MetricConnectorResourceInternalFailure)
		return true, errors.Join(errConnectorResourceResponse, retireConnectorRegistrationTransaction(transaction))
	}
	if authorityRan {
		s.recordConnectorResourceOutcome(result.Classification)
	}
	s.metrics.IncrCounter(MetricConnectorResourceResponseAttempt)
	deadline, live := s.connectorRegistrationResponseWriteDeadline(ppd.LocalInitTime, authorityRan, time.Now())
	if !live {
		if !connectorResourceDeadlineOutcomeAlreadyRecorded(authorityRan, result.Classification) {
			s.metrics.IncrCounter(MetricConnectorResourceDeadlineRejected)
		}
		return true, errors.Join(errConnectorResourceDeadline, retireConnectorRegistrationTransaction(transaction))
	}
	if err := s.forwardConnectorResourceToTransaction(ppd, transaction, result.Body, deadline); err != nil {
		if !errors.Is(err, errConnectorResourceDeadline) ||
			!connectorResourceDeadlineOutcomeAlreadyRecorded(authorityRan, result.Classification) {
			s.recordConnectorResourceResponseFailure(err)
		}
		return true, errors.Join(err, retireConnectorRegistrationTransaction(transaction))
	}
	s.metrics.IncrCounter(MetricConnectorResourceResponseSent)
	return true, nil
}

func connectorResourceDeadlineOutcomeAlreadyRecorded(authorityRan bool, classification connectorcell.Classification) bool {
	return authorityRan && classification == connectorcell.ClassificationDeadlineRejected
}

func (s *UdpServer) forwardConnectorResourceToTransaction(
	ppd *core.PacketParserData,
	transaction *core.RemoteTransaction,
	body []byte,
	deadline time.Time,
) error {
	if ppd == nil || ppd.ConnData == nil || transaction == nil {
		return common.ErrTransactionIdNotFound
	}
	ctx, cancel := context.WithDeadline(s.LifecycleCtx(), deadline)
	defer cancel()
	wire, err := s.buildRelayInnerReplyContext(ctx, ppd, core.NHP_LRT, body)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errConnectorResourceDeadline
		}
		return fmt.Errorf("%w: %w", errConnectorResourceResponseEncode, err)
	}
	defer clear(wire)
	if connectorResourceResponseIsOversize(len(wire)) {
		return errConnectorResourceResponseOversize
	}
	remote := ppd.ConnData.RemoteAddr
	if completeErr := transaction.CompleteContext(ctx); completeErr != nil {
		if errors.Is(completeErr, common.ErrTransactionClosed) {
			s.recordTransactionClosed(completeErr)
		}
		return fmt.Errorf("%w: %w", errConnectorResourceResponseHandoff, completeErr)
	}
	if _, err := s.writeUDPDatagram(ctx, wire, remote, deadline); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errConnectorResourceDeadline
		}
		if errors.Is(err, io.ErrShortWrite) {
			return errConnectorResourceResponseShortWrite
		}
		return fmt.Errorf("%w: %w", errConnectorResourceResponseWrite, err)
	}
	return nil
}

func connectorResourceResponseIsOversize(size int) bool {
	return size > connectorResourceMaxDatagramBytes
}

func (s *UdpServer) recordConnectorResourceOutcome(classification connectorcell.Classification) {
	metric := MetricConnectorResourceInternalFailure
	switch classification {
	case connectorcell.ClassificationSuccess:
		metric = MetricConnectorResourceSuccess
	case connectorcell.ClassificationRequestRejected:
		metric = MetricConnectorResourceRequestRejected
	case connectorcell.ClassificationDeadlineRejected:
		metric = MetricConnectorResourceDeadlineRejected
	case connectorcell.ClassificationAuthorityInvocationFailed:
		metric = MetricConnectorResourceInvokeFailed
	case connectorcell.ClassificationAuthorityResponseRejected:
		metric = MetricConnectorResourceAuthorityResponseRejected
	case connectorcell.ClassificationAuthoritySemanticError:
		metric = MetricConnectorResourceAuthorityRejected
	}
	s.metrics.IncrCounter(metric)
}

func (s *UdpServer) recordConnectorResourceResponseFailure(err error) {
	metric := MetricConnectorResourceResponseWriteFailed
	switch {
	case errors.Is(err, errConnectorResourceDeadline):
		metric = MetricConnectorResourceDeadlineRejected
	case errors.Is(err, errConnectorResourceResponseEncode):
		metric = MetricConnectorResourceResponseEncodeFailed
	case errors.Is(err, errConnectorResourceResponseHandoff), errors.Is(err, common.ErrTransactionIdNotFound), errors.Is(err, common.ErrTransactionClosed):
		metric = MetricConnectorResourceResponseHandoffFailed
	case errors.Is(err, errConnectorResourceResponseShortWrite):
		metric = MetricConnectorResourceResponseShortWrite
	case errors.Is(err, errConnectorResourceResponseOversize):
		metric = MetricConnectorResourceResponseOversizeRejected
	}
	s.metrics.IncrCounter(metric)
}
