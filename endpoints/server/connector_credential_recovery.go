package server

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorauthority"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorcell"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

const (
	ConnectorCredentialRecoveryAWSRegionEnvVar  = "NHP_CONNECTOR_CREDENTIAL_RECOVERY_AWS_REGION"
	ConnectorCredentialRecoveryAWSAccountEnvVar = "NHP_CONNECTOR_CREDENTIAL_RECOVERY_AWS_ACCOUNT_ID"
	ConnectorCredentialRecoveryAliasARNEnvVar   = "NHP_CONNECTOR_CREDENTIAL_RECOVERY_ALIAS_ARN"

	// connectorCredentialRecoveryBudget is anchored at PacketParserData.LocalInitTime,
	// the local UDP receipt timestamp. The same absolute deadline covers strict
	// decoding, the one-attempt Authority call, and transaction handoff.
	connectorCredentialRecoveryBudget       = 2500 * time.Millisecond
	credentialRecoveryStartupAWSLoadTimeout = 5 * time.Second
)

var (
	errInvalidCredentialRecoveryConfiguration = errors.New("connector credential recovery: invalid configuration")
	errCredentialRecoveryDeadline             = errors.New("connector credential recovery: request deadline exhausted")
	errCredentialRecoveryResponse             = errors.New("connector credential recovery: response unavailable")
	credentialRecoveryCellIDPattern           = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

// Fixed metric names are the complete observer surface for this dark slice.
// No source, peer, agent, credential, query, or other attacker-derived value is
// used as a dimension or metric name.
const (
	MetricConnectorCredentialRecoveryRequest           = "ConnectorCredentialRecoveryRequest"
	MetricConnectorCredentialRecoverySuccess           = "ConnectorCredentialRecoverySuccess"
	MetricConnectorCredentialRecoveryRequestRejected   = "ConnectorCredentialRecoveryRequestRejected"
	MetricConnectorCredentialRecoveryDeadlineRejected  = "ConnectorCredentialRecoveryDeadlineRejected"
	MetricConnectorCredentialRecoveryInvokeFailed      = "ConnectorCredentialRecoveryInvokeFailed"
	MetricConnectorCredentialRecoveryResponseRejected  = "ConnectorCredentialRecoveryResponseRejected"
	MetricConnectorCredentialRecoveryAuthorityRejected = "ConnectorCredentialRecoveryAuthorityRejected"
	MetricConnectorCredentialRecoveryInternalFailure   = "ConnectorCredentialRecoveryInternalFailure"
	MetricConnectorCredentialRecoveryRelayRejected     = "ConnectorCredentialRecoveryRelayRejected"
)

type credentialRecoveryDirectHandler interface {
	HandleDirect(context.Context, []byte, []byte) (connectorcell.HandleResult, bool)
}

type credentialRecoveryConfig struct {
	environment string
	cellID      string
	region      string
	accountID   string
	aliasARN    string
}

type credentialRecoveryAWSLoader func(context.Context, string) (aws.Config, error)

func loadCredentialRecoveryAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
}

func loadCredentialRecoveryConfig(lookupEnv func(string) (string, bool)) (*credentialRecoveryConfig, error) {
	if lookupEnv == nil {
		return nil, errInvalidCredentialRecoveryConfiguration
	}
	region, regionSet := lookupEnv(ConnectorCredentialRecoveryAWSRegionEnvVar)
	accountID, accountSet := lookupEnv(ConnectorCredentialRecoveryAWSAccountEnvVar)
	aliasARN, aliasSet := lookupEnv(ConnectorCredentialRecoveryAliasARNEnvVar)
	if !regionSet && !accountSet && !aliasSet {
		return nil, nil
	}
	// Once any recovery knob is present, all three must be explicitly present
	// and non-empty. LookupEnv preserves the important empty-vs-absent boundary.
	if !regionSet || !accountSet || !aliasSet || region == "" || accountID == "" || aliasARN == "" {
		return nil, errInvalidCredentialRecoveryConfiguration
	}
	environment, _ := lookupEnv("NHP_ENVIRONMENT")
	cellID, _ := lookupEnv("NHP_CELL_ID")
	config := &credentialRecoveryConfig{
		environment: environment,
		cellID:      cellID,
		region:      region,
		accountID:   accountID,
		aliasARN:    aliasARN,
	}
	if config.environment == "" || config.cellID == "" {
		return nil, errInvalidCredentialRecoveryConfiguration
	}
	if config.environment != "sandbox" && config.environment != "prod" {
		return nil, errInvalidCredentialRecoveryConfiguration
	}
	if len(config.cellID) > 32 || !credentialRecoveryCellIDPattern.MatchString(config.cellID) {
		return nil, errInvalidCredentialRecoveryConfiguration
	}

	boundary := connectorauthority.Boundary{AccountID: config.accountID, Region: config.region}
	target := connectorauthority.CredentialRecoveryCellTarget{
		CompleteCredentialRecoveryAliasARN: config.aliasARN,
	}
	if err := connectorauthority.ValidateCredentialRecoveryCellTarget(boundary, target); err != nil {
		return nil, errInvalidCredentialRecoveryConfiguration
	}
	parsed, err := arn.Parse(config.aliasARN)
	// The compact physical name leaves room for every Terraform-valid 32-byte
	// cell id within Lambda's 64-byte function-name limit. The operation remains
	// spelled CompleteCredentialRecovery in contracts, tags, and documentation.
	expectedFunction := fmt.Sprintf("layerv-nhp-%s-ca-ccr-%s", config.environment, config.cellID)
	if err != nil || parsed.Resource != "function:"+expectedFunction+":active" {
		return nil, errInvalidCredentialRecoveryConfiguration
	}
	return config, nil
}

// configureCredentialRecovery is the small startup seam. Configuration is
// fully validated before ambient AWS loading; a partial/invalid presence fails
// Start before UDP bind, while total absence leaves the handler nil.
func (s *UdpServer) configureCredentialRecovery(
	ctx context.Context,
	lookupEnv func(string) (string, bool),
	loadAWS credentialRecoveryAWSLoader,
) error {
	config, err := loadCredentialRecoveryConfig(lookupEnv)
	if err != nil {
		return err
	}
	if config == nil {
		s.credentialRecoveryHandler = nil
		return nil
	}
	if ctx == nil || loadAWS == nil || ctx.Err() != nil {
		return errInvalidCredentialRecoveryConfiguration
	}
	loadCtx, cancel := context.WithTimeout(ctx, credentialRecoveryStartupAWSLoadTimeout)
	defer cancel()
	awsConfig, err := loadAWS(loadCtx, config.region)
	if err != nil {
		return fmt.Errorf("connector credential recovery: load AWS configuration: %w", err)
	}
	authority, err := connectorauthority.NewCredentialRecoveryCellClient(
		awsConfig,
		connectorauthority.Boundary{AccountID: config.accountID, Region: config.region},
		connectorauthority.CredentialRecoveryCellTarget{CompleteCredentialRecoveryAliasARN: config.aliasARN},
	)
	if err != nil {
		return errInvalidCredentialRecoveryConfiguration
	}
	handler, err := connectorcell.NewHandler(authority)
	if err != nil {
		return errInvalidCredentialRecoveryConfiguration
	}
	s.credentialRecoveryHandler = handler
	return nil
}

// buildDirectCredentialRecoveryResult intercepts only recovery intent. It
// clears the caller-owned decrypted body if and only if the request is handled;
// ordinary LST bytes remain untouched for buildListResult. Returned LRT bytes
// are secret-free and remain owned by the caller so transaction SendMessage can
// consume them asynchronously without observing a wiped buffer.
func (s *UdpServer) buildDirectCredentialRecoveryResult(
	ppd *core.PacketParserData,
) (body []byte, handled bool, deadline time.Time, classification connectorcell.Classification, err error) {
	if s.credentialRecoveryHandler == nil || ppd == nil {
		return nil, false, time.Time{}, "", nil
	}
	now := time.Now()
	deadline, live := credentialRecoveryDeadline(ppd.LocalInitTime, now)
	if !live {
		deadline = time.Unix(0, 1)
	}
	requestCtx, cancel := context.WithDeadline(s.LifecycleCtx(), deadline)
	defer cancel()
	result, handled := s.credentialRecoveryHandler.HandleDirect(requestCtx, ppd.BodyMessage, ppd.RemotePubKey)
	if !handled {
		return nil, false, time.Time{}, "", nil
	}
	clear(ppd.BodyMessage)
	s.metrics.IncrCounter(MetricConnectorCredentialRecoveryRequest)
	if !live || requestCtx.Err() != nil || !deadline.After(time.Now()) {
		return nil, true, deadline, connectorcell.ClassificationDeadlineRejected, errCredentialRecoveryDeadline
	}
	if len(result.Body) == 0 {
		return nil, true, deadline, connectorcell.ClassificationInternalFailure, errCredentialRecoveryResponse
	}
	return result.Body, true, deadline, result.Classification, nil
}

func credentialRecoveryDeadline(receiptNanos int64, now time.Time) (time.Time, bool) {
	if receiptNanos <= 0 {
		return time.Time{}, false
	}
	receipt := time.Unix(0, receiptNanos)
	// LocalInitTime is server-observed receipt time, never the sender clock. A
	// future value therefore indicates corrupt construction and must not extend
	// the Authority budget.
	if receipt.After(now) {
		return time.Time{}, false
	}
	deadline := receipt.Add(connectorCredentialRecoveryBudget)
	return deadline, deadline.After(now)
}

func (s *UdpServer) recordCredentialRecoveryOutcome(classification connectorcell.Classification) {
	metric := MetricConnectorCredentialRecoveryInternalFailure
	switch classification {
	case connectorcell.ClassificationSuccess:
		metric = MetricConnectorCredentialRecoverySuccess
	case connectorcell.ClassificationRequestRejected:
		metric = MetricConnectorCredentialRecoveryRequestRejected
	case connectorcell.ClassificationDeadlineRejected:
		metric = MetricConnectorCredentialRecoveryDeadlineRejected
	case connectorcell.ClassificationAuthorityInvocationFailed:
		metric = MetricConnectorCredentialRecoveryInvokeFailed
	case connectorcell.ClassificationAuthorityResponseRejected:
		metric = MetricConnectorCredentialRecoveryResponseRejected
	case connectorcell.ClassificationAuthoritySemanticError:
		metric = MetricConnectorCredentialRecoveryAuthorityRejected
	}
	s.metrics.IncrCounter(metric)
}

func (s *UdpServer) rejectRelayedCredentialRecovery(raw []byte) ([]byte, bool) {
	// The relay guard is part of the same opt-in composition as direct recovery.
	// With no configured handler the entire feature stays dark and generic LST
	// behavior remains byte-for-byte unchanged.
	if s.credentialRecoveryHandler == nil {
		return nil, false
	}
	body, handled := connectorcell.RejectRelayedCompletion(raw)
	if !handled {
		return nil, false
	}
	clear(raw)
	if s.observeRelayedCredentialRecoveryBodyCleared != nil {
		s.observeRelayedCredentialRecoveryBodyCleared(raw)
	}
	s.metrics.IncrCounter(MetricConnectorCredentialRecoveryRelayRejected)
	return body, true
}

func (s *UdpServer) forwardCredentialRecoveryToTransaction(
	ppd *core.PacketParserData,
	body []byte,
	deadline time.Time,
) error {
	// This recovery path intentionally emits no transaction/source/peer log.
	// The caller maps failures to fixed aggregate metrics; recordTransactionClosed
	// below is also metric-only. Keep attacker-derived identifiers out of logs.
	if ppd == nil || ppd.ConnData == nil {
		return common.ErrTransactionIdNotFound
	}
	transaction := ppd.ConnData.FindRemoteTransaction(ppd.SenderTrxId)
	if transaction == nil {
		return common.ErrTransactionIdNotFound
	}
	ctx, cancel := context.WithDeadline(s.LifecycleCtx(), deadline)
	defer cancel()
	if err := transaction.SendMessageContext(ctx, makeMsgData(ppd, core.NHP_LRT, body)); err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errCredentialRecoveryDeadline
		}
		if errors.Is(err, common.ErrTransactionClosed) {
			s.recordTransactionClosed(err)
		}
		return err
	}
	return nil
}
