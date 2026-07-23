package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorauthority"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorcell"
)

const connectorCellAuthorityStartupAWSLoadTimeout = 5 * time.Second

var errInvalidConnectorCellAuthorityConfiguration = errors.New("connector cell authority: invalid configuration")

type connectorCellAuthorityAWSLoader func(context.Context, string) (aws.Config, error)

func loadConnectorCellAuthorityAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
}

// configureConnectorCellAuthority owns the atomic assigned-cell Authority
// startup boundary. Registration and recovery are either both absent or form
// one exact four-operation, one-color graph; no AWS client is loaded until that
// complete graph is valid. The two handlers still receive structurally narrow
// clients, so validating together does not widen either runtime capability.
func (s *UdpServer) configureConnectorCellAuthority(
	ctx context.Context,
	lookupEnv func(string) (string, bool),
	loadAWS connectorCellAuthorityAWSLoader,
) error {
	s.connectorRegistrationHandler = nil
	s.connectorRegistrationTiming = connectorRegistrationTiming{}
	s.credentialRecoveryHandler = nil

	registration, recovery, err := loadConnectorCellAuthorityConfigs(lookupEnv)
	if err != nil {
		return err
	}
	if registration == nil {
		return nil
	}
	if ctx == nil || loadAWS == nil || ctx.Err() != nil {
		return errInvalidConnectorCellAuthorityConfiguration
	}

	loadCtx, cancel := context.WithTimeout(ctx, connectorCellAuthorityStartupAWSLoadTimeout)
	defer cancel()
	awsConfig, err := loadAWS(loadCtx, registration.region)
	if err != nil {
		return fmt.Errorf("connector cell authority: load AWS configuration: %w", err)
	}
	if loadCtx.Err() != nil {
		return errInvalidConnectorCellAuthorityConfiguration
	}

	boundary := connectorCellBoundary(registration)
	registrationAuthority, err := connectorauthority.NewRegistrationCellClient(
		awsConfig,
		boundary,
		connectorauthority.RegistrationCellTargets{
			IssueRegistrationOTPAliasARN: registration.issueOTPAliasARN,
			ActivateRegistrationAliasARN: registration.activateAliasARN,
			CompleteRegistrationAliasARN: registration.completeAliasARN,
		},
	)
	if err != nil {
		return errInvalidConnectorCellAuthorityConfiguration
	}
	registrationHandler, err := connectorcell.NewRegistrationHandler(registrationAuthority)
	if err != nil {
		return errInvalidConnectorCellAuthorityConfiguration
	}

	recoveryAuthority, err := connectorauthority.NewCredentialRecoveryCellClient(
		awsConfig,
		boundary,
		connectorauthority.CredentialRecoveryCellTarget{
			CompleteCredentialRecoveryAliasARN: recovery.aliasARN,
		},
	)
	if err != nil {
		return errInvalidConnectorCellAuthorityConfiguration
	}
	recoveryHandler, err := connectorcell.NewHandler(recoveryAuthority)
	if err != nil {
		return errInvalidConnectorCellAuthorityConfiguration
	}

	// Publish both capabilities only after the shared AWS identity and both
	// narrow clients and handlers have been constructed successfully.
	s.connectorRegistrationHandler = registrationHandler
	s.connectorRegistrationTiming = registration.timing
	s.credentialRecoveryHandler = recoveryHandler
	return nil
}

func loadConnectorCellAuthorityConfigs(
	lookupEnv func(string) (string, bool),
) (*connectorRegistrationConfig, *credentialRecoveryConfig, error) {
	registration, err := loadConnectorRegistrationConfig(lookupEnv)
	if err != nil {
		return nil, nil, err
	}
	recovery, err := loadCredentialRecoveryConfig(lookupEnv)
	if err != nil {
		return nil, nil, err
	}
	if registration == nil && recovery == nil {
		return nil, nil, nil
	}
	if registration == nil || recovery == nil ||
		registration.environment != recovery.environment ||
		registration.cellID != recovery.cellID ||
		registration.region != recovery.region ||
		registration.accountID != recovery.accountID {
		return nil, nil, errInvalidConnectorCellAuthorityConfiguration
	}

	if err := connectorauthority.ValidateCellTargets(
		connectorCellBoundary(registration),
		connectorauthority.CellTargets{
			IssueRegistrationOTPAliasARN:       registration.issueOTPAliasARN,
			ActivateRegistrationAliasARN:       registration.activateAliasARN,
			CompleteRegistrationAliasARN:       registration.completeAliasARN,
			CompleteCredentialRecoveryAliasARN: recovery.aliasARN,
		},
	); err != nil {
		return nil, nil, errInvalidConnectorCellAuthorityConfiguration
	}
	return registration, recovery, nil
}

func connectorCellBoundary(config *connectorRegistrationConfig) connectorauthority.CellBoundary {
	return connectorauthority.CellBoundary{
		Boundary: connectorauthority.Boundary{
			Environment: config.environment,
			AccountID:   config.accountID,
			Region:      config.region,
		},
		CellID: config.cellID,
	}
}

func strictConnectorAuthorityEnvValue(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}
