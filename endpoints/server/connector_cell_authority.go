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
// startup boundary. Registration, recovery, and resource discovery are either
// all absent or form one exact five-operation, one-color graph; no AWS client is loaded until that
// complete graph is valid. The handlers still receive structurally narrow
// clients, so validating together does not widen either runtime capability.
func (s *UdpServer) configureConnectorCellAuthority(
	ctx context.Context,
	lookupEnv func(string) (string, bool),
	loadAWS connectorCellAuthorityAWSLoader,
) error {
	s.connectorRegistrationHandler = nil
	s.connectorRegistrationTiming = connectorRegistrationTiming{}
	s.credentialRecoveryHandler = nil
	s.connectorResourceHandler = nil

	registration, recovery, resource, err := loadConnectorCellAuthorityConfigs(lookupEnv)
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

	resourceAuthority, err := connectorauthority.NewConnectorResourceCellClient(
		awsConfig,
		boundary,
		connectorauthority.ConnectorResourceCellTarget{
			ResolveConnectorResourceAliasARN: resource.aliasARN,
		},
	)
	if err != nil {
		return errInvalidConnectorCellAuthorityConfiguration
	}
	resourceHandler, err := connectorcell.NewConnectorResourceHandler(resourceAuthority, registration.environment)
	if err != nil {
		return errInvalidConnectorCellAuthorityConfiguration
	}

	// Publish all capabilities only after the shared AWS identity and all
	// narrow clients and handlers have been constructed successfully.
	s.connectorRegistrationHandler = registrationHandler
	s.connectorRegistrationTiming = registration.timing
	s.credentialRecoveryHandler = recoveryHandler
	s.connectorResourceHandler = resourceHandler
	return nil
}

func loadConnectorCellAuthorityConfigs(
	lookupEnv func(string) (string, bool),
) (*connectorRegistrationConfig, *credentialRecoveryConfig, *connectorResourceConfig, error) {
	registration, err := loadConnectorRegistrationConfig(lookupEnv)
	if err != nil {
		return nil, nil, nil, err
	}
	recovery, err := loadCredentialRecoveryConfig(lookupEnv)
	if err != nil {
		return nil, nil, nil, err
	}
	resource, err := loadConnectorResourceConfig(lookupEnv)
	if err != nil {
		return nil, nil, nil, err
	}
	if registration == nil && recovery == nil && resource == nil {
		return nil, nil, nil, nil
	}
	if registration == nil || recovery == nil || resource == nil ||
		registration.environment != recovery.environment ||
		registration.cellID != recovery.cellID ||
		registration.region != recovery.region ||
		registration.accountID != recovery.accountID ||
		registration.environment != resource.environment ||
		registration.cellID != resource.cellID ||
		registration.region != resource.region ||
		registration.accountID != resource.accountID {
		return nil, nil, nil, errInvalidConnectorCellAuthorityConfiguration
	}

	if err := connectorauthority.ValidateCellTargets(
		connectorCellBoundary(registration),
		connectorauthority.CellTargets{
			IssueRegistrationOTPAliasARN:       registration.issueOTPAliasARN,
			ActivateRegistrationAliasARN:       registration.activateAliasARN,
			CompleteRegistrationAliasARN:       registration.completeAliasARN,
			CompleteCredentialRecoveryAliasARN: recovery.aliasARN,
			ResolveConnectorResourceAliasARN:   resource.aliasARN,
		},
	); err != nil {
		return nil, nil, nil, errInvalidConnectorCellAuthorityConfiguration
	}
	return registration, recovery, resource, nil
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
