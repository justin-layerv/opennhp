package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestConfigureConnectorCellAuthorityPublishesOneValidatedGraphAtomically(t *testing.T) {
	t.Parallel()

	env := validConnectorCellAuthorityEnvironment()
	server := &UdpServer{}
	loads := 0
	err := server.configureConnectorCellAuthority(
		context.Background(),
		mapEnvironment(env),
		func(_ context.Context, region string) (aws.Config, error) {
			loads++
			if region != "us-east-2" {
				t.Fatalf("region = %q", region)
			}
			return aws.Config{Region: region}, nil
		},
	)
	if err != nil || loads != 1 || server.connectorRegistrationHandler == nil ||
		server.credentialRecoveryHandler == nil ||
		server.connectorRegistrationTiming != validConnectorRegistrationTiming() {
		t.Fatalf(
			"configure = %v loads=%d registration=%T recovery=%T timing=%+v",
			err,
			loads,
			server.connectorRegistrationHandler,
			server.credentialRecoveryHandler,
			server.connectorRegistrationTiming,
		)
	}

	// A later invalid reconfiguration must clear both capabilities before any
	// ambient AWS load, never retain half of the previous graph.
	bad := validConnectorCellAuthorityEnvironment()
	bad[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.TrimSuffix(
		bad[ConnectorCredentialRecoveryAliasARNEnvVar],
		":blue",
	) + ":green"
	loads = 0
	err = server.configureConnectorCellAuthority(
		context.Background(),
		mapEnvironment(bad),
		func(context.Context, string) (aws.Config, error) {
			loads++
			return aws.Config{}, nil
		},
	)
	if !errors.Is(err, errInvalidConnectorCellAuthorityConfiguration) || loads != 0 {
		t.Fatalf("mixed-color configure = %v loads=%d; want closed pre-AWS rejection", err, loads)
	}
	if server.connectorRegistrationHandler != nil || server.credentialRecoveryHandler != nil ||
		server.connectorRegistrationTiming != (connectorRegistrationTiming{}) {
		t.Fatalf(
			"invalid reconfiguration retained state: registration=%T recovery=%T timing=%+v",
			server.connectorRegistrationHandler,
			server.credentialRecoveryHandler,
			server.connectorRegistrationTiming,
		)
	}
}

func TestConnectorCellAuthorityRejectsPartialAndCrossGraphDriftBeforeAWS(t *testing.T) {
	t.Parallel()

	registrationKeys := []string{
		ConnectorRegistrationAWSRegionEnvVar,
		ConnectorRegistrationAWSAccountEnvVar,
		ConnectorRegistrationIssueOTPAliasEnvVar,
		ConnectorRegistrationActivateAliasEnvVar,
		ConnectorRegistrationCompleteAliasEnvVar,
		ConnectorRegistrationLambdaTimeoutEnvVar,
		ConnectorRegistrationHandlerBudgetEnvVar,
		ConnectorRegistrationPacketBudgetEnvVar,
		ConnectorRegistrationResponseReserveEnvVar,
		ConnectorRegistrationWriteBudgetEnvVar,
	}
	recoveryKeys := []string{
		ConnectorCredentialRecoveryAWSRegionEnvVar,
		ConnectorCredentialRecoveryAWSAccountEnvVar,
		ConnectorCredentialRecoveryAliasARNEnvVar,
	}
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "registration only", mutate: func(env map[string]string) {
			for _, key := range recoveryKeys {
				delete(env, key)
			}
		}},
		{name: "recovery only", mutate: func(env map[string]string) {
			for _, key := range registrationKeys {
				delete(env, key)
			}
		}},
		{name: "registration partial", mutate: func(env map[string]string) {
			delete(env, ConnectorRegistrationCompleteAliasEnvVar)
		}},
		{name: "recovery partial", mutate: func(env map[string]string) {
			delete(env, ConnectorCredentialRecoveryAliasARNEnvVar)
		}},
		{name: "mixed registration color", mutate: func(env map[string]string) {
			env[ConnectorRegistrationCompleteAliasEnvVar] = strings.TrimSuffix(
				env[ConnectorRegistrationCompleteAliasEnvVar],
				":blue",
			) + ":green"
		}},
		{name: "mixed recovery color", mutate: func(env map[string]string) {
			env[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.TrimSuffix(
				env[ConnectorCredentialRecoveryAliasARNEnvVar],
				":blue",
			) + ":green"
		}},
		{name: "legacy registration active", mutate: func(env map[string]string) {
			env[ConnectorRegistrationActivateAliasEnvVar] = strings.TrimSuffix(
				env[ConnectorRegistrationActivateAliasEnvVar],
				":blue",
			) + ":active"
		}},
		{name: "recovery version", mutate: func(env map[string]string) {
			env[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.TrimSuffix(
				env[ConnectorCredentialRecoveryAliasARNEnvVar],
				":blue",
			) + ":7"
		}},
		{name: "wrong registration operation", mutate: func(env map[string]string) {
			env[ConnectorRegistrationIssueOTPAliasEnvVar] = strings.Replace(
				env[ConnectorRegistrationIssueOTPAliasEnvVar],
				"-ca-iro-",
				"-ca-ar-",
				1,
			)
		}},
		{name: "wrong recovery cell", mutate: func(env map[string]string) {
			env[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.Replace(
				env[ConnectorCredentialRecoveryAliasARNEnvVar],
				"-cell0:",
				"-cell1:",
				1,
			)
		}},
		{name: "declared account mismatch", mutate: func(env map[string]string) {
			env[ConnectorCredentialRecoveryAWSAccountEnvVar] = "999999999999"
			env[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.Replace(
				env[ConnectorCredentialRecoveryAliasARNEnvVar],
				"123456789012",
				"999999999999",
				1,
			)
		}},
		{name: "declared region mismatch", mutate: func(env map[string]string) {
			env[ConnectorCredentialRecoveryAWSRegionEnvVar] = "us-west-2"
			env[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.Replace(
				env[ConnectorCredentialRecoveryAliasARNEnvVar],
				"us-east-2",
				"us-west-2",
				1,
			)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			env := validConnectorCellAuthorityEnvironment()
			test.mutate(env)
			loads := 0
			server := &UdpServer{}
			err := server.configureConnectorCellAuthority(
				context.Background(),
				mapEnvironment(env),
				func(context.Context, string) (aws.Config, error) {
					loads++
					return aws.Config{}, nil
				},
			)
			if err == nil || loads != 0 {
				t.Fatalf("configure = %v loads=%d; want pre-AWS rejection", err, loads)
			}
			if server.connectorRegistrationHandler != nil || server.credentialRecoveryHandler != nil {
				t.Fatalf("partial capability published: registration=%T recovery=%T",
					server.connectorRegistrationHandler, server.credentialRecoveryHandler)
			}
		})
	}
}

func TestConnectorCellAuthorityStaysDarkOnlyWhenBothFamiliesAreAbsent(t *testing.T) {
	t.Parallel()

	server := &UdpServer{}
	loads := 0
	dark := map[string]string{"NHP_ENVIRONMENT": "sandbox", "NHP_CELL_ID": "cell0"}
	err := server.configureConnectorCellAuthority(
		context.Background(),
		mapEnvironment(dark),
		func(context.Context, string) (aws.Config, error) {
			loads++
			return aws.Config{}, nil
		},
	)
	if err != nil || loads != 0 || server.connectorRegistrationHandler != nil ||
		server.credentialRecoveryHandler != nil ||
		server.connectorRegistrationTiming != (connectorRegistrationTiming{}) {
		t.Fatalf(
			"dark configure = %v loads=%d registration=%T recovery=%T timing=%+v",
			err,
			loads,
			server.connectorRegistrationHandler,
			server.credentialRecoveryHandler,
			server.connectorRegistrationTiming,
		)
	}
}

func TestConnectorCellAuthorityDoesNotPublishOnAWSOrConstructorFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		load connectorCellAuthorityAWSLoader
	}{
		{name: "AWS load", load: func(context.Context, string) (aws.Config, error) {
			return aws.Config{}, errors.New("unavailable")
		}},
		{name: "SDK region", load: func(context.Context, string) (aws.Config, error) {
			return aws.Config{Region: "us-west-2"}, nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := &UdpServer{}
			err := server.configureConnectorCellAuthority(
				context.Background(),
				mapEnvironment(validConnectorCellAuthorityEnvironment()),
				test.load,
			)
			if err == nil {
				t.Fatal("configure succeeded")
			}
			if server.connectorRegistrationHandler != nil || server.credentialRecoveryHandler != nil ||
				server.connectorRegistrationTiming != (connectorRegistrationTiming{}) {
				t.Fatalf(
					"failure published state: registration=%T recovery=%T timing=%+v",
					server.connectorRegistrationHandler,
					server.credentialRecoveryHandler,
					server.connectorRegistrationTiming,
				)
			}
		})
	}
}

func TestConnectorCellAuthorityRejectsInvalidStartupDependencies(t *testing.T) {
	t.Parallel()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	canceledDuringLoad, cancelDuringLoad := context.WithCancel(context.Background())
	tests := []struct {
		name string
		ctx  context.Context
		load connectorCellAuthorityAWSLoader
	}{
		{name: "nil context", load: func(context.Context, string) (aws.Config, error) {
			return aws.Config{}, nil
		}},
		{name: "canceled context", ctx: canceled, load: func(context.Context, string) (aws.Config, error) {
			return aws.Config{}, nil
		}},
		{name: "nil loader", ctx: context.Background()},
		{name: "loader exhausts context", ctx: canceledDuringLoad, load: func(_ context.Context, region string) (aws.Config, error) {
			cancelDuringLoad()
			return aws.Config{Region: region}, nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := &UdpServer{}
			err := server.configureConnectorCellAuthority(
				test.ctx,
				mapEnvironment(validConnectorCellAuthorityEnvironment()),
				test.load,
			)
			if !errors.Is(err, errInvalidConnectorCellAuthorityConfiguration) {
				t.Fatalf("configure = %v, want invalid startup dependencies", err)
			}
			if server.connectorRegistrationHandler != nil || server.credentialRecoveryHandler != nil {
				t.Fatalf("startup dependency failure published capabilities: registration=%T recovery=%T",
					server.connectorRegistrationHandler, server.credentialRecoveryHandler)
			}
		})
	}
}

func validConnectorCellAuthorityEnvironment() map[string]string {
	env := validConnectorRegistrationEnvironment()
	for key, value := range validRecoveryEnvironment() {
		env[key] = value
	}
	return env
}
