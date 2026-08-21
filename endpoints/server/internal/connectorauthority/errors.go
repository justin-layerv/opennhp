package connectorauthority

import (
	"fmt"

	conformance "github.com/layervai/qurl-conformance"
)

// Operation identifies one fixed authority capability. It is safe for error reporting.
type Operation string

const (
	OperationIssueAssignment            Operation = "issue_assignment"
	OperationRefreshAssignment          Operation = "refresh_assignment"
	OperationIssueCredentialRecovery    Operation = "issue_credential_recovery"
	OperationIssueRegistrationOTP       Operation = "issue_registration_otp"
	OperationActivateRegistration       Operation = "activate_registration"
	OperationCompleteRegistration       Operation = "complete_registration"
	OperationCompleteCredentialRecovery Operation = "complete_credential_recovery"
	OperationResolveConnectorResource   Operation = conformance.ConnectorResourceLSTV1AuthorityOperation
)

// FailureKind is a redacted, programmatic invocation failure classification.
type FailureKind string

const (
	FailureDeadline         FailureKind = "deadline_required"
	FailureInvalidRequest   FailureKind = "invalid_request"
	FailureRequestTooLarge  FailureKind = "request_too_large"
	FailureSDK              FailureKind = "sdk"
	FailureThrottled        FailureKind = "throttled"
	FailureNilOutput        FailureKind = "nil_output"
	FailureStatus           FailureKind = "status"
	FailureFunction         FailureKind = "function"
	FailureInvalidResponse  FailureKind = "invalid_response"
	FailureResponseTooLarge FailureKind = "response_too_large"
)

// InvokeError reports a typed authority failure without retaining SDK errors,
// function-error payloads, alias ARNs, or request/response bodies.
type InvokeError struct {
	Operation  Operation
	Kind       FailureKind
	StatusCode int32
}

func newInvokeError(operation Operation, kind FailureKind, statusCode int32) *InvokeError {
	return &InvokeError{Operation: operation, Kind: kind, StatusCode: statusCode}
}

func (e *InvokeError) Error() string {
	if e.Kind == FailureStatus || e.StatusCode != 0 {
		return fmt.Sprintf("connector authority %s invocation failed: %s (%d)", e.Operation, e.Kind, e.StatusCode)
	}
	return fmt.Sprintf("connector authority %s invocation failed: %s", e.Operation, e.Kind)
}

// ConfigError reports only the invalid configuration field, never its value.
type ConfigError struct {
	Field string
}

func (e *ConfigError) Error() string {
	return "invalid connector authority configuration: " + e.Field
}
