// Package connectorauthority provides the private Lambda invocation boundary
// used by Connector hub and cell workers.
//
// It deliberately treats authority request and response bodies as opaque JSON.
// Application decoding and policy belong to the operation-specific plugins,
// while this package owns transport invariants and role separation.
// Calls are never retried internally: callers own bounded retry/backoff and
// operation idempotency within the surrounding NHP transaction policy.
// Every successful authority operation must return a non-empty JSON body.
package connectorauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Keep internal authority requests and responses small even though Lambda's
// synchronous transport permits much larger bodies. All current envelopes are
// bounded control-plane metadata with no blob fields, and the same fixed 64 KiB
// ceiling applies in both directions so configuration cannot weaken the boundary.
const maxPayloadBytes = 64 << 10

type invokeAPI interface {
	Invoke(context.Context, *lambda.InvokeInput, ...func(*lambda.Options)) (*lambda.InvokeOutput, error)
}

type invoker struct {
	api invokeAPI
}

// HubClient exposes only environment-global hub authority capabilities. Every
// method requires a live caller deadline and a non-empty, valid JSON body no
// larger than 64 KiB. Payloads are consumed synchronously and never retained;
// successful callers own the returned mutable buffer exclusively.
type HubClient struct {
	invoker
	issueAssignment         string
	refreshAssignment       string
	issueCredentialRecovery string
}

// RegistrationCellClient exposes only the three assigned-cell enrollment
// operations. Its closed method set makes it impossible for the registration
// composition to invoke credential recovery, even if a caller is later
// miswired.
type RegistrationCellClient struct {
	invoker
	issueRegistrationOTP string
	activateRegistration string
	completeRegistration string
}

// CredentialRecoveryCellClient exposes only the completion operation needed by
// the direct assigned-cell recovery path. It deliberately cannot be widened by
// passing a different operation at call time.
type CredentialRecoveryCellClient struct {
	invoker
	completeCredentialRecovery string
}

// ConnectorResourceCellClient exposes only the post-registration resource
// resolution operation. The target is fixed at construction; callers cannot
// select another Authority operation or alias.
type ConnectorResourceCellClient struct {
	invoker
	resolveConnectorResource string
}

// IssueAssignment invokes the configured IssueAssignment alias synchronously.
func (c *HubClient) IssueAssignment(ctx context.Context, payload []byte) ([]byte, error) {
	return c.invoke(ctx, OperationIssueAssignment, c.issueAssignment, payload)
}

// RefreshAssignment invokes the configured RefreshAssignment alias synchronously.
func (c *HubClient) RefreshAssignment(ctx context.Context, payload []byte) ([]byte, error) {
	return c.invoke(ctx, OperationRefreshAssignment, c.refreshAssignment, payload)
}

// IssueCredentialRecovery invokes the configured environment-global recovery alias synchronously.
func (c *HubClient) IssueCredentialRecovery(ctx context.Context, payload []byte) ([]byte, error) {
	return c.invoke(ctx, OperationIssueCredentialRecovery, c.issueCredentialRecovery, payload)
}

// IssueRegistrationOTP invokes the configured cell-scoped IssueRegistrationOTP alias synchronously.
func (c *RegistrationCellClient) IssueRegistrationOTP(ctx context.Context, payload []byte) ([]byte, error) {
	return c.invoke(ctx, OperationIssueRegistrationOTP, c.issueRegistrationOTP, payload)
}

// ActivateRegistration invokes the configured cell-scoped ActivateRegistration alias synchronously.
func (c *RegistrationCellClient) ActivateRegistration(ctx context.Context, payload []byte) ([]byte, error) {
	return c.invoke(ctx, OperationActivateRegistration, c.activateRegistration, payload)
}

// CompleteRegistration invokes the configured cell-scoped CompleteRegistration alias synchronously.
func (c *RegistrationCellClient) CompleteRegistration(ctx context.Context, payload []byte) ([]byte, error) {
	return c.invoke(ctx, OperationCompleteRegistration, c.completeRegistration, payload)
}

// CompleteCredentialRecovery invokes the one configured assigned-cell recovery alias synchronously.
func (c *CredentialRecoveryCellClient) CompleteCredentialRecovery(ctx context.Context, payload []byte) ([]byte, error) {
	return c.invoke(ctx, OperationCompleteCredentialRecovery, c.completeCredentialRecovery, payload)
}

func (c *ConnectorResourceCellClient) ResolveConnectorResource(ctx context.Context, payload []byte) ([]byte, error) {
	return c.invoke(ctx, OperationResolveConnectorResource, c.resolveConnectorResource, payload)
}

func (c *invoker) invoke(ctx context.Context, operation Operation, target string, payload []byte) ([]byte, error) {
	if ctx == nil {
		return nil, newInvokeError(operation, FailureDeadline, 0)
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return nil, newInvokeError(operation, FailureDeadline, 0)
	}
	if len(payload) > maxPayloadBytes {
		return nil, newInvokeError(operation, FailureRequestTooLarge, 0)
	}
	// Empty and malformed bodies intentionally share one transport-shape failure;
	// operation-specific decoding owns finer application diagnostics.
	if len(payload) == 0 || !json.Valid(payload) {
		return nil, newInvokeError(operation, FailureInvalidRequest, 0)
	}

	requestPayload := bytes.Clone(payload)
	defer clear(requestPayload)
	output, err := c.api.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   aws.String(target),
		InvocationType: types.InvocationTypeRequestResponse,
		LogType:        types.LogTypeNone,
		Payload:        requestPayload,
	})
	if output != nil {
		// The AWS SDK transfers its response buffer to this synchronous caller.
		// Wipe it on transport, status, function-error, shape-error, and success
		// paths; only a final validated clone crosses the package boundary.
		defer clear(output.Payload)
	}
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, newInvokeError(operation, FailureDeadline, 0)
		}
		if isThrottled(err) {
			return nil, newInvokeError(operation, FailureThrottled, http.StatusTooManyRequests)
		}
		return nil, newInvokeError(operation, FailureSDK, 0)
	}
	if output == nil {
		return nil, newInvokeError(operation, FailureNilOutput, 0)
	}
	if output.StatusCode != http.StatusOK {
		return nil, newInvokeError(operation, FailureStatus, output.StatusCode)
	}
	if output.FunctionError != nil {
		return nil, newInvokeError(operation, FailureFunction, 0)
	}
	if len(output.Payload) > maxPayloadBytes {
		return nil, newInvokeError(operation, FailureResponseTooLarge, 0)
	}
	if len(output.Payload) == 0 || !json.Valid(output.Payload) {
		return nil, newInvokeError(operation, FailureInvalidResponse, 0)
	}

	return bytes.Clone(output.Payload), nil
}

func isThrottled(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "TooManyRequestsException" {
		return true
	}

	var responseErr *smithyhttp.ResponseError
	return errors.As(err, &responseErr) && responseErr.HTTPStatusCode() == http.StatusTooManyRequests
}
