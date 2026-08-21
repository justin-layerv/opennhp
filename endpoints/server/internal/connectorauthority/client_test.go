package connectorauthority

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type fakeInvokeAPI struct {
	output        *lambda.InvokeOutput
	err           error
	inputs        []*lambda.InvokeInput
	payloadCopies [][]byte
	options       []int
	mutate        func(*lambda.InvokeInput)
}

func (f *fakeInvokeAPI) Invoke(_ context.Context, input *lambda.InvokeInput, options ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	f.inputs = append(f.inputs, input)
	f.payloadCopies = append(f.payloadCopies, bytes.Clone(input.Payload))
	f.options = append(f.options, len(options))
	if f.mutate != nil {
		f.mutate(input)
	}
	return f.output, f.err
}

func TestHubAndCellCapabilitiesAreStructurallySeparated(t *testing.T) {
	t.Parallel()

	hubMethods := exportedMethods(reflect.TypeOf((*HubClient)(nil)))
	registrationMethods := exportedMethods(reflect.TypeOf((*RegistrationCellClient)(nil)))
	recoveryMethods := exportedMethods(reflect.TypeOf((*CredentialRecoveryCellClient)(nil)))
	resourceMethods := exportedMethods(reflect.TypeOf((*ConnectorResourceCellClient)(nil)))

	wantHub := []string{"IssueAssignment", "IssueCredentialRecovery", "RefreshAssignment"}
	if !reflect.DeepEqual(hubMethods, wantHub) {
		t.Fatalf("HubClient methods = %v, want %v", hubMethods, wantHub)
	}
	if want := []string{"ActivateRegistration", "CompleteRegistration", "IssueRegistrationOTP"}; !reflect.DeepEqual(registrationMethods, want) {
		t.Fatalf("RegistrationCellClient methods = %v, want %v", registrationMethods, want)
	}
	if want := []string{"CompleteCredentialRecovery"}; !reflect.DeepEqual(recoveryMethods, want) {
		t.Fatalf("CredentialRecoveryCellClient methods = %v, want %v", recoveryMethods, want)
	}
	if want := []string{"ResolveConnectorResource"}; !reflect.DeepEqual(resourceMethods, want) {
		t.Fatalf("ConnectorResourceCellClient methods = %v, want %v", resourceMethods, want)
	}
}

func TestConnectorResourceCellClientUsesOnlyPinnedAliasAndOneAttempt(t *testing.T) {
	t.Parallel()
	target := validConnectorResourceCellTarget()
	api := &fakeInvokeAPI{output: &lambda.InvokeOutput{StatusCode: http.StatusOK, Payload: []byte(`{"version":1}`)}}
	client := newConnectorResourceCellClient(api, target)
	response, err := client.ResolveConnectorResource(liveContext(t), []byte(`{"version":1}`))
	if err != nil || string(response) != `{"version":1}` {
		t.Fatalf("ResolveConnectorResource = %q, %v", response, err)
	}
	if len(api.inputs) != 1 || api.inputs[0].FunctionName == nil ||
		*api.inputs[0].FunctionName != target.ResolveConnectorResourceAliasARN || len(api.options) != 1 || api.options[0] != 0 {
		t.Fatalf("invocations = %#v options=%v", api.inputs, api.options)
	}
}

func TestCredentialRecoveryCellClientUsesOnlyPinnedAliasAndOneAttempt(t *testing.T) {
	t.Parallel()
	target := validCredentialRecoveryCellTarget()
	api := &fakeInvokeAPI{output: &lambda.InvokeOutput{StatusCode: http.StatusOK, Payload: []byte(`{"version":1}`)}}
	client := newCredentialRecoveryCellClient(api, target)
	response, err := client.CompleteCredentialRecovery(liveContext(t), []byte(`{"version":1}`))
	if err != nil || string(response) != `{"version":1}` {
		t.Fatalf("CompleteCredentialRecovery = %q, %v", response, err)
	}
	if len(api.inputs) != 1 || api.inputs[0].FunctionName == nil ||
		*api.inputs[0].FunctionName != target.CompleteCredentialRecoveryAliasARN || len(api.options) != 1 || api.options[0] != 0 {
		t.Fatalf("invocations = %#v options=%v", api.inputs, api.options)
	}
}

func TestRegistrationCellClientUsesOnlyPinnedAliasesAndOneAttempt(t *testing.T) {
	t.Parallel()
	targets := validRegistrationCellTargets()
	tests := []struct {
		name   string
		target string
		call   func(*RegistrationCellClient, context.Context, []byte) ([]byte, error)
	}{
		{
			name: "issue OTP", target: targets.IssueRegistrationOTPAliasARN,
			call: func(client *RegistrationCellClient, ctx context.Context, payload []byte) ([]byte, error) {
				return client.IssueRegistrationOTP(ctx, payload)
			},
		},
		{
			name: "activate", target: targets.ActivateRegistrationAliasARN,
			call: func(client *RegistrationCellClient, ctx context.Context, payload []byte) ([]byte, error) {
				return client.ActivateRegistration(ctx, payload)
			},
		},
		{
			name: "complete", target: targets.CompleteRegistrationAliasARN,
			call: func(client *RegistrationCellClient, ctx context.Context, payload []byte) ([]byte, error) {
				return client.CompleteRegistration(ctx, payload)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			api := &fakeInvokeAPI{output: &lambda.InvokeOutput{StatusCode: http.StatusOK, Payload: []byte(`{"version":1}`)}}
			client := newRegistrationCellClient(api, targets)
			response, err := test.call(client, liveContext(t), []byte(`{"version":1}`))
			if err != nil || string(response) != `{"version":1}` {
				t.Fatalf("call = %q, %v", response, err)
			}
			if len(api.inputs) != 1 || api.inputs[0].FunctionName == nil ||
				*api.inputs[0].FunctionName != test.target || len(api.options) != 1 || api.options[0] != 0 {
				t.Fatalf("invocations = %#v options=%v want target=%q", api.inputs, api.options, test.target)
			}
		})
	}
}

func exportedMethods(clientType reflect.Type) []string {
	methods := make([]string, 0, clientType.NumMethod())
	for i := 0; i < clientType.NumMethod(); i++ {
		methods = append(methods, clientType.Method(i).Name)
	}
	return methods
}

func TestOperationsUseFixedTargetsAndInvokeContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		target    string
		call      func(context.Context, []byte) ([]byte, error)
	}{
		{
			name:      "issue assignment",
			operation: OperationIssueAssignment,
			target:    aliasARN(hubFunction("ia"), "blue"),
		},
		{
			name:      "refresh assignment",
			operation: OperationRefreshAssignment,
			target:    aliasARN(hubFunction("ra"), "blue"),
		},
		{
			name:      "issue credential recovery",
			operation: OperationIssueCredentialRecovery,
			target:    aliasARN(hubFunction("icr"), "blue"),
		},
		{
			name:      "issue registration OTP",
			operation: OperationIssueRegistrationOTP,
			target:    aliasARN(cellFunction("iro", testCellID), "blue"),
		},
		{
			name:      "activate registration",
			operation: OperationActivateRegistration,
			target:    aliasARN(cellFunction("ar", testCellID), "blue"),
		},
		{
			name:      "complete registration",
			operation: OperationCompleteRegistration,
			target:    aliasARN(cellFunction("cr", testCellID), "blue"),
		},
		{
			name:      "complete credential recovery",
			operation: OperationCompleteCredentialRecovery,
			target:    aliasARN(cellFunction("ccr", testCellID), "blue"),
		},
		{
			name:      "resolve connector resource",
			operation: OperationResolveConnectorResource,
			target:    aliasARN(cellFunction("creso", testCellID), "blue"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			api := &fakeInvokeAPI{output: &lambda.InvokeOutput{
				StatusCode: 200,
				Payload:    []byte(` {"ok":true} `),
			}}
			hub := newHubClient(api, HubTargets{
				IssueAssignmentAliasARN:         tests[0].target,
				RefreshAssignmentAliasARN:       tests[1].target,
				IssueCredentialRecoveryAliasARN: tests[2].target,
			})
			registration := newRegistrationCellClient(api, RegistrationCellTargets{
				IssueRegistrationOTPAliasARN: tests[3].target,
				ActivateRegistrationAliasARN: tests[4].target,
				CompleteRegistrationAliasARN: tests[5].target,
			})
			recovery := newCredentialRecoveryCellClient(api, CredentialRecoveryCellTarget{
				CompleteCredentialRecoveryAliasARN: tests[6].target,
			})
			resource := newConnectorResourceCellClient(api, ConnectorResourceCellTarget{
				ResolveConnectorResourceAliasARN: tests[7].target,
			})
			switch test.operation {
			case OperationIssueAssignment:
				test.call = hub.IssueAssignment
			case OperationRefreshAssignment:
				test.call = hub.RefreshAssignment
			case OperationIssueCredentialRecovery:
				test.call = hub.IssueCredentialRecovery
			case OperationIssueRegistrationOTP:
				test.call = registration.IssueRegistrationOTP
			case OperationActivateRegistration:
				test.call = registration.ActivateRegistration
			case OperationCompleteRegistration:
				test.call = registration.CompleteRegistration
			case OperationCompleteCredentialRecovery:
				test.call = recovery.CompleteCredentialRecovery
			case OperationResolveConnectorResource:
				test.call = resource.ResolveConnectorResource
			default:
				t.Fatalf("unhandled operation %q", test.operation)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			request := []byte(`{"request":true}`)
			got, err := test.call(ctx, request)
			if err != nil {
				t.Fatalf("invoke: %v", err)
			}
			if string(got) != ` {"ok":true} ` {
				t.Fatalf("response changed: %q", got)
			}
			if len(api.inputs) != 1 || len(api.options) != 1 || api.options[0] != 0 {
				t.Fatalf("Invoke calls = %d, option counts = %v", len(api.inputs), api.options)
			}
			input := api.inputs[0]
			if input.FunctionName == nil || *input.FunctionName != test.target {
				t.Fatalf("FunctionName = %v, want %q", input.FunctionName, test.target)
			}
			if input.InvocationType != types.InvocationTypeRequestResponse {
				t.Fatalf("InvocationType = %q", input.InvocationType)
			}
			if input.LogType != types.LogTypeNone {
				t.Fatalf("LogType = %q", input.LogType)
			}
			if input.Qualifier != nil || input.ClientContext != nil {
				t.Fatalf("unexpected qualifier or client context: %#v", input)
			}
			if !bytes.Equal(api.payloadCopies[0], request) {
				t.Fatalf("Payload = %q, want %q", api.payloadCopies[0], request)
			}
			if !zeroBytes(input.Payload) {
				t.Fatalf("SDK request payload retained after invoke: %q", input.Payload)
			}
			if !zeroBytes(api.output.Payload) {
				t.Fatalf("SDK response payload retained after invoke: %q", api.output.Payload)
			}
		})
	}
}

func TestInvokeDefensivelyCopiesPayloads(t *testing.T) {
	t.Parallel()

	request := []byte(`{"secret":"request"}`)
	response := []byte(`{"secret":"response"}`)
	api := &fakeInvokeAPI{
		output: &lambda.InvokeOutput{StatusCode: 200, Payload: response},
		mutate: func(input *lambda.InvokeInput) {
			input.Payload[0] = ' '
		},
	}
	client := newHubClient(api, validHubTargets())

	got, err := client.IssueAssignment(liveContext(t), request)
	if err != nil {
		t.Fatalf("IssueAssignment: %v", err)
	}
	if request[0] != '{' {
		t.Fatal("SDK-side request mutation reached the caller buffer")
	}
	if !zeroBytes(api.inputs[0].Payload) {
		t.Fatalf("SDK request payload retained after invoke: %q", api.inputs[0].Payload)
	}
	if !zeroBytes(response) {
		t.Fatalf("SDK response payload retained after invoke: %q", response)
	}
	response[0] = ' '
	if got[0] != '{' {
		t.Fatal("SDK-side response mutation reached the returned buffer")
	}
}

func TestInvokeRequiresLiveDeadline(t *testing.T) {
	t.Parallel()

	client := newHubClient(&fakeInvokeAPI{}, validHubTargets())
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()

	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "nil", ctx: nil},
		{name: "no deadline", ctx: context.Background()},
		{name: "canceled", ctx: canceled},
		{name: "expired", ctx: expired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.IssueAssignment(test.ctx, []byte(`{}`))
			assertInvokeError(t, err, OperationIssueAssignment, FailureDeadline, 0)
		})
	}
}

func TestInvokeRejectsInvalidRequestBeforeSDK(t *testing.T) {
	t.Parallel()

	api := &fakeInvokeAPI{}
	client := newHubClient(api, validHubTargets())
	tooLarge := append([]byte{'"'}, bytes.Repeat([]byte{'a'}, maxPayloadBytes)...)
	tooLarge = append(tooLarge, '"')

	for _, payload := range [][]byte{nil, {}, []byte(`{"unterminated":`)} {
		_, err := client.IssueAssignment(liveContext(t), payload)
		assertInvokeError(t, err, OperationIssueAssignment, FailureInvalidRequest, 0)
	}
	_, err := client.IssueAssignment(liveContext(t), tooLarge)
	assertInvokeError(t, err, OperationIssueAssignment, FailureRequestTooLarge, 0)
	if len(api.inputs) != 0 {
		t.Fatalf("SDK called %d times for invalid requests", len(api.inputs))
	}
}

func TestInvokeReturnsTypedRedactedFailures(t *testing.T) {
	t.Parallel()

	secret := "must-not-leak"
	tests := []struct {
		name       string
		output     *lambda.InvokeOutput
		err        error
		kind       FailureKind
		statusCode int32
	}{
		{name: "SDK", output: &lambda.InvokeOutput{Payload: []byte(secret)}, err: errors.New("sdk failed with " + secret), kind: FailureSDK},
		{name: "deadline during invoke", err: context.DeadlineExceeded, kind: FailureDeadline},
		{name: "cancel during invoke", err: context.Canceled, kind: FailureDeadline},
		{name: "throttled", err: &smithy.GenericAPIError{Code: "TooManyRequestsException", Message: secret}, kind: FailureThrottled, statusCode: 429},
		{name: "HTTP 429", err: &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusTooManyRequests}}, Err: errors.New(secret)}, kind: FailureThrottled, statusCode: 429},
		{name: "nil output", kind: FailureNilOutput},
		{name: "zero status", output: &lambda.InvokeOutput{Payload: []byte(secret)}, kind: FailureStatus},
		{name: "status", output: &lambda.InvokeOutput{StatusCode: 503, Payload: []byte(secret)}, kind: FailureStatus, statusCode: 503},
		{name: "function error", output: &lambda.InvokeOutput{StatusCode: 200, FunctionError: aws.String("Unhandled"), Payload: []byte(secret)}, kind: FailureFunction},
		{name: "empty function error", output: &lambda.InvokeOutput{StatusCode: 200, FunctionError: aws.String(""), Payload: []byte(`{}`)}, kind: FailureFunction},
		{name: "empty response", output: &lambda.InvokeOutput{StatusCode: 200}, kind: FailureInvalidResponse},
		{name: "invalid JSON", output: &lambda.InvokeOutput{StatusCode: 200, Payload: []byte(secret)}, kind: FailureInvalidResponse},
		{name: "oversize response", output: &lambda.InvokeOutput{StatusCode: 200, Payload: append([]byte{'"'}, append(bytes.Repeat([]byte{'a'}, maxPayloadBytes), '"')...)}, kind: FailureResponseTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			api := &fakeInvokeAPI{output: test.output, err: test.err}
			client := newRegistrationCellClient(api, validRegistrationCellTargets())
			got, err := client.ActivateRegistration(liveContext(t), []byte(`{"request":true}`))
			if got != nil {
				t.Fatalf("response = %q, want nil", got)
			}
			assertInvokeError(t, err, OperationActivateRegistration, test.kind, test.statusCode)
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaked payload or SDK detail: %q", err)
			}
			if test.name == "zero status" && !strings.Contains(err.Error(), "(0)") {
				t.Fatalf("zero status omitted from error: %q", err)
			}
			if len(api.inputs) != 1 || !zeroBytes(api.inputs[0].Payload) {
				t.Fatalf("SDK request payload retained after failure: %#v", api.inputs)
			}
			if test.output != nil && !zeroBytes(test.output.Payload) {
				t.Fatalf("SDK response payload retained after failure: %q", test.output.Payload)
			}
		})
	}
}

func zeroBytes(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func liveContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func assertInvokeError(t *testing.T, err error, operation Operation, kind FailureKind, statusCode int32) {
	t.Helper()
	var invokeErr *InvokeError
	if !errors.As(err, &invokeErr) {
		t.Fatalf("error = %T %v, want *InvokeError", err, err)
	}
	if invokeErr.Operation != operation || invokeErr.Kind != kind || invokeErr.StatusCode != statusCode {
		t.Fatalf("InvokeError = %#v, want operation=%q kind=%q status=%d", invokeErr, operation, kind, statusCode)
	}
}
