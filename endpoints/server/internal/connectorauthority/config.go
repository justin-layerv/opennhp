package connectorauthority

import (
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

var (
	accountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)
	cellIDPattern    = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	regionPattern    = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]$`)
)

const (
	maxCellIDLength = 32
	maxRegionLength = 32
)

type authorityFunctionSpec struct {
	operationSuffix string
	cellScoped      bool
}

// authorityFunctionInventory is the complete eight-operation Authority graph.
// Every consumer selects a least-privilege subset from this one closed map;
// adding a public operation without an explicit physical name and scope is a
// test failure rather than an ARN accepted by a generic parser.
var authorityFunctionInventory = map[Operation]authorityFunctionSpec{
	OperationIssueAssignment:            {operationSuffix: "ia"},
	OperationRefreshAssignment:          {operationSuffix: "ra"},
	OperationIssueCredentialRecovery:    {operationSuffix: "icr"},
	OperationIssueRegistrationOTP:       {operationSuffix: "iro", cellScoped: true},
	OperationActivateRegistration:       {operationSuffix: "ar", cellScoped: true},
	OperationCompleteRegistration:       {operationSuffix: "cr", cellScoped: true},
	OperationCompleteCredentialRecovery: {operationSuffix: "ccr", cellScoped: true},
	OperationResolveConnectorResource:   {operationSuffix: "creso", cellScoped: true},
}

// Boundary pins Hub-facing authority targets to one deployment environment,
// AWS account, and region. The environment is part of each exact physical
// function name, not an untrusted suffix inferred from an ARN.
type Boundary struct {
	Environment string
	AccountID   string
	Region      string
}

// CellBoundary adds the provisioned cell identity used by the five cell-scoped
// physical function names. A separate type prevents Hub construction from
// accidentally depending on a cell identifier.
type CellBoundary struct {
	Boundary
	CellID string
}

// HubTargets contains the three exact blue-or-green alias ARNs available to a
// Hub worker. All three must select the same color.
type HubTargets struct {
	IssueAssignmentAliasARN         string
	RefreshAssignmentAliasARN       string
	IssueCredentialRecoveryAliasARN string
}

// CellTargets contains the complete five-alias graph for one cell. It is used
// as the atomic startup validation surface even though the runtime clients stay
// split into three-method registration, one-method recovery, and one-method
// connector-resource capabilities. All five targets must select the same color.
type CellTargets struct {
	IssueRegistrationOTPAliasARN       string
	ActivateRegistrationAliasARN       string
	CompleteRegistrationAliasARN       string
	CompleteCredentialRecoveryAliasARN string
	ResolveConnectorResourceAliasARN   string
}

// RegistrationCellTargets is the exact three-alias capability set available
// to the assigned-cell registration composition.
type RegistrationCellTargets struct {
	IssueRegistrationOTPAliasARN string
	ActivateRegistrationAliasARN string
	CompleteRegistrationAliasARN string
}

// CredentialRecoveryCellTarget is the one alias available to the dedicated
// assigned-cell recovery composition. Keeping it separate from CellTargets
// makes least privilege structural: this client cannot invoke OTP or either
// registration operation even if the containing process is miswired.
type CredentialRecoveryCellTarget struct {
	CompleteCredentialRecoveryAliasARN string
}

type ConnectorResourceCellTarget struct {
	ResolveConnectorResourceAliasARN string
}

// NewHubClient constructs a hub-only client with a single-attempt Lambda SDK client.
func NewHubClient(cfg aws.Config, boundary Boundary, targets HubTargets) (*HubClient, error) {
	if err := ValidateHubTargets(boundary, targets); err != nil {
		return nil, err
	}
	if err := validateSDKRegion(cfg, boundary); err != nil {
		return nil, err
	}

	return newHubClient(newLambdaClient(cfg), targets), nil
}

// ValidateHubTargets applies the same exact physical-name, account, region, and
// common blue-or-green alias contract as NewHubClient without constructing an
// AWS client. Process owners use it before loading ambient AWS configuration.
func ValidateHubTargets(boundary Boundary, targets HubTargets) error {
	if err := validateBoundaryValues(boundary); err != nil {
		return err
	}
	return validateTargets(boundary, "",
		targetSpec{"issue_assignment", targets.IssueAssignmentAliasARN, OperationIssueAssignment},
		targetSpec{"refresh_assignment", targets.RefreshAssignmentAliasARN, OperationRefreshAssignment},
		targetSpec{"issue_credential_recovery", targets.IssueCredentialRecoveryAliasARN, OperationIssueCredentialRecovery},
	)
}

// ValidateCellTargets validates one complete cell operation graph before an
// ambient AWS client is loaded. Partial graphs, cross-cell names, wrong
// operations, and mixed deployment colors all fail closed.
func ValidateCellTargets(boundary CellBoundary, targets CellTargets) error {
	if err := validateCellBoundaryValues(boundary); err != nil {
		return err
	}
	return validateTargets(boundary.Boundary, boundary.CellID,
		targetSpec{"issue_registration_otp", targets.IssueRegistrationOTPAliasARN, OperationIssueRegistrationOTP},
		targetSpec{"activate_registration", targets.ActivateRegistrationAliasARN, OperationActivateRegistration},
		targetSpec{"complete_registration", targets.CompleteRegistrationAliasARN, OperationCompleteRegistration},
		targetSpec{"complete_credential_recovery", targets.CompleteCredentialRecoveryAliasARN, OperationCompleteCredentialRecovery},
		targetSpec{"resolve_connector_resource", targets.ResolveConnectorResourceAliasARN, OperationResolveConnectorResource},
	)
}

// NewRegistrationCellClient constructs a registration-only cell client with a
// single-attempt Lambda SDK client.
func NewRegistrationCellClient(
	cfg aws.Config,
	boundary CellBoundary,
	targets RegistrationCellTargets,
) (*RegistrationCellClient, error) {
	if err := ValidateRegistrationCellTargets(boundary, targets); err != nil {
		return nil, err
	}
	if err := validateSDKRegion(cfg, boundary.Boundary); err != nil {
		return nil, err
	}
	return newRegistrationCellClient(newLambdaClient(cfg), targets), nil
}

// ValidateRegistrationCellTargets validates the registration-only capability
// subset. Process startup must additionally validate the complete CellTargets
// graph so recovery and registration cannot select different colors.
func ValidateRegistrationCellTargets(boundary CellBoundary, targets RegistrationCellTargets) error {
	if err := validateCellBoundaryValues(boundary); err != nil {
		return err
	}
	return validateTargets(boundary.Boundary, boundary.CellID,
		targetSpec{"issue_registration_otp", targets.IssueRegistrationOTPAliasARN, OperationIssueRegistrationOTP},
		targetSpec{"activate_registration", targets.ActivateRegistrationAliasARN, OperationActivateRegistration},
		targetSpec{"complete_registration", targets.CompleteRegistrationAliasARN, OperationCompleteRegistration},
	)
}

// NewCredentialRecoveryCellClient constructs the completion-only assigned-cell
// client with a single-attempt Lambda SDK client.
func NewCredentialRecoveryCellClient(
	cfg aws.Config,
	boundary CellBoundary,
	target CredentialRecoveryCellTarget,
) (*CredentialRecoveryCellClient, error) {
	if err := ValidateCredentialRecoveryCellTarget(boundary, target); err != nil {
		return nil, err
	}
	if err := validateSDKRegion(cfg, boundary.Boundary); err != nil {
		return nil, err
	}
	return newCredentialRecoveryCellClient(newLambdaClient(cfg), target), nil
}

// ValidateCredentialRecoveryCellTarget validates the one fully qualified
// blue-or-green alias before ambient AWS configuration is loaded or a listener
// binds. Process startup also validates it as part of the complete cell graph.
func ValidateCredentialRecoveryCellTarget(boundary CellBoundary, target CredentialRecoveryCellTarget) error {
	if err := validateCellBoundaryValues(boundary); err != nil {
		return err
	}
	return validateTargets(boundary.Boundary, boundary.CellID,
		targetSpec{"complete_credential_recovery", target.CompleteCredentialRecoveryAliasARN, OperationCompleteCredentialRecovery},
	)
}

func NewConnectorResourceCellClient(
	cfg aws.Config,
	boundary CellBoundary,
	target ConnectorResourceCellTarget,
) (*ConnectorResourceCellClient, error) {
	if err := ValidateConnectorResourceCellTarget(boundary, target); err != nil {
		return nil, err
	}
	if err := validateSDKRegion(cfg, boundary.Boundary); err != nil {
		return nil, err
	}
	return newConnectorResourceCellClient(newLambdaClient(cfg), target), nil
}

func ValidateConnectorResourceCellTarget(boundary CellBoundary, target ConnectorResourceCellTarget) error {
	if err := validateCellBoundaryValues(boundary); err != nil {
		return err
	}
	return validateTargets(boundary.Boundary, boundary.CellID,
		targetSpec{"resolve_connector_resource", target.ResolveConnectorResourceAliasARN, OperationResolveConnectorResource},
	)
}

func newHubClient(api invokeAPI, targets HubTargets) *HubClient {
	return &HubClient{
		invoker:                 invoker{api: api},
		issueAssignment:         targets.IssueAssignmentAliasARN,
		refreshAssignment:       targets.RefreshAssignmentAliasARN,
		issueCredentialRecovery: targets.IssueCredentialRecoveryAliasARN,
	}
}

func newRegistrationCellClient(api invokeAPI, targets RegistrationCellTargets) *RegistrationCellClient {
	return &RegistrationCellClient{
		invoker:              invoker{api: api},
		issueRegistrationOTP: targets.IssueRegistrationOTPAliasARN,
		activateRegistration: targets.ActivateRegistrationAliasARN,
		completeRegistration: targets.CompleteRegistrationAliasARN,
	}
}

func newCredentialRecoveryCellClient(api invokeAPI, target CredentialRecoveryCellTarget) *CredentialRecoveryCellClient {
	return &CredentialRecoveryCellClient{
		invoker:                    invoker{api: api},
		completeCredentialRecovery: target.CompleteCredentialRecoveryAliasARN,
	}
}

func newConnectorResourceCellClient(api invokeAPI, target ConnectorResourceCellTarget) *ConnectorResourceCellClient {
	return &ConnectorResourceCellClient{
		invoker: invoker{api: api}, resolveConnectorResource: target.ResolveConnectorResourceAliasARN,
	}
}

func newLambdaClient(cfg aws.Config) *lambda.Client {
	// Endpoint and middleware overrides are intentionally discarded. Private
	// connectivity is supplied by normal Lambda DNS through a VPC interface
	// endpoint, never by a caller-controlled URL. Credentials and HTTP transport
	// remain trusted inputs from the containing server process by design. Dropping
	// APIOptions also drops inherited observability middleware; this boundary
	// favors a fixed SDK stack, and callers instrument around the typed operation.
	cfg.EndpointResolver = nil
	cfg.EndpointResolverWithOptions = nil
	cfg.BaseEndpoint = nil
	cfg.APIOptions = nil
	cfg.ServiceOptions = nil
	cfg.ConfigSources = nil
	cfg.Interceptors = smithyhttp.InterceptorRegistry{}
	cfg.AuthSchemePreference = nil
	// Recovery grants and candidate device keys are carried in Lambda payloads.
	// Ambient SDK body logging must never cross this boundary, even when the
	// containing process enables it globally for other AWS clients.
	cfg.ClientLogMode = 0
	cfg.RetryMaxAttempts = 1
	cfg.Retryer = func() aws.Retryer { return aws.NopRetryer{} }

	return lambda.NewFromConfig(cfg, func(options *lambda.Options) {
		options.BaseEndpoint = nil
		options.EndpointResolver = nil
		options.EndpointResolverV2 = lambda.NewDefaultEndpointResolverV2()
		options.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateDisabled
		options.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateDisabled
		options.Interceptors = smithyhttp.InterceptorRegistry{}
		options.AuthSchemePreference = nil
		options.ClientLogMode = 0
		options.RetryMaxAttempts = 1
		options.Retryer = aws.NopRetryer{}
	})
}

func validateSDKRegion(cfg aws.Config, boundary Boundary) error {
	if cfg.Region != boundary.Region {
		return &ConfigError{Field: "sdk_region"}
	}
	return nil
}

func validateBoundaryValues(boundary Boundary) error {
	if boundary.Environment != "sandbox" && boundary.Environment != "prod" {
		return &ConfigError{Field: "environment"}
	}
	if !accountIDPattern.MatchString(boundary.AccountID) {
		return &ConfigError{Field: "account_id"}
	}
	// Lambda's default resolver incorporates Region into an HTTPS hostname.
	// Keep it to the bounded canonical AWS region-label shape enforced by
	// terraform/variables.tf before any SDK
	// client exists; dots, slashes, URL syntax, and empty label components must
	// never turn operator configuration into a different DNS authority.
	if len(boundary.Region) == 0 || len(boundary.Region) > maxRegionLength ||
		!regionPattern.MatchString(boundary.Region) {
		return &ConfigError{Field: "region"}
	}
	return nil
}

func validateCellBoundaryValues(boundary CellBoundary) error {
	if err := validateBoundaryValues(boundary.Boundary); err != nil {
		return err
	}
	if len(boundary.CellID) == 0 || len(boundary.CellID) > maxCellIDLength ||
		!cellIDPattern.MatchString(boundary.CellID) {
		return &ConfigError{Field: "cell_id"}
	}
	return nil
}

type targetSpec struct {
	field     string
	value     string
	operation Operation
}

func validateTargets(boundary Boundary, cellID string, targets ...targetSpec) error {
	selectedColor := ""
	for _, target := range targets {
		expectedFunction, found := authorityFunctionName(boundary, cellID, target.operation)
		if !found {
			return &ConfigError{Field: target.field}
		}
		color, valid := parseAliasARN(target.value, boundary, expectedFunction)
		if !valid {
			return &ConfigError{Field: target.field}
		}
		if selectedColor == "" {
			selectedColor = color
		} else if color != selectedColor {
			return &ConfigError{Field: target.field}
		}
	}
	return nil
}

func parseAliasARN(value string, boundary Boundary, expectedFunction string) (string, bool) {
	target, err := arn.Parse(value)
	if err != nil || target.Partition != "aws" || target.Service != "lambda" ||
		target.Region != boundary.Region || target.AccountID != boundary.AccountID {
		return "", false
	}

	parts := strings.Split(target.Resource, ":")
	// AWS alias qualifiers are case-sensitive. Only the IaC-owned closed pair is
	// accepted; callers never invoke an unqualified function, version, $LATEST,
	// legacy active alias, or independently selected per-operation color.
	if len(parts) != 3 || parts[0] != "function" ||
		parts[1] != expectedFunction || (parts[2] != "blue" && parts[2] != "green") {
		return "", false
	}
	return parts[2], true
}

func authorityFunctionName(boundary Boundary, cellID string, operation Operation) (string, bool) {
	spec, found := authorityFunctionInventory[operation]
	if !found || spec.cellScoped != (cellID != "") {
		return "", false
	}
	name := "layerv-nhp-" + boundary.Environment + "-ca-" + spec.operationSuffix
	if spec.cellScoped {
		name += "-" + cellID
	}
	return name, true
}
