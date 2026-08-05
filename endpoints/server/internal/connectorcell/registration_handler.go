package connectorcell

import (
	"context"

	conformance "github.com/layervai/qurl-conformance"
)

// RegistrationAuthority is the narrow assigned-cell capability set. Each
// method must synchronously consume payload without retaining or aliasing it
// and return an exclusively owned mutable response buffer. The handler clears
// both buffers before returning.
type RegistrationAuthority interface {
	IssueRegistrationOTP(context.Context, []byte) ([]byte, error)
	ActivateRegistration(context.Context, []byte) ([]byte, error)
	CompleteRegistration(context.Context, []byte) ([]byte, error)
}

// RegistrationAction tells the future NHP integration exactly what application
// framing, if any, is permitted for this outcome.
type RegistrationAction string

const (
	RegistrationActionNoApplicationReply RegistrationAction = conformance.ConnectorAuthorityNHPActionNoReply
	RegistrationActionEmitRAK            RegistrationAction = conformance.ConnectorAuthorityNHPActionEmitRAK
	RegistrationActionEmitLRT            RegistrationAction = conformance.ConnectorAuthorityNHPActionEmitLRT
	RegistrationActionDropNoReply        RegistrationAction = conformance.ConnectorAuthorityNHPActionDropNoReply
)

// RegistrationRecoveryAction is deliberately narrow: only activation transport
// ambiguity permits a bounded exact retry of the pending NHP_REG.
type RegistrationRecoveryAction string

const (
	RegistrationRecoveryNone         RegistrationRecoveryAction = conformance.ConnectorAuthorityRecoveryNone
	RegistrationRecoveryPendingExact RegistrationRecoveryAction = conformance.ConnectorAuthorityRecoveryPendingExact
)

// RegistrationResult contains only public wire bytes and secret-free outcome
// metadata. A nil Body is required for both no-reply actions.
type RegistrationResult struct {
	Body             []byte
	Action           RegistrationAction
	RecoveryAction   RegistrationRecoveryAction
	Classification   Classification
	RequestRejection RequestRejection
}

// RegistrationHandler maps assigned-cell OTP, REG, and completion messages to
// exactly one separately permissioned Authority call. It performs no retries.
type RegistrationHandler struct{ authority RegistrationAuthority }

func NewRegistrationHandler(authority RegistrationAuthority) (*RegistrationHandler, error) {
	if authority == nil {
		return nil, ErrInvalidHandlerConfiguration
	}
	return &RegistrationHandler{authority: authority}, nil
}

// HandleOTP dispatches the account-only OTP operation. NHP_OTP is deliberately
// fire-and-forget, so every outcome has no application reply.
func (h *RegistrationHandler) HandleOTP(ctx context.Context, raw, authenticatedPeer []byte, observedSource string) RegistrationResult {
	if !liveDeadline(ctx) {
		return registrationNoReply(ClassificationDeadlineRejected)
	}
	request, rejection, err := DecodeOTPRequest(raw, authenticatedPeer, observedSource)
	if err != nil {
		return registrationRejected(RegistrationActionNoApplicationReply, nil, rejection)
	}
	payload, err := encodeOTPAuthorityRequest(request)
	if err != nil {
		return registrationRejected(RegistrationActionNoApplicationReply, nil, RequestRejectionSemantic)
	}
	defer clear(payload)
	if !liveDeadline(ctx) {
		return registrationNoReply(ClassificationDeadlineRejected)
	}
	response, err := h.authority.IssueRegistrationOTP(ctx, payload)
	defer clear(response)
	if err != nil || ctx.Err() != nil {
		return registrationNoReply(ClassificationAuthorityInvocationFailed)
	}
	body, action, outcome, err := decodeRegistrationAuthorityResponse(registrationAuthorityOTP, response)
	if err != nil {
		return registrationNoReply(ClassificationAuthorityResponseRejected)
	}
	return registrationAuthorityResult(body, action, outcome)
}

// HandleRegistration activates a registration ticket. Authority unavailability
// and ambiguous transport failures are dropped so the caller can perform only
// the contract's bounded exact pending-activation retry.
func (h *RegistrationHandler) HandleRegistration(ctx context.Context, raw, authenticatedPeer []byte) RegistrationResult {
	if !liveDeadline(ctx) {
		return registrationDrop(ClassificationDeadlineRejected)
	}
	request, rejection, err := DecodeRegistrationRequest(raw, authenticatedPeer)
	if err != nil {
		return registrationRejected(RegistrationActionEmitRAK, []byte(registrationInvalidRequestRAKJSON), rejection)
	}
	payload, err := encodeActivationAuthorityRequest(request)
	if err != nil {
		return registrationRejected(RegistrationActionEmitRAK, []byte(registrationInvalidRequestRAKJSON), RequestRejectionSemantic)
	}
	defer clear(payload)
	if !liveDeadline(ctx) {
		return registrationDrop(ClassificationDeadlineRejected)
	}
	response, err := h.authority.ActivateRegistration(ctx, payload)
	defer clear(response)
	if err != nil || ctx.Err() != nil {
		return registrationDrop(ClassificationAuthorityInvocationFailed)
	}
	body, action, outcome, err := decodeRegistrationAuthorityResponse(registrationAuthorityActivate, response)
	if err != nil {
		return registrationDrop(ClassificationAuthorityResponseRejected)
	}
	return registrationAuthorityResult(body, action, outcome)
}

// HandleRegistrationCompletion records the final device credential candidate.
// Private transport and producer failures become the frozen retryable LRT.
func (h *RegistrationHandler) HandleRegistrationCompletion(ctx context.Context, raw, authenticatedPeer []byte) RegistrationResult {
	if !liveDeadline(ctx) {
		return registrationCompletionUnavailable(ClassificationDeadlineRejected)
	}
	request, rejection, err := DecodeRegistrationCompletionRequest(raw, authenticatedPeer)
	if err != nil {
		return registrationRejected(RegistrationActionEmitLRT, []byte(registrationCompletionInvalidJSON), rejection)
	}
	payload, err := encodeRegistrationCompletionAuthorityRequest(request)
	if err != nil {
		return registrationRejected(RegistrationActionEmitLRT, []byte(registrationCompletionInvalidJSON), RequestRejectionSemantic)
	}
	defer clear(payload)
	if !liveDeadline(ctx) {
		return registrationCompletionUnavailable(ClassificationDeadlineRejected)
	}
	response, err := h.authority.CompleteRegistration(ctx, payload)
	defer clear(response)
	if err != nil || ctx.Err() != nil {
		return registrationCompletionUnavailable(ClassificationAuthorityInvocationFailed)
	}
	body, action, outcome, err := decodeRegistrationAuthorityResponse(registrationAuthorityComplete, response)
	if err != nil {
		return registrationCompletionUnavailable(ClassificationAuthorityResponseRejected)
	}
	return registrationAuthorityResult(body, action, outcome)
}

func registrationAuthorityResult(body []byte, action RegistrationAction, outcome registrationAuthorityOutcome) RegistrationResult {
	classification := ClassificationSuccess
	if outcome == registrationAuthoritySemanticError {
		classification = ClassificationAuthoritySemanticError
	}
	recovery := RegistrationRecoveryNone
	if action == RegistrationActionDropNoReply {
		recovery = RegistrationRecoveryPendingExact
	}
	return RegistrationResult{Body: body, Action: action, RecoveryAction: recovery, Classification: classification}
}

func registrationRejected(action RegistrationAction, body []byte, rejection RequestRejection) RegistrationResult {
	return RegistrationResult{
		Body: body, Action: action, RecoveryAction: RegistrationRecoveryNone,
		Classification: ClassificationRequestRejected, RequestRejection: rejection,
	}
}

func registrationNoReply(classification Classification) RegistrationResult {
	return RegistrationResult{
		Action: RegistrationActionNoApplicationReply, RecoveryAction: RegistrationRecoveryNone,
		Classification: classification,
	}
}

func registrationDrop(classification Classification) RegistrationResult {
	return RegistrationResult{
		Action: RegistrationActionDropNoReply, RecoveryAction: RegistrationRecoveryPendingExact,
		Classification: classification,
	}
}

func registrationCompletionUnavailable(classification Classification) RegistrationResult {
	return RegistrationResult{
		Body: []byte(registrationCompletionRetryJSON), Action: RegistrationActionEmitLRT,
		RecoveryAction: RegistrationRecoveryNone, Classification: classification,
	}
}

// RegistrationDisabledRAK is the frozen authenticated activation denial for a
// claimed Connector NHP_REG intent that reaches a cell with NO live Authority
// handler (the capability is dark, or the instance predates its activation
// rollout). It carries no Authority state — the caller emits it INSTEAD of
// dispatching to the Authority — so the server can answer a genuine
// assigned-cell registration with a proper aspId="agent" RAK denial rather than
// falling through to the generic qURL knock handler (wrong aspId) or dropping
// the datagram (client stall). RecoveryAction is None: this is a terminal RAK
// the client parses, not a bounded pending-exact retry. The aspId="agent"
// guarantee stays sourced in this package, the only place that pins it.
//
// Classification here (and on RegistrationCompletionUnavailableLRT) is a benign
// placeholder that is intentionally NOT consumed on the dark path: the server
// records MetricConnectorRegistrationHandlerAbsent directly and gates the
// Authority-outcome metric on authorityRan, so this value never reaches
// recordConnectorRegistrationOutcome. It is a placeholder rather than a
// fabricated Authority outcome; a future caller that records it unconditionally
// must first give the dark path its own classification.
func RegistrationDisabledRAK() RegistrationResult {
	return RegistrationResult{
		Body: []byte(registrationDisabledRAKJSON), Action: RegistrationActionEmitRAK,
		RecoveryAction: RegistrationRecoveryNone, Classification: ClassificationInternalFailure,
	}
}

// RegistrationCompletionUnavailableLRT is the completion-leg (NHP_LST → LRT)
// counterpart to RegistrationDisabledRAK: the frozen retryable "completion
// temporarily unavailable" LRT emitted when a post-RAK completion reaches a
// dark cell. It reuses the existing completion-unavailable body so a completion
// that lands on a different (dark) instance than its activation is answered
// visibly instead of leaking to the generic ListService dispatch.
func RegistrationCompletionUnavailableLRT() RegistrationResult {
	return RegistrationResult{
		Body: []byte(registrationCompletionRetryJSON), Action: RegistrationActionEmitLRT,
		RecoveryAction: RegistrationRecoveryNone, Classification: ClassificationInternalFailure,
	}
}
