package connectorhub

import (
	"context"
	"errors"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

var ErrInvalidHandlerConfiguration = errors.New("connector hub: invalid handler configuration")

// HubAuthority is the complete private authority surface available to the Hub.
// The separate methods preserve IAM and wire-contract separation; there is no
// generic operation dispatcher. Implementations must consume payloads
// synchronously without retaining or aliasing them and return exclusively owned
// mutable response buffers. Ownership of each response transfers to Handler.
type HubAuthority interface {
	IssueAssignment(context.Context, []byte) ([]byte, error)
	RefreshAssignment(context.Context, []byte) ([]byte, error)
	IssueCredentialRecovery(context.Context, []byte) ([]byte, error)
}

// AdmissionRequest deliberately excludes the credential and agent ID. The
// future Hub limiter needs only the authenticated peer and closed operation.
type AdmissionRequest struct {
	Mode                          Mode
	AuthenticatedPeerPublicKeyB64 string
}

type AdmissionDecision uint8

const (
	AdmissionAllow AdmissionDecision = iota + 1
	AdmissionRegistrationDisabled
	AdmissionRateLimited
	AdmissionUnavailable
)

type AdmissionResult struct {
	Decision          AdmissionDecision
	RetryAfterSeconds uint32
}

// AdmissionGate runs after strict NHP application decoding and peer binding but
// before any Authority invocation.
type AdmissionGate interface {
	AdmitAssignment(context.Context, AdmissionRequest) AdmissionResult
}

// Classification is a closed, secret-free, low-cardinality observation value.
// A later runtime may meter it directly without incorporating attacker input.
type Classification string

const (
	ClassificationSuccess                   Classification = "success"
	ClassificationRequestRejected           Classification = "request_rejected"
	ClassificationDeadlineRejected          Classification = "deadline_rejected"
	ClassificationRegistrationDisabled      Classification = "registration_disabled"
	ClassificationRateLimited               Classification = "rate_limited"
	ClassificationAdmissionUnavailable      Classification = "admission_unavailable"
	ClassificationAuthorityInvocationFailed Classification = "authority_invocation_failed"
	ClassificationAuthorityResponseRejected Classification = "authority_response_rejected"
	ClassificationAuthoritySemanticError    Classification = "authority_semantic_error"
	ClassificationInternalFailure           Classification = "internal_failure"
)

// HandleResult contains the exact canonical public LRT application body. It is
// kept as bytes so this dark application layer does not force the result through
// ServerListResultMsg's map[string]any and lose integer precision or wire order.
// A nil Body is an internal failure signal for the future runtime to drop and
// meter; it must never be transmitted as an LRT application body.
type HandleResult struct {
	Body           []byte
	Classification Classification
	// RequestRejection is set only for ClassificationRequestRejected. It is a
	// fixed internal label and never appears in Body.
	RequestRejection RequestRejection

	// Authority timing stays internal to connectorhub so the Worker can observe
	// the separately permissioned invocation without widening the public result
	// contract. A zero completion time means no Authority call occurred.
	mode                 Mode
	authorityDuration    time.Duration
	authorityCompletedAt time.Time
}

type Handler struct {
	environment string
	authority   HubAuthority
	admission   AdmissionGate
}

func NewHandler(environment string, authority HubAuthority, admission AdmissionGate) (*Handler, error) {
	if authority == nil || admission == nil || !validHandlerEnvironment(environment) {
		return nil, ErrInvalidHandlerConfiguration
	}
	return &Handler{environment: environment, authority: authority, admission: admission}, nil
}

// HandleAssignment handles one already-decrypted, Noise-authenticated LST. The
// caller must provide a live deadline; the handler never invents a deployment
// timeout and the Authority transport performs no internal retry.
func (h *Handler) HandleAssignment(ctx context.Context, raw, authenticatedPeer []byte) HandleResult {
	if !hasLiveDeadline(ctx) {
		// The mode is not trustworthy until strict decoding succeeds. Both public
		// assignment phases freeze this unavailable result to the same 52200 body.
		return h.unavailable(ModeRefresh, ClassificationDeadlineRejected)
	}
	request, rejection, err := decodeAssignmentRequestClassified(h.environment, raw, authenticatedPeer)
	if err != nil {
		// The single strict parse preserves only a uniquely decoded closed mode.
		// That is enough to keep authenticated recovery failures in the 524xx
		// family without retaining a secret or reparsing attacker input. Rejected
		// bodies are intentionally field-order-sensitive only at this boundary: a
		// fault before mode keeps the historical generic assignment rejection.
		mode := request.Mode
		if mode == 0 {
			mode = ModeRefresh
		}
		return h.invalidRequest(mode, rejection)
	}

	// Admit before the stricter private credential grammar so malformed or
	// obsolete credentials still spend the authenticated peer's own Hub budget
	// instead of creating an unmetered rejection path.
	admission := h.admission.AdmitAssignment(ctx, AdmissionRequest{
		Mode: request.Mode, AuthenticatedPeerPublicKeyB64: request.AuthenticatedPeerPublicKeyB64,
	})
	// Admission shares the caller's aggregate budget. Re-check after it returns
	// so an implementation that runs to the deadline (or ignores cancellation)
	// cannot hand an already-expired context to the Authority boundary.
	if !hasLiveDeadline(ctx) {
		return h.unavailable(request.Mode, ClassificationDeadlineRejected)
	}
	switch admission.Decision {
	case AdmissionAllow:
		if admission.RetryAfterSeconds != 0 {
			return h.unavailable(request.Mode, ClassificationAdmissionUnavailable)
		}
	case AdmissionRegistrationDisabled:
		if request.Mode != ModeEnroll || admission.RetryAfterSeconds != 0 {
			return h.unavailable(request.Mode, ClassificationAdmissionUnavailable)
		}
		body, err := EncodeEnrollError(EnrollErrorRegistrationDisabled, nil)
		return classifiedBody(body, err, ClassificationRegistrationDisabled)
	case AdmissionRateLimited:
		if admission.RetryAfterSeconds == 0 {
			return h.unavailable(request.Mode, ClassificationAdmissionUnavailable)
		}
		if request.Mode == ModeRecover {
			// Recovery's authenticated rate-limit delay is frozen at 60 seconds.
			// A differently configured gate is an unavailable admission boundary,
			// not authority to emit a contract-divergent delay.
			if admission.RetryAfterSeconds != recoveryRateLimitRetrySeconds {
				return h.unavailable(request.Mode, ClassificationAdmissionUnavailable)
			}
			body, err := EncodeRecoveryError(RecoveryErrorRateLimited)
			return classifiedBody(body, err, ClassificationRateLimited)
		}
		retry := admission.RetryAfterSeconds
		if request.Mode == ModeEnroll {
			body, err := EncodeEnrollError(EnrollErrorAssignmentRateLimited, &retry)
			return classifiedBody(body, err, ClassificationRateLimited)
		}
		body, err := EncodeRefreshError(AssignmentErrorRateLimited, &retry)
		return classifiedBody(body, err, ClassificationRateLimited)
	case AdmissionUnavailable:
		return h.unavailable(request.Mode, ClassificationAdmissionUnavailable)
	default:
		return h.unavailable(request.Mode, ClassificationAdmissionUnavailable)
	}

	payload, err := encodeAuthorityRequest(request)
	if err != nil {
		// The public LST credential is opaque, but the private Authority accepts
		// only canonical API keys. Reject malformed shapes locally before an
		// Authority lookup; only canonical-but-unknown keys reach Authority and
		// can map to the phase-specific credential-rejected result.
		if request.Mode == ModeEnroll {
			body, encodeErr := EncodeEnrollError(EnrollErrorInvalidInput, nil)
			result := classifiedBody(body, encodeErr, ClassificationRequestRejected)
			result.RequestRejection = RequestRejectionSemantic
			return result
		}
		return h.invalidRequest(request.Mode, RequestRejectionSemantic)
	}
	defer clear(payload)
	// Keep the final fence adjacent to the separately permissioned call. The
	// transport still owns cancellation after invocation begins; this prevents
	// locally observable expiry from starting an Authority operation.
	if !hasLiveDeadline(ctx) {
		return h.unavailable(request.Mode, ClassificationDeadlineRejected)
	}

	var response []byte
	authorityStartedAt := time.Now()
	switch request.Mode {
	case ModeEnroll:
		response, err = h.authority.IssueAssignment(ctx, payload)
	case ModeRefresh:
		response, err = h.authority.RefreshAssignment(ctx, payload)
	case ModeRecover:
		response, err = h.authority.IssueCredentialRecovery(ctx, payload)
	default:
		return h.invalidRequest(request.Mode, RequestRejectionSemantic)
	}
	authorityCompletedAt := time.Now()
	defer clear(response)
	if err != nil || ctx.Err() != nil {
		return withAuthorityTiming(
			h.unavailable(request.Mode, ClassificationAuthorityInvocationFailed),
			request.Mode, authorityStartedAt, authorityCompletedAt,
		)
	}

	body, kind, err := decodeAuthorityResponse(request, response)
	if err != nil {
		return withAuthorityTiming(
			h.unavailable(request.Mode, ClassificationAuthorityResponseRejected),
			request.Mode, authorityStartedAt, authorityCompletedAt,
		)
	}
	if kind == authorityResponseSemanticError {
		return withAuthorityTiming(
			HandleResult{Body: body, Classification: ClassificationAuthoritySemanticError},
			request.Mode, authorityStartedAt, authorityCompletedAt,
		)
	}
	return withAuthorityTiming(
		HandleResult{Body: body, Classification: ClassificationSuccess},
		request.Mode, authorityStartedAt, authorityCompletedAt,
	)
}

func withAuthorityTiming(result HandleResult, mode Mode, startedAt, completedAt time.Time) HandleResult {
	result.mode = mode
	result.authorityDuration = completedAt.Sub(startedAt)
	result.authorityCompletedAt = completedAt
	return result
}

func (h *Handler) invalidRequest(mode Mode, rejection RequestRejection) HandleResult {
	var result HandleResult
	if mode == ModeEnroll {
		body, err := EncodeEnrollError(EnrollErrorInvalidAssignmentRequest, nil)
		result = classifiedBody(body, err, ClassificationRequestRejected)
	} else if mode == ModeRecover {
		body, err := EncodeRecoveryError(RecoveryErrorInvalidRequest)
		result = classifiedBody(body, err, ClassificationRequestRejected)
	} else {
		body, err := EncodeRefreshError(AssignmentErrorInvalidRequest, nil)
		result = classifiedBody(body, err, ClassificationRequestRejected)
	}
	if result.Classification == ClassificationRequestRejected {
		result.RequestRejection = rejection
	}
	return result
}

func (h *Handler) unavailable(mode Mode, classification Classification) HandleResult {
	if mode == ModeEnroll {
		body, err := EncodeEnrollError(EnrollErrorAssignmentUnavailable, nil)
		return classifiedBody(body, err, classification)
	}
	if mode == ModeRecover {
		body, err := EncodeRecoveryError(RecoveryErrorUnavailable)
		return classifiedBody(body, err, classification)
	}
	body, err := EncodeRefreshError(AssignmentErrorUnavailable, nil)
	return classifiedBody(body, err, classification)
}

func classifiedBody(body []byte, err error, classification Classification) HandleResult {
	if err != nil {
		// The codec contract tests exhaust every fixed error used by Handler.
		// Keep this opaque fallback for future enum drift rather than emitting a
		// partial or malformed application response.
		return HandleResult{Classification: ClassificationInternalFailure}
	}
	return HandleResult{Body: body, Classification: classification}
}

func hasLiveDeadline(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && deadline.After(time.Now())
}

func validHandlerEnvironment(environment string) bool {
	peer := make([]byte, conformance.ConnectorHubRequestIDPeerBytes)
	nonce := make([]byte, conformance.ConnectorHubRequestIDNonceBytes)
	_, err := conformance.DeriveConnectorHubRequestID(
		environment, conformance.ConnectorHubRequestIDOperationIssue, peer, nonce,
	)
	return err == nil
}
