package connectorcell

import (
	"context"
	"errors"
	"time"
)

var ErrInvalidHandlerConfiguration = errors.New("connector cell: invalid handler configuration")

// Authority is the one separately permissioned assigned-cell capability. An
// implementation must consume payload synchronously without retaining or
// aliasing it, and must return an exclusively owned mutable response buffer.
// Ownership of that response transfers to the handler, which clears both
// buffers before HandleCompletion returns. After committing a replacement,
// the Authority must return the same success for an exact sealed-candidate
// replay: caller cancellation can hide a committed response and force that
// idempotent retry.
type Authority interface {
	CompleteCredentialRecovery(context.Context, []byte) ([]byte, error)
}

// Classification is a closed, low-cardinality handler outcome.
type Classification string

const (
	ClassificationSuccess                   Classification = "success"
	ClassificationRequestRejected           Classification = "request_rejected"
	ClassificationDeadlineRejected          Classification = "deadline_rejected"
	ClassificationAuthorityInvocationFailed Classification = "authority_invocation_failed"
	ClassificationAuthorityResponseRejected Classification = "authority_response_rejected"
	ClassificationAuthoritySemanticError    Classification = "authority_semantic_error"
	ClassificationInternalFailure           Classification = "internal_failure"
)

// HandleResult contains only a public body and secret-free classifications.
// Body is nil only for ClassificationInternalFailure, the defensive fallback
// if encoding a frozen public error unexpectedly fails.
type HandleResult struct {
	Body             []byte
	Classification   Classification
	RequestRejection RequestRejection
}

// Handler maps one authenticated assigned-cell completion LST to one LRT body.
type Handler struct{ authority Authority }

func NewHandler(authority Authority) (*Handler, error) {
	if authority == nil {
		return nil, ErrInvalidHandlerConfiguration
	}
	return &Handler{authority: authority}, nil
}

// HandleCompletion performs no retry. The caller owns receipt budgeting and
// must pass a live deadline covering Authority invocation and response sealing.
func (h *Handler) HandleCompletion(ctx context.Context, raw, authenticatedPeer []byte) HandleResult {
	if !liveDeadline(ctx) {
		return unavailable(ClassificationDeadlineRejected)
	}
	request, _, rejection, err := decodeRoutedCompletionRequest(raw, authenticatedPeer)
	return h.handleDecodedCompletion(ctx, request, rejection, err)
}

// HandleDirect performs one integrated intent-and-request parse. handled is
// true only for exact assigned-cell recovery intent, including malformed forms
// with duplicate/unknown/trailing fields; those fail as frozen 52414 and never
// fall through the generic ListService path. Ordinary LSTs are not modified.
func (h *Handler) HandleDirect(ctx context.Context, raw, authenticatedPeer []byte) (result HandleResult, handled bool) {
	request, routed, rejection, err := decodeRoutedCompletionRequest(raw, authenticatedPeer)
	if !routed {
		return HandleResult{}, false
	}
	return h.handleDecodedCompletion(ctx, request, rejection, err), true
}

// RejectRelayedCompletion recognizes the same exact intent without decoding
// recovery secrets into Go strings. Relay has no Authority capability, so every
// routed form returns the fixed invalid-request LRT and no attacker-controlled
// value can influence the response.
func RejectRelayedCompletion(raw []byte) ([]byte, bool) {
	if !routeCompletionIntent(raw) {
		return nil, false
	}
	return completionInvalidRequestBody(), true
}

func (h *Handler) handleDecodedCompletion(
	ctx context.Context,
	request CompletionRequest,
	rejection RequestRejection,
	decodeErr error,
) HandleResult {
	if !liveDeadline(ctx) {
		return unavailable(ClassificationDeadlineRejected)
	}
	if decodeErr != nil {
		return rejectRequest(rejection)
	}
	payload, err := encodeAuthorityRequest(request)
	if err != nil {
		// DecodeCompletionRequest already enforced the same closed grammar. This
		// branch is a defense-in-depth fence against validator/encoder drift.
		return rejectRequest(RequestRejectionSemantic)
	}
	defer clear(payload)
	// Keep the final deadline fence adjacent to the separately permissioned
	// invocation so local expiry cannot begin an Authority operation.
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) || ctx.Err() != nil {
		return unavailable(ClassificationDeadlineRejected)
	}
	response, err := h.authority.CompleteCredentialRecovery(ctx, payload)
	defer clear(response)
	if err != nil || ctx.Err() != nil {
		return unavailable(ClassificationAuthorityInvocationFailed)
	}
	body, kind, err := decodeAuthorityResponse(response)
	if err != nil {
		// The frozen public contract deliberately collapses a malformed private
		// response to retryable unavailable. Operators alarm on this distinct
		// classification so a persistent Authority defect is not hidden.
		return unavailable(ClassificationAuthorityResponseRejected)
	}
	if kind == authorityResponseSemanticError {
		return HandleResult{Body: body, Classification: ClassificationAuthoritySemanticError}
	}
	return HandleResult{Body: body, Classification: ClassificationSuccess}
}

func liveDeadline(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && deadline.After(time.Now())
}

func unavailable(classification Classification) HandleResult {
	body, err := EncodeCompletionError(CompletionErrorUnavailable)
	return classifiedBody(body, err, classification)
}

// rejectRequest emits the frozen invalid-request LRT and stamps the secret-free
// rejection class. The class is only attached when encoding succeeded; a failed
// encode falls through to ClassificationInternalFailure with no body.
func rejectRequest(rejection RequestRejection) HandleResult {
	body, err := EncodeCompletionError(CompletionErrorInvalidRequest)
	result := classifiedBody(body, err, ClassificationRequestRejected)
	if result.Classification == ClassificationRequestRejected {
		result.RequestRejection = rejection
	}
	return result
}

func classifiedBody(body []byte, err error, classification Classification) HandleResult {
	if err != nil {
		return HandleResult{Classification: ClassificationInternalFailure}
	}
	return HandleResult{Body: body, Classification: classification}
}
