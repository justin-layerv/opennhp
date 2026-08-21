package connectorcell

import (
	"context"
	"time"
)

// ConnectorResourceAuthority is the one-method assigned-cell resource
// capability. It cannot invoke registration or credential recovery operations.
type ConnectorResourceAuthority interface {
	ResolveConnectorResource(context.Context, []byte) ([]byte, error)
}

type ConnectorResourceHandler struct {
	authority   ConnectorResourceAuthority
	environment string
}

func NewConnectorResourceHandler(authority ConnectorResourceAuthority, environment string) (*ConnectorResourceHandler, error) {
	if authority == nil || !validConnectorResourceEnvironment(environment) {
		return nil, ErrInvalidHandlerConfiguration
	}
	return &ConnectorResourceHandler{authority: authority, environment: environment}, nil
}

func (h *ConnectorResourceHandler) HandleDirect(ctx context.Context, raw, authenticatedPeer []byte) (result HandleResult, handled bool) {
	request, routed, rejection, err := decodeRoutedConnectorResourceRequest(raw, authenticatedPeer)
	if !routed {
		return HandleResult{}, false
	}
	// Once the exact connector_resource intent is claimed, the response budget
	// intentionally wins over request taxonomy. An expired exchange is retriable
	// authenticated unavailable even when parsing also found a terminal defect;
	// it must not claim that invalid_request completed inside the handler budget.
	if !liveDeadline(ctx) {
		return connectorResourceUnavailable(ClassificationDeadlineRejected), true
	}
	if err != nil {
		return connectorResourceRejectRequest(rejection), true
	}
	payload, err := encodeConnectorResourceAuthorityRequest(h.environment, request)
	if err != nil {
		return connectorResourceRejectRequest(RequestRejectionSemantic), true
	}
	defer clear(payload)
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) || ctx.Err() != nil {
		return connectorResourceUnavailable(ClassificationDeadlineRejected), true
	}
	response, err := h.authority.ResolveConnectorResource(ctx, payload)
	defer clear(response)
	if err != nil || ctx.Err() != nil {
		return connectorResourceUnavailable(ClassificationAuthorityInvocationFailed), true
	}
	body, kind, err := decodeConnectorResourceAuthorityResponse(response, request)
	if err != nil {
		return connectorResourceUnavailable(ClassificationAuthorityResponseRejected), true
	}
	if kind == connectorResourceAuthorityResponseSemanticError {
		return HandleResult{Body: body, Classification: ClassificationAuthoritySemanticError}, true
	}
	return HandleResult{Body: body, Classification: ClassificationSuccess}, true
}

func connectorResourceUnavailable(classification Classification) HandleResult {
	body, err := EncodeConnectorResourceError(ConnectorResourceErrorUnavailable, 0)
	return classifiedBody(body, err, classification)
}

func connectorResourceRejectRequest(rejection RequestRejection) HandleResult {
	body, err := EncodeConnectorResourceError(ConnectorResourceErrorInvalidRequest, 0)
	result := classifiedBody(body, err, ClassificationRequestRejected)
	if result.Classification == ClassificationRequestRejected {
		result.RequestRejection = rejection
	}
	return result
}
