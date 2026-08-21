package connectorcell

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	conformance "github.com/layervai/qurl-conformance"
)

var (
	ErrInvalidConnectorResourceAuthorityRequest  = errors.New("connector cell: invalid connector resource authority request")
	ErrInvalidConnectorResourceAuthorityResponse = errors.New("connector cell: invalid connector resource authority response")
)

const (
	connectorResourceAuthorityVersion      = conformance.ConnectorResourceLSTV1Version
	connectorResourceCellRequestIDHexBytes = conformance.ConnectorResourceLSTV1CellRequestIDChars
)

type connectorResourceAuthorityRequestWire struct {
	Version                       int     `json:"version"`
	AuthenticatedPeerPublicKeyB64 string  `json:"authenticated_peer_public_key_b64"`
	AgentID                       string  `json:"agent_id"`
	CellRequestID                 string  `json:"cell_request_id"`
	ConnectorID                   string  `json:"connector_id"`
	ExpectedResourceID            *string `json:"expected_resource_id,omitempty"`
}

func encodeConnectorResourceAuthorityRequest(environment string, request ConnectorResourceRequest) ([]byte, error) {
	if !validAgentID(request.AgentID) || !validPeer(request.AuthenticatedPeerPublicKeyB64) ||
		!validConnectorResourceNonce(request.RequestNonce) || !validConnectorID(request.ConnectorID) ||
		(request.ExpectedResourceID != nil && !validConnectorResourceID(*request.ExpectedResourceID)) {
		return nil, ErrInvalidConnectorResourceAuthorityRequest
	}
	cellRequestID, ok := deriveConnectorResourceCellRequestID(
		environment,
		request.AuthenticatedPeerPublicKeyB64,
		request.RequestNonce,
	)
	if !ok {
		return nil, ErrInvalidConnectorResourceAuthorityRequest
	}
	body, err := json.Marshal(connectorResourceAuthorityRequestWire{
		Version: connectorResourceAuthorityVersion, AuthenticatedPeerPublicKeyB64: request.AuthenticatedPeerPublicKeyB64,
		AgentID: request.AgentID, CellRequestID: cellRequestID, ConnectorID: request.ConnectorID,
		ExpectedResourceID: request.ExpectedResourceID,
	})
	if err != nil || len(body) == 0 || len(body) > maxConnectorResourceAuthorityBodyBytes {
		clear(body)
		return nil, ErrInvalidConnectorResourceAuthorityRequest
	}
	return body, nil
}

const maxConnectorResourceAuthorityBodyBytes = 2048

// deriveConnectorResourceCellRequestID implements the qurl-conformance v1
// domain-separated replay-key derivation. The environment is server-owned and
// the peer is Noise-authenticated; neither is accepted from public JSON.
func deriveConnectorResourceCellRequestID(environment, peerB64, nonce string) (string, bool) {
	if !validConnectorResourceEnvironment(environment) {
		return "", false
	}
	peer, err := base64.StdEncoding.Strict().DecodeString(peerB64)
	if err != nil || len(peer) != x25519KeyBytes || base64.StdEncoding.EncodeToString(peer) != peerB64 {
		clear(peer)
		return "", false
	}
	defer clear(peer)
	decodedNonce, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(decodedNonce) != connectorResourceNonceBytes ||
		base64.RawURLEncoding.EncodeToString(decodedNonce) != nonce {
		clear(decodedNonce)
		return "", false
	}
	defer clear(decodedNonce)
	cellRequestID, err := conformance.DeriveConnectorResourceLSTV1CellRequestID(environment, peer, decodedNonce)
	return cellRequestID, err == nil
}

func validConnectorResourceEnvironment(value string) bool {
	if len(value) < 1 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	if len(value) > 1 && !lowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		character := value[index]
		if !lowerAlphaNumeric(character) && character != '-' {
			return false
		}
	}
	return true
}

type connectorResourceAuthorityResultWire struct {
	AgentID            string  `json:"agent_id"`
	ConnectorID        string  `json:"connector_id"`
	ResourceID         string  `json:"resource_id"`
	ConnectorRoutingID string  `json:"connector_routing_id"`
	KnockResourceID    string  `json:"knock_resource_id"`
	CRID               *string `json:"crid,omitempty"`
	FoundExisting      bool    `json:"found_existing"`
}

type connectorResourceAuthorityErrorWire struct {
	Code              string  `json:"code"`
	RetryAfterSeconds *uint32 `json:"retry_after_seconds,omitempty"`
}

type connectorResourceAuthorityResponseKind uint8

const (
	connectorResourceAuthorityResponseSuccess connectorResourceAuthorityResponseKind = iota + 1
	connectorResourceAuthorityResponseSemanticError
)

func decodeConnectorResourceAuthorityResponse(raw []byte, request ConnectorResourceRequest) ([]byte, connectorResourceAuthorityResponseKind, error) {
	if len(raw) == 0 || len(raw) > maxConnectorResourceAuthorityBodyBytes {
		return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
	}
	envelope, err := decodeAuthorityObject(raw, []string{"version"}, []string{"version", "result", "error"})
	if err != nil || !bytes.Equal(envelope["version"], []byte("1")) {
		clearRawObject(envelope)
		return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
	}
	defer clearRawObject(envelope)
	resultRaw, hasResult := envelope["result"]
	errorRaw, hasError := envelope["error"]
	if hasResult == hasError || bytes.Equal(resultRaw, []byte("null")) || bytes.Equal(errorRaw, []byte("null")) {
		return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
	}
	if hasResult {
		object, err := decodeAuthorityObject(resultRaw,
			[]string{"agent_id", "connector_id", "resource_id", "connector_routing_id", "knock_resource_id", "found_existing"},
			[]string{"agent_id", "connector_id", "resource_id", "connector_routing_id", "knock_resource_id", "crid", "found_existing"})
		if err != nil {
			return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
		}
		defer clearRawObject(object)
		var value connectorResourceAuthorityResultWire
		if err := json.Unmarshal(resultRaw, &value); err != nil || value.AgentID != request.AgentID || value.ConnectorID != request.ConnectorID ||
			(request.ExpectedResourceID != nil && value.ResourceID != *request.ExpectedResourceID) {
			return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
		}
		body, err := EncodeConnectorResourceSuccess(ConnectorResourceSuccess{
			AgentID: value.AgentID, ConnectorID: value.ConnectorID, ResourceID: value.ResourceID,
			ConnectorRoutingID: value.ConnectorRoutingID, KnockResourceID: value.KnockResourceID,
			CRID: value.CRID, FoundExisting: value.FoundExisting,
		})
		if err != nil {
			return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
		}
		return body, connectorResourceAuthorityResponseSuccess, nil
	}

	object, err := decodeAuthorityObject(errorRaw, []string{"code"}, []string{"code", "retry_after_seconds"})
	if err != nil {
		return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
	}
	defer clearRawObject(object)
	var value connectorResourceAuthorityErrorWire
	if err := json.Unmarshal(errorRaw, &value); err != nil {
		return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
	}
	var kind ConnectorResourceError
	switch value.Code {
	case "unavailable":
		kind = ConnectorResourceErrorUnavailable
	case "identity_rejected":
		kind = ConnectorResourceErrorIdentityRejected
	case "entitlement_denied":
		kind = ConnectorResourceErrorEntitlementDenied
	case "resource_identity_conflict":
		kind = ConnectorResourceErrorIdentityConflict
	case "quota":
		kind = ConnectorResourceErrorQuota
	case "rate_limited":
		kind = ConnectorResourceErrorRateLimited
	case "invalid_request":
		kind = ConnectorResourceErrorInvalidRequest
	default:
		return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
	}
	retry := uint32(0)
	if value.RetryAfterSeconds != nil {
		retry = *value.RetryAfterSeconds
	}
	if kind == ConnectorResourceErrorRateLimited && value.RetryAfterSeconds == nil {
		return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
	}
	if kind != ConnectorResourceErrorRateLimited && kind != ConnectorResourceErrorUnavailable && value.RetryAfterSeconds != nil {
		return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
	}
	body, err := EncodeConnectorResourceError(kind, retry)
	if err != nil {
		return nil, 0, ErrInvalidConnectorResourceAuthorityResponse
	}
	return body, connectorResourceAuthorityResponseSemanticError, nil
}
