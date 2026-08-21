package connectorcell

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"unicode/utf8"

	conformance "github.com/layervai/qurl-conformance"
)

const (
	connectorResourceQuery   = conformance.ConnectorResourceLSTV1Query
	connectorResourceVersion = conformance.ConnectorResourceLSTV1Version
	connectorResourceAspID   = conformance.ConnectorResourceLSTV1AspID

	connectorResourceNonceBytes         = conformance.ConnectorResourceLSTV1NonceBytes
	connectorResourceMaxBodyBytes       = conformance.ConnectorResourceLSTV1MaxPlaintextBodyBytes
	connectorResourceMaxRetryAfter      = conformance.ConnectorResourceLSTV1MaxRetryAfterSeconds
	connectorResourceInvalidRequestJSON = `{"errCode":"` + conformance.ConnectorResourceLSTV1ErrorInvalidRequest + `","errMsg":"invalid connector resource request"}`
)

var (
	ErrInvalidConnectorResourceRequest  = errors.New("connector cell: invalid connector resource request")
	ErrConnectorResourceRequestTooLarge = errors.New("connector cell: connector resource request too large")
	ErrInvalidConnectorResourceSuccess  = errors.New("connector cell: invalid connector resource success")
	ErrInvalidConnectorResourceError    = errors.New("connector cell: invalid connector resource error")
	connectorResourceCRIDEncoding       = base32.NewEncoding(conformance.CRIDV1Alphabet).WithPadding(base32.NoPadding)
	connectorResourceCRIDCRCTable       = crc32.MakeTable(crc32.Castagnoli)
)

// ConnectorResourceRequest is the bounded public request plus the
// Noise-authenticated peer identity. RequestNonce is replay material and must
// not be logged or reflected in the public LRT.
type ConnectorResourceRequest struct {
	AgentID                       string
	AuthenticatedPeerPublicKeyB64 string
	RequestNonce                  string
	ConnectorID                   string
	ExpectedResourceID            *string
}

func decodeRoutedConnectorResourceRequest(raw, authenticatedPeer []byte) (ConnectorResourceRequest, bool, RequestRejection, error) {
	routed := IsConnectorResourceIntent(raw)
	if len(authenticatedPeer) != x25519KeyBytes {
		return ConnectorResourceRequest{}, routed, RequestRejectionPeer, ErrInvalidAuthenticatedPeer
	}
	if len(raw) == 0 || len(raw) > connectorResourceMaxBodyBytes {
		return ConnectorResourceRequest{}, routed, RequestRejectionBodySize, ErrConnectorResourceRequestTooLarge
	}
	if !routed {
		return ConnectorResourceRequest{}, false, RequestRejectionSemantic, ErrInvalidConnectorResourceRequest
	}
	if !utf8.Valid(raw) {
		return ConnectorResourceRequest{}, true, RequestRejectionBodyParse, ErrInvalidConnectorResourceRequest
	}

	var data *trackedObject
	root := decodeTrackedObject(raw, func(key string, value json.RawMessage) bool {
		if key != "usrData" {
			return true
		}
		candidate := decodeTrackedObject(value, nil,
			"query", "version", "request_nonce", "connector_id", "expected_resource_id")
		if data == nil {
			data = candidate
		} else {
			candidate.clear()
		}
		return false
	}, "usrId", "devId", "aspId", "usrData")
	defer root.clear()
	defer data.clear()
	if rejection := root.strictRejection("usrId", "devId", "aspId", "usrData"); rejection != "" ||
		root.count("usrData") != 1 || data == nil {
		if rejection == "" {
			rejection = RequestRejectionBodyParse
		}
		return ConnectorResourceRequest{}, true, rejection, ErrInvalidConnectorResourceRequest
	}
	if data == nil || !data.syntax || data.unknown ||
		data.count("query") != 1 || data.count("version") != 1 ||
		data.count("request_nonce") != 1 || data.count("connector_id") != 1 ||
		data.count("expected_resource_id") > 1 {
		return ConnectorResourceRequest{}, true, RequestRejectionBodyParse, ErrInvalidConnectorResourceRequest
	}

	usrID, usrOK := trackedStrictString(root, "usrId")
	devID, devOK := trackedStrictString(root, "devId")
	aspID, aspOK := trackedStrictString(root, "aspId")
	query, queryOK := trackedStrictString(data, "query")
	nonce, nonceOK := trackedStrictString(data, "request_nonce")
	connectorID, connectorOK := trackedStrictString(data, "connector_id")
	version := trackedSingleValue(data, "version")
	if !usrOK || !devOK || !aspOK || !queryOK || !nonceOK || !connectorOK {
		return ConnectorResourceRequest{}, true, RequestRejectionBodyParse, ErrInvalidConnectorResourceRequest
	}
	if usrID != devID || !validAgentID(devID) || aspID != connectorResourceAspID || query != connectorResourceQuery ||
		!bytes.Equal(version, []byte("1")) || !validConnectorResourceNonce(nonce) || !validConnectorID(connectorID) {
		return ConnectorResourceRequest{}, true, RequestRejectionSemantic, ErrInvalidConnectorResourceRequest
	}

	var expected *string
	if data.count("expected_resource_id") == 1 {
		value, ok := trackedStrictString(data, "expected_resource_id")
		if !ok || !validConnectorResourceID(value) {
			return ConnectorResourceRequest{}, true, RequestRejectionSemantic, ErrInvalidConnectorResourceRequest
		}
		expected = &value
	}
	return ConnectorResourceRequest{
		AgentID: devID, AuthenticatedPeerPublicKeyB64: base64.StdEncoding.EncodeToString(authenticatedPeer),
		RequestNonce: nonce, ConnectorID: connectorID, ExpectedResourceID: expected,
	}, true, "", nil
}

type ConnectorResourceSuccess struct {
	AgentID            string
	ConnectorID        string
	ResourceID         string
	ConnectorRoutingID string
	KnockResourceID    string
	CRID               *string
	FoundExisting      bool
}

type connectorResourceListWire struct {
	Query              string  `json:"query"`
	Version            int     `json:"version"`
	AgentID            string  `json:"agent_id"`
	ConnectorID        string  `json:"connector_id"`
	ResourceID         string  `json:"resource_id"`
	ConnectorRoutingID string  `json:"connector_routing_id"`
	KnockResourceID    string  `json:"knock_resource_id"`
	CRID               *string `json:"crid,omitempty"`
	FoundExisting      bool    `json:"found_existing"`
}

type connectorResourceSuccessWire struct {
	ErrCode string                    `json:"errCode"`
	List    connectorResourceListWire `json:"list"`
}

func EncodeConnectorResourceSuccess(value ConnectorResourceSuccess) ([]byte, error) {
	if !validAgentID(value.AgentID) || !validConnectorID(value.ConnectorID) ||
		!validConnectorResourceID(value.ResourceID) || !validConnectorRoutingID(value.ConnectorRoutingID) ||
		!validKnockResourceID(value.KnockResourceID) || value.ResourceID == value.KnockResourceID ||
		value.ConnectorRoutingID == value.KnockResourceID ||
		(value.CRID != nil && !validCRIDForResource(*value.CRID, value.ResourceID)) {
		return nil, ErrInvalidConnectorResourceSuccess
	}
	body, err := json.Marshal(connectorResourceSuccessWire{ErrCode: "0", List: connectorResourceListWire{
		Query: connectorResourceQuery, Version: connectorResourceVersion, AgentID: value.AgentID,
		ConnectorID: value.ConnectorID, ResourceID: value.ResourceID,
		ConnectorRoutingID: value.ConnectorRoutingID, KnockResourceID: value.KnockResourceID,
		CRID: value.CRID, FoundExisting: value.FoundExisting,
	}})
	if err != nil || len(body) > connectorResourceMaxBodyBytes {
		clear(body)
		return nil, ErrInvalidConnectorResourceSuccess
	}
	return body, nil
}

type ConnectorResourceError uint8

const (
	ConnectorResourceErrorUnavailable ConnectorResourceError = iota + 1
	ConnectorResourceErrorIdentityRejected
	ConnectorResourceErrorEntitlementDenied
	ConnectorResourceErrorIdentityConflict
	ConnectorResourceErrorQuota
	ConnectorResourceErrorRateLimited
	ConnectorResourceErrorInvalidRequest
)

func EncodeConnectorResourceError(kind ConnectorResourceError, retryAfter uint32) ([]byte, error) {
	var value errorWire
	switch kind {
	case ConnectorResourceErrorUnavailable:
		if retryAfter > connectorResourceMaxRetryAfter {
			return nil, ErrInvalidConnectorResourceError
		}
		value = errorWire{ErrCode: conformance.ConnectorResourceLSTV1ErrorUnavailable, ErrMsg: "connector resource temporarily unavailable"}
		if retryAfter > 0 {
			value.RetryAfterSeconds = &retryAfter
		}
	case ConnectorResourceErrorIdentityRejected:
		if retryAfter != 0 {
			return nil, ErrInvalidConnectorResourceError
		}
		value = errorWire{ErrCode: conformance.ConnectorResourceLSTV1ErrorIdentityRejected, ErrMsg: "connector resource identity rejected"}
	case ConnectorResourceErrorEntitlementDenied:
		if retryAfter != 0 {
			return nil, ErrInvalidConnectorResourceError
		}
		value = errorWire{ErrCode: conformance.ConnectorResourceLSTV1ErrorEntitlement, ErrMsg: "connector resource entitlement denied"}
	case ConnectorResourceErrorIdentityConflict:
		if retryAfter != 0 {
			return nil, ErrInvalidConnectorResourceError
		}
		value = errorWire{ErrCode: conformance.ConnectorResourceLSTV1ErrorIdentityConflict, ErrMsg: "connector resource identity conflict"}
	case ConnectorResourceErrorQuota:
		if retryAfter != 0 {
			return nil, ErrInvalidConnectorResourceError
		}
		value = errorWire{ErrCode: conformance.ConnectorResourceLSTV1ErrorQuota, ErrMsg: "connector resource quota exceeded"}
	case ConnectorResourceErrorRateLimited:
		if retryAfter == 0 || retryAfter > connectorResourceMaxRetryAfter {
			return nil, ErrInvalidConnectorResourceError
		}
		value = errorWire{ErrCode: conformance.ConnectorResourceLSTV1ErrorRateLimited, ErrMsg: "connector resource rate limited", RetryAfterSeconds: &retryAfter}
	case ConnectorResourceErrorInvalidRequest:
		if retryAfter != 0 {
			return nil, ErrInvalidConnectorResourceError
		}
		return []byte(connectorResourceInvalidRequestJSON), nil
	default:
		return nil, ErrInvalidConnectorResourceError
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) > connectorResourceMaxBodyBytes {
		clear(body)
		return nil, ErrInvalidConnectorResourceError
	}
	return body, nil
}

func validConnectorResourceNonce(value string) bool {
	return conformance.ValidateConnectorResourceLSTV1Nonce(value) == nil
}

func validConnectorID(value string) bool {
	return conformance.ValidateConnectorResourceLSTV1ConnectorID(value)
}

func validConnectorResourceID(value string) bool {
	return conformance.ValidateConnectorResourceLSTV1ResourceID(value) == nil
}

func validConnectorRoutingID(value string) bool {
	return conformance.ValidateConnectorResourceLSTV1RoutingID(value) == nil
}

func validKnockResourceID(value string) bool {
	return conformance.ValidateConnectorResourceLSTV1KnockResourceID(value) == nil
}

func validCRIDForResource(value, resourceID string) bool {
	if len(value) != conformance.CRIDV1FullCRIDLength && len(value) != conformance.CRIDV1TruncatedCRIDLength {
		return false
	}
	decoded, err := connectorResourceCRIDEncoding.DecodeString(value)
	if err != nil || connectorResourceCRIDEncoding.EncodeToString(decoded) != value ||
		len(decoded) <= 1+conformance.CRIDV1ChecksumLength {
		clear(decoded)
		return false
	}
	defer clear(decoded)
	payload := decoded[:len(decoded)-conformance.CRIDV1ChecksumLength]
	checksum := decoded[len(decoded)-conformance.CRIDV1ChecksumLength:]
	if binary.BigEndian.Uint32(checksum) != crc32.Checksum(payload, connectorResourceCRIDCRCTable) {
		return false
	}
	digestLength := len(payload) - 1
	switch decoded[0] {
	case 0x01, 0x81:
		if digestLength != conformance.CRIDV1FullDigestLength {
			return false
		}
	case 0x02, 0x82:
		if digestLength != conformance.CRIDV1TruncatedDigestLength {
			return false
		}
	default:
		return false
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(resourceID)
	if err != nil || base64.RawURLEncoding.EncodeToString(der) != resourceID {
		clear(der)
		return false
	}
	defer clear(der)
	message := make([]byte, 0, len(conformance.CRIDV1DomainSeparationPrefix)+1+len(der))
	message = append(message, conformance.CRIDV1DomainSeparationPrefix...)
	message = append(message, conformance.CRIDV1DomainSeparator)
	message = append(message, der...)
	digest := sha256.Sum256(message)
	clear(message)
	return bytes.Equal(payload[1:], digest[:digestLength])
}
