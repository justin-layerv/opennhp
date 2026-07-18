// Package connectorhub owns the strict native-UDP assignment application
// codec. It is deliberately dark: the server plugin and authority transport
// compose this package in later changes.
package connectorhub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/curve25519"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/core/scheme/curve"
)

const (
	assignmentQuery   = "cell_assignment"
	assignmentVersion = 1
	assignmentAspID   = "agent"

	maxAssignmentTicketBytes = 2304
	maxApplicationBodyBytes  = core.PacketBufferSize - curve.HeaderSize - core.GCMTagSize
	x25519PublicKeyBytes     = 32
)

var canonicalX25519UPrime = func() (prime [x25519PublicKeyBytes]byte) {
	for i := range prime {
		prime[i] = 0xff
	}
	prime[0] = 0xed
	prime[x25519PublicKeyBytes-1] = 0x7f
	return prime
}()

var (
	// ErrInvalidAuthenticatedPeer means the Noise-authenticated peer key did
	// not have the exact X25519 public-key length. The raw key is never retained
	// in the error.
	ErrInvalidAuthenticatedPeer = errors.New("connector hub: invalid authenticated peer")
	// ErrInvalidAssignmentRequest covers every strict JSON or semantic request
	// rejection. It intentionally carries no parser detail because the request
	// may contain a registration credential.
	ErrInvalidAssignmentRequest = errors.New("connector hub: invalid assignment request")
	// ErrAssignmentRequestTooLarge is separate so the future packet handler can
	// meter body-size abuse without inspecting a secret-bearing request.
	ErrAssignmentRequestTooLarge = errors.New("connector hub: assignment request too large")
	// ErrInvalidEnrollSuccess and ErrInvalidRefreshSuccess identify producer
	// contract violations without retaining a ticket, key, host, or identifier.
	ErrInvalidEnrollSuccess  = errors.New("connector hub: invalid enroll success")
	ErrInvalidRefreshSuccess = errors.New("connector hub: invalid refresh success")
	// ErrInvalidEnrollError and ErrInvalidRefreshError identify an unsupported
	// error enum or retry-after combination. Callers cannot supply code/message.
	ErrInvalidEnrollError  = errors.New("connector hub: invalid enroll error")
	ErrInvalidRefreshError = errors.New("connector hub: invalid refresh error")
	// ErrAssignmentResponseTooLarge is returned before an oversized application
	// body can reach the fixed 4096-byte NHP packet buffer.
	ErrAssignmentResponseTooLarge = errors.New("connector hub: assignment response too large")
	// ErrAssignmentResponseEncoding identifies an internal JSON encoding
	// failure separately from the application-body size fence.
	ErrAssignmentResponseEncoding = errors.New("connector hub: assignment response encoding failed")
)

// Mode is the closed assignment operation decoded from one authenticated LST.
type Mode uint8

const (
	ModeEnroll Mode = iota + 1
	ModeRefresh
)

// Request is the normalized result of one strict parse. Credential is present
// only for ModeEnroll. AuthenticatedPeerPublicKeyB64 is derived from the Noise
// peer bytes; no JSON field can supply or override it.
type Request struct {
	Mode                          Mode
	AgentID                       string
	AuthenticatedPeerPublicKeyB64 string
	Credential                    string
}

// DecodeAssignmentRequest strictly parses one LST body exactly once and binds
// it to the independently authenticated Noise peer.
func DecodeAssignmentRequest(raw, authenticatedPeer []byte) (Request, error) {
	if len(authenticatedPeer) != x25519PublicKeyBytes {
		return Request{}, ErrInvalidAuthenticatedPeer
	}
	if len(raw) > maxApplicationBodyBytes {
		return Request{}, ErrAssignmentRequestTooLarge
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return Request{}, ErrInvalidAssignmentRequest
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	parsed, err := parseAssignmentRequest(decoder)
	if err != nil {
		return Request{}, ErrInvalidAssignmentRequest
	}

	request := Request{
		AgentID:                       parsed.agentID,
		AuthenticatedPeerPublicKeyB64: base64.StdEncoding.EncodeToString(authenticatedPeer),
	}
	switch parsed.mode {
	case "enroll":
		if !parsed.credentialPresent || parsed.credential == "" {
			return Request{}, ErrInvalidAssignmentRequest
		}
		request.Mode = ModeEnroll
		request.Credential = parsed.credential
	case "refresh":
		if parsed.credentialPresent {
			return Request{}, ErrInvalidAssignmentRequest
		}
		request.Mode = ModeRefresh
	default:
		return Request{}, ErrInvalidAssignmentRequest
	}
	return request, nil
}

type parsedRequest struct {
	agentID           string
	mode              string
	credential        string
	credentialPresent bool
}

func parseAssignmentRequest(decoder *json.Decoder) (parsedRequest, error) {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return parsedRequest{}, err
	}

	var parsed parsedRequest
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		key, err := readUniqueKey(decoder, seen)
		if err != nil {
			return parsedRequest{}, err
		}
		switch key {
		case "usrId":
			value, err := readString(decoder)
			if err != nil || value != "" {
				return parsedRequest{}, ErrInvalidAssignmentRequest
			}
		case "devId":
			value, err := readString(decoder)
			if err != nil || !validAgentID(value) {
				return parsedRequest{}, ErrInvalidAssignmentRequest
			}
			parsed.agentID = value
		case "aspId":
			value, err := readString(decoder)
			if err != nil || value != assignmentAspID {
				return parsedRequest{}, ErrInvalidAssignmentRequest
			}
		case "usrData":
			data, err := parseRequestData(decoder)
			if err != nil {
				return parsedRequest{}, err
			}
			parsed.mode = data.mode
			parsed.credential = data.credential
			parsed.credentialPresent = data.credentialPresent
		default:
			return parsedRequest{}, ErrInvalidAssignmentRequest
		}
	}
	if err := expectDelimiter(decoder, '}'); err != nil || !hasExactly(seen, "usrId", "devId", "aspId", "usrData") {
		return parsedRequest{}, ErrInvalidAssignmentRequest
	}
	if _, err := decoder.Token(); err != io.EOF {
		return parsedRequest{}, ErrInvalidAssignmentRequest
	}
	return parsed, nil
}

type parsedRequestData struct {
	mode              string
	credential        string
	credentialPresent bool
}

func parseRequestData(decoder *json.Decoder) (parsedRequestData, error) {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return parsedRequestData{}, err
	}
	var parsed parsedRequestData
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		key, err := readUniqueKey(decoder, seen)
		if err != nil {
			return parsedRequestData{}, err
		}
		switch key {
		case "query":
			value, err := readString(decoder)
			if err != nil || value != assignmentQuery {
				return parsedRequestData{}, ErrInvalidAssignmentRequest
			}
		case "version":
			value, err := decoder.Token()
			number, ok := value.(json.Number)
			if err != nil || !ok || number.String() != "1" {
				return parsedRequestData{}, ErrInvalidAssignmentRequest
			}
		case "mode":
			value, err := readString(decoder)
			if err != nil {
				return parsedRequestData{}, ErrInvalidAssignmentRequest
			}
			parsed.mode = value
		case "credential":
			value, err := readString(decoder)
			if err != nil {
				return parsedRequestData{}, ErrInvalidAssignmentRequest
			}
			parsed.credential = value
			parsed.credentialPresent = true
		default:
			return parsedRequestData{}, ErrInvalidAssignmentRequest
		}
	}
	if err := expectDelimiter(decoder, '}'); err != nil {
		return parsedRequestData{}, ErrInvalidAssignmentRequest
	}
	_, queryPresent := seen["query"]
	_, versionPresent := seen["version"]
	_, modePresent := seen["mode"]
	if !queryPresent || !versionPresent || !modePresent {
		return parsedRequestData{}, ErrInvalidAssignmentRequest
	}
	return parsed, nil
}

func readUniqueKey(decoder *json.Decoder, seen map[string]struct{}) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	key, ok := token.(string)
	if !ok {
		return "", ErrInvalidAssignmentRequest
	}
	if _, duplicate := seen[key]; duplicate {
		return "", ErrInvalidAssignmentRequest
	}
	seen[key] = struct{}{}
	return key, nil
}

func readString(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", ErrInvalidAssignmentRequest
	}
	return value, nil
}

func expectDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != want {
		return ErrInvalidAssignmentRequest
	}
	return nil
}

func hasExactly(seen map[string]struct{}, keys ...string) bool {
	if len(seen) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := seen[key]; !ok {
			return false
		}
	}
	return true
}

// RegistrationKeyKind is the exact public registration vocabulary. Private
// control-plane key kinds cannot be represented as constants here.
type RegistrationKeyKind string

const (
	KeyKindBootstrap          RegistrationKeyKind = "bootstrap"
	KeyKindConnectorBootstrap RegistrationKeyKind = "connector_bootstrap"
	KeyKindAccount            RegistrationKeyKind = "account"
	KeyKindAgent              RegistrationKeyKind = "agent"
)

// Registration is the assigned-cell enrollment identity returned only by an
// initial assignment.
type Registration struct {
	KeyID   string
	KeyKind RegistrationKeyKind
}

// UDPEndpoint is the public native-NHP endpoint selected by the control plane.
type UDPEndpoint struct {
	Host               string
	Port               uint16
	ServerPublicKeyB64 string
}

// Assignment is one sticky cell lease and endpoint revision. LeaseExpiresAt
// must have second precision and carry the time.UTC location.
type Assignment struct {
	CellID               string
	AssignmentGeneration int64
	EndpointRevision     int64
	LeaseExpiresAt       time.Time
	Endpoint             UDPEndpoint
}

// EnrollSuccess contains the one-shot registration material issued by an
// initial assignment. AssignmentTicketExpiresAt must have second precision
// and carry the time.UTC location.
type EnrollSuccess struct {
	AgentID                   string
	Registration              Registration
	Assignment                Assignment
	AssignmentTicket          string
	AssignmentTicketExpiresAt time.Time
}

// RefreshSuccess contains only the durable sticky assignment. Its shape cannot
// carry a registration identity or assignment ticket.
type RefreshSuccess struct {
	AgentID    string
	Assignment Assignment
}

type successEnvelope[T any] struct {
	ErrCode string `json:"errCode"`
	List    T      `json:"list"`
}

type enrollListWire struct {
	Query                     string           `json:"query"`
	Version                   int              `json:"version"`
	Mode                      string           `json:"mode"`
	AgentID                   string           `json:"agent_id"`
	Registration              registrationWire `json:"registration"`
	Assignment                assignmentWire   `json:"assignment"`
	AssignmentTicket          string           `json:"assignment_ticket"`
	AssignmentTicketExpiresAt string           `json:"assignment_ticket_expires_at"`
}

type refreshListWire struct {
	Query      string         `json:"query"`
	Version    int            `json:"version"`
	Mode       string         `json:"mode"`
	AgentID    string         `json:"agent_id"`
	Assignment assignmentWire `json:"assignment"`
}

type registrationWire struct {
	KeyID   string              `json:"key_id"`
	KeyKind RegistrationKeyKind `json:"key_kind"`
}

type assignmentWire struct {
	CellID               string       `json:"cell_id"`
	AssignmentGeneration int64        `json:"assignment_generation"`
	EndpointRevision     int64        `json:"endpoint_revision"`
	LeaseExpiresAt       string       `json:"lease_expires_at"`
	Endpoint             endpointWire `json:"nhp_udp_endpoint"`
}

type endpointWire struct {
	Host               string `json:"host"`
	Port               uint16 `json:"port"`
	ServerPublicKeyB64 string `json:"server_public_key_b64"`
}

// EncodeEnrollSuccess validates and encodes the exact successful enroll LRT
// body. Protocol constants and envelope fields are not caller-controlled.
func EncodeEnrollSuccess(success EnrollSuccess) ([]byte, error) {
	if !validAgentID(success.AgentID) || !validRegistration(success.Registration) ||
		!validAssignment(success.Assignment) || !validTicket(success.AssignmentTicket) ||
		!canonicalWireTime(success.AssignmentTicketExpiresAt) ||
		!success.AssignmentTicketExpiresAt.Before(success.Assignment.LeaseExpiresAt) {
		return nil, ErrInvalidEnrollSuccess
	}

	body := successEnvelope[enrollListWire]{
		ErrCode: "0",
		List: enrollListWire{
			Query: assignmentQuery, Version: assignmentVersion, Mode: "enroll", AgentID: success.AgentID,
			Registration:              registrationWire{KeyID: success.Registration.KeyID, KeyKind: success.Registration.KeyKind},
			Assignment:                toAssignmentWire(success.Assignment),
			AssignmentTicket:          success.AssignmentTicket,
			AssignmentTicketExpiresAt: success.AssignmentTicketExpiresAt.Format(time.RFC3339),
		},
	}
	return marshalBounded(body)
}

// EncodeRefreshSuccess validates and encodes the exact successful refresh LRT
// body. The type has no registration-ticket fields by construction.
func EncodeRefreshSuccess(success RefreshSuccess) ([]byte, error) {
	if !validAgentID(success.AgentID) || !validAssignment(success.Assignment) {
		return nil, ErrInvalidRefreshSuccess
	}
	body := successEnvelope[refreshListWire]{
		ErrCode: "0",
		List: refreshListWire{
			Query: assignmentQuery, Version: assignmentVersion, Mode: "refresh", AgentID: success.AgentID,
			Assignment: toAssignmentWire(success.Assignment),
		},
	}
	return marshalBounded(body)
}

// EnrollError is the closed error vocabulary for an initial assignment.
type EnrollError uint8

const (
	EnrollErrorInvalidAPIKey EnrollError = iota + 1
	EnrollErrorRegistrationDisabled
	EnrollErrorBootstrapConsumed
	EnrollErrorInvalidInput
	EnrollErrorAssignmentUnavailable
	EnrollErrorIdentityRejected
	EnrollErrorReassignmentInProgress
	EnrollErrorAssignmentQuotaExceeded
	EnrollErrorAssignmentRateLimited
	EnrollErrorInvalidAssignmentRequest
)

// AssignmentError is the closed 522xx vocabulary available on refresh.
type AssignmentError uint8

const (
	AssignmentErrorUnavailable AssignmentError = iota + 1
	AssignmentErrorIdentityRejected
	AssignmentErrorReassignmentInProgress
	AssignmentErrorQuotaExceeded
	AssignmentErrorRateLimited
	AssignmentErrorInvalidRequest
)

type retryPolicy uint8

const (
	retryForbidden retryPolicy = iota
	retryOptional
	retryRequired
)

type errorSpec struct {
	code        string
	message     string
	retryPolicy retryPolicy
}

type errorWire struct {
	ErrCode           string  `json:"errCode"`
	ErrMsg            string  `json:"errMsg"`
	RetryAfterSeconds *uint32 `json:"retryAfterSeconds,omitempty"`
}

// EncodeEnrollError emits only a frozen 52106-52109 or 52200-52205 result.
func EncodeEnrollError(kind EnrollError, retryAfterSeconds *uint32) ([]byte, error) {
	spec, ok := enrollErrorSpec(kind)
	if !ok || !validRetry(spec.retryPolicy, retryAfterSeconds) {
		return nil, ErrInvalidEnrollError
	}
	return marshalBounded(errorWire{ErrCode: spec.code, ErrMsg: spec.message, RetryAfterSeconds: retryAfterSeconds})
}

// EncodeRefreshError emits only a frozen 52200-52205 result.
func EncodeRefreshError(kind AssignmentError, retryAfterSeconds *uint32) ([]byte, error) {
	spec, ok := assignmentErrorSpec(kind)
	if !ok || !validRetry(spec.retryPolicy, retryAfterSeconds) {
		return nil, ErrInvalidRefreshError
	}
	return marshalBounded(errorWire{ErrCode: spec.code, ErrMsg: spec.message, RetryAfterSeconds: retryAfterSeconds})
}

func enrollErrorSpec(kind EnrollError) (errorSpec, bool) {
	switch kind {
	case EnrollErrorInvalidAPIKey:
		return errorSpec{code: "52106", message: "API key invalid"}, true
	case EnrollErrorRegistrationDisabled:
		return errorSpec{code: "52107", message: "registration disabled"}, true
	case EnrollErrorBootstrapConsumed:
		return errorSpec{code: "52108", message: "bootstrap key already consumed"}, true
	case EnrollErrorInvalidInput:
		return errorSpec{code: "52109", message: "invalid enrollment input"}, true
	case EnrollErrorAssignmentUnavailable:
		return assignmentErrorSpec(AssignmentErrorUnavailable)
	case EnrollErrorIdentityRejected:
		return assignmentErrorSpec(AssignmentErrorIdentityRejected)
	case EnrollErrorReassignmentInProgress:
		return assignmentErrorSpec(AssignmentErrorReassignmentInProgress)
	case EnrollErrorAssignmentQuotaExceeded:
		return assignmentErrorSpec(AssignmentErrorQuotaExceeded)
	case EnrollErrorAssignmentRateLimited:
		return assignmentErrorSpec(AssignmentErrorRateLimited)
	case EnrollErrorInvalidAssignmentRequest:
		return assignmentErrorSpec(AssignmentErrorInvalidRequest)
	default:
		return errorSpec{}, false
	}
}

func assignmentErrorSpec(kind AssignmentError) (errorSpec, bool) {
	switch kind {
	case AssignmentErrorUnavailable:
		return errorSpec{code: "52200", message: "assignment temporarily unavailable", retryPolicy: retryOptional}, true
	case AssignmentErrorIdentityRejected:
		return errorSpec{code: "52201", message: "assignment identity rejected"}, true
	case AssignmentErrorReassignmentInProgress:
		return errorSpec{code: "52202", message: "reassignment in progress"}, true
	case AssignmentErrorQuotaExceeded:
		return errorSpec{code: "52203", message: "assignment quota exceeded"}, true
	case AssignmentErrorRateLimited:
		return errorSpec{code: "52204", message: "assignment rate limited", retryPolicy: retryRequired}, true
	case AssignmentErrorInvalidRequest:
		return errorSpec{code: "52205", message: "invalid assignment request"}, true
	default:
		return errorSpec{}, false
	}
}

func validRetry(policy retryPolicy, retryAfterSeconds *uint32) bool {
	switch policy {
	case retryForbidden:
		return retryAfterSeconds == nil
	case retryOptional:
		return retryAfterSeconds == nil || *retryAfterSeconds > 0
	case retryRequired:
		return retryAfterSeconds != nil && *retryAfterSeconds > 0
	default:
		return false
	}
}

func toAssignmentWire(assignment Assignment) assignmentWire {
	return assignmentWire{
		CellID: assignment.CellID, AssignmentGeneration: assignment.AssignmentGeneration,
		EndpointRevision: assignment.EndpointRevision, LeaseExpiresAt: assignment.LeaseExpiresAt.Format(time.RFC3339),
		Endpoint: endpointWire{
			Host: assignment.Endpoint.Host, Port: assignment.Endpoint.Port,
			ServerPublicKeyB64: assignment.Endpoint.ServerPublicKeyB64,
		},
	}
}

func validRegistration(registration Registration) bool {
	if !validAPIKeyID(registration.KeyID) {
		return false
	}
	switch registration.KeyKind {
	case KeyKindBootstrap, KeyKindConnectorBootstrap, KeyKindAccount, KeyKindAgent:
		return true
	default:
		return false
	}
}

func validAssignment(assignment Assignment) bool {
	return validCellID(assignment.CellID) && assignment.AssignmentGeneration > 0 && assignment.EndpointRevision > 0 &&
		canonicalWireTime(assignment.LeaseExpiresAt) && validEndpoint(assignment.Endpoint)
}

func validEndpoint(endpoint UDPEndpoint) bool {
	if endpoint.Port == 0 || !validLayerVDNSName(endpoint.Host) {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(endpoint.ServerPublicKeyB64)
	return err == nil && base64.StdEncoding.EncodeToString(decoded) == endpoint.ServerPublicKeyB64 && validX25519PublicKey(decoded)
}

func validX25519PublicKey(raw []byte) bool {
	if len(raw) != x25519PublicKeyBytes || !canonicalX25519U(raw) {
		return false
	}
	// X25519 clamps this probe scalar internally. Every low-order public input
	// produces the forbidden all-zero shared secret and therefore an error.
	var probe [x25519PublicKeyBytes]byte
	_, err := curve25519.X25519(probe[:], raw)
	return err == nil
}

func canonicalX25519U(raw []byte) bool {
	for i := x25519PublicKeyBytes - 1; i >= 0; i-- {
		if raw[i] != canonicalX25519UPrime[i] {
			return raw[i] < canonicalX25519UPrime[i]
		}
	}
	return false
}

func validLayerVDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil ||
		(!strings.HasSuffix(host, ".layerv.ai") && !strings.HasSuffix(host, ".layerv.xyz")) {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !lowerAlphaNumeric(b) && b != '-' {
				return false
			}
		}
	}
	return true
}

func validAgentID(value string) bool {
	if len(value) < 2 || len(value) > 64 {
		return false
	}
	for i, b := range []byte(value) {
		alphaNumeric := lowerAlphaNumeric(b)
		if (i == 0 || i == len(value)-1) && !alphaNumeric {
			return false
		}
		if !alphaNumeric && b != '-' {
			return false
		}
	}
	return true
}

func validCellID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' || value[len(value)-1] == '-' {
		return false
	}
	for _, b := range []byte(value[1:]) {
		if !lowerAlphaNumeric(b) && b != '-' {
			return false
		}
	}
	return true
}

func validAPIKeyID(value string) bool {
	if len(value) != len("key_")+12 || !strings.HasPrefix(value, "key_") {
		return false
	}
	for _, b := range []byte(value[len("key_"):]) {
		if !lowerAlphaNumeric(b) && (b < 'A' || b > 'Z') {
			return false
		}
	}
	return true
}

func validTicket(ticket string) bool {
	if len(ticket) == 0 || len(ticket) > maxAssignmentTicketBytes {
		return false
	}
	for _, b := range []byte(ticket) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func canonicalWireTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0 && value.Year() >= 1 && value.Year() <= 9999
}

func lowerAlphaNumeric(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

func marshalBounded(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, ErrAssignmentResponseEncoding
	}
	if len(body) > maxApplicationBodyBytes {
		return nil, ErrAssignmentResponseTooLarge
	}
	return body, nil
}
