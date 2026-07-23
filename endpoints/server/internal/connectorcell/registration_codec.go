package connectorcell

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"unicode"
	"unicode/utf8"

	conformance "github.com/layervai/qurl-conformance"
)

const (
	registrationAspID                  = "agent"
	registrationOTPQuery               = "agent_registration_otp"
	registrationCompletionQuery        = "agent_registration_completion"
	registrationProtocolVersion        = 1
	registrationPublicMaxBodyBytes     = 3840
	registrationCredentialMaxBytes     = 128
	registrationHostnameMaxRunes       = 253
	registrationAgentVersionMaxRunes   = 64
	registrationSuccessRAKJSON         = `{"errCode":"0","aspId":"agent"}`
	registrationInvalidRequestRAKJSON  = `{"errCode":"52109","errMsg":"invalid enrollment input","aspId":"agent"}`
	registrationCredentialRAKJSON      = `{"errCode":"52100","errMsg":"registration credential invalid","aspId":"agent"}`
	registrationTicketInvalidRAKJSON   = `{"errCode":"52110","errMsg":"assignment ticket invalid","aspId":"agent"}`
	registrationTicketExpiredRAKJSON   = `{"errCode":"52111","errMsg":"assignment ticket expired","aspId":"agent"}`
	registrationIdentityConflictJSON   = `{"errCode":"52103","errMsg":"device identity already enrolled elsewhere","aspId":"agent"}`
	registrationQuotaRAKJSON           = `{"errCode":"52112","errMsg":"agent registration quota exceeded","aspId":"agent"}`
	registrationReenrollmentRAKJSON    = `{"errCode":"52101","errMsg":"registration credential expired","aspId":"agent"}`
	registrationCompletionInvalidJSON  = `{"errCode":"52304","errMsg":"invalid completion request"}`
	registrationCompletionIdentityJSON = `{"errCode":"52301","errMsg":"completion identity rejected"}`
	registrationCompletionQuotaJSON    = `{"errCode":"52302","errMsg":"device credential quota exceeded"}`
	registrationCompletionConflictJSON = `{"errCode":"52303","errMsg":"different device credential candidate already recorded"}`
	registrationCompletionRetryJSON    = `{"errCode":"52300","errMsg":"completion temporarily unavailable","retryAfterSeconds":5}`
)

var (
	ErrInvalidOTPRequest                    = errors.New("connector cell: invalid registration OTP request")
	ErrInvalidRegistrationRequest           = errors.New("connector cell: invalid registration request")
	ErrInvalidRegistrationCompletionRequest = errors.New("connector cell: invalid registration completion request")
	ErrRegistrationRequestTooLarge          = errors.New("connector cell: registration request too large")
	ErrInvalidRegistrationAuthorityRequest  = errors.New("connector cell: invalid registration authority request")
	ErrInvalidRegistrationAuthorityResponse = errors.New("connector cell: invalid registration authority response")
)

// OTPRequest is the secret-bearing account-credential OTP request after strict
// public decoding. The public pass field is opaque printable data; the narrower
// private Authority API-key grammar is enforced before invocation. The caller
// owns and must clear the original raw body.
type OTPRequest struct {
	AssignmentTicket              string
	CredentialKeyID               string
	CredentialSecret              string
	AuthenticatedPeerPublicKeyB64 string
	AgentID                       string
	ObservedSourceAddress         string
}

// RegistrationRequest is one assigned-cell NHP_REG activation request.
type RegistrationRequest struct {
	AssignmentTicket              string
	CredentialKeyID               string
	RegistrationCredential        string
	AuthenticatedPeerPublicKeyB64 string
	AgentID                       string
	Hostname                      string
	AgentVersion                  string
}

// RegistrationCompletionRequest is the post-RAK device credential candidate.
// DeviceAPIKey is secret-bearing and must never be logged.
type RegistrationCompletionRequest struct {
	AuthenticatedPeerPublicKeyB64 string
	AgentID                       string
	DeviceAPIKey                  string
}

// DecodeOTPRequest strictly consumes the one-way assigned-cell NHP_OTP body.
// observedSource may be a canonical IP or an IPv4-mapped IPv6 address; the
// returned private request always carries netip's canonical, unmapped spelling.
func DecodeOTPRequest(raw, authenticatedPeer []byte, observedSource string) (OTPRequest, RequestRejection, error) {
	if len(authenticatedPeer) != x25519KeyBytes {
		return OTPRequest{}, RequestRejectionPeer, ErrInvalidAuthenticatedPeer
	}
	if len(raw) > registrationPublicMaxBodyBytes {
		return OTPRequest{}, RequestRejectionBodySize, ErrRegistrationRequestTooLarge
	}
	source, ok := canonicalObservedSource(observedSource)
	if !ok {
		return OTPRequest{}, RequestRejectionSemantic, ErrInvalidOTPRequest
	}
	root, data, rejection := decodeRegistrationEnvelope(
		raw,
		[]string{"usrId", "devId", "aspId", "pass", "usrData"},
		[]string{"query", "version", "assignment_ticket"},
	)
	defer clearRegistrationEnvelope(root, data)
	if rejection != "" {
		return OTPRequest{}, rejection, ErrInvalidOTPRequest
	}
	credentialKeyID, keyOK := trackedStrictString(root, "usrId")
	agentID, agentOK := trackedStrictString(root, "devId")
	aspID, aspOK := trackedStrictString(root, "aspId")
	credential, credentialOK := trackedStrictString(root, "pass")
	query, queryOK := trackedStrictString(data, "query")
	ticket, ticketOK := trackedStrictString(data, "assignment_ticket")
	if !keyOK || !agentOK || !aspOK || !credentialOK || !queryOK || !ticketOK {
		return OTPRequest{}, RequestRejectionBodyParse, ErrInvalidOTPRequest
	}
	if !validAPIKeyID(credentialKeyID) || !validAgentID(agentID) || aspID != registrationAspID ||
		query != registrationOTPQuery || !bytes.Equal(trackedSingleValue(data, "version"), []byte("1")) ||
		!validPrintableASCII(credential, 1, registrationCredentialMaxBytes) || !validAssignmentTicket(ticket) {
		return OTPRequest{}, RequestRejectionSemantic, ErrInvalidOTPRequest
	}
	return OTPRequest{
		AssignmentTicket: ticket, CredentialKeyID: credentialKeyID, CredentialSecret: credential,
		AuthenticatedPeerPublicKeyB64: base64.StdEncoding.EncodeToString(authenticatedPeer),
		AgentID:                       agentID, ObservedSourceAddress: source,
	}, "", nil
}

// DecodeRegistrationRequest strictly consumes one assigned-cell NHP_REG body.
func DecodeRegistrationRequest(raw, authenticatedPeer []byte) (RegistrationRequest, RequestRejection, error) {
	if len(authenticatedPeer) != x25519KeyBytes {
		return RegistrationRequest{}, RequestRejectionPeer, ErrInvalidAuthenticatedPeer
	}
	if len(raw) > registrationPublicMaxBodyBytes {
		return RegistrationRequest{}, RequestRejectionBodySize, ErrRegistrationRequestTooLarge
	}
	root, data, rejection := decodeRegistrationEnvelope(
		raw,
		[]string{"usrId", "devId", "aspId", "otp", "usrData"},
		[]string{"hostname", "version", "assignment_ticket"},
	)
	defer clearRegistrationEnvelope(root, data)
	if rejection != "" {
		return RegistrationRequest{}, rejection, ErrInvalidRegistrationRequest
	}
	credentialKeyID, keyOK := trackedStrictString(root, "usrId")
	agentID, agentOK := trackedStrictString(root, "devId")
	aspID, aspOK := trackedStrictString(root, "aspId")
	credential, credentialOK := trackedStrictString(root, "otp")
	hostname, hostnameOK := trackedStrictString(data, "hostname")
	agentVersion, versionOK := trackedStrictString(data, "version")
	ticket, ticketOK := trackedStrictString(data, "assignment_ticket")
	if !keyOK || !agentOK || !aspOK || !credentialOK || !hostnameOK || !versionOK || !ticketOK {
		return RegistrationRequest{}, RequestRejectionBodyParse, ErrInvalidRegistrationRequest
	}
	if !validAPIKeyID(credentialKeyID) || !validAgentID(agentID) || aspID != registrationAspID ||
		!validPrintableASCII(credential, 0, registrationCredentialMaxBytes) || !validAssignmentTicket(ticket) ||
		!validRegistrationMetadata(hostname, 1, registrationHostnameMaxRunes) ||
		!validRegistrationMetadata(agentVersion, 1, registrationAgentVersionMaxRunes) {
		return RegistrationRequest{}, RequestRejectionSemantic, ErrInvalidRegistrationRequest
	}
	return RegistrationRequest{
		AssignmentTicket: ticket, CredentialKeyID: credentialKeyID, RegistrationCredential: credential,
		AuthenticatedPeerPublicKeyB64: base64.StdEncoding.EncodeToString(authenticatedPeer),
		AgentID:                       agentID, Hostname: hostname, AgentVersion: agentVersion,
	}, "", nil
}

// DecodeRegistrationCompletionRequest strictly consumes the assigned-cell LST
// sent after a successful RAK.
func DecodeRegistrationCompletionRequest(raw, authenticatedPeer []byte) (RegistrationCompletionRequest, RequestRejection, error) {
	if len(authenticatedPeer) != x25519KeyBytes {
		return RegistrationCompletionRequest{}, RequestRejectionPeer, ErrInvalidAuthenticatedPeer
	}
	if len(raw) > registrationPublicMaxBodyBytes {
		return RegistrationCompletionRequest{}, RequestRejectionBodySize, ErrRegistrationRequestTooLarge
	}
	root, data, rejection := decodeRegistrationEnvelope(
		raw,
		[]string{"usrId", "devId", "aspId", "usrData"},
		[]string{"query", "version", "device_api_key"},
	)
	defer clearRegistrationEnvelope(root, data)
	if rejection != "" {
		return RegistrationCompletionRequest{}, rejection, ErrInvalidRegistrationCompletionRequest
	}
	userID, userOK := trackedStrictString(root, "usrId")
	agentID, agentOK := trackedStrictString(root, "devId")
	aspID, aspOK := trackedStrictString(root, "aspId")
	query, queryOK := trackedStrictString(data, "query")
	deviceAPIKey, keyOK := trackedStrictString(data, "device_api_key")
	if !userOK || !agentOK || !aspOK || !queryOK || !keyOK {
		return RegistrationCompletionRequest{}, RequestRejectionBodyParse, ErrInvalidRegistrationCompletionRequest
	}
	if userID != "" || !validAgentID(agentID) || aspID != registrationAspID || query != registrationCompletionQuery ||
		!bytes.Equal(trackedSingleValue(data, "version"), []byte("1")) || !validAPIKey(deviceAPIKey) {
		return RegistrationCompletionRequest{}, RequestRejectionSemantic, ErrInvalidRegistrationCompletionRequest
	}
	return RegistrationCompletionRequest{
		AuthenticatedPeerPublicKeyB64: base64.StdEncoding.EncodeToString(authenticatedPeer),
		AgentID:                       agentID, DeviceAPIKey: deviceAPIKey,
	}, "", nil
}

func decodeRegistrationEnvelope(raw []byte, rootKeys, dataKeys []string) (*trackedObject, *trackedObject, RequestRejection) {
	if !utf8.Valid(raw) {
		return nil, nil, RequestRejectionBodyParse
	}
	var data *trackedObject
	root := decodeTrackedObject(raw, func(key string, value json.RawMessage) bool {
		if key != "usrData" {
			return true
		}
		decoded := decodeTrackedObject(value, nil, dataKeys...)
		if data == nil {
			data = decoded
		} else {
			decoded.clear()
		}
		return false
	}, rootKeys...)
	if rejection := root.strictRejection(rootKeys...); rejection != "" {
		return root, data, rejection
	}
	if root.count("usrData") != 1 || data == nil {
		return root, data, RequestRejectionBodyParse
	}
	return root, data, data.strictRejection(dataKeys...)
}

func clearRegistrationEnvelope(root, data *trackedObject) {
	root.clear()
	data.clear()
}

func canonicalObservedSource(value string) (string, bool) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return "", false
	}
	return address.Unmap().String(), true
}

func validAssignmentTicket(value string) bool {
	return validPrintableASCII(value, 1, conformance.ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes)
}

func validPrintableASCII(value string, minBytes, maxBytes int) bool {
	if len(value) < minBytes || len(value) > maxBytes {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validRegistrationMetadata(value string, minRunes, maxRunes int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	runes := utf8.RuneCountInString(value)
	if runes < minRunes || runes > maxRunes {
		return false
	}
	for _, character := range value {
		if !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

type registrationAuthorityOperation uint8

const (
	registrationAuthorityOTP registrationAuthorityOperation = iota + 1
	registrationAuthorityActivate
	registrationAuthorityComplete
)

func encodeOTPAuthorityRequest(request OTPRequest) ([]byte, error) {
	// This is intentionally narrower than DecodeOTPRequest: qurl-conformance's
	// public golden uses an opaque synthetic credential, while the private
	// Authority contract accepts only canonical LayerV API keys. Never send a
	// public-valid but private-invalid credential across the capability boundary.
	if !validAssignmentTicket(request.AssignmentTicket) || !validAPIKeyID(request.CredentialKeyID) ||
		!validAPIKey(request.CredentialSecret) ||
		!validPeer(request.AuthenticatedPeerPublicKeyB64) || !validAgentID(request.AgentID) {
		return nil, ErrInvalidRegistrationAuthorityRequest
	}
	if source, ok := canonicalObservedSource(request.ObservedSourceAddress); !ok || source != request.ObservedSourceAddress {
		return nil, ErrInvalidRegistrationAuthorityRequest
	}
	return encodeRegistrationAuthorityFields(
		authorityStringField{"assignment_ticket", request.AssignmentTicket},
		authorityStringField{"credential_key_id", request.CredentialKeyID},
		authorityStringField{"credential_secret", request.CredentialSecret},
		authorityStringField{"authenticated_peer_public_key_b64", request.AuthenticatedPeerPublicKeyB64},
		authorityStringField{"agent_id", request.AgentID},
		authorityStringField{"observed_source_address", request.ObservedSourceAddress},
	)
}

func encodeActivationAuthorityRequest(request RegistrationRequest) ([]byte, error) {
	if !validAssignmentTicket(request.AssignmentTicket) || !validAPIKeyID(request.CredentialKeyID) ||
		!validPrintableASCII(request.RegistrationCredential, 0, registrationCredentialMaxBytes) ||
		!validPeer(request.AuthenticatedPeerPublicKeyB64) || !validAgentID(request.AgentID) ||
		!validRegistrationMetadata(request.Hostname, 1, registrationHostnameMaxRunes) ||
		!validRegistrationMetadata(request.AgentVersion, 1, registrationAgentVersionMaxRunes) {
		return nil, ErrInvalidRegistrationAuthorityRequest
	}
	return encodeRegistrationAuthorityFields(
		authorityStringField{"assignment_ticket", request.AssignmentTicket},
		authorityStringField{"credential_key_id", request.CredentialKeyID},
		authorityStringField{"registration_credential", request.RegistrationCredential},
		authorityStringField{"authenticated_peer_public_key_b64", request.AuthenticatedPeerPublicKeyB64},
		authorityStringField{"agent_id", request.AgentID},
		authorityStringField{"hostname", request.Hostname},
		authorityStringField{"agent_version", request.AgentVersion},
	)
}

func encodeRegistrationCompletionAuthorityRequest(request RegistrationCompletionRequest) ([]byte, error) {
	if !validPeer(request.AuthenticatedPeerPublicKeyB64) || !validAgentID(request.AgentID) || !validAPIKey(request.DeviceAPIKey) {
		return nil, ErrInvalidRegistrationAuthorityRequest
	}
	return encodeRegistrationAuthorityFields(
		authorityStringField{"authenticated_peer_public_key_b64", request.AuthenticatedPeerPublicKeyB64},
		authorityStringField{"agent_id", request.AgentID},
		authorityStringField{"device_api_key", request.DeviceAPIKey},
	)
}

type authorityStringField struct {
	name  string
	value string
}

// encodeRegistrationAuthorityFields builds the private body in one exact-size
// owned buffer. It mirrors encoding/json's string escaping without using its
// pooled encoder, which could retain secret-bearing bytes after this handler's
// explicit clear.
func encodeRegistrationAuthorityFields(fields ...authorityStringField) ([]byte, error) {
	wantBytes := len(`{"version":1`) + 1
	for _, field := range fields {
		wantBytes += len(field.name) + 4 + authorityJSONStringBytes(field.value)
	}
	if wantBytes > conformance.ConnectorAuthorityLambdaMaxRequestBytes {
		return nil, ErrInvalidRegistrationAuthorityRequest
	}
	body := make([]byte, 0, wantBytes)
	body = append(body, `{"version":1`...)
	for _, field := range fields {
		body = append(body, ',', '"')
		body = append(body, field.name...)
		body = append(body, '"', ':')
		body = appendAuthorityJSONString(body, field.value)
	}
	body = append(body, '}')
	if len(body) != wantBytes || cap(body) != wantBytes {
		clear(body)
		return nil, ErrInvalidRegistrationAuthorityRequest
	}
	return body, nil
}

// authorityJSONStringBytes is the sizing pass paired with appendAuthorityJSONString.
// The two MUST keep identical escape tables: encodeRegistrationAuthorityFields
// fails closed if len(body) != wantBytes, so any divergence rejects otherwise
// valid requests. Their agreement with encoding/json is pinned by
// TestRegistrationAuthorityEncoderEscapesWithoutGrowingSecretBuffer. Kept as two
// passes (rather than a single-pass escaper) so the buffer is allocated at exact
// size and every secret-bearing byte is clearable.
func authorityJSONStringBytes(value string) int {
	bytes := 2 // surrounding quotes
	for _, character := range value {
		switch character {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			bytes += 2
		case '<', '>', '&', '\u2028', '\u2029':
			bytes += 6
		default:
			if character < 0x20 {
				bytes += 6
			} else {
				bytes += utf8.RuneLen(character)
			}
		}
	}
	return bytes
}

// appendAuthorityJSONString is the emit pass; keep its escape table byte-for-byte
// in lockstep with authorityJSONStringBytes above.
func appendAuthorityJSONString(body []byte, value string) []byte {
	const hex = "0123456789abcdef"
	body = append(body, '"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			body = append(body, '\\', byte(character))
		case '\b':
			body = append(body, `\b`...)
		case '\f':
			body = append(body, `\f`...)
		case '\n':
			body = append(body, `\n`...)
		case '\r':
			body = append(body, `\r`...)
		case '\t':
			body = append(body, `\t`...)
		case '<':
			body = append(body, `\u003c`...)
		case '>':
			body = append(body, `\u003e`...)
		case '&':
			body = append(body, `\u0026`...)
		case '\u2028':
			body = append(body, `\u2028`...)
		case '\u2029':
			body = append(body, `\u2029`...)
		default:
			if character < 0x20 {
				body = append(body, '\\', 'u', '0', '0', hex[character>>4], hex[character&0xf])
			} else {
				body = utf8.AppendRune(body, character)
			}
		}
	}
	return append(body, '"')
}

type registrationAuthorityOutcome uint8

const (
	registrationAuthoritySuccess registrationAuthorityOutcome = iota + 1
	registrationAuthoritySemanticError
)

func decodeRegistrationAuthorityResponse(operation registrationAuthorityOperation, raw []byte) ([]byte, RegistrationAction, registrationAuthorityOutcome, error) {
	if len(raw) == 0 || len(raw) > conformance.ConnectorAuthorityLambdaMaxResponseBytes || !utf8.Valid(raw) {
		return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
	}
	envelope, err := decodeAuthorityObject(raw, []string{"version"}, []string{"version", "result", "error"})
	if err != nil {
		return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
	}
	defer clearRawObject(envelope)
	if !bytes.Equal(envelope["version"], []byte("1")) {
		return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
	}
	result, hasResult := envelope["result"]
	errorBody, hasError := envelope["error"]
	if hasResult == hasError || bytes.Equal(result, []byte("null")) || bytes.Equal(errorBody, []byte("null")) {
		return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
	}
	if hasResult {
		return decodeRegistrationAuthoritySuccess(operation, result)
	}
	return decodeRegistrationAuthorityError(operation, errorBody)
}

func decodeRegistrationAuthoritySuccess(operation registrationAuthorityOperation, raw []byte) ([]byte, RegistrationAction, registrationAuthorityOutcome, error) {
	switch operation {
	case registrationAuthorityOTP, registrationAuthorityActivate:
		// Both OTP and activation success are the empty result object; only the
		// permitted application framing differs.
		object, err := decodeAuthorityObject(raw, nil, nil)
		defer clearRawObject(object)
		if err != nil || len(object) != 0 {
			return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
		}
		if operation == registrationAuthorityActivate {
			return []byte(registrationSuccessRAKJSON), RegistrationActionEmitRAK, registrationAuthoritySuccess, nil
		}
		return nil, RegistrationActionNoApplicationReply, registrationAuthoritySuccess, nil
	case registrationAuthorityComplete:
		object, err := decodeAuthorityObject(raw, []string{"device_api_key_id"}, []string{"device_api_key_id"})
		defer clearRawObject(object)
		if err != nil {
			return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
		}
		keyID, ok := strictString(object["device_api_key_id"])
		if !ok || !validAPIKeyID(keyID) {
			return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
		}
		body, err := json.Marshal(registrationCompletionSuccessWire{
			ErrCode: "0",
			List: registrationCompletionListWire{
				Query: registrationCompletionQuery, Version: registrationProtocolVersion, DeviceAPIKeyID: keyID,
			},
		})
		if err != nil || len(body) > registrationPublicMaxBodyBytes {
			clear(body)
			return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
		}
		return body, RegistrationActionEmitLRT, registrationAuthoritySuccess, nil
	default:
		return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
	}
}

// These types intentionally remain separate from the legacy completion wire
// types in codec.go. Their current JSON shape is identical, but the two frozen
// protocol contracts may evolve independently and must not change in lockstep
// by accident.
type registrationCompletionListWire struct {
	Query          string `json:"query"`
	Version        int    `json:"version"`
	DeviceAPIKeyID string `json:"device_api_key_id"`
}

type registrationCompletionSuccessWire struct {
	ErrCode string                         `json:"errCode"`
	List    registrationCompletionListWire `json:"list"`
}

func decodeRegistrationAuthorityError(operation registrationAuthorityOperation, raw []byte) ([]byte, RegistrationAction, registrationAuthorityOutcome, error) {
	allowed := []string{"code"}
	if operation == registrationAuthorityOTP {
		allowed = append(allowed, "retry_after_seconds")
	}
	object, err := decodeAuthorityObject(raw, []string{"code"}, allowed)
	defer clearRawObject(object)
	if err != nil {
		return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
	}
	code, ok := strictString(object["code"])
	if !ok {
		return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
	}
	retryAfter, hasRetryAfter := object["retry_after_seconds"]
	switch operation {
	case registrationAuthorityOTP:
		if code == "rate_limited" {
			if !hasRetryAfter || !strictPositiveInteger(retryAfter) {
				return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
			}
		} else if hasRetryAfter {
			return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
		}
		switch code {
		case "invalid_request", "rejected", "email_unavailable", "rate_limited", "send_failed", "unavailable":
			return nil, RegistrationActionNoApplicationReply, registrationAuthoritySemanticError, nil
		}
	case registrationAuthorityActivate:
		var body string
		switch code {
		case "invalid_request":
			body = registrationInvalidRequestRAKJSON
		case "credential_rejected":
			body = registrationCredentialRAKJSON
		case "ticket_invalid", "not_yet_valid":
			body = registrationTicketInvalidRAKJSON
		case "ticket_expired":
			body = registrationTicketExpiredRAKJSON
		case "identity_conflict":
			body = registrationIdentityConflictJSON
		case "quota":
			body = registrationQuotaRAKJSON
		case "reenrollment_required":
			body = registrationReenrollmentRAKJSON
		case "unavailable":
			return nil, RegistrationActionDropNoReply, registrationAuthoritySemanticError, nil
		default:
			return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
		}
		return []byte(body), RegistrationActionEmitRAK, registrationAuthoritySemanticError, nil
	case registrationAuthorityComplete:
		var body string
		switch code {
		case "invalid_request":
			body = registrationCompletionInvalidJSON
		case "identity_rejected":
			body = registrationCompletionIdentityJSON
		case "quota":
			body = registrationCompletionQuotaJSON
		case "conflict":
			body = registrationCompletionConflictJSON
		case "unavailable":
			body = registrationCompletionRetryJSON
		default:
			return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
		}
		return []byte(body), RegistrationActionEmitLRT, registrationAuthoritySemanticError, nil
	}
	return nil, "", 0, ErrInvalidRegistrationAuthorityResponse
}

func strictPositiveInteger(raw json.RawMessage) bool {
	text := string(raw)
	value, err := strconv.ParseInt(text, 10, 64)
	return err == nil && value > 0 && strconv.FormatInt(value, 10) == text
}
