package connectorcell

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

func TestRegistrationPublicGoldensDecode(t *testing.T) {
	t.Parallel()
	assignment := mustAgentAssignment(t)
	authority := mustConnectorAuthority(t)
	peer := registrationPeer(t, authority)

	otp, rejection, err := DecodeOTPRequest(
		[]byte(assignment.AccountCredentialOTP.Request.BodyJSON), peer, authority.Fixtures.ObservedSourceAddress,
	)
	if err != nil || rejection != "" || otp.AgentID != assignment.AccountCredentialOTP.EnrollmentBinding.RequestAgentID ||
		otp.CredentialKeyID != assignment.AccountCredentialOTP.EnrollmentBinding.RequestRegistrationKeyID ||
		otp.CredentialSecret != assignment.AccountCredentialOTP.EnrollmentBinding.RequestCredential ||
		otp.AssignmentTicket != assignment.AccountCredentialOTP.EnrollmentBinding.RequestAssignmentTicket {
		t.Fatalf("DecodeOTPRequest = %#v, %q, %v", otp, rejection, err)
	}

	registration, rejection, err := DecodeRegistrationRequest(
		[]byte(assignment.AssignedCellRegistration.Request.BodyJSON), peer,
	)
	if err != nil || rejection != "" || registration.AgentID != authority.Fixtures.AgentID ||
		registration.AssignmentTicket == "" || registration.CredentialKeyID == "" || registration.RegistrationCredential == "" {
		t.Fatalf("DecodeRegistrationRequest = %#v, %q, %v", registration, rejection, err)
	}

	completion, rejection, err := DecodeRegistrationCompletionRequest(
		[]byte(assignment.RegistrationCompletion.Request.BodyJSON), peer,
	)
	if err != nil || rejection != "" || completion.AgentID != authority.Fixtures.AgentID || completion.DeviceAPIKey == "" {
		t.Fatalf("DecodeRegistrationCompletionRequest = %#v, %q, %v", completion, rejection, err)
	}
}

func TestRegistrationPublicToPrivateGoldenMappings(t *testing.T) {
	t.Parallel()
	assignment := mustAgentAssignment(t)
	authority := mustConnectorAuthority(t)
	peer := registrationPeer(t, authority)

	otpBody := authorityCompatibleOTPBody(assignment, authority)
	otp, rejection, err := DecodeOTPRequest([]byte(otpBody), peer, authority.Fixtures.ObservedSourceAddress)
	if err != nil || rejection != "" {
		t.Fatalf("DecodeOTPRequest = %#v, %q, %v", otp, rejection, err)
	}
	payload, err := encodeOTPAuthorityRequest(otp)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(payload), authority.Operations[conformance.ConnectorAuthorityOperationIssueRegistrationOTP].RequestGolden.BodyJSON; got != want {
		t.Fatalf("OTP private request:\n got: %s\nwant: %s", got, want)
	}
	second, err := encodeOTPAuthorityRequest(otp)
	if err != nil || !bytes.Equal(payload, second) {
		t.Fatalf("OTP encoding is not deterministic: %v", err)
	}
	clear(second)
	clear(payload)

	registrationBody := replaceGoldenValues(assignment.AssignedCellRegistration.Request.BodyJSON, [][2]string{
		{registrationValue(t, assignment.AssignedCellRegistration.Request.BodyJSON, "usrId"), authority.Fixtures.CredentialKeyID},
		{registrationValue(t, assignment.AssignedCellRegistration.Request.BodyJSON, "otp"), authority.Fixtures.RegistrationCredential},
		{registrationDataValue(t, assignment.AssignedCellRegistration.Request.BodyJSON, "assignment_ticket"), authority.Fixtures.AssignmentTicket},
		{registrationDataValue(t, assignment.AssignedCellRegistration.Request.BodyJSON, "hostname"), authority.Fixtures.Hostname},
		{registrationDataValue(t, assignment.AssignedCellRegistration.Request.BodyJSON, "version"), authority.Fixtures.AgentVersion},
	})
	registration, rejection, err := DecodeRegistrationRequest([]byte(registrationBody), peer)
	if err != nil || rejection != "" {
		t.Fatalf("DecodeRegistrationRequest = %#v, %q, %v", registration, rejection, err)
	}
	payload, err = encodeActivationAuthorityRequest(registration)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(payload), authority.Operations[conformance.ConnectorAuthorityOperationActivateRegistration].RequestGolden.BodyJSON; got != want {
		t.Fatalf("activation private request:\n got: %s\nwant: %s", got, want)
	}
	second, err = encodeActivationAuthorityRequest(registration)
	if err != nil || !bytes.Equal(payload, second) {
		t.Fatalf("activation encoding is not deterministic: %v", err)
	}
	clear(second)
	clear(payload)

	completionBody := replaceGoldenValues(assignment.RegistrationCompletion.Request.BodyJSON, [][2]string{
		{registrationDataValue(t, assignment.RegistrationCompletion.Request.BodyJSON, "device_api_key"), authority.Fixtures.DeviceAPIKey},
	})
	completion, rejection, err := DecodeRegistrationCompletionRequest([]byte(completionBody), peer)
	if err != nil || rejection != "" {
		t.Fatalf("DecodeRegistrationCompletionRequest = %#v, %q, %v", completion, rejection, err)
	}
	payload, err = encodeRegistrationCompletionAuthorityRequest(completion)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(payload), authority.Operations[conformance.ConnectorAuthorityOperationCompleteRegistration].RequestGolden.BodyJSON; got != want {
		t.Fatalf("completion private request:\n got: %s\nwant: %s", got, want)
	}
	second, err = encodeRegistrationCompletionAuthorityRequest(completion)
	if err != nil || !bytes.Equal(payload, second) {
		t.Fatalf("completion encoding is not deterministic: %v", err)
	}
	clear(second)
	clear(payload)
}

func TestRegistrationPublicRequestRejects(t *testing.T) {
	t.Parallel()
	assignment := mustAgentAssignment(t)
	authority := mustConnectorAuthority(t)
	peer := registrationPeer(t, authority)

	for _, test := range assignment.AccountCredentialOTP.RequestCases {
		if test.RejectClass == "wrong_phase" {
			continue // Header type belongs to the future dispatcher, outside this codec.
		}
		t.Run("otp/"+test.Name, func(t *testing.T) {
			request, rejection, err := DecodeOTPRequest([]byte(test.BodyJSON), peer, authority.Fixtures.ObservedSourceAddress)
			if err == nil || request != (OTPRequest{}) {
				t.Fatalf("DecodeOTPRequest = %#v, %v", request, err)
			}
			assertVectorRejectionClass(t, test.RejectClass, rejection)
		})
	}
	for _, test := range assignment.RequestCases {
		test := test
		switch test.Phase {
		case "assigned_cell_registration":
			t.Run("registration/"+test.Name, func(t *testing.T) {
				request, rejection, err := DecodeRegistrationRequest([]byte(test.BodyJSON), peer)
				if err == nil || request != (RegistrationRequest{}) {
					t.Fatalf("DecodeRegistrationRequest = %#v, %v", request, err)
				}
				assertVectorRejectionClass(t, test.RejectClass, rejection)
			})
		case "registration_completion":
			t.Run("completion/"+test.Name, func(t *testing.T) {
				request, rejection, err := DecodeRegistrationCompletionRequest([]byte(test.BodyJSON), peer)
				if err == nil || request != (RegistrationCompletionRequest{}) {
					t.Fatalf("DecodeRegistrationCompletionRequest = %#v, %v", request, err)
				}
				assertVectorRejectionClass(t, test.RejectClass, rejection)
			})
		}
	}
}

func TestRegistrationCodecBoundaryValidation(t *testing.T) {
	t.Parallel()
	assignment := mustAgentAssignment(t)
	authority := mustConnectorAuthority(t)
	peer := registrationPeer(t, authority)
	otpBody := []byte(authorityCompatibleOTPBody(assignment, authority))

	for _, source := range []string{"203.0.113.10:62206", "fe80::1%eth0", "not-an-ip"} {
		request, rejection, err := DecodeOTPRequest(otpBody, peer, source)
		if request != (OTPRequest{}) || rejection != RequestRejectionSemantic || !errors.Is(err, ErrInvalidOTPRequest) {
			t.Fatalf("source %q = %#v, %q, %v", source, request, rejection, err)
		}
	}
	request, rejection, err := DecodeOTPRequest(otpBody, peer, "::ffff:203.0.113.10")
	if err != nil || rejection != "" || request.ObservedSourceAddress != "203.0.113.10" {
		t.Fatalf("mapped source = %#v, %q, %v", request, rejection, err)
	}

	request, rejection, err = DecodeOTPRequest(otpBody, peer[:31], authority.Fixtures.ObservedSourceAddress)
	if request != (OTPRequest{}) || rejection != RequestRejectionPeer || !errors.Is(err, ErrInvalidAuthenticatedPeer) {
		t.Fatalf("short peer = %#v, %q, %v", request, rejection, err)
	}

	oversize := bytes.Repeat([]byte{' '}, registrationPublicMaxBodyBytes+1)
	if request, rejection, err = DecodeOTPRequest(oversize, peer, authority.Fixtures.ObservedSourceAddress); request != (OTPRequest{}) ||
		rejection != RequestRejectionBodySize || !errors.Is(err, ErrRegistrationRequestTooLarge) {
		t.Fatalf("oversize = %#v, %q, %v", request, rejection, err)
	}
	if got, want := registrationPublicMaxBodyBytes, assignment.AccountCredentialOTP.PacketSizeContract.MaxPlaintextBodyBytes; got != want {
		t.Fatalf("public body ceiling = %d, conformance = %d", got, want)
	}
}

func TestRegistrationAuthorityResponseRejectsConformanceCases(t *testing.T) {
	t.Parallel()
	authority := mustConnectorAuthority(t)
	operations := []struct {
		name string
		op   registrationAuthorityOperation
	}{
		{conformance.ConnectorAuthorityOperationIssueRegistrationOTP, registrationAuthorityOTP},
		{conformance.ConnectorAuthorityOperationActivateRegistration, registrationAuthorityActivate},
		{conformance.ConnectorAuthorityOperationCompleteRegistration, registrationAuthorityComplete},
	}
	for _, operation := range operations {
		operation := operation
		for _, test := range authority.Operations[operation.name].ResponseProducerRejects {
			test := test
			t.Run(operation.name+"/"+test.Name, func(t *testing.T) {
				body := connectorAuthorityRejectBody(t, test)
				public, action, outcome, err := decodeRegistrationAuthorityResponse(operation.op, body)
				if public != nil || action != "" || outcome != 0 || !errors.Is(err, ErrInvalidRegistrationAuthorityResponse) {
					t.Fatalf("decode = %q, %q, %d, %v", public, action, outcome, err)
				}
			})
		}
	}
}

func TestRegistrationAuthorityEncoderEscapesWithoutGrowingSecretBuffer(t *testing.T) {
	t.Parallel()
	authority := mustConnectorAuthority(t)
	request := RegistrationRequest{
		AssignmentTicket:              strings.Repeat(`"\\`, 500),
		CredentialKeyID:               authority.Fixtures.CredentialKeyID,
		RegistrationCredential:        `code"\\value<>&`,
		AuthenticatedPeerPublicKeyB64: authority.Fixtures.AuthenticatedPeerPublicKeyB64,
		AgentID:                       authority.Fixtures.AgentID,
		Hostname:                      `builder-雪-"\\<>&`,
		AgentVersion:                  `v1-雪-"\\<>&`,
	}
	body, err := encodeActivationAuthorityRequest(request)
	if err != nil {
		t.Fatalf("encodeActivationAuthorityRequest: %v", err)
	}
	if cap(body) != len(body) || len(body) > conformance.ConnectorAuthorityLambdaMaxRequestBytes {
		t.Fatalf("encoded len/cap = %d/%d", len(body), cap(body))
	}
	want, err := json.Marshal(conformance.ConnectorAuthorityActivateRegistrationRequest{
		Version: registrationProtocolVersion, AssignmentTicket: request.AssignmentTicket,
		CredentialKeyID: request.CredentialKeyID, RegistrationCredential: request.RegistrationCredential,
		AuthenticatedPeerPublicKeyB64: request.AuthenticatedPeerPublicKeyB64,
		AgentID:                       request.AgentID, Hostname: request.Hostname, AgentVersion: request.AgentVersion,
	})
	if err != nil || !bytes.Equal(body, want) {
		t.Fatalf("manual encoder differs from encoding/json:\n got: %s\nwant: %s\nerr: %v", body, want, err)
	}
	clear(body)
	clear(want)
}

func TestRegistrationAuthorityRequestRejectsAreUnreachableByConstruction(t *testing.T) {
	t.Parallel()
	authority := mustConnectorAuthority(t)
	operations := []struct {
		name   string
		fields []string
		encode func() ([]byte, error)
	}{
		{
			name: conformance.ConnectorAuthorityOperationIssueRegistrationOTP,
			fields: []string{
				"version", "assignment_ticket", "credential_key_id", "credential_secret",
				"authenticated_peer_public_key_b64", "agent_id", "observed_source_address",
			},
			encode: func() ([]byte, error) {
				return encodeOTPAuthorityRequest(OTPRequest{
					AssignmentTicket: authority.Fixtures.AssignmentTicket, CredentialKeyID: authority.Fixtures.CredentialKeyID,
					CredentialSecret: authority.Fixtures.Credential, AuthenticatedPeerPublicKeyB64: authority.Fixtures.AuthenticatedPeerPublicKeyB64,
					AgentID: authority.Fixtures.AgentID, ObservedSourceAddress: authority.Fixtures.ObservedSourceAddress,
				})
			},
		},
		{
			name: conformance.ConnectorAuthorityOperationActivateRegistration,
			fields: []string{
				"version", "assignment_ticket", "credential_key_id", "registration_credential",
				"authenticated_peer_public_key_b64", "agent_id", "hostname", "agent_version",
			},
			encode: func() ([]byte, error) {
				return encodeActivationAuthorityRequest(RegistrationRequest{
					AssignmentTicket: authority.Fixtures.AssignmentTicket, CredentialKeyID: authority.Fixtures.CredentialKeyID,
					RegistrationCredential:        authority.Fixtures.RegistrationCredential,
					AuthenticatedPeerPublicKeyB64: authority.Fixtures.AuthenticatedPeerPublicKeyB64,
					AgentID:                       authority.Fixtures.AgentID, Hostname: authority.Fixtures.Hostname, AgentVersion: authority.Fixtures.AgentVersion,
				})
			},
		},
		{
			name:   conformance.ConnectorAuthorityOperationCompleteRegistration,
			fields: []string{"version", "authenticated_peer_public_key_b64", "agent_id", "device_api_key"},
			encode: func() ([]byte, error) {
				return encodeRegistrationCompletionAuthorityRequest(RegistrationCompletionRequest{
					AuthenticatedPeerPublicKeyB64: authority.Fixtures.AuthenticatedPeerPublicKeyB64,
					AgentID:                       authority.Fixtures.AgentID, DeviceAPIKey: authority.Fixtures.DeviceAPIKey,
				})
			},
		},
	}
	for _, operation := range operations {
		operation := operation
		t.Run(operation.name, func(t *testing.T) {
			body, err := operation.encode()
			if err != nil || !canonicalPrivateRegistrationRequest(body, operation.fields) {
				t.Fatalf("typed encoder produced non-canonical body %q: %v", body, err)
			}
			defer clear(body)
			for _, reject := range authority.Operations[operation.name].RequestRejects {
				rejectBody := connectorAuthorityRejectBody(t, reject)
				if canonicalPrivateRegistrationRequest(rejectBody, operation.fields) {
					t.Fatalf("private reject %q was accepted as canonical", reject.Name)
				}
				clear(rejectBody)
			}
		})
	}

	tooLargeTicket := strings.Repeat(`"`, conformance.ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes)
	if body, err := encodeOTPAuthorityRequest(OTPRequest{
		AssignmentTicket: tooLargeTicket, CredentialKeyID: authority.Fixtures.CredentialKeyID,
		CredentialSecret: authority.Fixtures.Credential, AuthenticatedPeerPublicKeyB64: authority.Fixtures.AuthenticatedPeerPublicKeyB64,
		AgentID: authority.Fixtures.AgentID, ObservedSourceAddress: authority.Fixtures.ObservedSourceAddress,
	}); body != nil || !errors.Is(err, ErrInvalidRegistrationAuthorityRequest) {
		t.Fatalf("oversize OTP body = %q, %v", body, err)
	}
	if body, err := encodeActivationAuthorityRequest(RegistrationRequest{
		AssignmentTicket: tooLargeTicket, CredentialKeyID: authority.Fixtures.CredentialKeyID,
		RegistrationCredential:        authority.Fixtures.RegistrationCredential,
		AuthenticatedPeerPublicKeyB64: authority.Fixtures.AuthenticatedPeerPublicKeyB64,
		AgentID:                       authority.Fixtures.AgentID, Hostname: authority.Fixtures.Hostname, AgentVersion: authority.Fixtures.AgentVersion,
	}); body != nil || !errors.Is(err, ErrInvalidRegistrationAuthorityRequest) {
		t.Fatalf("oversize activation body = %q, %v", body, err)
	}
}

func canonicalPrivateRegistrationRequest(body []byte, fields []string) bool {
	if len(body) == 0 || len(body) > conformance.ConnectorAuthorityLambdaMaxRequestBytes {
		return false
	}
	object, err := decodeAuthorityObject(body, fields, fields)
	if err != nil {
		return false
	}
	defer clearRawObject(object)
	if !bytes.Equal(object["version"], []byte("1")) {
		return false
	}
	for _, field := range fields[1:] {
		if _, ok := strictString(object[field]); !ok {
			return false
		}
	}
	return true
}

func authorityCompatibleOTPBody(assignment *conformance.AgentAssignmentFile, authority *conformance.ConnectorAuthorityLambdaFile) string {
	return replaceGoldenValues(assignment.AccountCredentialOTP.Request.BodyJSON, [][2]string{
		{assignment.AccountCredentialOTP.EnrollmentBinding.RequestAssignmentTicket, authority.Fixtures.AssignmentTicket},
		{assignment.AccountCredentialOTP.EnrollmentBinding.RequestRegistrationKeyID, authority.Fixtures.CredentialKeyID},
		{assignment.AccountCredentialOTP.EnrollmentBinding.RequestCredential, authority.Fixtures.Credential},
	})
}

func assertVectorRejectionClass(t *testing.T, vectorClass string, got RequestRejection) {
	t.Helper()
	switch vectorClass {
	case "body_parse", "unknown_field", "wrong_type":
		if got != RequestRejectionBodyParse {
			t.Fatalf("rejection = %q for vector class %q, want body_parse", got, vectorClass)
		}
	case "missing_field", "semantic":
		if got != RequestRejectionSemantic {
			t.Fatalf("rejection = %q for vector class %q, want semantic", got, vectorClass)
		}
	default:
		t.Fatalf("unhandled conformance rejection class %q", vectorClass)
	}
}

func mustAgentAssignment(t *testing.T) *conformance.AgentAssignmentFile {
	t.Helper()
	file, err := conformance.AgentAssignmentGolden()
	if err != nil {
		t.Fatalf("AgentAssignmentGolden: %v", err)
	}
	return file
}

func mustConnectorAuthority(t *testing.T) *conformance.ConnectorAuthorityLambdaFile {
	t.Helper()
	file, err := conformance.ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda: %v", err)
	}
	return file
}

func registrationPeer(t *testing.T, authority *conformance.ConnectorAuthorityLambdaFile) []byte {
	t.Helper()
	peer, err := base64.StdEncoding.Strict().DecodeString(authority.Fixtures.AuthenticatedPeerPublicKeyB64)
	if err != nil || len(peer) != x25519KeyBytes {
		t.Fatalf("decode peer: %v, len=%d", err, len(peer))
	}
	return peer
}

func replaceGoldenValues(body string, replacements [][2]string) string {
	for _, replacement := range replacements {
		body = strings.Replace(body, replacement[0], replacement[1], 1)
	}
	return body
}

func registrationValue(t *testing.T, body, key string) string {
	t.Helper()
	root := decodeTrackedObject([]byte(body), nil, "usrId", "devId", "aspId", "otp", "usrData")
	defer root.clear()
	value, ok := trackedStrictString(root, key)
	if !ok {
		t.Fatalf("missing string %q in %s", key, body)
	}
	return value
}

func registrationDataValue(t *testing.T, body, key string) string {
	t.Helper()
	var data *trackedObject
	root := decodeTrackedObject([]byte(body), func(name string, value json.RawMessage) bool {
		if name == "usrData" {
			data = decodeTrackedObject(value, nil, "query", "version", "device_api_key", "hostname", "assignment_ticket")
			return false
		}
		return true
	}, "usrId", "devId", "aspId", "otp", "usrData")
	defer clearRegistrationEnvelope(root, data)
	value, ok := trackedStrictString(data, key)
	if !ok {
		t.Fatalf("missing usrData string %q in %s", key, body)
	}
	return value
}

func connectorAuthorityRejectBody(t *testing.T, test conformance.ConnectorAuthorityLambdaRejectCase) []byte {
	t.Helper()
	if test.DerivedBodyBytes == 0 {
		return []byte(test.BodyJSON)
	}
	if test.BodyFillByteHex != "20" {
		t.Fatalf("unsupported fill byte %q", test.BodyFillByteHex)
	}
	return bytes.Repeat([]byte{' '}, test.DerivedBodyBytes)
}
