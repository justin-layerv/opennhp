package connectorhub

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

const testHubEnvironment = "sandbox"

func TestAssignmentVersionWireInvariant(t *testing.T) {
	t.Parallel()
	if got := strconv.Itoa(assignmentVersion); got != assignmentVersionString {
		t.Fatalf("assignment version wire form = %q, want %q", got, assignmentVersionString)
	}
}

func TestDecodeAssignmentRequestConformanceGolden(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	peer := agentPeer(t, vectors)

	tests := []struct {
		name       string
		body       string
		mode       Mode
		credential string
	}{
		{name: "enroll", body: vectors.InitialAssignment.Request.BodyJSON, mode: ModeEnroll, credential: conformance.AgentAssignmentBootstrapCredentialFixture},
		{name: "refresh", body: vectors.RefreshAssignment.Request.BodyJSON, mode: ModeRefresh},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, err := DecodeAssignmentRequest(testHubEnvironment, []byte(test.body), peer)
			if err != nil {
				t.Fatalf("DecodeAssignmentRequest() error = %v", err)
			}
			if request.Mode != test.mode || request.AgentID != "agent-conform" || request.Credential != test.credential {
				t.Fatalf("request = %#v, want mode=%v agent-conform credential length=%d", request, test.mode, len(test.credential))
			}
			wantPeer := base64.StdEncoding.EncodeToString(peer)
			if request.AuthenticatedPeerPublicKeyB64 != wantPeer {
				t.Fatalf("authenticated peer = %q, want %q", request.AuthenticatedPeerPublicKeyB64, wantPeer)
			}
		})
	}
}

func TestDecodeAssignmentRequestHubRequestIDConformanceKATs(t *testing.T) {
	t.Parallel()
	vectors, err := conformance.ConnectorHubRequestID()
	if err != nil {
		t.Fatalf("load request-ID vectors: %v", err)
	}

	for _, test := range vectors.Cases {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			peer, err := base64.StdEncoding.Strict().DecodeString(test.AuthenticatedPeerPublicKeyB64)
			if err != nil {
				t.Fatalf("decode peer: %v", err)
			}
			mode := "refresh"
			switch test.Operation {
			case conformance.ConnectorHubRequestIDOperationIssue:
				mode = "enroll"
			case conformance.ConnectorHubRequestIDOperationRecover:
				mode = "recover"
			}
			requestData := map[string]any{
				"query": assignmentQuery, "version": assignmentVersion,
				"mode": mode, "request_nonce": test.RequestNonce,
			}
			if test.Operation == conformance.ConnectorHubRequestIDOperationIssue {
				requestData["credential"] = conformance.AgentAssignmentBootstrapCredentialFixture
			} else if test.Operation == conformance.ConnectorHubRequestIDOperationRecover {
				requestData["credential"] = recoveryVectors(t).Fixtures.RecoveryCredential
			}
			body, err := json.Marshal(map[string]any{
				"usrId": "", "devId": "agent-conform", "aspId": assignmentAspID, "usrData": requestData,
			})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			request, err := DecodeAssignmentRequest(test.Environment, body, peer)
			if err != nil {
				t.Fatalf("DecodeAssignmentRequest() error = %v", err)
			}
			if request.HubRequestID() != test.HubRequestID {
				t.Fatalf("hub request ID = %q, want %q", request.HubRequestID(), test.HubRequestID)
			}
		})
	}
}

func TestRequestDoesNotRetainLogicalNonce(t *testing.T) {
	t.Parallel()
	requestType := reflect.TypeOf(Request{})
	for index := range requestType.NumField() {
		field := requestType.Field(index)
		if strings.Contains(strings.ToLower(field.Name), "nonce") {
			t.Fatalf("Request field %q retains the logical nonce instead of only its derived private ID", field.Name)
		}
	}
}

func TestDecodeAssignmentRequestIDExcludesBodyEncodingAndSemanticFingerprintFields(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	peer := agentPeer(t, vectors)
	canonical := vectors.RefreshAssignment.Request.BodyJSON
	reordered := ` { "usrData" : { "request_nonce" : "` + conformance.AgentAssignmentRefreshRequestNonceFixture + `", "mode" : "refresh", "version" : 1, "query" : "cell_assignment" }, "aspId" : "agent", "devId" : "agent-conform", "usrId" : "" } `
	changedAgent := strings.Replace(canonical, `"devId":"agent-conform"`, `"devId":"agent-conflict"`, 1)

	first, err := DecodeAssignmentRequest(testHubEnvironment, []byte(canonical), peer)
	if err != nil {
		t.Fatalf("decode canonical body: %v", err)
	}
	for name, body := range map[string]string{"reordered": reordered, "changed agent": changedAgent} {
		request, err := DecodeAssignmentRequest(testHubEnvironment, []byte(body), peer)
		if err != nil {
			t.Fatalf("decode %s body: %v", name, err)
		}
		if first.HubRequestID() == "" || first.HubRequestID() != request.HubRequestID() {
			t.Fatalf("%s body IDs = %q/%q, want one stable logical ID", name, first.HubRequestID(), request.HubRequestID())
		}
	}

	enrollBody := vectors.InitialAssignment.Request.BodyJSON
	changedCredential := conformance.AgentAssignmentBootstrapCredentialFixture[:len(conformance.AgentAssignmentBootstrapCredentialFixture)-1] + "4"
	changedEnrollBody := strings.Replace(enrollBody, conformance.AgentAssignmentBootstrapCredentialFixture, changedCredential, 1)
	changedEnrollBody = strings.Replace(changedEnrollBody, `"devId":"agent-conform"`, `"devId":"agent-conflict"`, 1)
	enroll, err := DecodeAssignmentRequest(testHubEnvironment, []byte(enrollBody), peer)
	if err != nil {
		t.Fatalf("decode canonical enroll body: %v", err)
	}
	changedEnroll, err := DecodeAssignmentRequest(testHubEnvironment, []byte(changedEnrollBody), peer)
	if err != nil {
		t.Fatalf("decode changed-semantics enroll body: %v", err)
	}
	// The private Authority fingerprint, not a new replay key, owns same-nonce
	// conflicts whose authenticated agent or credential semantics changed.
	if enroll.HubRequestID() == "" || enroll.HubRequestID() != changedEnroll.HubRequestID() {
		t.Fatalf("changed-semantics IDs = %q/%q, want Authority fingerprint conflict under one ID", enroll.HubRequestID(), changedEnroll.HubRequestID())
	}
}

func TestDecodeAssignmentRequestRejectsInvalidEnvironmentWithoutReflection(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	const invalidEnvironment = "Production-secret"
	request, err := DecodeAssignmentRequest(invalidEnvironment, []byte(vectors.RefreshAssignment.Request.BodyJSON), agentPeer(t, vectors))
	if !errors.Is(err, ErrInvalidHubEnvironment) || request != (Request{}) {
		t.Fatalf("request/error = %#v/%v, want zero request and ErrInvalidHubEnvironment", request, err)
	}
	if strings.Contains(err.Error(), invalidEnvironment) || strings.Contains(err.Error(), conformance.AgentAssignmentRefreshRequestNonceFixture) {
		t.Fatalf("environment error reflected input: %q", err)
	}
}

func TestDecodeAssignmentRequestConformanceRejects(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	peer := agentPeer(t, vectors)
	for _, test := range vectors.RequestCases {
		if test.Phase != "initial_assignment" && test.Phase != "refresh_assignment" {
			continue
		}
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeAssignmentRequest(testHubEnvironment, []byte(test.BodyJSON), peer)
			if !errors.Is(err, ErrInvalidAssignmentRequest) {
				t.Fatalf("error = %v, want ErrInvalidAssignmentRequest", err)
			}
		})
	}
}

func TestDecodeAssignmentRequestConformanceRejectionClasses(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	peer := agentPeer(t, vectors)
	for _, test := range vectors.RequestCases {
		if test.Phase != "initial_assignment" && test.Phase != "refresh_assignment" {
			continue
		}
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			request, rejection, err := DecodeAssignmentRequestClassified(testHubEnvironment, []byte(test.BodyJSON), peer)
			if !errors.Is(err, ErrInvalidAssignmentRequest) || request != (Request{}) {
				t.Fatalf("request/error = %#v/%v, want zero request and ErrInvalidAssignmentRequest", request, err)
			}
			if got, want := string(rejection), test.RejectClass; got != want {
				t.Fatalf("rejection = %q, want conformance class %q", got, want)
			}
		})
	}
}

func TestRequestRejectionVocabularyIsFixedAndSecretFree(t *testing.T) {
	t.Parallel()
	got := []RequestRejection{
		RequestRejectionBodyParse,
		RequestRejectionUnknownField,
		RequestRejectionMissingField,
		RequestRejectionWrongType,
		RequestRejectionSemantic,
		RequestRejectionPeer,
		RequestRejectionBodySize,
		RequestRejectionEnvironment,
	}
	want := []RequestRejection{
		"body_parse",
		"unknown_field",
		"missing_field",
		"wrong_type",
		"semantic",
		"authenticated_peer",
		"body_size",
		"environment",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rejection vocabulary = %q, want %q", got, want)
	}
	seen := make(map[RequestRejection]struct{}, len(got))
	for _, rejection := range got {
		if rejection == "" {
			t.Fatal("rejection vocabulary contains an empty label")
		}
		if _, duplicate := seen[rejection]; duplicate {
			t.Fatalf("rejection vocabulary contains duplicate %q", rejection)
		}
		seen[rejection] = struct{}{}
	}

	const secret = "customer-credential-must-never-be-a-label"
	body := `{"usrId":"","devId":"agent-conform","aspId":"agent","usrData":{"query":"wrong","version":1,"mode":"enroll","request_nonce":"` + conformance.AgentAssignmentInitialRequestNonceFixture + `","credential":"` + secret + `"}}`
	_, rejection, err := DecodeAssignmentRequestClassified(testHubEnvironment, []byte(body), make([]byte, 32))
	if !errors.Is(err, ErrInvalidAssignmentRequest) || rejection != RequestRejectionSemantic {
		t.Fatalf("error/rejection = %v/%q, want semantic request rejection", err, rejection)
	}
	if strings.Contains(string(rejection), secret) || strings.Contains(err.Error(), secret) {
		t.Fatalf("request rejection reflected credential: %q/%q", rejection, err)
	}
}

func TestDecodeAssignmentRequestClassifiedSeparatesNonParserFences(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	body := []byte(vectors.RefreshAssignment.Request.BodyJSON)
	tests := []struct {
		name        string
		environment string
		body        []byte
		peer        []byte
		want        RequestRejection
		wantErr     error
	}{
		{name: "peer", environment: testHubEnvironment, body: body, peer: make([]byte, 31), want: RequestRejectionPeer, wantErr: ErrInvalidAuthenticatedPeer},
		{name: "body size", environment: testHubEnvironment, body: make([]byte, maxApplicationBodyBytes+1), peer: make([]byte, 32), want: RequestRejectionBodySize, wantErr: ErrAssignmentRequestTooLarge},
		{name: "environment", environment: "Production-secret", body: body, peer: agentPeer(t, vectors), want: RequestRejectionEnvironment, wantErr: ErrInvalidHubEnvironment},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, rejection, err := DecodeAssignmentRequestClassified(test.environment, test.body, test.peer)
			if !errors.Is(err, test.wantErr) || rejection != test.want {
				t.Fatalf("error/rejection = %v/%q, want %v/%q", err, rejection, test.wantErr, test.want)
			}
		})
	}
}

func TestDecodeAssignmentRequestStrictBodyGrammar(t *testing.T) {
	t.Parallel()
	peer := make([]byte, 32)
	valid := `{"usrId":"","devId":"agent-conform","aspId":"agent","usrData":{"query":"cell_assignment","version":1,"mode":"refresh","request_nonce":"` + conformance.AgentAssignmentRefreshRequestNonceFixture + `"}}`
	tests := []struct {
		name string
		body string
	}{
		{name: "null root", body: `null`},
		{name: "array root", body: `[]`},
		{name: "scalar root", body: `"request"`},
		{name: "trailing value", body: valid + `{}`},
		{name: "null scalar", body: strings.Replace(valid, `"devId":"agent-conform"`, `"devId":null`, 1)},
		{name: "object for scalar", body: strings.Replace(valid, `"devId":"agent-conform"`, `"devId":{}`, 1)},
		{name: "array for scalar", body: strings.Replace(valid, `"devId":"agent-conform"`, `"devId":[]`, 1)},
		{name: "escaped duplicate", body: strings.Replace(valid, `"devId":"agent-conform"`, `"devId":"agent-conform","dev\u0049d":"attacker"`, 1)},
		{name: "noncanonical version", body: strings.Replace(valid, `"version":1`, `"version":1e0`, 1)},
		{name: "refresh credential present", body: strings.Replace(valid, `"mode":"refresh"`, `"mode":"refresh","credential":"unexpected"`, 1)},
		{name: "enroll empty credential", body: strings.Replace(valid, `"mode":"refresh"`, `"mode":"enroll","credential":""`, 1)},
		{name: "invalid UTF-8", body: valid[:len(valid)-1] + string([]byte{0xff})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeAssignmentRequest(testHubEnvironment, []byte(test.body), peer); !errors.Is(err, ErrInvalidAssignmentRequest) {
				t.Fatalf("error = %v, want ErrInvalidAssignmentRequest", err)
			}
		})
	}
}

func TestDecodeAssignmentRequestPeerAndSizeFences(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	if got, want := maxApplicationBodyBytes, vectors.AccountCredentialOTP.PacketSizeContract.MaxPlaintextBodyBytes; got != want {
		t.Fatalf("application body limit = %d, want qurl-conformance v0.8 schema-4 limit %d", got, want)
	}
	body := []byte(vectors.InitialAssignment.Request.BodyJSON)
	if _, err := DecodeAssignmentRequest(testHubEnvironment, body, make([]byte, 31)); !errors.Is(err, ErrInvalidAuthenticatedPeer) {
		t.Fatalf("short peer error = %v, want ErrInvalidAuthenticatedPeer", err)
	}
	if _, err := DecodeAssignmentRequest(testHubEnvironment, make([]byte, maxApplicationBodyBytes+1), make([]byte, 32)); !errors.Is(err, ErrAssignmentRequestTooLarge) {
		t.Fatalf("oversized body error = %v, want ErrAssignmentRequestTooLarge", err)
	}
}

func TestDecodeAssignmentRequestErrorsDoNotReflectCredentialOrNonce(t *testing.T) {
	t.Parallel()
	const secret = "customer-registration-secret-must-not-appear"
	const nonce = conformance.AgentAssignmentInitialRequestNonceFixture
	body := `{"usrId":"","devId":"agent-conform","aspId":"agent","usrData":{"query":"wrong","version":1,"mode":"enroll","request_nonce":"` + nonce + `","credential":"` + secret + `"}}`
	_, err := DecodeAssignmentRequest(testHubEnvironment, []byte(body), make([]byte, 32))
	if !errors.Is(err, ErrInvalidAssignmentRequest) {
		t.Fatalf("error = %v, want ErrInvalidAssignmentRequest", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), nonce) || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("error reflected request data: %q", err)
	}
}

func TestEncodeAssignmentSuccessConformanceGolden(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)

	var enrollGolden successEnvelope[enrollListWire]
	if err := json.Unmarshal([]byte(vectors.InitialAssignment.Result.BodyJSON), &enrollGolden); err != nil {
		t.Fatalf("decode enroll golden: %v", err)
	}
	enroll, err := enrollSuccessFromWire(enrollGolden.List)
	if err != nil {
		t.Fatalf("convert enroll golden: %v", err)
	}
	encoded, err := EncodeEnrollSuccess(enroll)
	if err != nil {
		t.Fatalf("EncodeEnrollSuccess() error = %v", err)
	}
	if string(encoded) != vectors.InitialAssignment.Result.BodyJSON {
		t.Fatalf("enroll body drift:\n got: %s\nwant: %s", encoded, vectors.InitialAssignment.Result.BodyJSON)
	}

	var refreshGolden successEnvelope[refreshListWire]
	if err := json.Unmarshal([]byte(vectors.RefreshAssignment.Result.BodyJSON), &refreshGolden); err != nil {
		t.Fatalf("decode refresh golden: %v", err)
	}
	refresh, err := refreshSuccessFromWire(refreshGolden.List)
	if err != nil {
		t.Fatalf("convert refresh golden: %v", err)
	}
	encoded, err = EncodeRefreshSuccess(refresh)
	if err != nil {
		t.Fatalf("EncodeRefreshSuccess() error = %v", err)
	}
	if string(encoded) != vectors.RefreshAssignment.Result.BodyJSON {
		t.Fatalf("refresh body drift:\n got: %s\nwant: %s", encoded, vectors.RefreshAssignment.Result.BodyJSON)
	}
}

func TestEncodeAssignmentErrorsConformanceGolden(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)

	for _, test := range vectors.ErrorContract.InitialCredentialCases {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			kind, ok := enrollErrorForCode(test.ErrCode)
			if !ok {
				t.Fatalf("test does not map enroll code %s", test.ErrCode)
			}
			got, err := EncodeEnrollError(kind, retryFromVector(test.RetryAfterSeconds))
			if err != nil {
				t.Fatalf("EncodeEnrollError() error = %v", err)
			}
			if string(got) != test.BodyJSON {
				t.Fatalf("body = %s, want %s", got, test.BodyJSON)
			}
		})
	}

	for _, test := range vectors.ErrorContract.AssignmentCases {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			assignmentKind, enrollKind, ok := assignmentErrorsForCode(test.ErrCode)
			if !ok {
				t.Fatalf("test does not map assignment code %s", test.ErrCode)
			}
			retry := retryFromVector(test.RetryAfterSeconds)
			refreshBody, err := EncodeRefreshError(assignmentKind, retry)
			if err != nil {
				t.Fatalf("EncodeRefreshError() error = %v", err)
			}
			enrollBody, err := EncodeEnrollError(enrollKind, retry)
			if err != nil {
				t.Fatalf("EncodeEnrollError() error = %v", err)
			}
			if string(refreshBody) != test.BodyJSON || string(enrollBody) != test.BodyJSON {
				t.Fatalf("bodies = refresh:%s enroll:%s, want %s", refreshBody, enrollBody, test.BodyJSON)
			}
		})
	}
}

func TestAssignmentErrorAcceptedPhasesConformance(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	want52205Phases := []string{"initial_assignment", "refresh_assignment"}
	found52205 := 0

	// assignmentVectors pins schema v4; these are all error-case groups in that
	// schema. A future schema bump must update both that pin and this exhaustive
	// list, rather than silently widening the accepted phase surface.
	groups := [][]conformance.AgentAssignmentErrorCase{
		vectors.ErrorContract.AssignmentCases,
		vectors.ErrorContract.InitialCredentialCases,
		vectors.ErrorContract.CompletionCases,
		vectors.ErrorContract.RegistrationCases,
	}
	for _, cases := range groups {
		for _, test := range cases {
			if test.ErrCode == "52205" {
				found52205++
				if !reflect.DeepEqual(test.AcceptedPhases, want52205Phases) {
					t.Fatalf("52205 accepted phases = %v, want %v", test.AcceptedPhases, want52205Phases)
				}
				continue
			}
			if test.AcceptedPhases != nil {
				t.Fatalf("error %s accepted phases = %v, want metadata omitted", test.ErrCode, test.AcceptedPhases)
			}
		}
	}
	if found52205 != 1 {
		t.Fatalf("52205 cases = %d, want exactly 1", found52205)
	}
}

func TestEncodeAssignmentErrorsRejectInvalidCombinations(t *testing.T) {
	t.Parallel()
	zero, one := uint32(0), uint32(1)
	tests := []struct {
		name string
		call func() error
		want error
	}{
		{name: "unknown enroll", call: func() error { _, err := EncodeEnrollError(0, nil); return err }, want: ErrInvalidEnrollError},
		{name: "unknown refresh", call: func() error { _, err := EncodeRefreshError(0, nil); return err }, want: ErrInvalidRefreshError},
		{name: "rate limit missing", call: func() error { _, err := EncodeRefreshError(AssignmentErrorRateLimited, nil); return err }, want: ErrInvalidRefreshError},
		{name: "rate limit zero", call: func() error { _, err := EncodeEnrollError(EnrollErrorAssignmentRateLimited, &zero); return err }, want: ErrInvalidEnrollError},
		{name: "unavailable zero", call: func() error { _, err := EncodeRefreshError(AssignmentErrorUnavailable, &zero); return err }, want: ErrInvalidRefreshError},
		{name: "retry forbidden", call: func() error { _, err := EncodeEnrollError(EnrollErrorInvalidAPIKey, &one); return err }, want: ErrInvalidEnrollError},
		{name: "refresh retry forbidden", call: func() error { _, err := EncodeRefreshError(AssignmentErrorIdentityRejected, &one); return err }, want: ErrInvalidRefreshError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.call(); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestEncodeAssignmentSuccessRejectsInvalidValues(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	var golden successEnvelope[enrollListWire]
	if err := json.Unmarshal([]byte(vectors.InitialAssignment.Result.BodyJSON), &golden); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	baseline, err := enrollSuccessFromWire(golden.List)
	if err != nil {
		t.Fatalf("convert golden: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*EnrollSuccess)
	}{
		{name: "private key kind", mutate: func(s *EnrollSuccess) { s.Registration.KeyKind = "tunnel_bootstrap" }},
		{name: "invalid key id", mutate: func(s *EnrollSuccess) { s.Registration.KeyID = "key_bad" }},
		{name: "raw cloud endpoint", mutate: func(s *EnrollSuccess) { s.Assignment.Endpoint.Host = "internal.elb.amazonaws.com" }},
		{name: "ip endpoint", mutate: func(s *EnrollSuccess) { s.Assignment.Endpoint.Host = "192.0.2.1" }},
		{name: "wrong key encoding", mutate: func(s *EnrollSuccess) {
			s.Assignment.Endpoint.ServerPublicKeyB64 = strings.TrimRight(s.Assignment.Endpoint.ServerPublicKeyB64, "=")
		}},
		{name: "low-order server key", mutate: func(s *EnrollSuccess) {
			s.Assignment.Endpoint.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(make([]byte, x25519PublicKeyBytes))
		}},
		{name: "non-canonical u-coordinate", mutate: func(s *EnrollSuccess) {
			s.Assignment.Endpoint.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(canonicalX25519UPrime[:])
		}},
		{name: "zero generation", mutate: func(s *EnrollSuccess) { s.Assignment.AssignmentGeneration = 0 }},
		{name: "non-UTC lease", mutate: func(s *EnrollSuccess) {
			s.Assignment.LeaseExpiresAt = s.Assignment.LeaseExpiresAt.In(time.FixedZone("other", 0))
		}},
		{name: "fractional ticket time", mutate: func(s *EnrollSuccess) { s.AssignmentTicketExpiresAt = s.AssignmentTicketExpiresAt.Add(time.Nanosecond) }},
		{name: "out-of-range RFC3339 year", mutate: func(s *EnrollSuccess) { s.Assignment.LeaseExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{name: "ticket not before lease", mutate: func(s *EnrollSuccess) { s.AssignmentTicketExpiresAt = s.Assignment.LeaseExpiresAt }},
		{name: "oversized ticket", mutate: func(s *EnrollSuccess) { s.AssignmentTicket = strings.Repeat("a", maxAssignmentTicketBytes+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := baseline
			test.mutate(&candidate)
			if _, err := EncodeEnrollSuccess(candidate); !errors.Is(err, ErrInvalidEnrollSuccess) {
				t.Fatalf("error = %v, want ErrInvalidEnrollSuccess", err)
			}
		})
	}

	refresh := RefreshSuccess{AgentID: baseline.AgentID, Assignment: baseline.Assignment}
	refresh.Assignment.CellID = "Cell0"
	if _, err := EncodeRefreshSuccess(refresh); !errors.Is(err, ErrInvalidRefreshSuccess) {
		t.Fatalf("refresh error = %v, want ErrInvalidRefreshSuccess", err)
	}

	expanded := baseline
	expanded.AssignmentTicket = strings.Repeat(`"`, maxAssignmentTicketBytes)
	if _, err := EncodeEnrollSuccess(expanded); !errors.Is(err, ErrAssignmentResponseTooLarge) {
		t.Fatalf("JSON-expanded ticket error = %v, want ErrAssignmentResponseTooLarge", err)
	}
}

func TestEnrollSuccessOwnedEncoderMatchesJSONMarshal(t *testing.T) {
	t.Parallel()
	vectors := assignmentVectors(t)
	var golden successEnvelope[enrollListWire]
	if err := json.Unmarshal([]byte(vectors.InitialAssignment.Result.BodyJSON), &golden); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	baseline, err := enrollSuccessFromWire(golden.List)
	if err != nil {
		t.Fatalf("convert golden: %v", err)
	}
	// appendEscapedTicket relies on validTicket admitting only printable ASCII.
	// Exercise every byte in that accepted alphabet against encoding/json so a
	// future validator or encoder change cannot silently break that coupling.
	tickets := []string{baseline.AssignmentTicket, `ticket-\"\\<>&-safe`}
	for value := byte(0x21); value <= 0x7e; value++ {
		tickets = append(tickets, string(value))
	}
	for _, ticket := range tickets {
		candidate := baseline
		candidate.AssignmentTicket = ticket
		got, err := EncodeEnrollSuccess(candidate)
		if err != nil {
			t.Fatalf("EncodeEnrollSuccess(%q): %v", ticket, err)
		}
		want, err := json.Marshal(successEnvelope[enrollListWire]{
			ErrCode: "0",
			List: enrollListWire{
				Query: assignmentQuery, Version: assignmentVersion, Mode: "enroll", AgentID: candidate.AgentID,
				Registration:              registrationWire{KeyID: candidate.Registration.KeyID, KeyKind: candidate.Registration.KeyKind},
				Assignment:                toAssignmentWire(candidate.Assignment),
				AssignmentTicket:          candidate.AssignmentTicket,
				AssignmentTicketExpiresAt: candidate.AssignmentTicketExpiresAt.Format(time.RFC3339),
			},
		})
		if err != nil {
			t.Fatalf("json.Marshal expected enroll success: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("owned enroll encoding differs from encoding/json:\n got: %s\nwant: %s", got, want)
		}
	}
}

func TestEncodeAssignmentUnavailableAllowsPositiveRetryHint(t *testing.T) {
	t.Parallel()
	retry := uint32(5)
	want := `{"errCode":"52200","errMsg":"assignment temporarily unavailable","retryAfterSeconds":5}`
	for name, encode := range map[string]func() ([]byte, error){
		"enroll":  func() ([]byte, error) { return EncodeEnrollError(EnrollErrorAssignmentUnavailable, &retry) },
		"refresh": func() ([]byte, error) { return EncodeRefreshError(AssignmentErrorUnavailable, &retry) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body, err := encode()
			if err != nil {
				t.Fatalf("encode error = %v", err)
			}
			if string(body) != want {
				t.Fatalf("body = %s, want %s", body, want)
			}
		})
	}
}

func TestMarshalBoundedRejectsOversizedBody(t *testing.T) {
	t.Parallel()
	if _, err := marshalBounded(struct {
		Value string `json:"value"`
	}{Value: strings.Repeat("x", maxApplicationBodyBytes)}); !errors.Is(err, ErrAssignmentResponseTooLarge) {
		t.Fatalf("error = %v, want ErrAssignmentResponseTooLarge", err)
	}
}

func TestMarshalBoundedDistinguishesEncodingFailure(t *testing.T) {
	t.Parallel()
	if _, err := marshalBounded(make(chan struct{})); !errors.Is(err, ErrAssignmentResponseEncoding) {
		t.Fatalf("error = %v, want ErrAssignmentResponseEncoding", err)
	}
}

func assignmentVectors(t *testing.T) *conformance.AgentAssignmentFile {
	t.Helper()
	vectors, err := conformance.AgentAssignmentGolden()
	if err != nil {
		t.Fatalf("load qurl-conformance assignment vectors: %v", err)
	}
	if vectors.SchemaVersion != 4 {
		t.Fatalf("schema version = %d, want 4", vectors.SchemaVersion)
	}
	return vectors
}

func agentPeer(t *testing.T, vectors *conformance.AgentAssignmentFile) []byte {
	t.Helper()
	peer, err := hex.DecodeString(vectors.Keys.Agent.StaticPubHex)
	if err != nil {
		t.Fatalf("decode agent public key: %v", err)
	}
	return peer
}

func enrollSuccessFromWire(wire enrollListWire) (EnrollSuccess, error) {
	assignment, err := assignmentFromWire(wire.Assignment)
	if err != nil {
		return EnrollSuccess{}, err
	}
	ticketExpiry, err := time.Parse(time.RFC3339, wire.AssignmentTicketExpiresAt)
	if err != nil {
		return EnrollSuccess{}, err
	}
	return EnrollSuccess{
		AgentID:      wire.AgentID,
		Registration: Registration{KeyID: wire.Registration.KeyID, KeyKind: wire.Registration.KeyKind},
		Assignment:   assignment, AssignmentTicket: wire.AssignmentTicket, AssignmentTicketExpiresAt: ticketExpiry,
	}, nil
}

func refreshSuccessFromWire(wire refreshListWire) (RefreshSuccess, error) {
	assignment, err := assignmentFromWire(wire.Assignment)
	if err != nil {
		return RefreshSuccess{}, err
	}
	return RefreshSuccess{AgentID: wire.AgentID, Assignment: assignment}, nil
}

func assignmentFromWire(wire assignmentWire) (Assignment, error) {
	lease, err := time.Parse(time.RFC3339, wire.LeaseExpiresAt)
	if err != nil {
		return Assignment{}, err
	}
	return Assignment{
		CellID: wire.CellID, AssignmentGeneration: wire.AssignmentGeneration, EndpointRevision: wire.EndpointRevision,
		LeaseExpiresAt: lease,
		Endpoint:       UDPEndpoint{Host: wire.Endpoint.Host, Port: wire.Endpoint.Port, ServerPublicKeyB64: wire.Endpoint.ServerPublicKeyB64},
	}, nil
}

func retryFromVector(value *int) *uint32 {
	if value == nil {
		return nil
	}
	retry := uint32(*value)
	return &retry
}

func enrollErrorForCode(code string) (EnrollError, bool) {
	switch code {
	case "52106":
		return EnrollErrorInvalidAPIKey, true
	case "52107":
		return EnrollErrorRegistrationDisabled, true
	case "52108":
		return EnrollErrorBootstrapConsumed, true
	case "52109":
		return EnrollErrorInvalidInput, true
	default:
		return 0, false
	}
}

func assignmentErrorsForCode(code string) (AssignmentError, EnrollError, bool) {
	switch code {
	case "52200":
		return AssignmentErrorUnavailable, EnrollErrorAssignmentUnavailable, true
	case "52201":
		return AssignmentErrorIdentityRejected, EnrollErrorIdentityRejected, true
	case "52202":
		return AssignmentErrorReassignmentInProgress, EnrollErrorReassignmentInProgress, true
	case "52203":
		return AssignmentErrorQuotaExceeded, EnrollErrorAssignmentQuotaExceeded, true
	case "52204":
		return AssignmentErrorRateLimited, EnrollErrorAssignmentRateLimited, true
	case "52205":
		return AssignmentErrorInvalidRequest, EnrollErrorInvalidAssignmentRequest, true
	default:
		return 0, 0, false
	}
}
