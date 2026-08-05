package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorcell"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

func validConnectorRegistrationEnvironment() map[string]string {
	return map[string]string{
		"NHP_ENVIRONMENT":                          "sandbox",
		"NHP_CELL_ID":                              "cell0",
		ConnectorRegistrationAWSRegionEnvVar:       "us-east-2",
		ConnectorRegistrationAWSAccountEnvVar:      "123456789012",
		ConnectorRegistrationIssueOTPAliasEnvVar:   "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-iro-cell0:blue",
		ConnectorRegistrationActivateAliasEnvVar:   "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ar-cell0:blue",
		ConnectorRegistrationCompleteAliasEnvVar:   "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-cr-cell0:blue",
		ConnectorRegistrationLambdaTimeoutEnvVar:   "3s",
		ConnectorRegistrationHandlerBudgetEnvVar:   "3200ms",
		ConnectorRegistrationPacketBudgetEnvVar:    "3900ms",
		ConnectorRegistrationResponseReserveEnvVar: "700ms",
		ConnectorRegistrationWriteBudgetEnvVar:     "137ms",
	}
}

func validConnectorRegistrationTiming() connectorRegistrationTiming {
	return connectorRegistrationTiming{
		authorityLambdaTimeout: 3 * time.Second,
		handlerBudget:          3200 * time.Millisecond,
		packetBudget:           3900 * time.Millisecond,
		responseReserve:        700 * time.Millisecond,
		writeBudget:            137 * time.Millisecond,
	}
}

func TestConnectorRegistrationConfigurationIsDarkOrAllOrNone(t *testing.T) {
	t.Parallel()
	dark := validConnectorRegistrationEnvironment()
	for _, key := range []string{
		ConnectorRegistrationAWSRegionEnvVar,
		ConnectorRegistrationAWSAccountEnvVar,
		ConnectorRegistrationIssueOTPAliasEnvVar,
		ConnectorRegistrationActivateAliasEnvVar,
		ConnectorRegistrationCompleteAliasEnvVar,
		ConnectorRegistrationLambdaTimeoutEnvVar,
		ConnectorRegistrationHandlerBudgetEnvVar,
		ConnectorRegistrationPacketBudgetEnvVar,
		ConnectorRegistrationResponseReserveEnvVar,
		ConnectorRegistrationWriteBudgetEnvVar,
	} {
		delete(dark, key)
	}
	if config, err := loadConnectorRegistrationConfig(mapEnvironment(dark)); config != nil || err != nil {
		t.Fatalf("absent registration config = %#v, %v; want dark nil", config, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "missing region", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationAWSRegionEnvVar) }},
		{name: "missing account", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationAWSAccountEnvVar) }},
		{name: "missing OTP alias", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationIssueOTPAliasEnvVar) }},
		{name: "missing activation alias", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationActivateAliasEnvVar) }},
		{name: "missing completion alias", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationCompleteAliasEnvVar) }},
		{name: "missing lambda timeout", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationLambdaTimeoutEnvVar) }},
		{name: "missing handler budget", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationHandlerBudgetEnvVar) }},
		{name: "missing packet budget", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationPacketBudgetEnvVar) }},
		{name: "missing response reserve", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationResponseReserveEnvVar) }},
		{name: "missing write budget", mutate: func(env map[string]string) { delete(env, ConnectorRegistrationWriteBudgetEnvVar) }},
		{name: "present empty", mutate: func(env map[string]string) { env[ConnectorRegistrationActivateAliasEnvVar] = "" }},
		{name: "whitespace region", mutate: func(env map[string]string) { env[ConnectorRegistrationAWSRegionEnvVar] = " us-east-2" }},
		{name: "whitespace account", mutate: func(env map[string]string) { env[ConnectorRegistrationAWSAccountEnvVar] += " " }},
		{name: "whitespace OTP alias", mutate: func(env map[string]string) {
			env[ConnectorRegistrationIssueOTPAliasEnvVar] = " " + env[ConnectorRegistrationIssueOTPAliasEnvVar]
		}},
		{name: "whitespace activation alias", mutate: func(env map[string]string) { env[ConnectorRegistrationActivateAliasEnvVar] += " " }},
		{name: "whitespace completion alias", mutate: func(env map[string]string) {
			env[ConnectorRegistrationCompleteAliasEnvVar] = "\t" + env[ConnectorRegistrationCompleteAliasEnvVar]
		}},
		{name: "missing environment", mutate: func(env map[string]string) { delete(env, "NHP_ENVIRONMENT") }},
		{name: "missing cell", mutate: func(env map[string]string) { delete(env, "NHP_CELL_ID") }},
		{name: "bad environment", mutate: func(env map[string]string) { env["NHP_ENVIRONMENT"] = "stage" }},
		{name: "bad cell", mutate: func(env map[string]string) { env["NHP_CELL_ID"] = "Cell0" }},
		{name: "wrong account", mutate: func(env map[string]string) {
			env[ConnectorRegistrationIssueOTPAliasEnvVar] = strings.Replace(env[ConnectorRegistrationIssueOTPAliasEnvVar], "123456789012", "999999999999", 1)
		}},
		{name: "wrong region", mutate: func(env map[string]string) {
			env[ConnectorRegistrationActivateAliasEnvVar] = strings.Replace(env[ConnectorRegistrationActivateAliasEnvVar], "us-east-2", "us-west-2", 1)
		}},
		{name: "numeric qualifier", mutate: func(env map[string]string) {
			env[ConnectorRegistrationCompleteAliasEnvVar] = strings.TrimSuffix(env[ConnectorRegistrationCompleteAliasEnvVar], ":blue") + ":7"
		}},
		{name: "wrong operation", mutate: func(env map[string]string) {
			env[ConnectorRegistrationIssueOTPAliasEnvVar] = strings.Replace(env[ConnectorRegistrationIssueOTPAliasEnvVar], "ca-iro", "ca-ar", 1)
		}},
		{name: "wrong environment name", mutate: func(env map[string]string) {
			env[ConnectorRegistrationCompleteAliasEnvVar] = strings.Replace(env[ConnectorRegistrationCompleteAliasEnvVar], "nhp-sandbox", "nhp-prod", 1)
		}},
		{name: "wrong cell name", mutate: func(env map[string]string) {
			env[ConnectorRegistrationActivateAliasEnvVar] = strings.Replace(env[ConnectorRegistrationActivateAliasEnvVar], "cell0", "cell1", 1)
		}},
		{name: "unitless budget", mutate: func(env map[string]string) { env[ConnectorRegistrationHandlerBudgetEnvVar] = "3200" }},
		{name: "lambda below floor", mutate: func(env map[string]string) { env[ConnectorRegistrationLambdaTimeoutEnvVar] = "2s" }},
		{name: "lambda non-integral", mutate: func(env map[string]string) { env[ConnectorRegistrationLambdaTimeoutEnvVar] = "3001ms" }},
		{name: "handler not above lambda", mutate: func(env map[string]string) { env[ConnectorRegistrationHandlerBudgetEnvVar] = "3s" }},
		{name: "packet not above handler", mutate: func(env map[string]string) { env[ConnectorRegistrationPacketBudgetEnvVar] = "3200ms" }},
		{name: "packet reaches transaction timeout", mutate: func(env map[string]string) { env[ConnectorRegistrationPacketBudgetEnvVar] = "10s" }},
		{name: "reserve exceeds tail", mutate: func(env map[string]string) { env[ConnectorRegistrationResponseReserveEnvVar] = "701ms" }},
		{name: "write exceeds reserve", mutate: func(env map[string]string) { env[ConnectorRegistrationWriteBudgetEnvVar] = "701ms" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			env := validConnectorRegistrationEnvironment()
			test.mutate(env)
			if config, err := loadConnectorRegistrationConfig(mapEnvironment(env)); config != nil ||
				!errors.Is(err, errInvalidConnectorRegistrationConfiguration) {
				t.Fatalf("config = %#v, error = %v", config, err)
			}
		})
	}
}

type capturingRegistrationAuthority struct {
	mu             sync.Mutex
	responses      map[string][]byte
	errors         map[string]error
	calls          map[string]int
	payloadAliases [][]byte
	returnAliases  [][]byte
	deadlines      map[string]time.Time
	payloadCopies  map[string][]byte
}

func newCapturingRegistrationAuthority(vectors *conformance.ConnectorAuthorityLambdaFile) *capturingRegistrationAuthority {
	return &capturingRegistrationAuthority{
		responses: map[string][]byte{
			conformance.ConnectorAuthorityOperationIssueRegistrationOTP: []byte(vectors.Operations[conformance.ConnectorAuthorityOperationIssueRegistrationOTP].SuccessGolden.BodyJSON),
			conformance.ConnectorAuthorityOperationActivateRegistration: []byte(vectors.Operations[conformance.ConnectorAuthorityOperationActivateRegistration].SuccessGolden.BodyJSON),
			conformance.ConnectorAuthorityOperationCompleteRegistration: []byte(vectors.Operations[conformance.ConnectorAuthorityOperationCompleteRegistration].SuccessGolden.BodyJSON),
		},
		errors: make(map[string]error), calls: make(map[string]int), deadlines: make(map[string]time.Time),
		payloadCopies: make(map[string][]byte),
	}
}

func (a *capturingRegistrationAuthority) IssueRegistrationOTP(ctx context.Context, payload []byte) ([]byte, error) {
	return a.invoke(ctx, conformance.ConnectorAuthorityOperationIssueRegistrationOTP, payload)
}

func (a *capturingRegistrationAuthority) ActivateRegistration(ctx context.Context, payload []byte) ([]byte, error) {
	return a.invoke(ctx, conformance.ConnectorAuthorityOperationActivateRegistration, payload)
}

func (a *capturingRegistrationAuthority) CompleteRegistration(ctx context.Context, payload []byte) ([]byte, error) {
	return a.invoke(ctx, conformance.ConnectorAuthorityOperationCompleteRegistration, payload)
}

func (a *capturingRegistrationAuthority) invoke(ctx context.Context, operation string, payload []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls[operation]++
	a.payloadAliases = append(a.payloadAliases, payload)
	a.payloadCopies[operation] = bytes.Clone(payload)
	deadline, _ := ctx.Deadline()
	a.deadlines[operation] = deadline
	response := bytes.Clone(a.responses[operation])
	a.returnAliases = append(a.returnAliases, response)
	return response, a.errors[operation]
}

func (a *capturingRegistrationAuthority) callCount(operation string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls[operation]
}

func (a *capturingRegistrationAuthority) deadline(operation string) time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deadlines[operation]
}

func (a *capturingRegistrationAuthority) buffersCleared() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, buffer := range append(a.payloadAliases, a.returnAliases...) {
		if !allZero(buffer) {
			return false
		}
	}
	return true
}

func connectorRegistrationFixture(t *testing.T) (*conformance.AgentAssignmentFile, *conformance.ConnectorAuthorityLambdaFile, []byte, []byte, []byte, []byte) {
	t.Helper()
	assignment, err := conformance.AgentAssignmentGolden()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := conformance.ConnectorAuthorityLambda()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := base64.StdEncoding.Strict().DecodeString(authority.Fixtures.AuthenticatedPeerPublicKeyB64)
	if err != nil || len(peer) != 32 {
		t.Fatalf("peer = %d bytes, %v", len(peer), err)
	}
	otp := assignment.AccountCredentialOTP.Request.BodyJSON
	otp = strings.Replace(otp, assignment.AccountCredentialOTP.EnrollmentBinding.RequestAssignmentTicket, authority.Fixtures.AssignmentTicket, 1)
	otp = strings.Replace(otp, assignment.AccountCredentialOTP.EnrollmentBinding.RequestRegistrationKeyID, authority.Fixtures.CredentialKeyID, 1)
	otp = strings.Replace(otp, assignment.AccountCredentialOTP.EnrollmentBinding.RequestCredential, authority.Fixtures.Credential, 1)
	return assignment, authority, peer, []byte(otp),
		[]byte(assignment.AssignedCellRegistration.Request.BodyJSON),
		[]byte(assignment.RegistrationCompletion.Request.BodyJSON)
}

func connectorRegistrationServer(t *testing.T, authority *capturingRegistrationAuthority, plugin *recordingRegOTPPlugin) *UdpServer {
	t.Helper()
	handler, err := connectorcell.NewRegistrationHandler(authority)
	if err != nil {
		t.Fatal(err)
	}
	server := &UdpServer{
		connectorRegistrationHandler: handler,
		connectorRegistrationTiming:  validConnectorRegistrationTiming(),
		metrics:                      metrics.NewPublisherForTest(t),
		pluginHandlerMap:             make(map[string]plugins.PluginHandler),
	}
	if plugin != nil {
		server.pluginHandlerMap["agent"] = plugin
	}
	return server
}

func directRegistrationPPD(body, peer []byte, headerType int, trxID uint64, receipt time.Time, response chan *core.MsgData) *core.PacketParserData {
	transactions := make(map[uint64]*core.RemoteTransaction)
	if response != nil {
		transactions[trxID] = core.NewRemoteTransactionForTest(trxID, response)
	}
	return &core.PacketParserData{
		LocalInitTime: receipt.UnixNano(), RemotePubKey: bytes.Clone(peer), BodyMessage: body,
		HeaderType: headerType, SenderTrxId: trxID,
		ConnData: &core.ConnectionData{
			RemoteAddr:           &net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.19"), Port: 44444},
			IngressTransport:     core.IngressTransportDirectUDP,
			RemoteTransactionMap: transactions,
		},
	}
}

func realDirectRegistrationRequest(
	t *testing.T,
	server *UdpServer,
	agent *core.Device,
	agentListener *net.UDPConn,
	headerType int,
	transactionID uint64,
	body []byte,
	receipt time.Time,
) (*core.PacketParserData, <-chan *core.PacketParserData, *core.RemoteTransaction) {
	return realDirectRegistrationRequestOnConnection(
		t, server, agent, agentListener, headerType, transactionID, body, receipt, nil,
	)
}

func realDirectRegistrationRequestOnConnection(
	t *testing.T,
	server *UdpServer,
	agent *core.Device,
	agentListener *net.UDPConn,
	headerType int,
	transactionID uint64,
	body []byte,
	receipt time.Time,
	serverConnection *core.ConnectionData,
) (*core.PacketParserData, <-chan *core.PacketParserData, *core.RemoteTransaction) {
	t.Helper()
	if server == nil || server.device == nil || server.listenConn == nil {
		t.Fatal("real direct registration request requires a server device and UDP listener")
	}
	serverAddress := server.listenConn.LocalAddr().(*net.UDPAddr)
	agent.AddPeer(&core.UdpPeer{
		PubKeyBase64: server.device.PublicKeyBase64(),
		Ip:           serverAddress.IP.String(),
		Port:         serverAddress.Port,
		Type:         core.NHP_SERVER,
	})
	agentConnection := newSpikeConn(agent, serverAddress)
	responses := make(chan *core.PacketParserData, 1)
	agent.SendMsgToPacket(&core.MsgData{
		ConnData:      agentConnection,
		PeerPk:        decodeBase64PubKey(server.device.PublicKeyBase64()),
		HeaderType:    headerType,
		TransactionId: transactionID,
		Message:       bytes.Clone(body),
		ResponseMsgCh: responses,
	})
	wire := drainEncryptedPacket(t, agentConnection)
	if serverConnection == nil {
		serverConnection = newSpikeConn(server.device, agentListener.LocalAddr().(*net.UDPAddr))
		serverConnection.IngressTransport = core.IngressTransportDirectUDP
		serverConnection.RemoteTransactionMap = make(map[uint64]*core.RemoteTransaction)
	}
	parsed, err := server.device.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: wire},
		ConnData:   serverConnection,
		InitTime:   receipt.UnixNano(),
	})
	if err != nil {
		t.Fatalf("decrypt direct registration request: %v", err)
	}
	transaction := core.StartRemoteTransactionForTest(parsed, time.Second)
	if transaction == nil {
		t.Fatal("start direct registration remote transaction returned nil")
	}
	return parsed, responses, transaction
}

func awaitConnectorRegistrationTransactionRetired(
	t *testing.T,
	request *core.PacketParserData,
	transaction *core.RemoteTransaction,
) {
	t.Helper()
	select {
	case <-transaction.Done():
	case <-time.After(time.Second):
		t.Fatal("connector registration transaction did not retire")
	}
	if got := request.ConnData.FindRemoteTransaction(request.SenderTrxId); got != nil {
		t.Fatalf("retired connector registration transaction remained mapped: %p", got)
	}
}

func assertNoConnectorRegistrationDatagram(t *testing.T, listener *net.UDPConn) {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	if n, _, err := listener.ReadFromUDP(buffer); err == nil {
		t.Fatalf("terminal connector registration path emitted %d bytes", n)
	} else if !isTimeout(err) {
		t.Fatalf("terminal connector registration read: %v", err)
	}
}

func readDirectRegistrationResponse(
	t *testing.T,
	agent *core.Device,
	agentListener *net.UDPConn,
	responses <-chan *core.PacketParserData,
) *core.PacketParserData {
	t.Helper()
	wire := readUDPWithTimeout(t, agentListener, time.Second)
	routeResponseToTransaction(t, agent, wire)
	select {
	case response := <-responses:
		return response
	case <-time.After(time.Second):
		t.Fatal("agent did not receive strict direct response")
		return nil
	}
}

func TestConnectorRegistrationDirectUDPRoutesBeforePluginsAndWipesSecrets(t *testing.T) {
	assignment, vectors, peer, otp, registration, completion := connectorRegistrationFixture(t)
	authority := newCapturingRegistrationAuthority(vectors)
	plugin := &recordingRegOTPPlugin{}
	server := connectorRegistrationServer(t, authority, plugin)
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0xa2, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.listenConn = mustUDPListener(t)
	agent := newSpikeDevice(t, core.NHP_AGENT, 0xa1, nil)
	agentListener := mustUDPListener(t)
	receipt := time.Now().Add(-25 * time.Millisecond)

	otpPPD := directRegistrationPPD(otp, peer, core.NHP_OTP, 101, receipt, nil)
	if err := server.HandleOTPRequest(otpPPD); err != nil {
		t.Fatalf("HandleOTPRequest: %v", err)
	}
	if authority.callCount(conformance.ConnectorAuthorityOperationIssueRegistrationOTP) != 1 || plugin.otpCalls != 0 || !allZero(otp) {
		t.Fatalf("OTP authority=%d plugin=%d wiped=%v", authority.callCount(conformance.ConnectorAuthorityOperationIssueRegistrationOTP), plugin.otpCalls, allZero(otp))
	}

	regPPD, regResponses, regTransaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_REG, 102, registration, receipt,
	)
	if err := server.HandleRegisterRequest(regPPD); err != nil {
		t.Fatalf("HandleRegisterRequest: %v", err)
	}
	response := readDirectRegistrationResponse(t, agent, agentListener, regResponses)
	if response.HeaderType != core.NHP_RAK || string(response.BodyMessage) != assignment.AssignedCellRegistration.Result.BodyJSON {
		t.Fatalf("RAK type=%d body=%q", response.HeaderType, response.BodyMessage)
	}
	select {
	case <-regTransaction.Done():
	case <-time.After(time.Second):
		t.Fatal("direct registration transaction did not complete")
	}
	if plugin.regCalls != 0 || !allZero(regPPD.BodyMessage) {
		t.Fatalf("registration plugin=%d wiped=%v", plugin.regCalls, allZero(regPPD.BodyMessage))
	}

	completionPPD, completionResponses, completionTransaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_LST, 103, completion, receipt,
	)
	if err := server.HandleListRequest(completionPPD); err != nil {
		t.Fatalf("HandleListRequest: %v", err)
	}
	response = readDirectRegistrationResponse(t, agent, agentListener, completionResponses)
	if response.HeaderType != core.NHP_LRT || string(response.BodyMessage) != assignment.RegistrationCompletion.Result.BodyJSON {
		t.Fatalf("LRT type=%d body=%q", response.HeaderType, response.BodyMessage)
	}
	select {
	case <-completionTransaction.Done():
	case <-time.After(time.Second):
		t.Fatal("direct completion transaction did not complete")
	}
	if plugin.listCalls != 0 || !allZero(completionPPD.BodyMessage) || !authority.buffersCleared() {
		t.Fatalf("completion plugin=%d wiped=%v authorityCleared=%v", plugin.listCalls, allZero(completionPPD.BodyMessage), authority.buffersCleared())
	}

	wantDeadline := receipt.Add(validConnectorRegistrationTiming().handlerBudget)
	for _, operation := range []string{
		conformance.ConnectorAuthorityOperationIssueRegistrationOTP,
		conformance.ConnectorAuthorityOperationActivateRegistration,
		conformance.ConnectorAuthorityOperationCompleteRegistration,
	} {
		if got := authority.deadline(operation); !got.Equal(wantDeadline) {
			t.Errorf("%s deadline=%s want=%s", operation, got, wantDeadline)
		}
	}
	var otpPrivate map[string]any
	if err := json.Unmarshal(authority.payloadCopies[conformance.ConnectorAuthorityOperationIssueRegistrationOTP], &otpPrivate); err != nil {
		t.Fatal(err)
	}
	if got := otpPrivate["observed_source_address"]; got != "203.0.113.19" {
		t.Fatalf("observed source = %#v, want canonical unmapped IP", got)
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricConnectorRegistrationResponseSent] != 2 || counters[MetricConnectorRegistrationResponseAttempt] != 2 {
		t.Fatalf("direct response counters=%v", counters)
	}
}

func TestConnectorRegistrationMalformedExactIntentNeverDispatchesPlugin(t *testing.T) {
	_, vectors, peer, _, _, _ := connectorRegistrationFixture(t)
	for _, test := range []struct {
		name       string
		headerType int
		body       string
		wantHeader int
	}{
		{name: "OTP", headerType: core.NHP_OTP, body: `{"aspId":"agent","aspId":"agent"}`},
		{name: "registration", headerType: core.NHP_REG, body: `{"aspId":"agent","usrData":{}}`, wantHeader: core.NHP_RAK},
		{name: "completion", headerType: core.NHP_LST, body: `{"aspId":"agent","usrData":{"query":"agent_registration_completion"`, wantHeader: core.NHP_LRT},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := newCapturingRegistrationAuthority(vectors)
			plugin := &recordingRegOTPPlugin{}
			server := connectorRegistrationServer(t, authority, plugin)
			body := []byte(test.body)
			var (
				ppd           *core.PacketParserData
				responses     <-chan *core.PacketParserData
				transaction   *core.RemoteTransaction
				agent         *core.Device
				agentListener *net.UDPConn
			)
			if test.wantHeader == 0 {
				ppd = directRegistrationPPD(body, peer, test.headerType, 201, time.Now(), nil)
			} else {
				server.device = newSpikeDevice(t, core.NHP_SERVER, 0xb2, &core.DeviceOptions{DisableAgentPeerValidation: true})
				server.listenConn = mustUDPListener(t)
				agent = newSpikeDevice(t, core.NHP_AGENT, 0xb1, nil)
				agentListener = mustUDPListener(t)
				ppd, responses, transaction = realDirectRegistrationRequest(
					t, server, agent, agentListener, test.headerType, 201, body, time.Now(),
				)
			}
			var err error
			switch test.headerType {
			case core.NHP_OTP:
				err = server.HandleOTPRequest(ppd)
			case core.NHP_REG:
				err = server.HandleRegisterRequest(ppd)
			case core.NHP_LST:
				err = server.HandleListRequest(ppd)
			}
			if err != nil || plugin.otpCalls+plugin.regCalls+plugin.listCalls != 0 || !allZero(ppd.BodyMessage) {
				t.Fatalf("error=%v plugin calls=%d wiped=%v", err, plugin.otpCalls+plugin.regCalls+plugin.listCalls, allZero(ppd.BodyMessage))
			}
			if test.wantHeader != 0 {
				response := readDirectRegistrationResponse(t, agent, agentListener, responses)
				if response.HeaderType != test.wantHeader {
					t.Fatalf("header=%d want=%d", response.HeaderType, test.wantHeader)
				}
				select {
				case <-transaction.Done():
				case <-time.After(time.Second):
					t.Fatal("strict rejection transaction did not complete")
				}
			}
		})
	}
}

func TestConnectorRegistrationDarkAndOtherASPsUseGenericDispatch(t *testing.T) {
	_, vectors, peer, _, _, _ := connectorRegistrationFixture(t)
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "dark", true: "configured_other_asp"}[configured], func(t *testing.T) {
			plugin := &recordingRegOTPPlugin{regAck: &common.ServerRegisterAckMsg{ErrCode: "0", AuthServiceId: "other"}}
			server := &UdpServer{
				device: newSpikeDevice(t, core.NHP_SERVER, 0x55, nil), metrics: metrics.NewPublisherForTest(t),
				pluginHandlerMap: map[string]plugins.PluginHandler{"other": plugin},
			}
			if configured {
				handler, err := connectorcell.NewRegistrationHandler(newCapturingRegistrationAuthority(vectors))
				if err != nil {
					t.Fatal(err)
				}
				server.connectorRegistrationHandler = handler
			}
			body := []byte(`{"usrId":"u","devId":"d","aspId":"other","otp":"x"}`)
			responses := make(chan *core.MsgData, 1)
			ppd := directRegistrationPPD(body, peer, core.NHP_REG, 301, time.Now(), responses)
			if transaction := ppd.ConnData.FindRemoteTransaction(301); transaction != nil {
				t.Cleanup(transaction.CloseForTest)
			}
			if err := server.HandleRegisterRequest(ppd); err != nil {
				t.Fatal(err)
			}
			if plugin.regCalls != 1 || !bytes.Equal(body, []byte(`{"usrId":"u","devId":"d","aspId":"other","otp":"x"}`)) {
				t.Fatalf("generic calls=%d body=%q", plugin.regCalls, body)
			}
		})
	}
}

// TestConnectorRegistrationDarkCellDeniesAgentIntentInsteadOfFallthrough is the
// regression for the assigned-cell (cell0) rollout incident: a first-time
// native Connector registration that reaches an instance whose connector
// authority is dark (no NHP_CONNECTOR_REGISTRATION_* env, or an instance that
// predates its activation rollout) must be answered with a proper authenticated
// aspId="agent" denial — NOT leaked to the generic qURL knock handler (whose
// ServerRegisterAckMsg carries aspId "" / "qurl" and surfaces to qurl-go as
// "native registration reply aspId is invalid") and NOT dropped (client stall).
// The dark server deliberately leaves connectorRegistrationHandler nil AND
// connectorRegistrationTiming zero, exactly as configureConnectorCellAuthority
// does on a dark cell, so this also exercises the config-independent write
// deadline.
func TestConnectorRegistrationDarkCellDeniesAgentIntentInsteadOfFallthrough(t *testing.T) {
	_, _, peer, otp, registration, completion := connectorRegistrationFixture(t)

	t.Run("activation emits authenticated registration-disabled RAK", func(t *testing.T) {
		// A plugin that WOULD answer with the wrong aspId if the generic path
		// were reached, so a non-zero regCalls or an aspId != "agent" fails.
		plugin := &recordingRegOTPPlugin{regAck: &common.ServerRegisterAckMsg{ErrCode: "0", AuthServiceId: "qurl"}}
		server := &UdpServer{metrics: metrics.NewPublisherForTest(t), pluginHandlerMap: map[string]plugins.PluginHandler{"agent": plugin}}
		server.device = newSpikeDevice(t, core.NHP_SERVER, 0xe2, &core.DeviceOptions{DisableAgentPeerValidation: true})
		server.listenConn = mustUDPListener(t)
		agent := newSpikeDevice(t, core.NHP_AGENT, 0xe1, nil)
		agentListener := mustUDPListener(t)

		request, responses, transaction := realDirectRegistrationRequest(
			t, server, agent, agentListener, core.NHP_REG, 501, registration, time.Now(),
		)
		if err := server.HandleRegisterRequest(request); err != nil {
			t.Fatalf("HandleRegisterRequest: %v", err)
		}
		response := readDirectRegistrationResponse(t, agent, agentListener, responses)
		if response.HeaderType != core.NHP_RAK ||
			string(response.BodyMessage) != `{"errCode":"52107","errMsg":"registration disabled","aspId":"agent"}` {
			t.Fatalf("dark activation RAK type=%d body=%q", response.HeaderType, response.BodyMessage)
		}
		select {
		case <-transaction.Done():
		case <-time.After(time.Second):
			t.Fatal("dark activation transaction did not complete")
		}
		counters, _ := server.metrics.CountersForTest(t)
		if counters[MetricConnectorRegistrationHandlerAbsent] != 1 ||
			counters[MetricConnectorRegistrationResponseSent] != 1 ||
			counters[MetricConnectorRegistrationActivationRequest] != 0 {
			t.Fatalf("dark activation counters=%v", counters)
		}
		if plugin.regCalls != 0 || !allZero(request.BodyMessage) {
			t.Fatalf("dark activation leaked to generic plugin=%d wiped=%v", plugin.regCalls, allZero(request.BodyMessage))
		}
	})

	t.Run("completion emits authenticated unavailable LRT", func(t *testing.T) {
		plugin := &recordingRegOTPPlugin{}
		server := &UdpServer{metrics: metrics.NewPublisherForTest(t), pluginHandlerMap: map[string]plugins.PluginHandler{"agent": plugin}}
		server.device = newSpikeDevice(t, core.NHP_SERVER, 0xe4, &core.DeviceOptions{DisableAgentPeerValidation: true})
		server.listenConn = mustUDPListener(t)
		agent := newSpikeDevice(t, core.NHP_AGENT, 0xe3, nil)
		agentListener := mustUDPListener(t)

		request, responses, transaction := realDirectRegistrationRequest(
			t, server, agent, agentListener, core.NHP_LST, 502, completion, time.Now(),
		)
		if err := server.HandleListRequest(request); err != nil {
			t.Fatalf("HandleListRequest: %v", err)
		}
		response := readDirectRegistrationResponse(t, agent, agentListener, responses)
		if response.HeaderType != core.NHP_LRT ||
			string(response.BodyMessage) != `{"errCode":"52300","errMsg":"completion temporarily unavailable","retryAfterSeconds":5}` {
			t.Fatalf("dark completion LRT type=%d body=%q", response.HeaderType, response.BodyMessage)
		}
		select {
		case <-transaction.Done():
		case <-time.After(time.Second):
			t.Fatal("dark completion transaction did not complete")
		}
		counters, _ := server.metrics.CountersForTest(t)
		if counters[MetricConnectorRegistrationHandlerAbsent] != 1 ||
			counters[MetricConnectorRegistrationResponseSent] != 1 ||
			counters[MetricConnectorRegistrationCompletionRequest] != 0 ||
			counters[MetricConnectorRegistrationActivationRequest] != 0 {
			t.Fatalf("dark completion counters=%v", counters)
		}
		if plugin.listCalls != 0 || !allZero(request.BodyMessage) {
			t.Fatalf("dark completion leaked to generic plugin=%d wiped=%v", plugin.listCalls, allZero(request.BodyMessage))
		}
	})

	t.Run("otp is claimed and dropped without generic dispatch", func(t *testing.T) {
		plugin := &recordingRegOTPPlugin{}
		server := &UdpServer{
			device:           newSpikeDevice(t, core.NHP_SERVER, 0xe6, nil),
			metrics:          metrics.NewPublisherForTest(t),
			pluginHandlerMap: map[string]plugins.PluginHandler{"agent": plugin},
		}
		otpBody := bytes.Clone(otp)
		ppd := directRegistrationPPD(otpBody, peer, core.NHP_OTP, 503, time.Now(), nil)
		if err := server.HandleOTPRequest(ppd); err != nil {
			t.Fatalf("HandleOTPRequest: %v", err)
		}
		counters, _ := server.metrics.CountersForTest(t)
		if counters[MetricConnectorRegistrationHandlerAbsent] != 1 || counters[MetricConnectorRegistrationOTPRequest] != 0 {
			t.Fatalf("dark otp counters=%v", counters)
		}
		if plugin.otpCalls != 0 || !allZero(otpBody) {
			t.Fatalf("dark otp leaked to generic plugin=%d wiped=%v", plugin.otpCalls, allZero(otpBody))
		}
	})
}

// TestConnectorRegistrationResponseWriteDeadlineSelectsByAuthorityRan pins the
// live-vs-dark write-deadline contract directly, complementing the full-path
// dark test above: a live Authority response must use the receipt-anchored
// ladder, while the handler-absent denial must use the fixed budget from now and
// stay live even under the zero-value timing a dark cell carries.
func TestConnectorRegistrationResponseWriteDeadlineSelectsByAuthorityRan(t *testing.T) {
	t.Parallel()
	now := time.Now()
	receipt := now.Add(-20 * time.Millisecond).UnixNano()

	// authorityRan == true delegates to the receipt-anchored packet/write ladder,
	// so a future regression that accidentally routes the live path through the
	// fixed budget is caught here.
	live := &UdpServer{connectorRegistrationTiming: validConnectorRegistrationTiming()}
	wantDeadline, wantLive := live.connectorRegistrationWriteDeadline(receipt, now)
	gotDeadline, gotLive := live.connectorRegistrationResponseWriteDeadline(receipt, true, now)
	if !gotLive || gotLive != wantLive || !gotDeadline.Equal(wantDeadline) {
		t.Fatalf("authorityRan=true deadline=%v live=%v, want %v live=%v", gotDeadline, gotLive, wantDeadline, wantLive)
	}

	// authorityRan == false uses the fixed budget from now and stays live even
	// with the zero-value timing a dark cell carries — the property that keeps the
	// dark denial from being computed non-live and dropped.
	dark := &UdpServer{}
	deadline, isLive := dark.connectorRegistrationResponseWriteDeadline(receipt, false, now)
	if !isLive || !deadline.Equal(now.Add(connectorRegistrationHandlerAbsentWriteBudget)) {
		t.Fatalf("authorityRan=false deadline=%v live=%v, want %v live=true", deadline, isLive, now.Add(connectorRegistrationHandlerAbsentWriteBudget))
	}
	// Prove the fixed budget is load-bearing: the receipt-anchored ladder is NOT
	// live under a dark cell's zero timing, so without the authorityRan branch the
	// denial would be dropped — the exact stall this path fixes.
	if _, ladderLive := dark.connectorRegistrationWriteDeadline(receipt, now); ladderLive {
		t.Fatal("zero-timing receipt ladder unexpectedly live")
	}
}

func TestConnectorRegistrationDeadlinesAndTransportFailuresFailClosed(t *testing.T) {
	_, vectors, peer, otp, registration, completion := connectorRegistrationFixture(t)
	authority := newCapturingRegistrationAuthority(vectors)
	server := connectorRegistrationServer(t, authority, &recordingRegOTPPlugin{})
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0xd2, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.listenConn = mustUDPListener(t)
	agent := newSpikeDevice(t, core.NHP_AGENT, 0xd1, nil)
	agentListener := mustUDPListener(t)
	stale := time.Now().Add(-validConnectorRegistrationTiming().packetBudget - time.Millisecond)
	if err := server.HandleOTPRequest(directRegistrationPPD(otp, peer, core.NHP_OTP, 401, stale, nil)); err != nil {
		t.Fatal(err)
	}
	staleRegistration, _, staleRegistrationTransaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_REG, 402, registration, stale,
	)
	if err := server.HandleRegisterRequest(staleRegistration); err != nil {
		t.Fatal(err)
	}
	awaitConnectorRegistrationTransactionRetired(t, staleRegistration, staleRegistrationTransaction)
	assertNoConnectorRegistrationDatagram(t, agentListener)

	staleCompletion, _, staleCompletionTransaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_LST, 403, completion, stale,
	)
	if err := server.HandleListRequest(staleCompletion); !errors.Is(err, errConnectorRegistrationDeadline) {
		t.Fatalf("completion stale error=%v", err)
	}
	awaitConnectorRegistrationTransactionRetired(t, staleCompletion, staleCompletionTransaction)
	assertNoConnectorRegistrationDatagram(t, agentListener)
	if authority.callCount(conformance.ConnectorAuthorityOperationIssueRegistrationOTP)+
		authority.callCount(conformance.ConnectorAuthorityOperationActivateRegistration)+
		authority.callCount(conformance.ConnectorAuthorityOperationCompleteRegistration) != 0 {
		t.Fatal("stale requests reached Authority")
	}

	_, vectors, peer, _, registration, completion = connectorRegistrationFixture(t)
	authority = newCapturingRegistrationAuthority(vectors)
	server = connectorRegistrationServer(t, authority, nil)
	if err := server.HandleRegisterRequest(directRegistrationPPD(registration, peer, core.NHP_REG, 404, time.Now(), nil)); !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("registration transport error=%v", err)
	}
	if err := server.HandleListRequest(directRegistrationPPD(completion, peer, core.NHP_LST, 405, time.Now(), nil)); !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("completion transport error=%v", err)
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricConnectorRegistrationInternalFailure] != 2 {
		t.Fatalf("nil transaction internal-failure counters=%v", counters)
	}
}

func TestConnectorRegistrationBlockedWriterExpiresWithoutLateDatagram(t *testing.T) {
	_, vectors, _, _, _, completion := connectorRegistrationFixture(t)
	authority := newCapturingRegistrationAuthority(vectors)
	server := connectorRegistrationServer(t, authority, nil)
	server.connectorRegistrationTiming.writeBudget = 30 * time.Millisecond
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0xc2, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.listenConn = mustUDPListener(t)
	agent := newSpikeDevice(t, core.NHP_AGENT, 0xc1, nil)
	agentListener := mustUDPListener(t)
	request, _, transaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_LST, 408, completion, time.Now(),
	)

	server.initUDPWriteGate()
	if err := server.udpWriteGate.Acquire(context.Background(), udpWriteGateWeight); err != nil {
		t.Fatalf("acquire UDP write gate: %v", err)
	}
	started := time.Now()
	err := server.HandleListRequest(request)
	elapsed := time.Since(started)
	server.udpWriteGate.Release(udpWriteGateWeight)
	if !errors.Is(err, errConnectorRegistrationDeadline) {
		t.Fatalf("blocked writer error=%v, want deadline", err)
	}
	if elapsed < 15*time.Millisecond || elapsed > time.Second {
		t.Fatalf("blocked writer elapsed=%s, want bounded write budget", elapsed)
	}
	select {
	case <-transaction.Done():
	case <-time.After(time.Second):
		t.Fatal("response transaction did not complete before the blocked physical write")
	}

	if err := agentListener.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	if n, _, readErr := agentListener.ReadFromUDP(buffer); readErr == nil {
		t.Fatalf("deadline path emitted a late %d-byte datagram", n)
	} else if !isTimeout(readErr) {
		t.Fatalf("late-datagram read: %v", readErr)
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricConnectorRegistrationResponseAttempt] != 1 ||
		counters[MetricConnectorRegistrationResponseDeadline] != 1 ||
		counters[MetricConnectorRegistrationResponseSent] != 0 {
		t.Fatalf("blocked writer counters=%v", counters)
	}
}

func TestConnectorRegistrationAuthorityDropRetiresTransactionWithoutDatagram(t *testing.T) {
	_, vectors, _, _, registration, _ := connectorRegistrationFixture(t)
	authority := newCapturingRegistrationAuthority(vectors)
	authority.errors[conformance.ConnectorAuthorityOperationActivateRegistration] = errors.New("authority unavailable")
	server := connectorRegistrationServer(t, authority, nil)
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0xc4, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.listenConn = mustUDPListener(t)
	agent := newSpikeDevice(t, core.NHP_AGENT, 0xc3, nil)
	agentListener := mustUDPListener(t)
	request, _, transaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_REG, 410, registration, time.Now(),
	)

	if err := server.HandleRegisterRequest(request); err != nil {
		t.Fatalf("HandleRegisterRequest: %v", err)
	}
	if got := authority.callCount(conformance.ConnectorAuthorityOperationActivateRegistration); got != 1 {
		t.Fatalf("Authority calls=%d, want exactly one", got)
	}
	awaitConnectorRegistrationTransactionRetired(t, request, transaction)
	assertNoConnectorRegistrationDatagram(t, agentListener)
}

func TestConnectorRegistrationEncryptionFailureRetiresTransactionWithoutDatagram(t *testing.T) {
	_, _, _, _, registration, _ := connectorRegistrationFixture(t)
	server := &UdpServer{
		connectorRegistrationHandler: scriptedConnectorRegistrationHandler{
			result: connectorcell.RegistrationResult{
				Body:           []byte(`{"errCode":"0"}`),
				Action:         connectorcell.RegistrationActionEmitRAK,
				RecoveryAction: connectorcell.RegistrationRecoveryNone,
			},
		},
		connectorRegistrationTiming: validConnectorRegistrationTiming(),
		metrics:                     metrics.NewPublisherForTest(t),
	}
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0xc6, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.listenConn = mustUDPListener(t)
	agent := newSpikeDevice(t, core.NHP_AGENT, 0xc5, nil)
	agentListener := mustUDPListener(t)
	request, _, transaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_REG, 411, registration, time.Now(),
	)
	// The scripted handler does not consume the peer. Removing it after the real
	// decrypt forces the synchronous response-encryption seam to fail before
	// transaction completion or any physical write.
	request.RemotePubKey = nil

	if err := server.HandleRegisterRequest(request); !errors.Is(err, errConnectorRegistrationResponseEncode) {
		t.Fatalf("HandleRegisterRequest error=%v, want response encode failure", err)
	}
	awaitConnectorRegistrationTransactionRetired(t, request, transaction)
	assertNoConnectorRegistrationDatagram(t, agentListener)
}

func TestConnectorRegistrationConcurrentSameIDUsesExactOwningTransaction(t *testing.T) {
	_, _, _, _, registration, _ := connectorRegistrationFixture(t)
	server := &UdpServer{
		connectorRegistrationHandler: scriptedConnectorRegistrationHandler{
			result: connectorcell.RegistrationResult{
				Action:         connectorcell.RegistrationActionDropNoReply,
				RecoveryAction: connectorcell.RegistrationRecoveryPendingExact,
			},
		},
		connectorRegistrationTiming: validConnectorRegistrationTiming(),
		metrics:                     metrics.NewPublisherForTest(t),
	}
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0xc8, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.listenConn = mustUDPListener(t)
	agent := newSpikeDevice(t, core.NHP_AGENT, 0xc7, nil)
	agentListener := mustUDPListener(t)
	const transactionID = 412
	firstRequest, _, firstTransaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_REG, transactionID, bytes.Clone(registration), time.Now(),
	)
	// NHP's authenticated receive flood floor is 20 ms. Keep both responder
	// transactions live while making the second same-id packet independently
	// admissible.
	time.Sleep(25 * time.Millisecond)
	secondRequest, _, secondTransaction := realDirectRegistrationRequestOnConnection(
		t, server, agent, agentListener, core.NHP_REG, transactionID, bytes.Clone(registration),
		time.Now(), firstRequest.ConnData,
	)
	if got := firstRequest.ConnData.FindRemoteTransaction(transactionID); got != secondTransaction {
		t.Fatalf("same-id replacement=%p, want second transaction %p", got, secondTransaction)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, request := range []*core.PacketParserData{firstRequest, secondRequest} {
		go func() {
			<-start
			results <- server.HandleRegisterRequest(request)
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent same-id request: %v", err)
		}
	}
	select {
	case <-firstTransaction.Done():
	case <-time.After(time.Second):
		t.Fatal("first same-id owner did not retire")
	}
	select {
	case <-secondTransaction.Done():
	case <-time.After(time.Second):
		t.Fatal("second same-id owner did not retire")
	}
	if got := firstRequest.ConnData.FindRemoteTransaction(transactionID); got != nil {
		t.Fatalf("concurrent same-id transactions remained mapped: %p", got)
	}
	assertNoConnectorRegistrationDatagram(t, agentListener)
}

func TestConnectorRegistrationHandlerDeadlineUsesPacketTailForCompletionRetry(t *testing.T) {
	_, vectors, _, _, _, completion := connectorRegistrationFixture(t)
	authority := newCapturingRegistrationAuthority(vectors)
	server := connectorRegistrationServer(t, authority, nil)
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0xe2, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.listenConn = mustUDPListener(t)
	agent := newSpikeDevice(t, core.NHP_AGENT, 0xe1, nil)
	agentListener := mustUDPListener(t)
	receipt := time.Now().Add(-server.connectorRegistrationTiming.handlerBudget - 20*time.Millisecond)
	request, responses, transaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_LST, 409, completion, receipt,
	)

	if err := server.HandleListRequest(request); err != nil {
		t.Fatalf("HandleListRequest: %v", err)
	}
	response := readDirectRegistrationResponse(t, agent, agentListener, responses)
	if response.HeaderType != core.NHP_LRT || string(response.BodyMessage) !=
		`{"errCode":"52300","errMsg":"completion temporarily unavailable","retryAfterSeconds":5}` {
		t.Fatalf("tail response header=%d body=%q", response.HeaderType, response.BodyMessage)
	}
	select {
	case <-transaction.Done():
	case <-time.After(time.Second):
		t.Fatal("completion retry transaction did not complete")
	}
	if authority.callCount(conformance.ConnectorAuthorityOperationCompleteRegistration) != 0 {
		t.Fatal("expired handler deadline reached Authority")
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricConnectorRegistrationDeadlineRejected] != 1 ||
		counters[MetricConnectorRegistrationResponseSent] != 1 {
		t.Fatalf("handler-deadline tail counters=%v", counters)
	}
}

func TestConnectorRegistrationDeadlineRejectsInvalidReceiptAnchors(t *testing.T) {
	t.Parallel()
	now := time.Now()
	for _, test := range []struct {
		name    string
		receipt int64
	}{
		{name: "zero"},
		{name: "future", receipt: now.Add(time.Second).UnixNano()},
		{name: "expired", receipt: now.Add(-validConnectorRegistrationTiming().handlerBudget).UnixNano()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if deadline, live := connectorRegistrationDeadline(test.receipt, validConnectorRegistrationTiming().handlerBudget, now); live || !deadline.IsZero() && test.name != "expired" {
				t.Fatalf("deadline=%s live=%v", deadline, live)
			}
		})
	}
	receipt := now.Add(-time.Second)
	deadline, live := connectorRegistrationDeadline(receipt.UnixNano(), validConnectorRegistrationTiming().handlerBudget, now)
	if !live || !deadline.Equal(receipt.Add(validConnectorRegistrationTiming().handlerBudget)) {
		t.Fatalf("live deadline=%s live=%v", deadline, live)
	}
}

func TestConnectorRegistrationOTPLimiterPrecedesAuthority(t *testing.T) {
	_, vectors, peer, otp, _, _ := connectorRegistrationFixture(t)
	authority := newCapturingRegistrationAuthority(vectors)
	server := connectorRegistrationServer(t, authority, &recordingRegOTPPlugin{})
	server.otpRateLimiter = NewOTPRateLimiter(OTPRateLimiterConfig{
		Capacity: 1, RefillInterval: time.Hour, GlobalCapacity: 100, GlobalRate: 1, IdleTTL: time.Minute, MaxKeys: 16,
	})
	peerID := base64.StdEncoding.EncodeToString(peer)
	if !server.otpRateLimiter.Allow(peerID) {
		t.Fatal("failed to drain precondition token")
	}
	if err := server.HandleOTPRequest(directRegistrationPPD(otp, peer, core.NHP_OTP, 406, time.Now(), nil)); err != nil {
		t.Fatal(err)
	}
	if authority.callCount(conformance.ConnectorAuthorityOperationIssueRegistrationOTP) != 0 || !allZero(otp) {
		t.Fatalf("Authority calls=%d wiped=%v", authority.callCount(conformance.ConnectorAuthorityOperationIssueRegistrationOTP), allZero(otp))
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricOTPRejectRateLimited] != 1 || counters[MetricConnectorRegistrationOTPAdmissionRejected] != 1 {
		t.Fatalf("rate-limit counters=%v", counters)
	}
}

type scriptedConnectorRegistrationHandler struct {
	result connectorcell.RegistrationResult
}

func (h scriptedConnectorRegistrationHandler) HandleOTP(context.Context, []byte, []byte, string) connectorcell.RegistrationResult {
	return h.result
}
func (h scriptedConnectorRegistrationHandler) HandleRegistration(context.Context, []byte, []byte) connectorcell.RegistrationResult {
	return h.result
}
func (h scriptedConnectorRegistrationHandler) HandleRegistrationCompletion(context.Context, []byte, []byte) connectorcell.RegistrationResult {
	return h.result
}

func TestConnectorRegistrationRejectsImpossibleHandlerActions(t *testing.T) {
	_, _, peer, otp, registration, completion := connectorRegistrationFixture(t)
	for _, test := range []struct {
		name      string
		operation connectorRegistrationOperation
		body      []byte
		result    connectorcell.RegistrationResult
	}{
		{name: "OTP reply", operation: connectorRegistrationOTP, body: otp, result: connectorcell.RegistrationResult{Action: connectorcell.RegistrationActionEmitRAK, Body: []byte(`{}`)}},
		{name: "REG wrong reply", operation: connectorRegistrationActivation, body: registration, result: connectorcell.RegistrationResult{Action: connectorcell.RegistrationActionEmitLRT, Body: []byte(`{}`)}},
		{name: "REG reply with retry action", operation: connectorRegistrationActivation, body: registration, result: connectorcell.RegistrationResult{Action: connectorcell.RegistrationActionEmitRAK, Body: []byte(`{}`), RecoveryAction: connectorcell.RegistrationRecoveryPendingExact}},
		{name: "REG drop without retry action", operation: connectorRegistrationActivation, body: registration, result: connectorcell.RegistrationResult{Action: connectorcell.RegistrationActionDropNoReply}},
		{name: "completion drop", operation: connectorRegistrationCompletion, body: completion, result: connectorcell.RegistrationResult{Action: connectorcell.RegistrationActionDropNoReply}},
	} {
		t.Run(test.name, func(t *testing.T) {
			resultBody := test.result.Body
			server := &UdpServer{
				connectorRegistrationHandler: scriptedConnectorRegistrationHandler{result: test.result},
				connectorRegistrationTiming:  validConnectorRegistrationTiming(),
				metrics:                      metrics.NewPublisherForTest(t),
			}
			var (
				ppd           *core.PacketParserData
				transaction   *core.RemoteTransaction
				agentListener *net.UDPConn
			)
			if test.operation == connectorRegistrationOTP {
				ppd = directRegistrationPPD(bytes.Clone(test.body), peer, core.NHP_OTP, 501, time.Now(), nil)
			} else {
				server.device = newSpikeDevice(t, core.NHP_SERVER, 0xf2, &core.DeviceOptions{DisableAgentPeerValidation: true})
				server.listenConn = mustUDPListener(t)
				agent := newSpikeDevice(t, core.NHP_AGENT, 0xf1, nil)
				agentListener = mustUDPListener(t)
				headerType := core.NHP_REG
				if test.operation == connectorRegistrationCompletion {
					headerType = core.NHP_LST
				}
				ppd, _, transaction = realDirectRegistrationRequest(
					t, server, agent, agentListener, headerType, 501, test.body, time.Now(),
				)
			}
			var err error
			if test.operation == connectorRegistrationOTP {
				_, err = server.handleConnectorRegistrationOTP(ppd)
			} else {
				_, err = server.handleDirectConnectorRegistration(ppd, test.operation)
			}
			if !errors.Is(err, errConnectorRegistrationAction) {
				t.Fatalf("error=%v, want invalid action", err)
			}
			if len(resultBody) != 0 && !allZero(resultBody) {
				t.Fatal("rejected handler response body was not cleared")
			}
			if transaction != nil {
				awaitConnectorRegistrationTransactionRetired(t, ppd, transaction)
				assertNoConnectorRegistrationDatagram(t, agentListener)
			}
		})
	}
}

func TestConnectorRegistrationRelayedLifecycleRejectedBeforeAuthorityOrPlugins(t *testing.T) {
	_, vectors, _, otp, registration, completion := connectorRegistrationFixture(t)
	for _, test := range []struct {
		name       string
		headerType int
		operation  string
		body       []byte
	}{
		{
			name: "otp", headerType: core.NHP_OTP,
			operation: conformance.ConnectorAuthorityOperationIssueRegistrationOTP, body: otp,
		},
		{
			name: "activation", headerType: core.NHP_REG,
			operation: conformance.ConnectorAuthorityOperationActivateRegistration, body: registration,
		},
		{
			name: "completion", headerType: core.NHP_LST,
			operation: conformance.ConnectorAuthorityOperationCompleteRegistration, body: completion,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x82, &core.DeviceOptions{DisableAgentPeerValidation: true})
			agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x81, nil)
			serverListen := mustUDPListener(t)
			relayListen := mustUDPListener(t)
			authority := newCapturingRegistrationAuthority(vectors)
			plugin := &recordingRegOTPPlugin{}
			server := connectorRegistrationServer(t, authority, plugin)
			server.device = serverDev
			server.listenConn = serverListen
			server.relayPeerMap = make(map[string]*core.UdpPeer)
			inner := encryptRawInnerForRelay(
				t, agentDev, decodeBase64PubKey(serverDev.PublicKeyBase64()), test.headerType, 611, test.body,
			)
			outer, _, _ := buildRealRelayForwardOuterPpd(t, server, relayListen.LocalAddr().(*net.UDPAddr), inner, nil)
			server.HandleRelayForward(outer)

			if authority.callCount(test.operation) != 0 || plugin.otpCalls+plugin.regCalls+plugin.listCalls != 0 {
				t.Fatalf("authority=%d plugins=%d", authority.callCount(test.operation),
					plugin.otpCalls+plugin.regCalls+plugin.listCalls)
			}
			counters, _ := server.metrics.CountersForTest(t)
			if counters[MetricRelayForwardReject] != 1 ||
				counters[MetricConnectorRegistrationIngressRejected] != 0 {
				t.Fatalf("relay rejection counters=%v", counters)
			}
			if err := relayListen.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 2048)
			if n, _, err := relayListen.ReadFromUDP(buffer); err == nil {
				t.Fatalf("relay-rejected lifecycle request emitted %d bytes", n)
			} else if !isTimeout(err) {
				t.Fatalf("relay-rejected lifecycle read: %v", err)
			}
		})
	}
}

func TestConnectorRegistrationNonDirectIngressFailsClosed(t *testing.T) {
	_, vectors, peer, otp, registration, completion := connectorRegistrationFixture(t)
	operations := []struct {
		name       string
		headerType int
		operation  string
		body       []byte
	}{
		{
			name: "otp", headerType: core.NHP_OTP,
			operation: conformance.ConnectorAuthorityOperationIssueRegistrationOTP, body: otp,
		},
		{
			name: "activation", headerType: core.NHP_REG,
			operation: conformance.ConnectorAuthorityOperationActivateRegistration, body: registration,
		},
		{
			name: "completion", headerType: core.NHP_LST,
			operation: conformance.ConnectorAuthorityOperationCompleteRegistration, body: completion,
		},
	}
	ingresses := []struct {
		name      string
		transport core.IngressTransport
	}{
		{name: "unknown", transport: core.IngressTransportUnknown},
		{name: "webrtc", transport: core.IngressTransportWebRTC},
		{name: "future", transport: core.IngressTransport(255)},
	}
	for _, ingress := range ingresses {
		for _, operation := range operations {
			t.Run(ingress.name+"/"+operation.name, func(t *testing.T) {
				authority := newCapturingRegistrationAuthority(vectors)
				plugin := &recordingRegOTPPlugin{}
				server := connectorRegistrationServer(t, authority, plugin)
				wiped := false
				server.observeConnectorRegistrationRejectedBodyCleared = func(body []byte) { wiped = allZero(body) }
				body := bytes.Clone(operation.body)
				var (
					ppd           *core.PacketParserData
					transaction   *core.RemoteTransaction
					agentListener *net.UDPConn
				)
				if operation.headerType == core.NHP_OTP {
					ppd = directRegistrationPPD(body, peer, operation.headerType, 701, time.Now(), nil)
				} else {
					server.device = newSpikeDevice(t, core.NHP_SERVER, 0x72, &core.DeviceOptions{DisableAgentPeerValidation: true})
					server.listenConn = mustUDPListener(t)
					agent := newSpikeDevice(t, core.NHP_AGENT, 0x71, nil)
					agentListener = mustUDPListener(t)
					ppd, _, transaction = realDirectRegistrationRequest(
						t, server, agent, agentListener, operation.headerType, 701, body, time.Now(),
					)
				}
				ppd.ConnData.IngressTransport = ingress.transport

				var err error
				switch operation.headerType {
				case core.NHP_OTP:
					err = server.HandleOTPRequest(ppd)
				case core.NHP_REG:
					err = server.HandleRegisterRequest(ppd)
				case core.NHP_LST:
					err = server.HandleListRequest(ppd)
				}
				if err != nil {
					t.Fatalf("non-direct rejection returned error: %v", err)
				}
				if authority.callCount(operation.operation) != 0 ||
					plugin.otpCalls+plugin.regCalls+plugin.listCalls != 0 || !wiped || !allZero(ppd.BodyMessage) {
					t.Fatalf("authority=%d plugins=%d wiped=%v bodyCleared=%v",
						authority.callCount(operation.operation), plugin.otpCalls+plugin.regCalls+plugin.listCalls,
						wiped, allZero(ppd.BodyMessage))
				}
				counters, _ := server.metrics.CountersForTest(t)
				if counters[MetricConnectorRegistrationIngressRejected] != 1 ||
					counters[MetricConnectorRegistrationResponseAttempt] != 0 {
					t.Fatalf("non-direct rejection counters=%v", counters)
				}
				if transaction != nil {
					awaitConnectorRegistrationTransactionRetired(t, ppd, transaction)
					assertNoConnectorRegistrationDatagram(t, agentListener)
				}
			})
		}
	}
}

func TestConnectorRegistrationConfiguredRelayRejectsOtherASPLifecycle(t *testing.T) {
	_, vectors, _, _, _, _ := connectorRegistrationFixture(t)
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x92, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x91, nil)
	serverListen := mustUDPListener(t)
	relayListen := mustUDPListener(t)
	plugin := &recordingRegOTPPlugin{}
	server := connectorRegistrationServer(t, newCapturingRegistrationAuthority(vectors), nil)
	server.device = serverDev
	server.listenConn = serverListen
	server.relayPeerMap = make(map[string]*core.UdpPeer)
	server.pluginHandlerMap["other"] = plugin
	body := []byte(`{"usrId":"u","devId":"d","aspId":"other","pass":"secret"}`)
	inner := encryptRawInnerForRelay(t, agentDev, decodeBase64PubKey(serverDev.PublicKeyBase64()), core.NHP_OTP, 621, body)
	outer, _, _ := buildRealRelayForwardOuterPpd(t, server, relayListen.LocalAddr().(*net.UDPAddr), inner, nil)
	server.HandleRelayForward(outer)
	if plugin.otpCalls != 0 {
		t.Fatalf("generic plugin calls=%d, want 0", plugin.otpCalls)
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricRelayForwardReject] != 1 {
		t.Fatalf("relay rejection counters=%v", counters)
	}
}
