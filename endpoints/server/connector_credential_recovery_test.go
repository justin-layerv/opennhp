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

func validRecoveryEnvironment() map[string]string {
	return map[string]string{
		"NHP_ENVIRONMENT": "sandbox",
		"NHP_CELL_ID":     "cell0",
		ConnectorCredentialRecoveryAWSRegionEnvVar:  "us-east-2",
		ConnectorCredentialRecoveryAWSAccountEnvVar: "123456789012",
		ConnectorCredentialRecoveryAliasARNEnvVar:   "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ccr-cell0:blue",
	}
}

func mapEnvironment(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestCredentialRecoveryConfigurationIsDarkWhenAbsentAndFailsClosedWhenPresentInvalid(t *testing.T) {
	t.Parallel()
	dark := validRecoveryEnvironment()
	delete(dark, ConnectorCredentialRecoveryAWSRegionEnvVar)
	delete(dark, ConnectorCredentialRecoveryAWSAccountEnvVar)
	delete(dark, ConnectorCredentialRecoveryAliasARNEnvVar)
	if config, err := loadCredentialRecoveryConfig(mapEnvironment(dark)); config != nil || err != nil {
		t.Fatalf("absent config = %#v, %v; want dark nil", config, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "partial region", mutate: func(env map[string]string) { delete(env, ConnectorCredentialRecoveryAWSAccountEnvVar) }},
		{name: "partial alias", mutate: func(env map[string]string) { delete(env, ConnectorCredentialRecoveryAliasARNEnvVar) }},
		{name: "empty region present", mutate: func(env map[string]string) { env[ConnectorCredentialRecoveryAWSRegionEnvVar] = "" }},
		{name: "empty account present", mutate: func(env map[string]string) { env[ConnectorCredentialRecoveryAWSAccountEnvVar] = "" }},
		{name: "empty alias present", mutate: func(env map[string]string) { env[ConnectorCredentialRecoveryAliasARNEnvVar] = "" }},
		{name: "whitespace region", mutate: func(env map[string]string) { env[ConnectorCredentialRecoveryAWSRegionEnvVar] += " " }},
		{name: "whitespace account", mutate: func(env map[string]string) {
			env[ConnectorCredentialRecoveryAWSAccountEnvVar] = " " + env[ConnectorCredentialRecoveryAWSAccountEnvVar]
		}},
		{name: "whitespace alias", mutate: func(env map[string]string) { env[ConnectorCredentialRecoveryAliasARNEnvVar] += "\t" }},
		{name: "missing environment", mutate: func(env map[string]string) { delete(env, "NHP_ENVIRONMENT") }},
		{name: "missing cell", mutate: func(env map[string]string) { delete(env, "NHP_CELL_ID") }},
		{name: "wrong cell alias", mutate: func(env map[string]string) {
			env[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.Replace(env[ConnectorCredentialRecoveryAliasARNEnvVar], "cell0:blue", "cell1:blue", 1)
		}},
		{name: "wrong environment alias", mutate: func(env map[string]string) {
			env[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.Replace(env[ConnectorCredentialRecoveryAliasARNEnvVar], "nhp-sandbox-", "nhp-prod-", 1)
		}},
		{name: "invalid environment", mutate: func(env map[string]string) {
			env["NHP_ENVIRONMENT"] = "staging"
			env[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.Replace(env[ConnectorCredentialRecoveryAliasARNEnvVar], "nhp-sandbox-", "nhp-staging-", 1)
		}},
		{name: "numeric version", mutate: func(env map[string]string) {
			env[ConnectorCredentialRecoveryAliasARNEnvVar] = strings.TrimSuffix(env[ConnectorCredentialRecoveryAliasARNEnvVar], ":blue") + ":7"
		}},
		{name: "whitespace", mutate: func(env map[string]string) { env["NHP_CELL_ID"] = " cell0" }},
		{name: "leading dash", mutate: func(env map[string]string) { env["NHP_CELL_ID"] = "-cell0" }},
		{name: "trailing dash", mutate: func(env map[string]string) { env["NHP_CELL_ID"] = "cell0-" }},
		{name: "double dash", mutate: func(env map[string]string) { env["NHP_CELL_ID"] = "cell--0" }},
		{name: "uppercase", mutate: func(env map[string]string) { env["NHP_CELL_ID"] = "Cell0" }},
		{name: "too long", mutate: func(env map[string]string) { env["NHP_CELL_ID"] = strings.Repeat("a", 33) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			env := validRecoveryEnvironment()
			test.mutate(env)
			if config, err := loadCredentialRecoveryConfig(mapEnvironment(env)); config != nil ||
				!errors.Is(err, errInvalidCredentialRecoveryConfiguration) {
				t.Fatalf("config = %#v, error = %v", config, err)
			}
		})
	}
}

func TestCredentialRecoveryConfigurationAcceptsTerraformCellIDBoundaries(t *testing.T) {
	t.Parallel()
	for _, cellID := range []string{"0", "0-cell", strings.Repeat("a", 32)} {
		t.Run(cellID, func(t *testing.T) {
			env := validRecoveryEnvironment()
			env["NHP_CELL_ID"] = cellID
			env[ConnectorCredentialRecoveryAliasARNEnvVar] =
				"arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ccr-" + cellID + ":green"
			if config, err := loadCredentialRecoveryConfig(mapEnvironment(env)); err != nil || config == nil {
				t.Fatalf("cell %q config = %#v, %v", cellID, config, err)
			}
		})
	}
}

type capturingRecoveryAuthority struct {
	mu       sync.Mutex
	response []byte
	calls    int
	payload  []byte
	returned []byte
	deadline time.Time
}

func (a *capturingRecoveryAuthority) CompleteCredentialRecovery(ctx context.Context, payload []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	a.payload = payload
	a.deadline, _ = ctx.Deadline()
	a.returned = bytes.Clone(a.response)
	return a.returned, nil
}

func (a *capturingRecoveryAuthority) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func (a *capturingRecoveryAuthority) buffersCleared() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return allZero(a.payload) && allZero(a.returned)
}

func (a *capturingRecoveryAuthority) contextDeadline() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deadline
}

func allZero(values []byte) bool {
	for _, value := range values {
		if value != 0 {
			return false
		}
	}
	return true
}

func recoveryFixture(t *testing.T) (*conformance.AgentCredentialRecoveryFile, []byte, []byte, []byte) {
	t.Helper()
	vectors, err := conformance.AgentCredentialRecovery()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := base64.StdEncoding.Strict().DecodeString(vectors.Fixtures.AuthenticatedPeerPublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte(vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].RequestBodyJSON)
	for _, mapping := range vectors.PrivateOperations[conformance.AgentCredentialRecoveryCompleteOperation].PublicMappings {
		if mapping.PrivateOutcome == "success" {
			return vectors, peer, request, []byte(mapping.PrivateResponseBodyJSON)
		}
	}
	t.Fatal("missing recovery success mapping")
	return nil, nil, nil, nil
}

func recoveryServer(t *testing.T, authority *capturingRecoveryAuthority) *UdpServer {
	t.Helper()
	handler, err := connectorcell.NewHandler(authority)
	if err != nil {
		t.Fatal(err)
	}
	return &UdpServer{
		credentialRecoveryHandler: handler,
		metrics:                   metrics.NewPublisherForTest(t),
	}
}

func TestDirectCredentialRecoveryExactGoldenUsesReceiptDeadlineAndWipesRequest(t *testing.T) {
	t.Parallel()
	vectors, peer, request, privateResponse := recoveryFixture(t)
	authority := &capturingRecoveryAuthority{response: privateResponse}
	server := recoveryServer(t, authority)
	receipt := time.Now().Add(-20 * time.Millisecond)
	ppd := &core.PacketParserData{LocalInitTime: receipt.UnixNano(), RemotePubKey: peer, BodyMessage: request}

	body, handled, deadline, _, err := server.buildDirectCredentialRecoveryResult(ppd)
	want := vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].SuccessBodyJSON
	if err != nil || !handled || string(body) != want || authority.callCount() != 1 {
		t.Fatalf("body=%q handled=%v err=%v calls=%d", body, handled, err, authority.callCount())
	}
	if wantDeadline := receipt.Add(connectorCredentialRecoveryBudget); !deadline.Equal(wantDeadline) ||
		!authority.contextDeadline().Equal(wantDeadline) {
		t.Fatalf("deadlines result=%s authority=%s want=%s", deadline, authority.contextDeadline(), wantDeadline)
	}
	if !allZero(request) || !authority.buffersCleared() {
		t.Fatal("direct request or Authority-owned secret buffer was not cleared")
	}
	if string(body) != want {
		t.Fatal("secret-free LRT response was cleared or changed before transaction ownership")
	}
}

func TestDirectCredentialRecoveryMalformedIntentIsFixedInvalidAndOrdinaryIsUntouched(t *testing.T) {
	t.Parallel()
	_, peer, valid, _ := recoveryFixture(t)
	wantInvalid, err := connectorcell.EncodeCompletionError(connectorcell.CompletionErrorInvalidRequest)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{
		[]byte(strings.Replace(string(valid), `"aspId":"agent"`, `"aspId":"other","aspId":"agent"`, 1)),
		[]byte(strings.Replace(string(valid), `"query":"agent_credential_recovery"`, `"query":"ordinary","query":"agent_credential_recovery"`, 1)),
		[]byte(string(valid) + `{}`),
		append(bytes.Clone(valid), 0xff),
	} {
		authority := &capturingRecoveryAuthority{}
		server := recoveryServer(t, authority)
		body, handled, _, _, buildErr := server.buildDirectCredentialRecoveryResult(&core.PacketParserData{
			LocalInitTime: time.Now().UnixNano(), RemotePubKey: peer, BodyMessage: malformed,
		})
		if buildErr != nil || !handled || !bytes.Equal(body, wantInvalid) || authority.callCount() != 0 || !allZero(malformed) {
			t.Fatalf("body=%q handled=%v err=%v calls=%d wiped=%v", body, handled, buildErr, authority.callCount(), allZero(malformed))
		}
	}

	ordinary := []byte(strings.Replace(string(valid), `"query":"agent_credential_recovery"`, `"query":"ordinary"`, 1))
	wantOrdinary := bytes.Clone(ordinary)
	authority := &capturingRecoveryAuthority{}
	server := recoveryServer(t, authority)
	body, handled, _, _, buildErr := server.buildDirectCredentialRecoveryResult(&core.PacketParserData{
		LocalInitTime: time.Now().UnixNano(), RemotePubKey: peer, BodyMessage: ordinary,
	})
	if buildErr != nil || handled || body != nil || authority.callCount() != 0 || !bytes.Equal(ordinary, wantOrdinary) {
		t.Fatalf("ordinary body=%q handled=%v err=%v calls=%d", body, handled, buildErr, authority.callCount())
	}
}

func TestDirectCredentialRecoveryRejectsInvalidReceiptAndCancellationBeforeAuthority(t *testing.T) {
	t.Parallel()
	_, peer, valid, _ := recoveryFixture(t)
	now := time.Now()
	for _, test := range []struct {
		name    string
		receipt int64
	}{
		{name: "zero", receipt: 0},
		{name: "stale", receipt: now.Add(-connectorCredentialRecoveryBudget).UnixNano()},
		{name: "future", receipt: now.Add(time.Minute).UnixNano()},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &capturingRecoveryAuthority{}
			server := recoveryServer(t, authority)
			request := bytes.Clone(valid)
			body, handled, _, _, err := server.buildDirectCredentialRecoveryResult(&core.PacketParserData{
				LocalInitTime: test.receipt, RemotePubKey: peer, BodyMessage: request,
			})
			if !handled || body != nil || !errors.Is(err, errCredentialRecoveryDeadline) ||
				authority.callCount() != 0 || !allZero(request) {
				t.Fatalf("body=%q handled=%v err=%v calls=%d wiped=%v", body, handled, err, authority.callCount(), allZero(request))
			}
		})
	}

	authority := &capturingRecoveryAuthority{}
	server := recoveryServer(t, authority)
	server.lifecycleCtx, server.lifecycleCancel = context.WithCancel(context.Background())
	server.lifecycleCancel()
	request := bytes.Clone(valid)
	body, handled, _, _, err := server.buildDirectCredentialRecoveryResult(&core.PacketParserData{
		LocalInitTime: time.Now().UnixNano(), RemotePubKey: peer, BodyMessage: request,
	})
	if !handled || body != nil || !errors.Is(err, errCredentialRecoveryDeadline) || authority.callCount() != 0 || !allZero(request) {
		t.Fatalf("canceled body=%q handled=%v err=%v calls=%d", body, handled, err, authority.callCount())
	}
}

func TestHandleListRequestLateMalformedRecoveryIsDeadlineWithNoReply(t *testing.T) {
	t.Parallel()
	_, peer, valid, _ := recoveryFixture(t)
	request := []byte(strings.Replace(
		string(valid),
		`"query":"agent_credential_recovery"`,
		`"query":"ordinary","query":"agent_credential_recovery"`,
		1,
	))
	authority := &capturingRecoveryAuthority{}
	plugin := &recordingRegOTPPlugin{}
	server := recoveryServer(t, authority)
	server.pluginHandlerMap = map[string]plugins.PluginHandler{"agent": plugin}
	responseMessages := make(chan *core.MsgData, 1)
	transaction := core.NewRemoteTransactionForTest(44, responseMessages)
	t.Cleanup(transaction.CloseForTest)
	ppd := &core.PacketParserData{
		LocalInitTime: time.Now().Add(-connectorCredentialRecoveryBudget - time.Second).UnixNano(),
		RemotePubKey:  peer,
		BodyMessage:   request,
		HeaderType:    core.NHP_LST,
		SenderTrxId:   44,
		ConnData: &core.ConnectionData{
			RemoteAddr:           &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 62206},
			RemoteTransactionMap: map[uint64]*core.RemoteTransaction{44: transaction},
		},
	}
	if err := server.HandleListRequest(ppd); !errors.Is(err, errCredentialRecoveryDeadline) {
		t.Fatalf("HandleListRequest error = %v, want receipt deadline", err)
	}
	select {
	case message := <-responseMessages:
		t.Fatalf("late malformed request unexpectedly queued LRT %q", message.Message)
	default:
	}
	if authority.callCount() != 0 || plugin.listCalls != 0 || !allZero(request) {
		t.Fatalf("authority calls=%d plugin calls=%d request wiped=%v", authority.callCount(), plugin.listCalls, allZero(request))
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricConnectorCredentialRecoveryRequest] != 1 ||
		counters[MetricConnectorCredentialRecoveryDeadlineRejected] != 1 ||
		counters[MetricConnectorCredentialRecoveryRequestRejected] != 0 {
		t.Fatalf("late malformed terminal counters = %#v", counters)
	}
}

func TestHandleListRequestRecoveryBypassesGenericPluginAndPreservesQueuedLRT(t *testing.T) {
	t.Parallel()
	vectors, peer, request, privateResponse := recoveryFixture(t)
	authority := &capturingRecoveryAuthority{response: privateResponse}
	plugin := &recordingRegOTPPlugin{}
	server := recoveryServer(t, authority)
	server.pluginHandlerMap = map[string]plugins.PluginHandler{"agent": plugin}
	responseMessages := make(chan *core.MsgData, 1)
	ppd := &core.PacketParserData{
		LocalInitTime: time.Now().UnixNano(),
		RemotePubKey:  peer,
		BodyMessage:   request,
		HeaderType:    core.NHP_LST,
		SenderTrxId:   41,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 62206},
			RemoteTransactionMap: map[uint64]*core.RemoteTransaction{
				41: core.NewRemoteTransactionForTest(41, responseMessages),
			},
		},
	}
	if err := server.HandleListRequest(ppd); err != nil {
		t.Fatalf("HandleListRequest: %v", err)
	}
	select {
	case message := <-responseMessages:
		if message.HeaderType != core.NHP_LRT || string(message.Message) !=
			vectors.PublicExchanges[conformance.AgentCredentialRecoveryCellPhase].SuccessBodyJSON {
			t.Fatalf("queued response = type %d body %q", message.HeaderType, message.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("credential-recovery LRT was not queued")
	}
	if plugin.listCalls != 0 || authority.callCount() != 1 || !allZero(request) {
		t.Fatalf("plugin calls=%d authority calls=%d wiped=%v", plugin.listCalls, authority.callCount(), allZero(request))
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricConnectorCredentialRecoveryRequest] != 1 ||
		counters[MetricConnectorCredentialRecoverySuccess] != 1 ||
		counters[MetricConnectorCredentialRecoveryDeadlineRejected] != 0 {
		t.Fatalf("terminal counters = %#v", counters)
	}
}

func TestHandleListRequestRecoveryTransactionHandoffUsesReceiptDeadline(t *testing.T) {
	_, peer, request, privateResponse := recoveryFixture(t)
	authority := &capturingRecoveryAuthority{response: privateResponse}
	server := recoveryServer(t, authority)
	responseMessages := make(chan *core.MsgData)
	transaction := core.NewRemoteTransactionForTest(42, responseMessages)
	t.Cleanup(transaction.CloseForTest)
	remaining := 150 * time.Millisecond
	receipt := time.Now().Add(-(connectorCredentialRecoveryBudget - remaining))
	ppd := &core.PacketParserData{
		LocalInitTime: receipt.UnixNano(),
		RemotePubKey:  peer,
		BodyMessage:   request,
		HeaderType:    core.NHP_LST,
		SenderTrxId:   42,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 62206},
			RemoteTransactionMap: map[uint64]*core.RemoteTransaction{
				42: transaction,
			},
		},
	}
	started := time.Now()
	err := server.HandleListRequest(ppd)
	elapsed := time.Since(started)
	if !errors.Is(err, errCredentialRecoveryDeadline) {
		t.Fatalf("HandleListRequest error = %v, want receipt deadline", err)
	}
	if elapsed < 50*time.Millisecond || elapsed > time.Second {
		t.Fatalf("blocked transaction handoff elapsed %s", elapsed)
	}
	if authority.callCount() != 1 || !allZero(request) {
		t.Fatalf("authority calls=%d request wiped=%v", authority.callCount(), allZero(request))
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricConnectorCredentialRecoveryRequest] != 1 ||
		counters[MetricConnectorCredentialRecoveryDeadlineRejected] != 1 ||
		counters[MetricConnectorCredentialRecoverySuccess] != 0 {
		t.Fatalf("terminal counters = %#v", counters)
	}

	// The timeout must not be implemented with an abandoned sender goroutine:
	// making a receiver available after return must not receive a stale LRT.
	select {
	case message := <-responseMessages:
		t.Fatalf("late LRT delivered after receipt deadline: %q", message.Message)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestHandleListRequestWithRecoveryConfiguredLeavesOrdinaryLSTOnGenericPath(t *testing.T) {
	t.Parallel()
	_, peer, recoveryRequest, _ := recoveryFixture(t)
	ordinary := []byte(strings.Replace(
		string(recoveryRequest), `"query":"agent_credential_recovery"`, `"query":"ordinary"`, 1,
	))
	wantOrdinary := bytes.Clone(ordinary)
	authority := &capturingRecoveryAuthority{}
	plugin := &recordingRegOTPPlugin{listAck: &common.ServerListResultMsg{
		ErrCode: common.ErrSuccess.ErrorCode(), ListResults: map[string]any{"resource": "allowed"},
	}}
	server := recoveryServer(t, authority)
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.pluginHandlerMap = map[string]plugins.PluginHandler{"agent": plugin}
	responseMessages := make(chan *core.MsgData, 1)
	transaction := core.NewRemoteTransactionForTest(43, responseMessages)
	t.Cleanup(transaction.CloseForTest)
	ppd := &core.PacketParserData{
		LocalInitTime: time.Now().UnixNano(), RemotePubKey: peer, BodyMessage: ordinary,
		HeaderType: core.NHP_LST, SenderTrxId: 43,
		ConnData: &core.ConnectionData{
			RemoteAddr:           &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 62206},
			RemoteTransactionMap: map[uint64]*core.RemoteTransaction{43: transaction},
		},
	}
	if err := server.HandleListRequest(ppd); err != nil {
		t.Fatalf("HandleListRequest: %v", err)
	}
	select {
	case message := <-responseMessages:
		var result common.ServerListResultMsg
		if message.HeaderType != core.NHP_LRT || json.Unmarshal(message.Message, &result) != nil ||
			result.ErrCode != common.ErrSuccess.ErrorCode() || result.ListResults["resource"] != "allowed" {
			t.Fatalf("generic LRT = type %d body %q", message.HeaderType, message.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("generic LRT was not queued")
	}
	if plugin.listCalls != 1 || authority.callCount() != 0 || !bytes.Equal(ordinary, wantOrdinary) {
		t.Fatalf("plugin calls=%d authority calls=%d request changed=%v", plugin.listCalls, authority.callCount(), !bytes.Equal(ordinary, wantOrdinary))
	}
}
