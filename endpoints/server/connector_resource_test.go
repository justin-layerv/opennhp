package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorcell"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type fixedConnectorResourceAuthority struct{ response []byte }

func (a fixedConnectorResourceAuthority) ResolveConnectorResource(context.Context, []byte) ([]byte, error) {
	return append([]byte(nil), a.response...), nil
}

type recordingConnectorResourceHandler struct{ calls int }

func (h *recordingConnectorResourceHandler) HandleDirect(context.Context, []byte, []byte) (connectorcell.HandleResult, bool) {
	h.calls++
	return connectorcell.HandleResult{}, true
}

func connectorResourceServerRequest(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	for index := range nonce {
		nonce[index] = byte(index)
	}
	body, err := json.Marshal(map[string]any{
		"usrId": "agent-1", "devId": "agent-1", "aspId": "agent",
		"usrData": map[string]any{
			"query": "connector_resource", "version": 1,
			"request_nonce": base64.RawURLEncoding.EncodeToString(nonce),
			"connector_id":  "prod-dashboard",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestConnectorResourceRealSealedLRTsFitOperationalDatagramCeiling(t *testing.T) {
	const resourceID = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"
	const crid = "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha"
	const routingID = "c-pvlulb4otmwg4scb7dajq37eiov6xdwptfxp2uwdsy2j23uo7zda"
	agentID := "a" + strings.Repeat("bc", 31) + "1"
	connectorID := "a" + strings.Repeat("de", 31) + "1"
	// A valid less-than-only value forces encoding/json's HTML-safe encoder to
	// render every byte as \u003c. This is the conformance contract's maximum
	// encoded knock_resource_id contribution.
	knockResourceID := strings.Repeat("<", 64)
	if len(agentID) != 64 || len(connectorID) != 64 || len(knockResourceID) != 64 {
		t.Fatal("maximum-field fixture lengths drifted")
	}
	nonce := make([]byte, 32)
	for index := range nonce {
		nonce[index] = byte(0x80 + index)
	}
	request, err := json.Marshal(map[string]any{
		"usrId": agentID, "devId": agentID, "aspId": "agent",
		"usrData": map[string]any{
			"query": "connector_resource", "version": 1,
			"request_nonce":        base64.RawURLEncoding.EncodeToString(nonce),
			"connector_id":         connectorID,
			"expected_resource_id": resourceID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	success := []byte(`{"version":1,"result":{"agent_id":"` + agentID + `","connector_id":"` + connectorID +
		`","resource_id":"` + resourceID + `","connector_routing_id":"` + routingID +
		`","knock_resource_id":"` + knockResourceID + `","crid":"` + crid + `","found_existing":true}}`)

	tests := []struct {
		name     string
		response []byte
		wantCode string
		minBody  int
	}{
		{name: "maximum success", response: success, wantCode: "0", minBody: 943},
		{name: "unavailable", response: []byte(`{"version":1,"error":{"code":"unavailable"}}`), wantCode: "52500"},
		{name: "unavailable retry", response: []byte(`{"version":1,"error":{"code":"unavailable","retry_after_seconds":3600}}`), wantCode: "52500"},
		{name: "identity rejected", response: []byte(`{"version":1,"error":{"code":"identity_rejected"}}`), wantCode: "52501"},
		{name: "entitlement denied", response: []byte(`{"version":1,"error":{"code":"entitlement_denied"}}`), wantCode: "52502"},
		{name: "identity conflict", response: []byte(`{"version":1,"error":{"code":"resource_identity_conflict"}}`), wantCode: "52503"},
		{name: "quota", response: []byte(`{"version":1,"error":{"code":"quota"}}`), wantCode: "52504"},
		{name: "rate limited", response: []byte(`{"version":1,"error":{"code":"rate_limited","retry_after_seconds":3600}}`), wantCode: "52505"},
		{name: "invalid request", response: []byte(`{"version":1,"error":{"code":"invalid_request"}}`), wantCode: "52506"},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plugin := &recordingRegOTPPlugin{}
			server := connectorResourceTestServer(t, test.response, plugin)
			server.device = newSpikeDevice(t, core.NHP_SERVER, byte(0x30+index*2), &core.DeviceOptions{DisableAgentPeerValidation: true})
			server.listenConn = mustUDPListener(t)
			agent := newSpikeDevice(t, core.NHP_AGENT, byte(0x31+index*2), nil)
			agentListener := mustUDPListener(t)
			ppd, responses, transaction := realDirectRegistrationRequest(
				t, server, agent, agentListener, core.NHP_LST, uint64(7000+index), request, time.Now(),
			)
			if err := server.HandleListRequest(ppd); err != nil {
				t.Fatalf("HandleListRequest: %v", err)
			}
			wire := readUDPWithTimeout(t, agentListener, time.Second)
			if connectorResourceResponseIsOversize(len(wire)) {
				t.Fatalf("sealed %s LRT = %d bytes, exceeds %d", test.name, len(wire), connectorResourceMaxDatagramBytes)
			}
			routeResponseToTransaction(t, agent, wire)
			var response *core.PacketParserData
			select {
			case response = <-responses:
			case <-time.After(time.Second):
				t.Fatal("agent did not decrypt sealed LRT")
			}
			if response.HeaderType != core.NHP_LRT {
				t.Fatalf("header type = %d, want NHP_LRT", response.HeaderType)
			}
			var public struct {
				ErrCode string `json:"errCode"`
			}
			if err := json.Unmarshal(response.BodyMessage, &public); err != nil || public.ErrCode != test.wantCode {
				t.Fatalf("decrypted body = %s, err=%v, want errCode %s", response.BodyMessage, err, test.wantCode)
			}
			if len(response.BodyMessage) < test.minBody {
				t.Fatalf("decrypted success body = %d bytes, fixture no longer exercises maximum fields", len(response.BodyMessage))
			}
			select {
			case <-transaction.Done():
			case <-time.After(time.Second):
				t.Fatal("connector resource transaction did not complete")
			}
			if plugin.listCalls != 0 {
				t.Fatalf("generic plugin received %d connector resource calls", plugin.listCalls)
			}
			t.Logf("real sealed %s LRT: body=%d datagram=%d ceiling=%d", test.name, len(response.BodyMessage), len(wire), connectorResourceMaxDatagramBytes)
		})
	}
}

func TestConnectorResourceResponseOversizeBoundary(t *testing.T) {
	if got, want := conformance.ConnectorResourceLSTV1MaxPlaintextBodyBytes+
		conformance.ConnectorResourceLSTV1ConservativeSealBudgetBytes,
		connectorResourceMaxDatagramBytes; got != want {
		t.Fatalf("conformance body + seal budget = %d, want packet ceiling %d", got, want)
	}
	for _, test := range []struct {
		size int
		want bool
	}{
		{connectorResourceMaxDatagramBytes - 1, false},
		{connectorResourceMaxDatagramBytes, false},
		{connectorResourceMaxDatagramBytes + 1, true},
	} {
		if got := connectorResourceResponseIsOversize(test.size); got != test.want {
			t.Fatalf("connectorResourceResponseIsOversize(%d) = %t, want %t", test.size, got, test.want)
		}
	}
}

func TestConnectorResourceExpiredHandlerAndResponseDeadlineCountOnce(t *testing.T) {
	server := connectorResourceTestServer(t, []byte(`{"version":1,"error":{"code":"unavailable"}}`), &recordingRegOTPPlugin{})
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0xc2, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.listenConn = mustUDPListener(t)
	agent := newSpikeDevice(t, core.NHP_AGENT, 0xc1, nil)
	agentListener := mustUDPListener(t)
	request, _, transaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_LST, 8300, connectorResourceServerRequest(t),
		time.Now().Add(-server.connectorRegistrationTiming.packetBudget-time.Second),
	)

	if err := server.HandleListRequest(request); !errors.Is(err, errConnectorResourceDeadline) {
		t.Fatalf("HandleListRequest error = %v, want %v", err, errConnectorResourceDeadline)
	}
	awaitConnectorRegistrationTransactionRetired(t, request, transaction)
	assertNoConnectorRegistrationDatagram(t, agentListener)
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricConnectorResourceDeadlineRejected] != 1 ||
		counters[MetricConnectorResourceResponseAttempt] != 1 ||
		counters[MetricConnectorResourceResponseSent] != 0 {
		t.Fatalf("expired connector-resource counters=%v", counters)
	}
}

func TestConnectorResourceNonDirectIngressRetiresWithoutAuthorityPluginOrResponse(t *testing.T) {
	for index, ingress := range []struct {
		name      string
		transport core.IngressTransport
	}{
		{name: "unknown", transport: core.IngressTransportUnknown},
		{name: "webrtc", transport: core.IngressTransportWebRTC},
		{name: "relayed", transport: core.IngressTransportRelayed},
		{name: "future", transport: core.IngressTransport(255)},
	} {
		t.Run(ingress.name, func(t *testing.T) {
			handler := &recordingConnectorResourceHandler{}
			plugin := &recordingRegOTPPlugin{}
			server := &UdpServer{
				connectorResourceHandler:    handler,
				connectorRegistrationTiming: validConnectorRegistrationTiming(),
				metrics:                     metrics.NewPublisherForTest(t),
				pluginHandlerMap:            map[string]plugins.PluginHandler{"agent": plugin},
			}
			server.device = newSpikeDevice(t, core.NHP_SERVER, byte(0x92+index*2), &core.DeviceOptions{DisableAgentPeerValidation: true})
			server.listenConn = mustUDPListener(t)
			agent := newSpikeDevice(t, core.NHP_AGENT, byte(0x91+index*2), nil)
			agentListener := mustUDPListener(t)
			body := connectorResourceServerRequest(t)
			request, _, transaction := realDirectRegistrationRequest(
				t, server, agent, agentListener, core.NHP_LST, uint64(8100+index), body, time.Now(),
			)
			request.ConnData.IngressTransport = ingress.transport

			if err := server.HandleListRequest(request); err != nil {
				t.Fatalf("HandleListRequest: %v", err)
			}
			awaitConnectorRegistrationTransactionRetired(t, request, transaction)
			assertNoConnectorRegistrationDatagram(t, agentListener)
			counters, _ := server.metrics.CountersForTest(t)
			if counters[MetricConnectorResourceIngressRejected] != 1 ||
				counters[MetricConnectorResourceRequest] != 0 ||
				counters[MetricConnectorResourceResponseAttempt] != 0 {
				t.Fatalf("non-direct counters=%v", counters)
			}
			if handler.calls != 0 || plugin.listCalls != 0 || !allZero(request.BodyMessage) {
				t.Fatalf("handler=%d plugin=%d requestWiped=%v",
					handler.calls, plugin.listCalls, allZero(request.BodyMessage))
			}
		})
	}
}

func TestConnectorResourceDarkHandlerReturnsAuthenticatedUnavailableWithoutPluginFallback(t *testing.T) {
	plugin := &recordingRegOTPPlugin{}
	server := &UdpServer{
		metrics:          metrics.NewPublisherForTest(t),
		pluginHandlerMap: map[string]plugins.PluginHandler{"agent": plugin},
	}
	server.device = newSpikeDevice(t, core.NHP_SERVER, 0xb2, &core.DeviceOptions{DisableAgentPeerValidation: true})
	server.listenConn = mustUDPListener(t)
	agent := newSpikeDevice(t, core.NHP_AGENT, 0xb1, nil)
	agentListener := mustUDPListener(t)
	body := connectorResourceServerRequest(t)
	request, responses, transaction := realDirectRegistrationRequest(
		t, server, agent, agentListener, core.NHP_LST, 8200, body, time.Now(),
	)

	if err := server.HandleListRequest(request); err != nil {
		t.Fatalf("HandleListRequest: %v", err)
	}
	response := readDirectRegistrationResponse(t, agent, agentListener, responses)
	const unavailable = `{"errCode":"52500","errMsg":"connector resource temporarily unavailable"}`
	if response.HeaderType != core.NHP_LRT || !bytes.Equal(response.BodyMessage, []byte(unavailable)) {
		t.Fatalf("dark connector-resource response type=%d body=%q", response.HeaderType, response.BodyMessage)
	}
	awaitConnectorRegistrationTransactionRetired(t, request, transaction)
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricConnectorResourceHandlerAbsent] != 1 ||
		counters[MetricConnectorResourceRequest] != 1 ||
		counters[MetricConnectorResourceResponseAttempt] != 1 ||
		counters[MetricConnectorResourceResponseSent] != 1 {
		t.Fatalf("dark connector-resource counters=%v", counters)
	}
	if plugin.listCalls != 0 || !allZero(request.BodyMessage) {
		t.Fatalf("dark connector-resource plugin=%d requestWiped=%v",
			plugin.listCalls, allZero(request.BodyMessage))
	}
}

func connectorResourceTestServer(t *testing.T, authorityResponse []byte, plugin *recordingRegOTPPlugin) *UdpServer {
	t.Helper()
	handler, err := connectorcell.NewConnectorResourceHandler(
		fixedConnectorResourceAuthority{response: authorityResponse}, "sandbox",
	)
	if err != nil {
		t.Fatal(err)
	}
	return &UdpServer{
		connectorResourceHandler:    handler,
		connectorRegistrationTiming: validConnectorRegistrationTiming(),
		metrics:                     metrics.NewPublisherForTest(t),
		pluginHandlerMap:            map[string]plugins.PluginHandler{"agent": plugin},
	}
}
