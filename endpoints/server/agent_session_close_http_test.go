package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/layervai/nhp/internalauth"

	"github.com/OpenNHP/opennhp/nhp/core"
)

func newFleetCloseTestSigner(t *testing.T) *internalauth.Signer {
	t.Helper()
	signer, err := internalauth.New(strings.Repeat("f", internalauth.MinSecretLength))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func configureFleetCloseTestOrigin(s *UdpServer, instanceID, ip string, port int) {
	s.localIp = ip
	s.instanceIdentityMu.Lock()
	s.instanceID = instanceID
	s.instanceIdentityMu.Unlock()
	hs := &HttpServer{listenAddr: &net.TCPAddr{IP: net.ParseIP(ip), Port: port}}
	hs.running.Store(true)
	s.httpServer = hs
	// httptest allocates ephemeral loopback ports; production leaves this seam
	// nil and is restricted to the Terraform-admitted listener set.
	s.fleetCloseHTTPPortAllowedFn = func(int) bool { return true }
}

func fleetCloseTestBody(t *testing.T, agentKey []byte, originID, originIP string, now time.Time) []byte {
	t.Helper()
	body, err := json.Marshal(&agentSessionCloseFleetEvent{
		EventID:            "00112233445566778899aabbccddeeff",
		AgentPublicKey:     base64.StdEncoding.EncodeToString(agentKey),
		IssuedThroughNanos: now.UnixNano(),
		ExpiresAt:          now.Add(agentSessionCloseEventTTL).Unix(),
		OriginServer:       originID,
		OriginIP:           originIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func serveFleetCloseRequest(t *testing.T, hs *HttpServer, signer *internalauth.Signer, body []byte, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(agentSessionCloseFleetPath, hs.handleInternalAgentSessionClose)
	req := httptest.NewRequest(http.MethodPost, agentSessionCloseFleetPath, bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set(internalauth.Header, signer.Sign(http.MethodPost, agentSessionCloseFleetPath, body))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func serveExactFleetCloseRequest(t *testing.T, hs *HttpServer, signer *internalauth.Signer, body []byte, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(exactSessionCloseFleetPath, hs.handleInternalExactSessionClose)
	req := httptest.NewRequest(http.MethodPost, exactSessionCloseFleetPath, bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set(internalauth.Header, signer.Sign(http.MethodPost, exactSessionCloseFleetPath, body))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestHandleInternalAgentSessionCloseReturnsAfterTrackedAdmission(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	signer := newFleetCloseTestSigner(t)
	s.fleetCloseSigner = signer
	s.cloudMap = &CloudMapClient{
		cachedInstances: []ServerInfo{{ID: "i-origin", InternalIP: "10.0.0.10", HTTPPort: 8888}},
		instancesExpiry: time.Now().Add(time.Minute),
	}
	agentKey := bytes.Repeat([]byte{0x71}, core.PublicKeySize)
	now := time.Now()
	activateTestAgentSession(t, s, agentKey, 701, now.Add(-time.Second), now.Add(time.Minute), "ac-http")
	addLiveTestAC(t, s, "ac-http", "10.0.0.20", 62206)
	started := make(chan struct{})
	release := make(chan struct{})
	var closeCalls atomic.Int32
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
		if closeCalls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil
	}
	hs := &HttpServer{udpServer: s}
	body := fleetCloseTestBody(t, agentKey, "i-origin", "10.0.0.10", now)

	requestStarted := time.Now()
	recorder := serveFleetCloseRequest(t, hs, signer, body, "10.0.0.10:44123")
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("fleet close status = %d, want 204", recorder.Code)
	}
	if elapsed := time.Since(requestStarted); elapsed > 100*time.Millisecond {
		t.Fatalf("fleet close response waited for AC close work: %s", elapsed)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("tracked local close worker did not start")
	}
	close(release)
	waitFor(t, time.Second, "tracked HTTP close completion", func() bool {
		return !testRegistryHasSession(s.sessionRegistry(), 701)
	})
	s.agentSessionCloseWorkerWG.Wait()
}

func TestHandleInternalAgentSessionCloseRequiresInstanceIDNotHostname(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	signer := newFleetCloseTestSigner(t)
	s.fleetCloseSigner = signer
	servers := []ServerInfo{{ID: "i-origin", InternalIP: "10.0.0.10", HTTPPort: 8888}}
	s.cloudMap = &CloudMapClient{
		cachedInstances: servers,
		instancesExpiry: time.Now().Add(time.Minute),
		discoverFreshFn: func(context.Context) ([]ServerInfo, error) {
			return servers, nil
		},
	}
	hs := &HttpServer{udpServer: s}
	agentKey := bytes.Repeat([]byte{0x72}, core.PublicKeySize)
	now := time.Now()

	hostnameBody := fleetCloseTestBody(t, agentKey, "friendly-server-name", "10.0.0.10", now)
	if got := serveFleetCloseRequest(t, hs, signer, hostnameBody, "10.0.0.10:44123").Code; got != http.StatusForbidden {
		t.Fatalf("hostname-origin status = %d, want 403", got)
	}
	instanceBody := fleetCloseTestBody(t, agentKey, "i-origin", "10.0.0.10", now)
	if got := serveFleetCloseRequest(t, hs, signer, instanceBody, "10.0.0.10:44123").Code; got != http.StatusNoContent {
		t.Fatalf("instance-origin status = %d, want 204", got)
	}
	s.agentSessionCloseWorkerWG.Wait()
}

func TestHandleInternalAgentSessionCloseRejectsInvalidAuthBeforeCutoff(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	signer := newFleetCloseTestSigner(t)
	s.fleetCloseSigner = signer
	s.cloudMap = &CloudMapClient{
		cachedInstances: []ServerInfo{{ID: "i-origin", InternalIP: "10.0.0.10", HTTPPort: 8888}},
		instancesExpiry: time.Now().Add(time.Minute),
	}
	hs := &HttpServer{udpServer: s}
	agentKey := bytes.Repeat([]byte{0x73}, core.PublicKeySize)
	body := fleetCloseTestBody(t, agentKey, "i-origin", "10.0.0.10", time.Now())

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(agentSessionCloseFleetPath, hs.handleInternalAgentSessionClose)
	req := httptest.NewRequest(http.MethodPost, agentSessionCloseFleetPath, bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.10:44123"
	req.Header.Set(internalauth.Header, signer.Sign(http.MethodPost, agentSessionCloseFleetPath, append(body, 'x')))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("invalid auth status = %d, want 401", recorder.Code)
	}
	if snapshots := s.sessionRegistry().snapshotAgentSessions(agentKey, time.Now().Add(time.Second)); len(snapshots) != 0 {
		t.Fatalf("invalid auth created close state: %+v", snapshots)
	}
}

func TestHandleInternalAgentSessionCloseForceRefreshesStaleMembership(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	signer := newFleetCloseTestSigner(t)
	s.fleetCloseSigner = signer
	var freshCalls atomic.Int32
	s.cloudMap = &CloudMapClient{
		cachedInstances: []ServerInfo{{ID: "i-old", InternalIP: "10.0.0.9", HTTPPort: 8888}},
		instancesExpiry: time.Now().Add(time.Minute),
		discoverFreshFn: func(context.Context) ([]ServerInfo, error) {
			freshCalls.Add(1)
			return []ServerInfo{{ID: "i-new", InternalIP: "10.0.0.10", HTTPPort: 8888}}, nil
		},
	}
	hs := &HttpServer{udpServer: s}
	agentKey := bytes.Repeat([]byte{0x74}, core.PublicKeySize)
	body := fleetCloseTestBody(t, agentKey, "i-new", "10.0.0.10", time.Now())
	if got := serveFleetCloseRequest(t, hs, signer, body, "10.0.0.10:44123").Code; got != http.StatusNoContent {
		t.Fatalf("freshly registered origin status = %d, want 204", got)
	}
	if got := freshCalls.Load(); got != 1 {
		t.Fatalf("force-fresh discovery calls = %d, want 1", got)
	}
	s.agentSessionCloseWorkerWG.Wait()
}

func TestHandleInternalAgentSessionCloseWorkerAdmissionFailureRemainsRetryable(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	signer := newFleetCloseTestSigner(t)
	s.fleetCloseSigner = signer
	s.cloudMap = &CloudMapClient{
		cachedInstances: []ServerInfo{{ID: "i-origin", InternalIP: "10.0.0.10", HTTPPort: 8888}},
		instancesExpiry: time.Now().Add(time.Minute),
	}
	hs := &HttpServer{udpServer: s}
	agentKey := bytes.Repeat([]byte{0x75}, core.PublicKeySize)
	body := fleetCloseTestBody(t, agentKey, "i-origin", "10.0.0.10", time.Now())

	s.agentSessionCloseWorkerMu.Lock()
	s.agentSessionCloseWorkersStopping = true
	s.agentSessionCloseWorkerMu.Unlock()
	if got := serveFleetCloseRequest(t, hs, signer, body, "10.0.0.10:44123").Code; got != http.StatusServiceUnavailable {
		t.Fatalf("worker-admission failure status = %d, want 503", got)
	}

	s.agentSessionCloseWorkerMu.Lock()
	s.agentSessionCloseWorkersStopping = false
	s.agentSessionCloseWorkerMu.Unlock()
	if got := serveFleetCloseRequest(t, hs, signer, body, "10.0.0.10:44123").Code; got != http.StatusNoContent {
		t.Fatalf("retry status = %d, want 204", got)
	}
	s.agentSessionCloseWorkerWG.Wait()
}

func TestBroadcastAgentSessionCloseUsesFreshDiscoveryOnFirstAttempt(t *testing.T) {
	peerReceived := make(chan struct{}, 1)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentSessionCloseFleetPath {
			t.Errorf("path = %q, want %q", r.URL.Path, agentSessionCloseFleetPath)
		}
		peerReceived <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer peer.Close()
	peerURL, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	peerHost := peerURL.Hostname()
	peerPort, err := strconv.Atoi(peerURL.Port())
	if err != nil {
		t.Fatal(err)
	}

	s, _ := newTestServerForBroadcast(t)
	configureFleetCloseTestOrigin(s, "i-origin", "127.0.0.2", 8888)
	s.fleetCloseSigner = newFleetCloseTestSigner(t)
	s.fleetCloseHTTPClient = peer.Client()
	var freshCalls atomic.Int32
	s.cloudMap = &CloudMapClient{
		cachedInstances: []ServerInfo{{ID: "i-origin", InternalIP: s.localIp, HTTPPort: 8888}},
		instancesExpiry: time.Now().Add(time.Minute),
		discoverFreshFn: func(context.Context) ([]ServerInfo, error) {
			freshCalls.Add(1)
			return []ServerInfo{
				{ID: "i-origin", InternalIP: s.localIp, HTTPPort: 8888},
				{ID: "i-new-peer", InternalIP: peerHost, HTTPPort: peerPort},
			}, nil
		},
	}
	now := time.Now()
	event := &agentSessionCloseFleetEvent{
		EventID:            "11223344556677889900aabbccddeeff",
		AgentPublicKey:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x76}, core.PublicKeySize)),
		IssuedThroughNanos: now.UnixNano(),
		ExpiresAt:          now.Add(agentSessionCloseEventTTL).Unix(),
		OriginServer:       "i-origin",
		OriginIP:           s.localIp,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.broadcastAgentSessionClose(ctx, event)
	select {
	case <-peerReceived:
	default:
		t.Fatal("new peer omitted from stale cache did not receive fleet close")
	}
	if got := freshCalls.Load(); got != 1 {
		t.Fatalf("force-fresh discovery calls = %d, want 1", got)
	}
}

func TestConfigureAgentSessionCloseFleetAuthDisablesEnvironmentProxy(t *testing.T) {
	var proxyCalls atomic.Int32
	poisonProxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		proxyCalls.Add(1)
	}))
	defer poisonProxy.Close()
	t.Setenv("HTTP_PROXY", poisonProxy.URL)
	t.Setenv("NO_PROXY", "")

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	s := &UdpServer{config: &Config{PrivateKeyBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, core.PrivateKeySize))}}
	if err := s.configureAgentSessionCloseFleetAuth(); err != nil {
		t.Fatal(err)
	}
	transport, ok := s.fleetCloseHTTPClient.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("fleet transport proxy = %#v, want nil", transport)
	}
	resp, err := s.fleetCloseHTTPClient.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := proxyCalls.Load(); got != 0 {
		t.Fatalf("environment proxy calls = %d, want 0", got)
	}
}

func TestEffectiveHTTPPortAdvertisesOnlyVPCAdmittedPorts(t *testing.T) {
	for _, test := range []struct {
		name string
		port int
		want int
	}{
		{name: "plugin listener", port: 8888, want: 8888},
		{name: "traefik listener", port: 62206, want: 62206},
		{name: "unadmitted custom listener", port: 9000, want: 0},
		{name: "invalid listener", port: -1, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			hs := &HttpServer{listenAddr: &net.TCPAddr{IP: net.IPv4zero, Port: test.port}}
			hs.running.Store(true)
			s := &UdpServer{httpServer: hs, httpConfig: &HttpConfig{EnableHttp: true, HttpListenPort: 8888}}
			if got := s.effectiveHTTPPort(); got != test.want {
				t.Fatalf("effective HTTP port = %d, want %d", got, test.want)
			}
		})
	}
	t.Run("TLS listener is never advertised by plaintext fleet client", func(t *testing.T) {
		hs := &HttpServer{listenAddr: &net.TCPAddr{IP: net.IPv4zero, Port: 8888}, tlsEnabled: true}
		hs.running.Store(true)
		if got := (&UdpServer{httpServer: hs}).effectiveHTTPPort(); got != 0 {
			t.Fatalf("TLS effective HTTP port = %d, want 0", got)
		}
	})
	t.Run("config drift cannot replace actual listener", func(t *testing.T) {
		hs := &HttpServer{listenAddr: &net.TCPAddr{IP: net.IPv4zero, Port: 62206}}
		hs.running.Store(true)
		s := &UdpServer{httpServer: hs, httpConfig: &HttpConfig{EnableHttp: true, HttpListenPort: 8888}}
		if got := s.effectiveHTTPPort(); got != 62206 {
			t.Fatalf("effective HTTP port = %d, want actual 62206", got)
		}
	})
	t.Run("no running listener is not advertised", func(t *testing.T) {
		s := &UdpServer{httpConfig: &HttpConfig{EnableHttp: true, HttpListenPort: 8888}}
		if got := s.effectiveHTTPPort(); got != 0 {
			t.Fatalf("effective HTTP port = %d, want 0", got)
		}
	})
}

func TestRegisterWithCloudMapRequiresFleetControlListener(t *testing.T) {
	s := &UdpServer{instanceID: "i-test", instanceAZ: "us-east-2a"}
	err := s.registerWithCloudMap()
	if err == nil || !strings.Contains(err.Error(), "fleet-control HTTP listener") {
		t.Fatalf("registerWithCloudMap error = %v, want missing fleet-control listener", err)
	}
}

func TestHandleInternalExactSessionCloseClosesOnlyExactLogicalSession(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	signer := newFleetCloseTestSigner(t)
	s.fleetCloseSigner = signer
	s.cloudMap = &CloudMapClient{
		cachedInstances: []ServerInfo{{ID: "i-origin", InternalIP: "10.0.0.10", HTTPPort: 8888}},
		instancesExpiry: time.Now().Add(time.Minute),
	}
	agentKey := bytes.Repeat([]byte{0x77}, core.PublicKeySize)
	issuedAt := time.Now().Add(-time.Second)
	activateTestAgentSession(t, s, agentKey, 801, issuedAt, time.Now().Add(time.Minute), "ac-exact")
	activateTestAgentSession(t, s, agentKey, 802, issuedAt.Add(time.Nanosecond), time.Now().Add(time.Minute), "ac-sibling")
	addLiveTestAC(t, s, "ac-exact", "10.0.0.20", 62206)
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error { return nil }
	now := time.Now()
	body, err := json.Marshal(&exactSessionCloseFleetEvent{
		EventID:              "22334455667788990011aabbccddeeff",
		AgentPublicKey:       base64.StdEncoding.EncodeToString(agentKey),
		SessionID:            801,
		SessionIssuedAtNanos: issuedAt.UnixNano(),
		ExpiresAt:            now.Add(agentSessionCloseEventTTL).Unix(),
		OriginServer:         "i-origin",
		OriginIP:             "10.0.0.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := &HttpServer{udpServer: s}
	if got := serveExactFleetCloseRequest(t, hs, signer, body, "10.0.0.10:44123").Code; got != http.StatusAccepted {
		t.Fatalf("exact close status = %d, want 202 while tracked close runs", got)
	}
	waitFor(t, time.Second, "exact session compensation", func() bool {
		return !testRegistryHasSession(s.sessionRegistry(), 801)
	})
	if !testRegistryHasSession(s.sessionRegistry(), 802) {
		t.Fatal("exact-session compensation closed sibling session")
	}
	if got := serveExactFleetCloseRequest(t, hs, signer, body, "10.0.0.10:44123").Code; got != http.StatusNoContent {
		t.Fatalf("completed exact close replay status = %d, want 204", got)
	}
	s.agentSessionCloseWorkerWG.Wait()
}

func TestBroadcastAgentSessionCloseReachesMoreThanFiveColdPeers(t *testing.T) {
	const peerCount = 6
	var received atomic.Int32
	peers := make([]*httptest.Server, 0, peerCount)
	servers := make([]ServerInfo, 0, peerCount+1)
	servers = append(servers, ServerInfo{ID: "i-origin", InternalIP: "127.0.0.2", HTTPPort: 8888})
	for i := 0; i < peerCount; i++ {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			received.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		peers = append(peers, peer)
		parsed, err := url.Parse(peer.URL)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(parsed.Port())
		if err != nil {
			t.Fatal(err)
		}
		servers = append(servers, ServerInfo{ID: fmt.Sprintf("i-peer-%d", i), InternalIP: parsed.Hostname(), HTTPPort: port})
	}
	defer func() {
		for _, peer := range peers {
			peer.Close()
		}
	}()

	s, _ := newTestServerForBroadcast(t)
	configureFleetCloseTestOrigin(s, "i-origin", "127.0.0.2", 8888)
	s.fleetCloseSigner = newFleetCloseTestSigner(t)
	s.fleetCloseHTTPClient = peers[0].Client()
	s.cloudMap = &CloudMapClient{discoverFreshFn: func(context.Context) ([]ServerInfo, error) { return servers, nil }}
	now := time.Now()
	event := &agentSessionCloseFleetEvent{
		EventID:            "33445566778899001122aabbccddeeff",
		AgentPublicKey:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x78}, core.PublicKeySize)),
		IssuedThroughNanos: now.UnixNano(), ExpiresAt: now.Add(agentSessionCloseEventTTL).Unix(),
		OriginServer: "i-origin", OriginIP: s.localIp,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s.broadcastAgentSessionClose(ctx, event)
	if got := received.Load(); got != peerCount {
		t.Fatalf("fleet close recipients = %d, want %d", got, peerCount)
	}
}

func TestBroadcastAgentSessionCloseRetriesTransientPeerFailure(t *testing.T) {
	var calls atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer peer.Close()
	parsed, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newTestServerForBroadcast(t)
	configureFleetCloseTestOrigin(s, "i-origin", "127.0.0.2", 8888)
	s.fleetCloseSigner = newFleetCloseTestSigner(t)
	s.fleetCloseHTTPClient = peer.Client()
	s.cloudMap = &CloudMapClient{discoverFreshFn: func(context.Context) ([]ServerInfo, error) {
		return []ServerInfo{
			{ID: "i-origin", InternalIP: s.localIp, HTTPPort: 8888},
			{ID: "i-peer", InternalIP: parsed.Hostname(), HTTPPort: port},
		}, nil
	}}
	now := time.Now()
	event := &agentSessionCloseFleetEvent{
		EventID: "44556677889900112233aabbccddeeff", AgentPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x79}, core.PublicKeySize)),
		IssuedThroughNanos: now.UnixNano(), ExpiresAt: now.Add(agentSessionCloseEventTTL).Unix(), OriginServer: "i-origin", OriginIP: s.localIp,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s.broadcastAgentSessionClose(ctx, event)
	if got := calls.Load(); got != 2 {
		t.Fatalf("transient peer attempts = %d, want 2", got)
	}
}

func TestExactSessionFleetCompensationClosesRemoteForwardedSessionOnly(t *testing.T) {
	signer := newFleetCloseTestSigner(t)
	peer, _ := newTestServerForBroadcast(t)
	peer.fleetCloseSigner = signer
	peer.cloudMap = &CloudMapClient{
		cachedInstances: []ServerInfo{{ID: "i-origin", InternalIP: "127.0.0.1", HTTPPort: 8888}},
		instancesExpiry: time.Now().Add(time.Minute),
	}
	agentKey := bytes.Repeat([]byte{0x7a}, core.PublicKeySize)
	issuedAt := time.Now().Add(-time.Second)
	activateTestAgentSession(t, peer, agentKey, 904, issuedAt, time.Now().Add(time.Minute), "ac-remote")
	activateTestAgentSession(t, peer, agentKey, 905, issuedAt.Add(time.Nanosecond), time.Now().Add(time.Minute), "ac-sibling")
	addLiveTestAC(t, peer, "ac-remote", "10.0.0.24", 62206)
	peer.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error { return nil }
	hs := &HttpServer{udpServer: peer}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(exactSessionCloseFleetPath, hs.handleInternalExactSessionClose)
	peerHTTP := httptest.NewServer(router)
	defer peerHTTP.Close()
	peerHost, portText, err := net.SplitHostPort(peerHTTP.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	origin, _ := newTestServerForBroadcast(t)
	configureFleetCloseTestOrigin(origin, "i-origin", "127.0.0.1", 8888)
	origin.fleetCloseSigner = signer
	origin.fleetCloseHTTPClient = peerHTTP.Client()
	origin.cloudMap = &CloudMapClient{discoverFreshFn: func(context.Context) ([]ServerInfo, error) {
		return []ServerInfo{
			{ID: "i-origin", InternalIP: origin.localIp, HTTPPort: 8888},
			{ID: "i-peer", InternalIP: peerHost, HTTPPort: port},
		}, nil
	}}
	if !origin.compensateFailedNHPSessionFleet(agentKey, 904, issuedAt, 60) {
		t.Fatal("origin exact-session fleet compensation did not schedule")
	}
	waitFor(t, 2*time.Second, "remote exact session close", func() bool {
		return !testRegistryHasSession(peer.sessionRegistry(), 904)
	})
	if !testRegistryHasSession(peer.sessionRegistry(), 905) {
		t.Fatal("remote exact-session compensation closed sibling session")
	}
	origin.agentSessionCloseWorkerWG.Wait()
	peer.agentSessionCloseWorkerWG.Wait()
}
