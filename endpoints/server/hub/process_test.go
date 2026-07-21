package hub

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorhub"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func runWithTestMetrics(t *testing.T, ctx context.Context, config Config, awsConfig aws.Config) error {
	t.Helper()
	return runWithAWSConfig(ctx, config, awsConfig, metrics.NewPublisherForTest(t))
}

func TestRunLifecycleServesPrivateTCPHealthAndClosesBothListeners(t *testing.T) {
	config := validConfig()
	config.UDPListenAddr = freeUDPAddr(t)
	config.HealthListenAddr = freeTCPAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runWithTestMetrics(t, ctx, config, aws.Config{Region: config.AWSRegion})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", config.HealthListenAddr, 100*time.Millisecond)
		if err == nil {
			_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 1)
			if n, _ := conn.Read(buffer); n != 0 {
				_ = conn.Close()
				cancel()
				t.Fatal("private health listener returned application payload")
			}
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("private TCP health listener did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runWithAWSConfig returned on cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("process did not stop after context cancellation")
	}

	healthListener, err := net.Listen("tcp", config.HealthListenAddr)
	if err != nil {
		t.Fatalf("health listener was not released: %v", err)
	}
	_ = healthListener.Close()
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPListenAddr)
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("UDP listener was not released: %v", err)
	}
	_ = udpConn.Close()
}

func TestRunClosesHealthListenerWhenWorkerConstructionFails(t *testing.T) {
	config := validConfig()
	config.UDPListenAddr = freeUDPAddr(t)
	config.HealthListenAddr = freeTCPAddr(t)
	config.MaxConcurrentPackets = core.RecvQueueSize + 1

	err := runWithTestMetrics(t, context.Background(), config, aws.Config{Region: config.AWSRegion})
	if !errors.Is(err, connectorhub.ErrInvalidWorkerConfiguration) {
		t.Fatalf("runWithAWSConfig error = %v, want invalid worker configuration", err)
	}
	listener, listenErr := net.Listen("tcp", config.HealthListenAddr)
	if listenErr != nil {
		t.Fatalf("health listener leaked after construction failure: %v", listenErr)
	}
	_ = listener.Close()
}

func TestRunClosesHealthListenerWhenUDPBindFails(t *testing.T) {
	occupiedUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer occupiedUDP.Close()

	config := validConfig()
	config.UDPListenAddr = occupiedUDP.LocalAddr().String()
	config.HealthListenAddr = freeTCPAddr(t)

	err = runWithTestMetrics(t, context.Background(), config, aws.Config{Region: config.AWSRegion})
	if err == nil {
		t.Fatal("runWithAWSConfig succeeded with an occupied UDP address")
	}
	listener, listenErr := net.Listen("tcp", config.HealthListenAddr)
	if listenErr != nil {
		t.Fatalf("health listener leaked after UDP bind failure: %v", listenErr)
	}
	_ = listener.Close()
}

func TestRunPreCanceledContextDoesNotClaimListeners(t *testing.T) {
	config := validConfig()
	config.UDPListenAddr = freeUDPAddr(t)
	config.HealthListenAddr = freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runWithTestMetrics(t, ctx, config, aws.Config{Region: config.AWSRegion})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runWithAWSConfig error = %v, want context.Canceled", err)
	}
	healthListener, err := net.Listen("tcp", config.HealthListenAddr)
	if err != nil {
		t.Fatalf("health listener was claimed by pre-canceled run: %v", err)
	}
	_ = healthListener.Close()
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPListenAddr)
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("UDP listener was claimed by pre-canceled run: %v", err)
	}
	_ = udpConn.Close()
}

func TestRunInvalidKeyDoesNotClaimListeners(t *testing.T) {
	config := validConfig()
	config.UDPListenAddr = freeUDPAddr(t)
	config.HealthListenAddr = freeTCPAddr(t)
	config.PrivateKeyBase64 += "\n"

	err := runWithTestMetrics(t, context.Background(), config, aws.Config{Region: config.AWSRegion})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("runWithAWSConfig error = %v, want ErrInvalidConfig", err)
	}
	healthListener, err := net.Listen("tcp", config.HealthListenAddr)
	if err != nil {
		t.Fatalf("health listener was claimed by invalid config: %v", err)
	}
	_ = healthListener.Close()
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPListenAddr)
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("UDP listener was claimed by invalid config: %v", err)
	}
	_ = udpConn.Close()
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

type scriptedHealthAccepter struct {
	errors []error
	calls  int
}

func (a *scriptedHealthAccepter) Accept() (net.Conn, error) {
	a.calls++
	if len(a.errors) == 0 {
		return nil, net.ErrClosed
	}
	err := a.errors[0]
	a.errors = a.errors[1:]
	return nil, err
}

func TestServeHealthRetriesTransientAcceptErrors(t *testing.T) {
	listener := &scriptedHealthAccepter{errors: []error{
		temporaryAcceptError{},
		temporaryAcceptError{},
		net.ErrClosed,
	}}
	publisher := metrics.NewPublisherForTest(t)

	err := serveHealthWithBackoff(context.Background(), listener, publisher, time.Millisecond, 2*time.Millisecond)
	if err != nil {
		t.Fatalf("serveHealthWithBackoff returned transient error: %v", err)
	}
	if listener.calls != 3 {
		t.Fatalf("Accept calls = %d, want 3", listener.calls)
	}
	counters, _ := publisher.CountersForTest(t)
	if got := counters[metricHubHealthAcceptRetry]; got != 2 {
		t.Fatalf("%s = %v, want 2", metricHubHealthAcceptRetry, got)
	}
}

func TestServeHealthReturnsPermanentAcceptError(t *testing.T) {
	want := errors.New("permanent accept failure")
	listener := &scriptedHealthAccepter{errors: []error{want}}
	publisher := metrics.NewPublisherForTest(t)

	err := serveHealthWithBackoff(context.Background(), listener, publisher, time.Millisecond, 2*time.Millisecond)
	if !errors.Is(err, want) {
		t.Fatalf("serveHealthWithBackoff error = %v, want %v", err, want)
	}
	if listener.calls != 1 {
		t.Fatalf("Accept calls = %d, want 1", listener.calls)
	}
	counters, _ := publisher.CountersForTest(t)
	if got := counters[metricHubHealthAcceptRetry]; got != 0 {
		t.Fatalf("%s = %v, want 0", metricHubHealthAcceptRetry, got)
	}
}

type notifyingTemporaryAccepter struct {
	once   sync.Once
	called chan struct{}
}

func (a *notifyingTemporaryAccepter) Accept() (net.Conn, error) {
	a.once.Do(func() { close(a.called) })
	return nil, temporaryAcceptError{}
}

func TestServeHealthTransientBackoffIsCancellable(t *testing.T) {
	listener := &notifyingTemporaryAccepter{called: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- serveHealthWithBackoff(ctx, listener, nil, time.Hour, time.Hour)
	}()
	<-listener.called
	cancel()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("serveHealthWithBackoff returned on cancellation: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("transient accept backoff did not stop on context cancellation")
	}
}

func TestAuthorityAdmissionGateFailsClosed(t *testing.T) {
	gate := authorityAdmissionGate{}
	// The closed allowlist admits exactly the three assignment operations. Recovery
	// is included here and nowhere else: this is the single point that lets a
	// ModeRecover request reach the recovery-capable Authority.
	for _, mode := range []connectorhub.Mode{connectorhub.ModeEnroll, connectorhub.ModeRefresh, connectorhub.ModeRecover} {
		if got := gate.AdmitAssignment(context.Background(), connectorhub.AdmissionRequest{Mode: mode}); got.Decision != connectorhub.AdmissionAllow {
			t.Fatalf("admission for mode %d = %v, want allow", mode, got.Decision)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	// A dead context fails closed even for an allowlisted mode.
	if got := gate.AdmitAssignment(canceled, connectorhub.AdmissionRequest{Mode: connectorhub.ModeRecover}); got.Decision != connectorhub.AdmissionUnavailable {
		t.Fatalf("canceled admission = %v, want unavailable", got.Decision)
	}
	// The zero/undecoded mode is outside the allowlist and is rejected.
	if got := gate.AdmitAssignment(context.Background(), connectorhub.AdmissionRequest{}); got.Decision != connectorhub.AdmissionUnavailable {
		t.Fatalf("unknown-mode admission = %v, want unavailable", got.Decision)
	}
}

// recordingRecoveryAuthority stands in for the Lambda-backed
// connectorauthority.HubClient at the process's trust boundary. It returns a
// canned recovery grant and records which operation the composed hub invoked,
// so a round-trip proves the closed gate admitted ModeRecover and the handler
// routed to the general recovery-capable method rather than issue/refresh.
type recordingRecoveryAuthority struct {
	mu               sync.Mutex
	recoveryResponse []byte
	issueCalls       int
	refreshCalls     int
	recoveryCalls    int
}

func (a *recordingRecoveryAuthority) IssueAssignment(context.Context, []byte) ([]byte, error) {
	a.mu.Lock()
	a.issueCalls++
	a.mu.Unlock()
	return nil, errors.New("unexpected IssueAssignment on recovery path")
}

func (a *recordingRecoveryAuthority) RefreshAssignment(context.Context, []byte) ([]byte, error) {
	a.mu.Lock()
	a.refreshCalls++
	a.mu.Unlock()
	return nil, errors.New("unexpected RefreshAssignment on recovery path")
}

func (a *recordingRecoveryAuthority) IssueCredentialRecovery(_ context.Context, _ []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.recoveryCalls++
	return bytes.Clone(a.recoveryResponse), nil
}

func (a *recordingRecoveryAuthority) counts() (issue, refresh, recovery int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.issueCalls, a.refreshCalls, a.recoveryCalls
}

// TestRecoveryRoundTripThroughComposedHub drives an encrypted credential-
// recovery exchange all the way through the composed hub: the real closed
// admission gate, the real handler, the real UDP worker, and the real
// cookie/LST/LRT crypto. Only the Authority Lambda (the trust boundary) is
// faked. It proves the recovery path round-trips end to end — encrypted cookie
// challenge, encrypted recovery LST with proof, encrypted recovery LRT — using
// the conformance recovery vectors as the client request and expected result.
func TestRecoveryRoundTripThroughComposedHub(t *testing.T) {
	vectors, err := conformance.AgentCredentialRecovery()
	if err != nil {
		t.Fatalf("load recovery vectors: %v", err)
	}
	hubExchange := vectors.PublicExchanges[conformance.AgentCredentialRecoveryHubPhase]
	requestBody := []byte(hubExchange.RequestBodyJSON)
	wantLRT := []byte(hubExchange.SuccessBodyJSON)
	authorityPrivateSuccess := []byte(vectors.PrivateOperations[conformance.AgentCredentialRecoveryIssueOperation].SuccessBodyJSON)
	if len(requestBody) == 0 || len(wantLRT) == 0 || len(authorityPrivateSuccess) == 0 {
		t.Fatal("recovery conformance vectors are incomplete")
	}

	base := validConfig()
	authority := &recordingRecoveryAuthority{recoveryResponse: authorityPrivateSuccess}
	// Compose exactly as runWithAWSConfig does: the REAL authorityAdmissionGate
	// and the REAL handler. Substituting a fake HubAuthority for the Lambda-
	// backed HubClient keeps the gate, handler, worker, crypto, and observer all
	// production types; only the synchronous Authority Lambda is stubbed.
	handler, err := connectorhub.NewHandler(base.Environment, authority, authorityAdmissionGate{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	observer := newWorkerMetrics()
	worker, err := connectorhub.NewWorker(serverConn, connectorhub.WorkerConfig{
		PrivateKeyBase64:      base.PrivateKeyBase64,
		ActiveCookieKeyBase64: base.ActiveCookieKeyBase64,
		Handler:               handler,
		Observer:              observer,
		MaxConcurrentPackets:  8,
		PacketsPerSecond:      100,
		PacketBurst:           100,
		MaxConcurrentPerPeer:  2,
		ResponseQueueCapacity: 8,
	})
	if err != nil {
		_ = serverConn.Close()
		t.Fatalf("NewWorker: %v", err)
	}
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Worker.Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Worker.Serve did not stop after cancellation")
		}
	})

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer client.Close()

	serverPublicKey, err := base64.StdEncoding.DecodeString(worker.PublicKeyBase64())
	if err != nil {
		t.Fatalf("decode worker public key: %v", err)
	}
	// The authenticated peer is bound from this Noise handshake, not from a JSON
	// field, so any agent key drives the recovery body; the fake Authority
	// ignores the derived HubRequestID.
	agent := core.NewDevice(core.NHP_AGENT, bytesOf(0x61, core.PrivateKeySize), &core.DeviceOptions{DisableServerPeerValidation: true})
	if agent == nil {
		t.Fatal("NewDevice(agent) returned nil")
	}

	sealLST := func(transactionID uint64, proof *[core.CookieSize]byte) []byte {
		t.Helper()
		mad, err := agent.MsgToPacket(&core.MsgData{
			RemoteAddr:        serverAddr,
			PeerPk:            serverPublicKey,
			CipherScheme:      common.CIPHER_SCHEME_CURVE,
			TransactionId:     transactionID,
			HeaderType:        core.NHP_LST,
			Compress:          false,
			HubLSTCookieProof: proof,
			Message:           requestBody,
		})
		if err != nil {
			t.Fatalf("seal recovery LST: %v", err)
		}
		wire, err := core.ConsumeEncryptedPacket(mad)
		if err != nil {
			t.Fatalf("consume recovery LST: %v", err)
		}
		return wire
	}
	readResponse := func() []byte {
		t.Helper()
		if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		buffer := make([]byte, core.PacketBufferSize)
		n, _, err := client.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("ReadFromUDP: %v", err)
		}
		return buffer[:n]
	}
	decrypt := func(wire []byte, headerType int) *core.PacketParserData {
		t.Helper()
		ppd, err := agent.PacketToMsg(&core.PacketData{
			BasePacket: &core.Packet{Content: bytes.Clone(wire), HeaderType: headerType},
			ConnData:   &core.ConnectionData{RemoteAddr: serverAddr},
		})
		if err != nil {
			t.Fatalf("decrypt %s: %v", core.HeaderTypeToString(headerType), err)
		}
		return ppd
	}

	// Phase 1 — encrypted cookie challenge. The first recovery LST carries no
	// proof; the composed hub answers with a strictly smaller encrypted COK and
	// must not have reached the Authority yet.
	initial := sealLST(0xC0FFEE01, nil)
	if _, err := client.WriteToUDP(initial, serverAddr); err != nil {
		t.Fatalf("send initial recovery LST: %v", err)
	}
	challengeWire := readResponse()
	if len(challengeWire) >= len(initial) {
		t.Fatalf("COK challenge size = %d, request = %d; want strictly smaller", len(challengeWire), len(initial))
	}
	cok := decrypt(challengeWire, core.NHP_COK)
	var cookieMsg common.ServerCookieMsg
	if err := json.Unmarshal(cok.BodyMessage, &cookieMsg); err != nil {
		t.Fatalf("decode COK body: %v", err)
	}
	cookieBytes, err := base64.StdEncoding.Strict().DecodeString(cookieMsg.Cookie)
	if err != nil || len(cookieBytes) != core.CookieSize {
		t.Fatalf("COK cookie is not canonical %d-byte base64", core.CookieSize)
	}
	var cookie [core.CookieSize]byte
	copy(cookie[:], cookieBytes)
	clear(cookieBytes)
	if issue, refresh, recovery := authority.counts(); issue != 0 || refresh != 0 || recovery != 0 {
		t.Fatalf("Authority invoked before cookie proof: issue=%d refresh=%d recovery=%d", issue, refresh, recovery)
	}

	// Phase 2 — encrypted recovery LST bearing the cookie proof. The composed
	// hub admits ModeRecover through the real gate, routes to
	// IssueCredentialRecovery, and returns the encrypted recovery LRT.
	proof := sealLST(0xC0FFEE02, &cookie)
	clear(cookie[:])
	if _, err := client.WriteToUDP(proof, serverAddr); err != nil {
		t.Fatalf("send proof recovery LST: %v", err)
	}
	lrt := decrypt(readResponse(), core.NHP_LRT)
	if !bytes.Equal(lrt.BodyMessage, wantLRT) {
		t.Fatalf("recovery LRT body = %s, want %s", lrt.BodyMessage, wantLRT)
	}

	// Exactly one recovery invocation, and no issue/refresh: the gate admitted
	// ModeRecover and the handler used the general recovery-capable method.
	if issue, refresh, recovery := authority.counts(); issue != 0 || refresh != 0 || recovery != 1 {
		t.Fatalf("Authority calls = issue %d, refresh %d, recovery %d; want 0/0/1", issue, refresh, recovery)
	}

	// The wired closed observer metered the encrypted round-trip end to end.
	if got := observer.outcomeCount(connectorhub.WorkerOutcomeChallengeSent); got != 1 {
		t.Fatalf("challenge_sent = %d, want 1", got)
	}
	if got := observer.outcomeCount(connectorhub.WorkerOutcomeResponseSent); got != 1 {
		t.Fatalf("response_sent = %d, want 1", got)
	}
	if got := observer.classificationCount(connectorhub.ClassificationSuccess); got != 1 {
		t.Fatalf("success classifications = %d, want 1", got)
	}
	observations, requestBytes, responseBytes := observer.challengeStats()
	if observations != 1 || responseBytes >= requestBytes {
		t.Fatalf("challenge datagram stats = %d obs, %d req, %d resp; want one strict reduction", observations, requestBytes, responseBytes)
	}
}
