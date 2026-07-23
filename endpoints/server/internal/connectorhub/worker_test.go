package connectorhub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

const workerTestTimeout = 3 * time.Second

type recordingWorkerObserver struct {
	mu                    sync.Mutex
	outcomes              map[WorkerOutcome]int
	classifications       map[Classification]int
	rejections            map[RequestRejection]int
	challengeSizes        [][2]int
	authorityTimings      []durationObservation
	responseTimings       []durationObservation
	postAuthorityObserved chan struct{}
}

type durationObservation struct {
	mode     Mode
	duration time.Duration
}

type deadlineWorkerAuthority struct {
	mu        sync.Mutex
	issues    int
	refreshes int
	deadlines chan time.Time
}

func (a *deadlineWorkerAuthority) IssueAssignment(context.Context, []byte) ([]byte, error) {
	a.mu.Lock()
	a.issues++
	a.mu.Unlock()
	return nil, errors.New("unexpected issue call")
}

func (a *deadlineWorkerAuthority) RefreshAssignment(ctx context.Context, _ []byte) ([]byte, error) {
	a.mu.Lock()
	a.refreshes++
	a.mu.Unlock()
	deadline, ok := ctx.Deadline()
	if ok {
		a.deadlines <- deadline
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (a *deadlineWorkerAuthority) IssueCredentialRecovery(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unexpected credential recovery call")
}

func (a *deadlineWorkerAuthority) callCounts() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.issues, a.refreshes
}

func newRecordingWorkerObserver() *recordingWorkerObserver {
	return &recordingWorkerObserver{
		outcomes:              make(map[WorkerOutcome]int),
		classifications:       make(map[Classification]int),
		rejections:            make(map[RequestRejection]int),
		postAuthorityObserved: make(chan struct{}),
	}
}

func (o *recordingWorkerObserver) ObserveWorkerOutcome(outcome WorkerOutcome) {
	o.mu.Lock()
	o.outcomes[outcome]++
	o.mu.Unlock()
}

func (o *recordingWorkerObserver) ObserveHandlerResult(classification Classification, rejection RequestRejection) {
	o.mu.Lock()
	o.classifications[classification]++
	if rejection != "" {
		o.rejections[rejection]++
	}
	o.mu.Unlock()
}

func (o *recordingWorkerObserver) ObserveChallengeDatagramBytes(requestBytes, responseBytes int) {
	o.mu.Lock()
	o.challengeSizes = append(o.challengeSizes, [2]int{requestBytes, responseBytes})
	o.mu.Unlock()
}

func (o *recordingWorkerObserver) ObserveAuthorityDuration(mode Mode, duration time.Duration) {
	o.mu.Lock()
	o.authorityTimings = append(o.authorityTimings, durationObservation{mode: mode, duration: duration})
	o.mu.Unlock()
}

func (o *recordingWorkerObserver) ObservePostAuthorityDuration(mode Mode, duration time.Duration) {
	o.mu.Lock()
	o.responseTimings = append(o.responseTimings, durationObservation{mode: mode, duration: duration})
	if len(o.responseTimings) == 1 {
		close(o.postAuthorityObserved)
	}
	o.mu.Unlock()
}

// waitForPostAuthorityObservation synchronizes assertions with the writer's
// final callback; UDP delivery can wake the client before that callback runs.
func (o *recordingWorkerObserver) waitForPostAuthorityObservation(t *testing.T) {
	t.Helper()
	timer := time.NewTimer(workerTestTimeout)
	defer timer.Stop()
	select {
	case <-o.postAuthorityObserved:
	case <-timer.C:
		t.Fatal("worker did not observe a post-Authority response write")
	}
}

func (o *recordingWorkerObserver) outcome(outcome WorkerOutcome) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.outcomes[outcome]
}

func (o *recordingWorkerObserver) classification(classification Classification) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.classifications[classification]
}

func (o *recordingWorkerObserver) rejection(rejection RequestRejection) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.rejections[rejection]
}

func (o *recordingWorkerObserver) challengeSize() (requestBytes, responseBytes int, count int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.challengeSizes) == 0 {
		return 0, 0, 0
	}
	last := o.challengeSizes[len(o.challengeSizes)-1]
	return last[0], last[1], len(o.challengeSizes)
}

func (o *recordingWorkerObserver) timings() (authority, response []durationObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.authorityTimings), slices.Clone(o.responseTimings)
}

type workerFixture struct {
	worker     *Worker
	agent      *core.Device
	client     *net.UDPConn
	serverAddr *net.UDPAddr
	authority  workerTestAuthority
	observer   *recordingWorkerObserver
	request    []byte
	cancel     context.CancelFunc
	done       chan error
}

type workerTestAuthority interface {
	HubAuthority
	callCounts() (issue, refresh int)
}

func testWorkerTiming() WorkerTiming {
	return WorkerTiming{
		AuthorityLambdaTimeout: 3 * time.Second,
		HandlerBudget:          3100 * time.Millisecond,
		PacketBudget:           3500 * time.Millisecond,
		ResponseReserve:        400 * time.Millisecond,
		WriteBudget:            173 * time.Millisecond,
	}
}

func newWorkerFixture(t *testing.T) *workerFixture {
	t.Helper()
	authorityContract := authorityVectors(t)
	authority := &fakeHubAuthority{
		refreshResponse: []byte(authorityContract.Operations[conformance.ConnectorAuthorityOperationRefreshAssignment].SuccessGolden.BodyJSON),
	}
	return newWorkerFixtureWithAuthority(t, authority)
}

func newWorkerFixtureWithAuthority(t *testing.T, authority workerTestAuthority) *workerFixture {
	return newWorkerFixtureConfigured(t, authority, nil)
}

func newWorkerFixtureConfigured(t *testing.T, authority workerTestAuthority, configure func(*WorkerConfig)) *workerFixture {
	t.Helper()
	assignmentContract := assignmentVectors(t)
	handler := mustHandler(t, authority, &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}})
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = serverConn.Close()
		t.Fatalf("ListenUDP(client): %v", err)
	}
	observer := newRecordingWorkerObserver()
	config := WorkerConfig{
		PrivateKeyBase64:      base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, core.PrivateKeySize)),
		ActiveCookieKeyBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, core.SymmetricKeySize)),
		Handler:               handler,
		Observer:              observer,
		MaxConcurrentPackets:  8,
		PacketsPerSecond:      100,
		PacketBurst:           100,
		MaxConcurrentPerPeer:  2,
		ResponseQueueCapacity: 8,
		Timing:                testWorkerTiming(),
	}
	if configure != nil {
		configure(&config)
	}
	worker, err := NewWorker(serverConn, config)
	if err != nil {
		_ = serverConn.Close()
		_ = clientConn.Close()
		t.Fatalf("NewWorker: %v", err)
	}
	agent := core.NewDevice(core.NHP_AGENT, bytes.Repeat([]byte{0x61}, core.PrivateKeySize), &core.DeviceOptions{DisableServerPeerValidation: true})
	if agent == nil {
		_ = serverConn.Close()
		_ = clientConn.Close()
		t.Fatal("NewDevice(agent) returned nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Serve(ctx) }()

	fixture := &workerFixture{
		worker: worker, agent: agent, client: clientConn,
		serverAddr: serverConn.LocalAddr().(*net.UDPAddr), authority: authority,
		observer: observer, request: []byte(assignmentContract.RefreshAssignment.Request.BodyJSON),
		cancel: cancel, done: done,
	}
	t.Cleanup(func() { fixture.stop(t) })
	return fixture
}

func (f *workerFixture) stop(t *testing.T) {
	t.Helper()
	if f.cancel == nil {
		return
	}
	f.cancel()
	select {
	case err := <-f.done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Worker.Serve: %v", err)
		}
	case <-time.After(workerTestTimeout):
		t.Error("Worker.Serve did not stop")
	}
	_ = f.client.Close()
	f.cancel = nil
}

func (f *workerFixture) sealLST(t *testing.T, transactionID uint64, proof *[core.CookieSize]byte) []byte {
	t.Helper()
	serverPublicKey, err := base64.StdEncoding.DecodeString(f.worker.PublicKeyBase64())
	if err != nil {
		t.Fatalf("decode worker public key: %v", err)
	}
	mad, err := f.agent.MsgToPacket(&core.MsgData{
		RemoteAddr:        f.serverAddr,
		PeerPk:            serverPublicKey,
		CipherScheme:      common.CIPHER_SCHEME_CURVE,
		TransactionId:     transactionID,
		HeaderType:        core.NHP_LST,
		Compress:          false,
		HubLSTCookieProof: proof,
		Message:           f.request,
	})
	if err != nil {
		t.Fatalf("seal LST: %v", err)
	}
	wire, err := core.ConsumeEncryptedPacket(mad)
	if err != nil {
		t.Fatalf("consume LST: %v", err)
	}
	return wire
}

func (f *workerFixture) send(t *testing.T, packet []byte) {
	t.Helper()
	if _, err := f.client.WriteToUDP(packet, f.serverAddr); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
}

func (f *workerFixture) read(t *testing.T, timeout time.Duration) []byte {
	t.Helper()
	if err := f.client.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, core.PacketBufferSize)
	n, _, err := f.client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	return buffer[:n]
}

func (f *workerFixture) decrypt(t *testing.T, wire []byte, headerType int) *core.PacketParserData {
	t.Helper()
	ppd, err := f.agent.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: bytes.Clone(wire), HeaderType: headerType},
		ConnData:   &core.ConnectionData{RemoteAddr: f.serverAddr},
	})
	if err != nil {
		t.Fatalf("decrypt %s: %v", core.HeaderTypeToString(headerType), err)
	}
	return ppd
}

func (f *workerFixture) challenge(t *testing.T, transactionID uint64) ([core.CookieSize]byte, []byte) {
	t.Helper()
	initial := f.sealLST(t, transactionID, nil)
	f.send(t, initial)
	challengeWire := f.read(t, time.Second)
	if len(challengeWire) >= len(initial) {
		t.Fatalf("challenge size = %d, request = %d", len(challengeWire), len(initial))
	}
	ppd := f.decrypt(t, challengeWire, core.NHP_COK)
	var message common.ServerCookieMsg
	if err := json.Unmarshal(ppd.BodyMessage, &message); err != nil {
		t.Fatalf("decode COK: %v", err)
	}
	if message.TransactionId != transactionID {
		t.Fatalf("COK transaction = %d, want %d", message.TransactionId, transactionID)
	}
	cookieBytes, err := base64.StdEncoding.Strict().DecodeString(message.Cookie)
	if err != nil || len(cookieBytes) != core.CookieSize || base64.StdEncoding.EncodeToString(cookieBytes) != message.Cookie {
		t.Fatalf("COK cookie is not canonical %d-byte base64", core.CookieSize)
	}
	var cookie [core.CookieSize]byte
	copy(cookie[:], cookieBytes)
	clear(cookieBytes)
	return cookie, initial
}

func TestWorkerChallengeProofRoundTripCallsAuthorityOnlyAfterProof(t *testing.T) {
	f := newWorkerFixture(t)
	cookie, _ := f.challenge(t, 101)
	issueCalls, refreshCalls := f.authority.callCounts()
	if issueCalls != 0 || refreshCalls != 0 {
		t.Fatalf("authority called before proof: %d/%d", issueCalls, refreshCalls)
	}

	proof := f.sealLST(t, 102, &cookie)
	clear(cookie[:])
	f.send(t, proof)
	response := f.read(t, time.Second)
	ppd := f.decrypt(t, response, core.NHP_LRT)
	if !json.Valid(ppd.BodyMessage) || !bytes.Contains(ppd.BodyMessage, []byte(`"nhp_udp_endpoint"`)) {
		t.Fatalf("unexpected LRT body: %s", ppd.BodyMessage)
	}
	f.observer.waitForPostAuthorityObservation(t)
	issueCalls, refreshCalls = f.authority.callCounts()
	if issueCalls != 0 || refreshCalls != 1 {
		t.Fatalf("authority calls after proof = %d/%d, want 0/1", issueCalls, refreshCalls)
	}
	if f.observer.outcome(WorkerOutcomeChallengeSent) != 1 || f.observer.outcome(WorkerOutcomeResponseSent) != 1 {
		t.Fatalf("challenge/response outcomes = %d/%d, want 1/1",
			f.observer.outcome(WorkerOutcomeChallengeSent), f.observer.outcome(WorkerOutcomeResponseSent))
	}
	if f.observer.classification(ClassificationSuccess) != 1 {
		t.Fatalf("success classifications = %d, want 1", f.observer.classification(ClassificationSuccess))
	}
	authorityTimings, responseTimings := f.observer.timings()
	if len(authorityTimings) != 1 || authorityTimings[0].mode != ModeRefresh || authorityTimings[0].duration < 0 {
		t.Fatalf("authority timings = %#v, want one nonnegative refresh observation", authorityTimings)
	}
	if len(responseTimings) != 1 || responseTimings[0].mode != ModeRefresh || responseTimings[0].duration < 0 {
		t.Fatalf("post-authority timings = %#v, want one nonnegative refresh observation", responseTimings)
	}
	requestBytes, responseBytes, count := f.observer.challengeSize()
	if count != 1 || responseBytes >= requestBytes {
		t.Fatalf("challenge size observations = %d: %d -> %d, want one strict reduction", count, requestBytes, responseBytes)
	}
}

func TestWorkerRejectsExactProofReplayAcrossFreshConnectionState(t *testing.T) {
	f := newWorkerFixture(t)
	cookie, _ := f.challenge(t, 201)
	proof := f.sealLST(t, 202, &cookie)
	clear(cookie[:])
	f.send(t, proof)
	_ = f.read(t, time.Second)

	f.send(t, proof)
	if err := f.client.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, core.PacketBufferSize)
	if _, _, err := f.client.ReadFromUDP(buffer); err == nil {
		t.Fatal("exact replay received a response")
	}
	issueCalls, refreshCalls := f.authority.callCounts()
	if issueCalls != 0 || refreshCalls != 1 {
		t.Fatalf("authority calls after replay = %d/%d, want 0/1", issueCalls, refreshCalls)
	}
	if f.observer.outcome(WorkerOutcomeReplayRejected) != 1 {
		t.Fatalf("replay outcomes = %d, want 1", f.observer.outcome(WorkerOutcomeReplayRejected))
	}
}

func TestWorkerReturnsOnlyOneChallengeForExactInitialReplay(t *testing.T) {
	f := newWorkerFixture(t)
	_, initial := f.challenge(t, 211)
	f.send(t, initial)
	if err := f.client.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, core.PacketBufferSize)
	if _, _, err := f.client.ReadFromUDP(buffer); err == nil {
		t.Fatal("exact initial replay received a second COK")
	}
	issueCalls, refreshCalls := f.authority.callCounts()
	if issueCalls != 0 || refreshCalls != 0 {
		t.Fatalf("initial replay reached authority: %d/%d", issueCalls, refreshCalls)
	}
	if f.observer.outcome(WorkerOutcomeChallengeSent) != 1 || f.observer.outcome(WorkerOutcomeReplayRejected) != 1 {
		t.Fatalf("challenge/replay outcomes = %d/%d, want 1/1",
			f.observer.outcome(WorkerOutcomeChallengeSent), f.observer.outcome(WorkerOutcomeReplayRejected))
	}
}

func TestWorkerRejectsCookieProofFromDifferentSourceIP(t *testing.T) {
	f := newWorkerFixture(t)
	cookie, _ := f.challenge(t, 221)
	proof := f.sealLST(t, 222, &cookie)
	clear(cookie[:])
	packet := make([]byte, core.PacketBufferSize)
	packet = packet[:copy(packet, proof)]
	f.worker.workers.Add(1)
	f.worker.handlePacket(context.Background(), time.Now(),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 12345}, packet, func() {})
	issueCalls, refreshCalls := f.authority.callCounts()
	if issueCalls != 0 || refreshCalls != 0 {
		t.Fatalf("different-source proof reached authority: %d/%d", issueCalls, refreshCalls)
	}
	if f.observer.outcome(WorkerOutcomeCryptoRejected) != 1 {
		t.Fatalf("crypto rejection outcomes = %d, want 1", f.observer.outcome(WorkerOutcomeCryptoRejected))
	}
}

func TestWorkerMetersClosedRequestRejectionWithoutCallingAuthority(t *testing.T) {
	f := newWorkerFixture(t)
	// Keep the cryptographically valid LST larger than its COK while making the
	// application object fail the strict required-field grammar after proof.
	f.request = append(bytes.Repeat([]byte{' '}, 200), '{', '}')
	cookie, _ := f.challenge(t, 251)
	proof := f.sealLST(t, 252, &cookie)
	clear(cookie[:])
	f.send(t, proof)
	response := f.read(t, time.Second)
	ppd := f.decrypt(t, response, core.NHP_LRT)
	wantBody, err := EncodeRefreshError(AssignmentErrorInvalidRequest, nil)
	if err != nil {
		t.Fatalf("EncodeRefreshError: %v", err)
	}
	if !bytes.Equal(ppd.BodyMessage, wantBody) {
		t.Fatalf("rejection LRT body = %s, want %s", ppd.BodyMessage, wantBody)
	}
	issueCalls, refreshCalls := f.authority.callCounts()
	if issueCalls != 0 || refreshCalls != 0 {
		t.Fatalf("invalid request reached authority: %d/%d", issueCalls, refreshCalls)
	}
	if f.observer.classification(ClassificationRequestRejected) != 1 ||
		f.observer.rejection(RequestRejectionMissingField) != 1 {
		t.Fatalf("request rejection metrics = %d/%d, want 1/1",
			f.observer.classification(ClassificationRequestRejected), f.observer.rejection(RequestRejectionMissingField))
	}
}

func TestWorkerDropsNonLSTBeforeCryptoAndAuthority(t *testing.T) {
	f := newWorkerFixture(t)
	packet := f.sealLST(t, 301, nil)
	preamble := binary.BigEndian.Uint32(packet[:4])
	typeAndSize := preamble ^ binary.BigEndian.Uint32(packet[4:8])
	typeAndSize = uint32(core.NHP_KNK)<<16 | typeAndSize&0xffff
	binary.BigEndian.PutUint32(packet[4:8], preamble^typeAndSize)
	f.send(t, packet)
	if err := f.client.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, core.PacketBufferSize)
	if _, _, err := f.client.ReadFromUDP(buffer); err == nil {
		t.Fatal("non-LST received a response")
	}
	issueCalls, refreshCalls := f.authority.callCounts()
	if issueCalls != 0 || refreshCalls != 0 {
		t.Fatalf("authority calls = %d/%d, want 0/0", issueCalls, refreshCalls)
	}
	if f.observer.outcome(WorkerOutcomeEnvelopeRejected) != 1 {
		t.Fatalf("envelope rejection outcomes = %d, want 1", f.observer.outcome(WorkerOutcomeEnvelopeRejected))
	}
}

func TestValidHubEnvelopeAllowsOnlyExactUncompressedLSTStates(t *testing.T) {
	f := newWorkerFixture(t)
	initial := f.sealLST(t, 351, nil)
	var cookie [core.CookieSize]byte
	cookie[0] = 1
	proof := f.sealLST(t, 352, &cookie)
	clear(cookie[:])
	withFlag := func(flag uint16) []byte {
		packet := bytes.Clone(initial)
		binary.BigEndian.PutUint16(packet[10:12], flag)
		return packet
	}
	zeroPayload := bytes.Clone(initial)
	preamble := binary.BigEndian.Uint32(zeroPayload[:4])
	typeAndSize := uint32(core.NHP_LST) << 16
	binary.BigEndian.PutUint32(zeroPayload[4:8], preamble^typeAndSize)

	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{name: "initial", packet: initial, want: true},
		{name: "proof", packet: proof, want: true},
		{name: "compress", packet: withFlag(common.NHP_FLAG_COMPRESS)},
		{name: "proof plus compress", packet: withFlag(common.NHP_FLAG_HUB_LST_COOKIE_PROOF | common.NHP_FLAG_COMPRESS)},
		{name: "unknown flag", packet: withFlag(1 << 11)},
		{name: "zero payload", packet: zeroPayload},
		{name: "declared size mismatch", packet: initial[:len(initial)-1]},
		{name: "short header", packet: initial[:8]},
		{name: "oversize", packet: make([]byte, core.PacketBufferSize+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validHubEnvelope(test.packet); got != test.want {
				t.Fatalf("validHubEnvelope() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNewWorkerRejectsInvalidConfiguration(t *testing.T) {
	listener := func(t *testing.T) *net.UDPConn {
		t.Helper()
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("ListenUDP: %v", err)
		}
		return conn
	}
	base := WorkerConfig{
		PrivateKeyBase64:      base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, core.PrivateKeySize)),
		ActiveCookieKeyBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, core.SymmetricKeySize)),
		Handler:               mustHandler(t, &fakeHubAuthority{}, &fakeAdmissionGate{result: AdmissionResult{Decision: AdmissionAllow}}),
		MaxConcurrentPackets:  1,
		PacketsPerSecond:      1,
		PacketBurst:           1,
		MaxConcurrentPerPeer:  1,
		ResponseQueueCapacity: 1,
		Timing:                testWorkerTiming(),
	}
	tests := []struct {
		name   string
		mutate func(*WorkerConfig)
	}{
		{name: "private newline", mutate: func(c *WorkerConfig) { c.PrivateKeyBase64 += "\n" }},
		{name: "private all zero", mutate: func(c *WorkerConfig) {
			c.PrivateKeyBase64 = base64.StdEncoding.EncodeToString(make([]byte, core.PrivateKeySize))
		}},
		{name: "private short", mutate: func(c *WorkerConfig) {
			c.PrivateKeyBase64 = base64.StdEncoding.EncodeToString(make([]byte, core.PrivateKeySize-1))
		}},
		{name: "cookie raw url", mutate: func(c *WorkerConfig) {
			c.ActiveCookieKeyBase64 = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, core.SymmetricKeySize))
		}},
		{name: "previous short", mutate: func(c *WorkerConfig) {
			c.PreviousCookieKeyBase64 = base64.StdEncoding.EncodeToString(make([]byte, core.SymmetricKeySize-1))
		}},
		{name: "replay capacity base overflow", mutate: func(c *WorkerConfig) {
			c.MaxConcurrentPackets = int(^uint(0) >> 1)
		}},
		{name: "replay capacity rate overflow", mutate: func(c *WorkerConfig) {
			c.PacketsPerSecond = int(^uint(0) >> 1)
		}},
		{name: "concurrency exceeds core receive queue", mutate: func(c *WorkerConfig) {
			c.MaxConcurrentPackets = core.RecvQueueSize + 1
		}},
		{name: "per-peer concurrency exceeds aggregate", mutate: func(c *WorkerConfig) {
			c.MaxConcurrentPerPeer = c.MaxConcurrentPackets + 1
		}},
		{name: "response queue exceeds core send queue", mutate: func(c *WorkerConfig) {
			c.ResponseQueueCapacity = core.SendQueueSize + 1
		}},
		{name: "replay capacity exceeds core packet pool", mutate: func(c *WorkerConfig) {
			c.PacketsPerSecond = core.PacketBufferPoolSize/int(hubWorkerReplayTTL/time.Second) + 1
		}},
		{name: "timing omitted", mutate: func(c *WorkerConfig) { c.Timing = WorkerTiming{} }},
		{name: "lambda timeout fractional", mutate: func(c *WorkerConfig) {
			c.Timing.AuthorityLambdaTimeout = 3001 * time.Millisecond
		}},
		{name: "lambda timeout below floor", mutate: func(c *WorkerConfig) {
			c.Timing.AuthorityLambdaTimeout = 2 * time.Second
		}},
		{name: "lambda timeout reaches handler", mutate: func(c *WorkerConfig) {
			c.Timing.AuthorityLambdaTimeout = c.Timing.HandlerBudget
		}},
		{name: "handler reaches packet", mutate: func(c *WorkerConfig) {
			c.Timing.HandlerBudget = c.Timing.PacketBudget
		}},
		{name: "response reserve exceeds tail", mutate: func(c *WorkerConfig) {
			c.Timing.ResponseReserve = c.Timing.PacketBudget - c.Timing.HandlerBudget + time.Millisecond
		}},
		{name: "write exceeds response reserve", mutate: func(c *WorkerConfig) {
			c.Timing.WriteBudget = c.Timing.ResponseReserve + time.Millisecond
		}},
		{name: "packet reaches safety ceiling", mutate: func(c *WorkerConfig) {
			c.Timing.PacketBudget = maxWorkerPacketBudgetExclusive
		}},
		{name: "negative handler", mutate: func(c *WorkerConfig) {
			c.Timing.HandlerBudget = -time.Millisecond
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			conn := listener(t)
			defer conn.Close()
			if _, err := NewWorker(conn, config); !errors.Is(err, ErrInvalidWorkerConfiguration) {
				t.Fatalf("NewWorker error = %v, want invalid configuration", err)
			}
		})
	}
}

func TestValidateWorkerKeyMaterialMatchesNewWorkerKeyContract(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, core.PrivateKeySize))
	activeCookieKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, core.SymmetricKeySize))
	previousCookieKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, core.SymmetricKeySize))
	if err := ValidateWorkerKeyMaterial(privateKey, activeCookieKey, previousCookieKey); err != nil {
		t.Fatalf("ValidateWorkerKeyMaterial: %v", err)
	}
	if err := ValidateWorkerKeyMaterial(privateKey, activeCookieKey+"\n", previousCookieKey); !errors.Is(err, ErrInvalidWorkerConfiguration) {
		t.Fatalf("noncanonical key error = %v, want invalid worker configuration", err)
	}
}

func TestAggregateAndPeerAdmissionRemainBounded(t *testing.T) {
	now := time.Unix(100, 0)
	aggregate := newAggregateAdmission(1, 1, 1, now)
	release, _, ok := aggregate.acquire(now)
	if !ok {
		t.Fatal("first aggregate admission rejected")
	}
	if _, outcome, ok := aggregate.acquire(now); ok || outcome != WorkerOutcomeAggregateRateRejected {
		t.Fatalf("second aggregate admission = %v/%q, want rate rejection", ok, outcome)
	}
	release()
	if release, _, ok := aggregate.acquire(now.Add(time.Second)); !ok {
		t.Fatal("refilled aggregate admission rejected")
	} else {
		release()
	}
	concurrency := newAggregateAdmission(1, 10, 2, now)
	releaseConcurrent, _, ok := concurrency.acquire(now)
	if !ok {
		t.Fatal("first concurrency admission rejected")
	}
	if _, outcome, ok := concurrency.acquire(now); ok || outcome != WorkerOutcomeAggregateLimitRejected {
		t.Fatalf("second concurrency admission = %v/%q, want limit rejection", ok, outcome)
	}
	releaseConcurrent()

	peers := newPeerAdmission(1)
	peer := bytes.Repeat([]byte{0x91}, core.PublicKeySize)
	releasePeer, outcome, ok := peers.acquire(peer)
	if !ok {
		t.Fatalf("first peer admission rejected: %q", outcome)
	}
	if _, outcome, ok := peers.acquire(peer); ok || outcome != WorkerOutcomePeerLimitRejected {
		t.Fatalf("second same-peer admission = %v/%q, want peer-limit rejection", ok, outcome)
	}
	if _, outcome, ok := peers.acquire(peer[:len(peer)-1]); ok || outcome != WorkerOutcomeCryptoRejected {
		t.Fatalf("wrong-length peer admission = %v/%q, want crypto rejection", ok, outcome)
	}
	releasePeer()
	if releasePeer, outcome, ok := peers.acquire(peer); !ok {
		t.Fatalf("released peer admission remained blocked: %q", outcome)
	} else {
		releasePeer()
	}
}

func TestWorkerLiveIngressAppliesAggregateRateAdmission(t *testing.T) {
	authorityContract := authorityVectors(t)
	authority := &fakeHubAuthority{
		refreshResponse: []byte(authorityContract.Operations[conformance.ConnectorAuthorityOperationRefreshAssignment].SuccessGolden.BodyJSON),
	}
	f := newWorkerFixtureConfigured(t, authority, func(config *WorkerConfig) {
		config.PacketsPerSecond = 1
		config.PacketBurst = 1
	})
	_, _ = f.challenge(t, 371)

	f.send(t, f.sealLST(t, 372, nil))
	if err := f.client.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, core.PacketBufferSize)
	if _, _, err := f.client.ReadFromUDP(buffer); err == nil {
		t.Fatal("rate-rejected live packet received a challenge")
	}
	if f.observer.outcome(WorkerOutcomeAggregateRateRejected) != 1 {
		t.Fatalf("aggregate rate outcomes = %d, want 1", f.observer.outcome(WorkerOutcomeAggregateRateRejected))
	}
	issueCalls, refreshCalls := f.authority.callCounts()
	if issueCalls != 0 || refreshCalls != 0 {
		t.Fatalf("rate-rejected packet reached authority: %d/%d", issueCalls, refreshCalls)
	}
}

func TestWorkerClassifiesHandlerDropInvalidResponseAndQueueFull(t *testing.T) {
	observer := newRecordingWorkerObserver()
	worker := &Worker{
		observer: observer,
		replay:   newPacketReplayCache(1),
		writes:   make(chan outboundDatagram, 1),
	}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}
	now := time.Unix(100, 0)
	digestA := sha256.Sum256([]byte("accepted"))
	digestB := sha256.Sum256([]byte("capacity"))

	if !worker.acceptReplay(digestA, now) {
		t.Fatal("first replay digest rejected")
	}
	if worker.acceptReplay(digestB, now) {
		t.Fatal("capacity-full replay cache accepted a new digest")
	}
	if worker.acceptReplay(digestA, now) {
		t.Fatal("exact replay accepted")
	}
	if worker.hasHandlerBody(nil) {
		t.Fatal("empty handler body accepted")
	}
	if !worker.hasHandlerBody([]byte("body")) {
		t.Fatal("nonempty handler body rejected")
	}
	invalidRemotePayload := []byte("invalid-remote")
	worker.enqueueResponse(invalidRemotePayload, nil, WorkerOutcomeResponseSent, 0, time.Now().Add(time.Second), 0, time.Time{})
	if !bytes.Equal(invalidRemotePayload, make([]byte, len(invalidRemotePayload))) {
		t.Fatal("invalid response payload was not wiped")
	}
	worker.enqueueResponse(nil, remote, WorkerOutcomeResponseSent, 0, time.Now().Add(time.Second), 0, time.Time{})

	queuedPayload := []byte("queued")
	worker.enqueueResponse(queuedPayload, remote, WorkerOutcomeResponseSent, 0, time.Now().Add(time.Second), 0, time.Time{})
	droppedPayload := []byte("queue-full")
	worker.enqueueResponse(droppedPayload, remote, WorkerOutcomeResponseSent, 0, time.Now().Add(time.Second), 0, time.Time{})
	if !bytes.Equal(droppedPayload, make([]byte, len(droppedPayload))) {
		t.Fatal("queue-rejected response payload was not wiped")
	}

	if observer.outcome(WorkerOutcomeReplayCapacityRejected) != 1 ||
		observer.outcome(WorkerOutcomeReplayRejected) != 1 ||
		observer.outcome(WorkerOutcomeHandlerDropped) != 1 ||
		observer.outcome(WorkerOutcomeResponseInvalidRejected) != 2 ||
		observer.outcome(WorkerOutcomeResponseQueueRejected) != 1 {
		t.Fatalf("new worker outcomes = capacity %d, replay %d, handler %d, invalid %d, queue %d; want 1/1/1/2/1",
			observer.outcome(WorkerOutcomeReplayCapacityRejected),
			observer.outcome(WorkerOutcomeReplayRejected),
			observer.outcome(WorkerOutcomeHandlerDropped),
			observer.outcome(WorkerOutcomeResponseInvalidRejected),
			observer.outcome(WorkerOutcomeResponseQueueRejected))
	}
	queued := <-worker.writes
	if queued.remote != remote || !bytes.Equal(queued.payload, queuedPayload) {
		t.Fatal("queued response did not retain transferred ownership")
	}
	clear(queued.payload)
}

func TestValidateWorkerTimingAcceptsInclusiveReserveBoundaries(t *testing.T) {
	timing := WorkerTiming{
		AuthorityLambdaTimeout: 3 * time.Second,
		HandlerBudget:          3100 * time.Millisecond,
		PacketBudget:           3500 * time.Millisecond,
		ResponseReserve:        400 * time.Millisecond,
		WriteBudget:            400 * time.Millisecond,
	}
	if err := ValidateWorkerTiming(timing); err != nil {
		t.Fatalf("ValidateWorkerTiming equality boundaries: %v", err)
	}
}

func TestWorkerDropsPacketWhoseReceiptBudgetAlreadyExpired(t *testing.T) {
	timing := WorkerTiming{
		AuthorityLambdaTimeout: 3 * time.Second,
		HandlerBudget:          3200 * time.Millisecond,
		PacketBudget:           3900 * time.Millisecond,
		ResponseReserve:        700 * time.Millisecond,
		WriteBudget:            137 * time.Millisecond,
	}
	authorityContract := authorityVectors(t)
	authority := &fakeHubAuthority{
		refreshResponse: []byte(authorityContract.Operations[conformance.ConnectorAuthorityOperationRefreshAssignment].SuccessGolden.BodyJSON),
	}
	f := newWorkerFixtureConfigured(t, authority, func(config *WorkerConfig) { config.Timing = timing })
	if f.worker.packetBudget != timing.PacketBudget || f.worker.handlerBudget != timing.HandlerBudget ||
		f.worker.writeBudget != timing.WriteBudget {
		t.Fatalf("worker timing = %v/%v/%v, want %v/%v/%v",
			f.worker.packetBudget, f.worker.handlerBudget, f.worker.writeBudget,
			timing.PacketBudget, timing.HandlerBudget, timing.WriteBudget)
	}
	packet := make([]byte, core.PacketBufferSize)
	released := false
	f.worker.workers.Add(1)
	f.worker.handlePacket(context.Background(), time.Now().Add(-timing.PacketBudget-time.Millisecond),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, packet, func() { released = true })
	if !released {
		t.Fatal("aggregate admission was not released")
	}
	if f.observer.outcome(WorkerOutcomeDeadlineRejected) != 1 {
		t.Fatalf("deadline outcomes = %d, want 1", f.observer.outcome(WorkerOutcomeDeadlineRejected))
	}
	issueCalls, refreshCalls := f.authority.callCounts()
	if issueCalls != 0 || refreshCalls != 0 {
		t.Fatalf("expired packet reached authority: %d/%d", issueCalls, refreshCalls)
	}
}

func TestWorkerStopsAuthorityAtConfiguredHandlerDeadline(t *testing.T) {
	authority := &deadlineWorkerAuthority{deadlines: make(chan time.Time, 1)}
	timing := WorkerTiming{
		AuthorityLambdaTimeout: 3 * time.Second,
		HandlerBudget:          3150 * time.Millisecond,
		PacketBudget:           3800 * time.Millisecond,
		ResponseReserve:        650 * time.Millisecond,
		WriteBudget:            149 * time.Millisecond,
	}
	f := newWorkerFixtureConfigured(t, authority, func(config *WorkerConfig) { config.Timing = timing })
	cookie, _ := f.challenge(t, 401)
	proof := f.sealLST(t, 402, &cookie)
	clear(cookie[:])
	packet := make([]byte, core.PacketBufferSize)
	packet = packet[:copy(packet, proof)]
	receivedAt := time.Now().Add(-timing.HandlerBudget + 40*time.Millisecond)
	f.worker.workers.Add(1)
	f.worker.handlePacket(context.Background(), receivedAt, cloneUDPAddr(f.client.LocalAddr().(*net.UDPAddr)), packet, func() {})

	select {
	case got := <-authority.deadlines:
		want := receivedAt.Add(timing.HandlerBudget)
		if !got.Equal(want) {
			t.Fatalf("authority deadline = %v, want %v", got, want)
		}
	default:
		t.Fatal("authority did not observe a deadline")
	}
	response := f.read(t, time.Second)
	ppd := f.decrypt(t, response, core.NHP_LRT)
	wantBody, err := EncodeRefreshError(AssignmentErrorUnavailable, nil)
	if err != nil {
		t.Fatalf("EncodeRefreshError: %v", err)
	}
	if !bytes.Equal(ppd.BodyMessage, wantBody) {
		t.Fatalf("deadline LRT body = %s, want %s", ppd.BodyMessage, wantBody)
	}
	f.observer.waitForPostAuthorityObservation(t)
	issueCalls, refreshCalls := authority.callCounts()
	if issueCalls != 0 || refreshCalls != 1 {
		t.Fatalf("authority calls = %d/%d, want 0/1", issueCalls, refreshCalls)
	}
	authorityTimings, responseTimings := f.observer.timings()
	if len(authorityTimings) != 1 || authorityTimings[0].mode != ModeRefresh || authorityTimings[0].duration < 0 {
		t.Fatalf("deadline authority timings = %#v, want one nonnegative refresh observation", authorityTimings)
	}
	if len(responseTimings) != 1 || responseTimings[0].mode != ModeRefresh || responseTimings[0].duration < 0 {
		t.Fatalf("deadline response timings = %#v, want one nonnegative refresh observation", responseTimings)
	}
}

func TestWorkerWriterDropsQueuedResponseAfterReceiptBudget(t *testing.T) {
	f := newWorkerFixture(t)
	f.worker.enqueueResponse([]byte("must-not-send"), f.client.LocalAddr().(*net.UDPAddr),
		WorkerOutcomeResponseSent, 0, time.Now().Add(-time.Millisecond), ModeRefresh, time.Now())
	deadline := time.Now().Add(time.Second)
	for f.observer.outcome(WorkerOutcomeDeadlineRejected) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.observer.outcome(WorkerOutcomeDeadlineRejected) != 1 {
		t.Fatalf("writer deadline outcomes = %d, want 1", f.observer.outcome(WorkerOutcomeDeadlineRejected))
	}
	_, responseTimings := f.observer.timings()
	if len(responseTimings) != 0 {
		t.Fatalf("expired queued response recorded successful-write timing: %#v", responseTimings)
	}
	if err := f.client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, 32)
	if _, _, err := f.client.ReadFromUDP(buffer); err == nil {
		t.Fatal("writer sent an expired response")
	}
}

func TestResponseWriteDeadlineUsesEarlierConfiguredOrReceiptBound(t *testing.T) {
	now := time.Unix(100, 0)
	writeBudget := 137 * time.Millisecond
	for _, test := range []struct {
		name            string
		requestDeadline time.Time
		writeBudget     time.Duration
		want            time.Time
	}{
		{
			name:            "configured write cap",
			requestDeadline: now.Add(time.Second),
			writeBudget:     writeBudget,
			want:            now.Add(writeBudget),
		},
		{
			name:            "receipt anchored packet deadline",
			requestDeadline: now.Add(100 * time.Millisecond),
			writeBudget:     writeBudget,
			want:            now.Add(100 * time.Millisecond),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := responseWriteDeadline(now, test.requestDeadline, test.writeBudget); !got.Equal(test.want) {
				t.Fatalf("responseWriteDeadline = %v, want %v", got, test.want)
			}
		})
	}
}
