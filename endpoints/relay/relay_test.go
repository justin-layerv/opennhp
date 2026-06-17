package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

func keyBytes(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i) + seed
	}
	return k
}

// devicePubKey returns the NHP static public key for a private key.
func devicePubKey(t *testing.T, deviceType int, priv []byte) []byte {
	t.Helper()
	d := core.NewDevice(deviceType, priv, nil)
	if d == nil {
		t.Fatal("NewDevice returned nil")
	}
	pub, err := base64.StdEncoding.DecodeString(d.PublicKeyBase64())
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	d.Stop()
	return pub
}

// makeInnerKnock produces a real encrypted NHP_KNK (as an agent would emit it)
// carrying the given counter — a well-formed packet the relay can RecvPrecheck.
func makeInnerKnock(t *testing.T, serverPub []byte, counter uint64) []byte {
	t.Helper()
	agentDev := core.NewDevice(core.NHP_AGENT, keyBytes(0x11), nil)
	agentDev.Start()
	t.Cleanup(agentDev.Stop)

	conn := &core.ConnectionData{
		Device:           agentDev,
		LocalAddr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		RemoteAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206},
		InitTime:         time.Now().UnixNano(),
		SendQueue:        make(chan *core.Packet, 8),
		RecvQueue:        make(chan *core.Packet, 8),
		BlockSignal:      make(chan struct{}, 1),
		SetTimeoutSignal: make(chan struct{}, 1),
		StopSignal:       make(chan struct{}),
	}
	body, err := json.Marshal(&common.AgentKnockMsg{HeaderType: core.NHP_KNK, UserId: "u", AuthServiceId: "asp", ResourceId: "res"})
	if err != nil {
		t.Fatalf("marshal knock: %v", err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      conn,
		PeerPk:        serverPub,
		HeaderType:    core.NHP_KNK,
		TransactionId: counter,
		Message:       body,
	})
	select {
	case pkt := <-conn.SendQueue:
		return append([]byte(nil), pkt.Content...)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout producing inner knock")
		return nil
	}
}

func testStop(rs *RelayServer) {
	// CAS-guarded so it's idempotent — a test may also call rs.Stop explicitly;
	// only one runs the teardown (no double-close of stopCh).
	if !rs.running.CompareAndSwap(true, false) {
		return
	}
	close(rs.stopCh)
	_ = rs.udpConn.Close()
	rs.wg.Wait()
	rs.device.Stop()
}

func newTestRelay(t *testing.T, serverPub []byte, serverPort int, mode SourceAddrMode) *RelayServer {
	t.Helper()
	cfg := &Config{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(keyBytes(0x80)),
		UDPListenAddr:    "127.0.0.1:0",
		SourceAddrMode:   mode,
		Servers: []ServerConfig{{
			Name:         "test-cell",
			PubKeyBase64: base64.StdEncoding.EncodeToString(serverPub),
			Host:         "127.0.0.1",
			Port:         serverPort,
		}},
	}
	rs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rs.startBackground()
	t.Cleanup(func() { testStop(rs) })
	return rs
}

// makeRealAck has the server device decrypt the inner knock and emit a genuine
// NHP_ACK (encrypted for the agent, carrying the inner counter) — the actual
// packet type the relay's recv path runs RecvPrecheck on in production. Using a
// real ACK (not an echoed KNK) proves NHP_ACK is accepted at an NHP_RELAY device
// and counter-correlated, instead of a type-confused lookalike.
func makeRealAck(t *testing.T, serverDev *core.Device, innerKnock []byte, srcAddr *net.UDPAddr) []byte {
	t.Helper()
	pd := &core.PacketData{
		BasePacket: &core.Packet{Content: innerKnock},
		ConnData:   &core.ConnectionData{Device: serverDev, RemoteAddr: srcAddr},
		InitTime:   time.Now().UnixNano(),
	}
	innerPpd, err := serverDev.PacketToMsg(pd)
	if err != nil {
		t.Fatalf("server decrypt inner knock: %v", err)
	}
	ackBody, err := json.Marshal(&common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()})
	if err != nil {
		t.Fatalf("marshal ack: %v", err)
	}
	encCh := make(chan *core.MsgAssemblerData, 1)
	serverDev.SendMsgToPacket(&core.MsgData{
		HeaderType:     core.NHP_ACK,
		TransactionId:  innerPpd.SenderTrxId,
		Compress:       true,
		PrevParserData: innerPpd,
		Message:        ackBody,
		EncryptedPktCh: encCh,
	})
	select {
	case mad := <-encCh:
		if mad.Error != nil {
			t.Fatalf("server encrypt ack: %v", mad.Error)
		}
		ack := append([]byte(nil), mad.BasePacket.Content...)
		mad.Destroy()
		return ack
	case <-time.After(5 * time.Second):
		t.Fatal("timeout building real ack")
		return nil
	}
}

// makeRealCookie drives the server's real overload path: an overloaded server
// decrypts the inner knock and, in validatePeer, emits a genuine NHP_COK
// (overload cookie) via sendCookie. It returns the encrypted COK bytes the
// server would put on the wire. This exercises the exact production path #2529 /
// #2611 concern — the COK must carry the inner KNK's counter so the one-shot
// relay can correlate it — rather than a hand-built lookalike.
func makeRealCookie(t *testing.T, serverDev *core.Device, innerKnock []byte, srcAddr *net.UDPAddr) []byte {
	t.Helper()
	serverDev.SetOverload(true)
	t.Cleanup(func() { serverDev.SetOverload(false) })

	// The COK is encrypted on the normal send path and routed to this connection's
	// SendQueue by ForwardOutboundPacket (sendCookie does not divert via
	// EncryptedPktCh). Device + RemoteAddr identify and address the reply;
	// SendQueue (where the COK lands) and CookieStore (generateCookie/sendCookie
	// read+write it) are the only channels/stores this path exercises.
	conn := &core.ConnectionData{
		Device:      serverDev,
		RemoteAddr:  srcAddr,
		CookieStore: &core.CookieStore{},
		SendQueue:   make(chan *core.Packet, 1),
	}
	pd := &core.PacketData{
		BasePacket: &core.Packet{Content: innerKnock},
		ConnData:   conn,
		InitTime:   time.Now().UnixNano(),
	}
	// An overloaded server rejects the knock with a cookie; PacketToMsg surfaces
	// ErrServerRejectWithCookie and sendCookie has queued the encrypted COK.
	if _, err := serverDev.PacketToMsg(pd); err == nil {
		t.Fatal("overloaded server accepted the knock; expected a cookie rejection")
	}
	select {
	case pkt := <-conn.SendQueue:
		return append([]byte(nil), pkt.Content...)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for the server to emit an overload cookie")
		return nil
	}
}

// driveRelayRoundTrip exercises the relay's full forward path for one
// server->agent reply type: it POSTs a fresh inner knock to handleRelay while a
// one-shot fake cell server echoes back a real reply built from serverDev. It
// returns the relay, recorded HTTP response, and reply bytes so each test keeps
// only its reply-specific assertions.
func driveRelayRoundTrip(t *testing.T, counter uint64, makeReply func(*testing.T, *core.Device, []byte, *net.UDPAddr) []byte) (*RelayServer, *httptest.ResponseRecorder, []byte) {
	t.Helper()
	serverDev := core.NewDevice(core.NHP_SERVER, keyBytes(0x40), &core.DeviceOptions{DisableAgentPeerValidation: true})
	serverDev.Start()
	t.Cleanup(serverDev.Stop)
	serverPub, err := base64.StdEncoding.DecodeString(serverDev.PublicKeyBase64())
	if err != nil {
		t.Fatalf("decode server pubkey: %v", err)
	}

	fakeServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("fake server listen: %v", err)
	}
	t.Cleanup(func() { _ = fakeServer.Close() })

	srcAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444}
	innerKnock := makeInnerKnock(t, serverPub, counter)
	reply := makeReply(t, serverDev, innerKnock, srcAddr)

	// Fake server: read the NHP_RLY, reply with the real NHP reply to the relay's
	// source addr (the server replies to the packet's source).
	go func() {
		buf := make([]byte, 65536)
		_, from, rerr := fakeServer.ReadFromUDP(buf)
		if rerr != nil {
			return
		}
		_, _ = fakeServer.WriteToUDP(reply, from)
	}()

	rs := newTestRelay(t, serverPub, fakeServer.LocalAddr().(*net.UDPAddr).Port, SourceAddrModeRemoteAddr)
	rs.cors = newCORSAllowlist(testKnockOrigin)

	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerKnock))
	req.RemoteAddr = "203.0.113.7:44444"
	req.Header.Set("Origin", testKnockOrigin)
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	return rs, w, reply
}

// TestRelay_OverloadCookie_RoundTrip is the #2529 proof: an overloaded cell
// server's NHP_COK reply is correctly dispatched back to the waiting HTTP
// handler through the one-shot relay path. Before the #2611 fix the COK carried
// a fresh server-side counter, so the relay (which matches replies to pending
// requests by the inner KNK counter) silently dropped it and the browser timed
// out instead of receiving the cookie challenge. The COK challenge is now
// live-reachable through the relay, unblocking the COK->RKN follow-up.
func TestRelay_OverloadCookie_RoundTrip(t *testing.T) {
	const counter = uint64(6611)
	rs, w, realCookie := driveRelayRoundTrip(t, counter, makeRealCookie)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q — the overload COK was not dispatched back through the relay (counter-correlation regression)", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), realCookie) {
		t.Errorf("relayed NHP_COK bytes mismatch (got %d bytes, want %d)", w.Body.Len(), len(realCookie))
	}
	// Independently confirm the COK's cleartext counter is the inner KNK counter
	// the relay keyed its pending request on — the property the dispatch relies on.
	if cokCounter, cerr := rs.innerCounter(realCookie); cerr != nil {
		t.Fatalf("innerCounter(COK): %v", cerr)
	} else if cokCounter != counter {
		t.Errorf("COK wire counter = %d, want inner KNK counter %d (relay matches replies by this counter)", cokCounter, counter)
	}
}

// TestRelay_RoundTrip drives the full path: HTTPS POST -> NHP_RLY to the (fake)
// cell server on the shared socket -> a REAL NHP_ACK, counter-correlated,
// returned to the HTTP response.
func TestRelay_RoundTrip(t *testing.T) {
	const counter = uint64(7777)
	_, w, realAck := driveRelayRoundTrip(t, counter, makeRealAck)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), realAck) {
		t.Errorf("relayed NHP_ACK bytes mismatch (got %d bytes, want %d)", w.Body.Len(), len(realAck))
	}
	// The actual production flow: a successful 200 also carries the echoed CORS
	// header so the browser can read the ACK.
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != testKnockOrigin {
		t.Errorf("Allow-Origin = %q on the 200 ACK, want %q", got, testKnockOrigin)
	}
}

// TestRelay_DispatchToConcurrentWaiters fences the composite-key design: two
// clients sharing a transaction counter both receive the dispatched ACK (the
// reason registration is (counter, client) but dispatch is by counter).
func TestRelay_DispatchToConcurrentWaiters(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)

	const counter = uint64(9999)
	ch1 := make(chan []byte, 1)
	ch2 := make(chan []byte, 1)
	rs.pendingMu.Lock()
	rs.pending[pendingKey{counter: counter, clientAddr: "203.0.113.7:1"}] = ch1
	rs.pending[pendingKey{counter: counter, clientAddr: "198.51.100.4:2"}] = ch2
	rs.pendingMu.Unlock()

	rs.dispatch(counter, []byte("ack-bytes"))

	for i, ch := range []chan []byte{ch1, ch2} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Errorf("waiter %d on the shared counter did not receive the dispatched ACK", i)
		}
	}
}

func TestRelay_UnknownServer_404(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	req := httptest.NewRequest(http.MethodPost, "/relay/not-a-real-fingerprint", bytes.NewReader([]byte("x")))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for unknown server", w.Code)
	}
}

// TestRelay_InFlightCap_Sheds fences the backpressure cap (#2553): when a cell's
// in-flight slots are all taken, a new POST is SHED (503) rather than parking
// another goroutine + pending entry. Deterministic — it pre-fills the semaphore
// to the cap under no concurrency, so it asserts the shedding behavior directly
// without racing real goroutines (and without waiting out a 5s timeout). It also
// asserts the shed happens BEFORE any work: no pending entry is registered, a
// Retry-After hint is set, and the CORS headers are present (#2631) so a browser
// can read the 503.
func TestRelay_InFlightCap_Sheds(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	innerKnock := makeInnerKnock(t, serverPub, 4242)
	// Route to a dead port so that, absent shedding, the handler WOULD park on
	// respCh — making "did it shed?" unambiguous (a non-shed path would block,
	// not return 503 immediately).
	rs := newTestRelay(t, serverPub, 62299, SourceAddrModeRemoteAddr)
	rs.cors = newCORSAllowlist(testKnockOrigin)
	serverID := utils.PubKeyFingerprint(serverPub)
	srv := rs.servers[serverID]

	// Saturate the cell's in-flight semaphore (simulating maxInFlightPerServer
	// requests already in flight). cap(...) proves we fill exactly the cap.
	if cap(srv.inFlight) != maxInFlightPerServer {
		t.Fatalf("inFlight cap = %d, want %d", cap(srv.inFlight), maxInFlightPerServer)
	}
	for i := 0; i < maxInFlightPerServer; i++ {
		srv.inFlight <- struct{}{}
	}

	rs.pendingMu.Lock()
	pendingBefore := len(rs.pending)
	rs.pendingMu.Unlock()
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerKnock))
	req.RemoteAddr = "203.0.113.7:44444"
	req.Header.Set("Origin", testKnockOrigin)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { rs.handleRelay(w, req); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleRelay did not return — it parked instead of shedding at the in-flight cap")
	}

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when the in-flight cap is reached", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Error("shed response missing Retry-After hint")
	}
	// CORS headers must be set before the shed branch (#2631) so a browser can read
	// the 503 — guards against a future reorder that sheds above the CORS block.
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != testKnockOrigin {
		t.Errorf("Allow-Origin = %q on the 503 shed, want %q (CORS must precede the shed)", got, testKnockOrigin)
	}
	// The shed must happen before any pending registration — otherwise the map
	// (and goroutine count) would still grow under a stuck cell, defeating the cap.
	rs.pendingMu.Lock()
	pendingAfter := len(rs.pending)
	rs.pendingMu.Unlock()
	if pendingAfter != pendingBefore {
		t.Errorf("pending grew from %d to %d on a shed request; the cap must shed BEFORE registering a waiter", pendingBefore, pendingAfter)
	}
}

// TestRelay_InFlightSlotReleased fences that a slot is returned after the handler
// completes: a request that runs to its (timeout) completion must free its
// in-flight slot so the cap is not permanently consumed by transient load.
func TestRelay_InFlightSlotReleased(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	innerKnock := makeInnerKnock(t, serverPub, 4243)
	rs := newTestRelay(t, serverPub, 62299, SourceAddrModeRemoteAddr) // dead port -> 504
	rs.responseTimeout = 50 * time.Millisecond
	serverID := utils.PubKeyFingerprint(serverPub)
	srv := rs.servers[serverID]

	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerKnock))
	req.RemoteAddr = "203.0.113.7:44444"
	rs.handleRelay(httptest.NewRecorder(), req)

	if got := len(srv.inFlight); got != 0 {
		t.Errorf("in-flight slots held after handler returned = %d, want 0 (slot must be released on every exit path)", got)
	}
}

// TestRelay_RejectedRequestConsumesNoSlot locks in the load-bearing ordering: the
// in-flight slot is acquired only AFTER the serverID lookup, so a request that is
// rejected earlier (wrong method, unknown server) consumes none. A future
// reordering that moved acquisition before the lookup would let unroutable junk
// burn the cap; this catches that.
func TestRelay_RejectedRequestConsumesNoSlot(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	serverID := utils.PubKeyFingerprint(serverPub)
	srv := rs.servers[serverID]

	// Wrong method: the 405 method gate runs BEFORE the serverID lookup, so a GET
	// never reaches slot acquisition. (The known serverID in the path just gives
	// the assertion below a per-cell semaphore to inspect; the 405 is independent
	// of the cell. The 404 unknown-server path resolves no serverRuntime at all.)
	getReq := httptest.NewRequest(http.MethodGet, "/relay/"+serverID, nil)
	rs.handleRelay(httptest.NewRecorder(), getReq)

	// Unknown server: 404 before any acquisition; the known cell must be untouched.
	unknownReq := httptest.NewRequest(http.MethodPost, "/relay/not-a-real-fingerprint", bytes.NewReader([]byte("x")))
	unknownReq.RemoteAddr = "203.0.113.7:44444"
	rs.handleRelay(httptest.NewRecorder(), unknownReq)

	if got := len(srv.inFlight); got != 0 {
		t.Errorf("known cell holds %d in-flight slots after rejected requests, want 0 (slot must be acquired only after the serverID lookup)", got)
	}
}

// TestRelay_ShedLogThrottle fences the throttled shed log (#2553 cr): many sheds
// in a window must drain into ONE log carrying the full count, and the first shed
// after a quiet period must log immediately. Driven by Store-ing lastShedLogNano
// directly (not by sleeping the 10s window) so it is deterministic and fast.
func TestRelay_ShedLogThrottle(t *testing.T) {
	srv := &serverRuntime{name: "cell", inFlight: make(chan struct{}, 1)}

	// Fresh runtime: lastShedLogNano==0, so the first shed logs immediately and
	// drains the count to 0 (it logged "1"). shedCount returns to 0 post-emit.
	srv.logShed()
	if got := srv.shedCount.Load(); got != 0 {
		t.Errorf("after the first (immediately-logged) shed, shedCount = %d, want 0 (drained by the emit)", got)
	}
	if srv.lastShedLogNano.Load() == 0 {
		t.Error("first shed did not stamp lastShedLogNano (it should have logged + stamped)")
	}

	// Force "inside the window": pin lastShedLogNano to now. Subsequent sheds must
	// only accumulate the counter, never emit (so never drain it).
	srv.lastShedLogNano.Store(time.Now().UnixNano())
	const suppressed = 5
	for i := 0; i < suppressed; i++ {
		srv.logShed()
	}
	if got := srv.shedCount.Load(); got != suppressed {
		t.Errorf("in-window sheds accumulated to %d, want %d (they must count but not emit/drain)", got, suppressed)
	}

	// Force "past the window": the next shed wins the CAS, emits, and drains the
	// accumulated 5 + its own 1 = 6 in one log line.
	srv.lastShedLogNano.Store(time.Now().Add(-2 * shedLogWindow).UnixNano())
	srv.logShed()
	if got := srv.shedCount.Load(); got != 0 {
		t.Errorf("post-window shed did not drain the counter: shedCount = %d, want 0 (the emit should have swapped it, logging 6)", got)
	}
}

// TestNew_TrustedHeaderBindCoherence fences the boot-time spoofing-combo guard
// (#2553): New must REFUSE trusted_header configs that provably defeat its safety
// precondition (a TLS-terminating relay, or a public bind), and must ACCEPT the
// coherent ones — including the unspecified bind the production deployment uses
// (terraform/modules/relay/user_data.sh.tpl renders listen_addr=":8080").
func TestNew_TrustedHeaderBindCoherence(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	base := func() *Config {
		return &Config{
			PrivateKeyBase64: base64.StdEncoding.EncodeToString(keyBytes(0x80)),
			UDPListenAddr:    "127.0.0.1:0",
			Servers:          []ServerConfig{{Name: "c", PubKeyBase64: base64.StdEncoding.EncodeToString(serverPub), Host: "127.0.0.1", Port: 62206}},
		}
	}
	tests := []struct {
		name       string
		mode       SourceAddrMode
		listenAddr string
		enableTLS  bool
		wantErr    bool
	}{
		// Dangerous combos — must fail closed.
		{"trusted_header + TLS terminate is rejected", SourceAddrModeTrustedHeader, ":8080", true, true},
		{"trusted_header + public IPv4 bind is rejected", SourceAddrModeTrustedHeader, "203.0.113.7:8080", false, true},
		{"trusted_header + public IPv6 bind is rejected", SourceAddrModeTrustedHeader, "[2001:db8::1]:8080", false, true},
		// Conservative fail-closed: not IsPrivate/IsLoopback/IsUnspecified, so
		// treated as public and rejected. Locks the posture against accidental
		// broadening of the allowlist (see assertTrustedHeaderBindCoherent doc).
		{"trusted_header + IPv4 link-local bind is rejected", SourceAddrModeTrustedHeader, "169.254.1.1:8080", false, true},
		{"trusted_header + CGNAT bind is rejected", SourceAddrModeTrustedHeader, "100.64.0.1:8080", false, true},
		{"trusted_header + IPv6 link-local bind is rejected", SourceAddrModeTrustedHeader, "[fe80::1]:8080", false, true},
		// Coherent combos — must start.
		{"trusted_header + unspecified host (prod :8080) is allowed", SourceAddrModeTrustedHeader, ":8080", false, false},
		{"trusted_header + 0.0.0.0 bind is allowed", SourceAddrModeTrustedHeader, "0.0.0.0:8080", false, false},
		{"trusted_header + loopback bind is allowed", SourceAddrModeTrustedHeader, "127.0.0.1:8080", false, false},
		{"trusted_header + private bind is allowed", SourceAddrModeTrustedHeader, "10.0.0.5:8080", false, false},
		{"trusted_header + hostname bind is allowed (not classifiable)", SourceAddrModeTrustedHeader, "relay.internal:8080", false, false},
		// RemoteAddr mode is spoof-proof regardless of bind/TLS — never gated.
		{"remoteaddr + public bind + TLS is allowed", SourceAddrModeRemoteAddr, "203.0.113.7:8080", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			cfg.SourceAddrMode = tc.mode
			cfg.ListenAddr = tc.listenAddr
			cfg.EnableTLS = tc.enableTLS
			rs, err := New(cfg)
			if rs != nil {
				_ = rs.udpConn.Close() // release the socket New bound on the accept path
			}
			if tc.wantErr && err == nil {
				t.Fatalf("New accepted a dangerous trusted_header combo (%s); it must fail closed", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("New rejected a coherent combo (%s): %v", tc.name, err)
			}
		})
	}
}

func TestNew_UnknownSourceMode_Rejected(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	cfg := &Config{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(keyBytes(0x80)),
		UDPListenAddr:    "127.0.0.1:0",
		SourceAddrMode:   "trusted-header", // hyphen typo — must NOT silently fall back to RemoteAddr
		Servers:          []ServerConfig{{Name: "c", PubKeyBase64: base64.StdEncoding.EncodeToString(serverPub), Host: "127.0.0.1", Port: 62206}},
	}
	if rs, err := New(cfg); err == nil {
		_ = rs.udpConn.Close()
		t.Error("New accepted an unknown source_addr_mode; it must fail closed")
	}
}

func TestRelay_WrongMethod_405(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	req := httptest.NewRequest(http.MethodGet, "/relay/"+utils.PubKeyFingerprint(serverPub), nil)
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405 for GET", w.Code)
	}
}

func TestRelay_OversizeBody_400(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	big := make([]byte, maxInnerPacketSize+10)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+utils.PubKeyFingerprint(serverPub), bytes.NewReader(big))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for oversize body", w.Code)
	}
}

// TestRelay_Timeout_504 fences the no-ACK path: the handler returns 504 after
// responseTimeout when the server never replies.
func TestRelay_Timeout_504(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	innerKnock := makeInnerKnock(t, serverPub, 8888)
	rs := newTestRelay(t, serverPub, 62299, SourceAddrModeRemoteAddr) // nothing listening -> no ACK
	rs.responseTimeout = 80 * time.Millisecond                        // keep the test fast

	req := httptest.NewRequest(http.MethodPost, "/relay/"+utils.PubKeyFingerprint(serverPub), bytes.NewReader(innerKnock))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504 when no ACK arrives", w.Code)
	}
}

func TestRelay_MalformedInner_400(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader([]byte("not a valid nhp packet")))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for malformed inner packet", w.Code)
	}
}

// TestRelay_SameClientSameCounter_NoOverwrite fences the per-request seq fix:
// two concurrent requests from the SAME client sharing a counter (a browser
// retrying an identical knock) must both register and both be served — the
// pre-fix (counter,client) key was last-writer-wins, 504ing one and deleting
// the other's registration.
func TestRelay_SameClientSameCounter_NoOverwrite(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)

	const counter = uint64(3333)
	k1 := pendingKey{counter: counter, clientAddr: "203.0.113.7:1", seq: rs.seq.Add(1)}
	k2 := pendingKey{counter: counter, clientAddr: "203.0.113.7:1", seq: rs.seq.Add(1)}
	ch1 := make(chan []byte, 1)
	ch2 := make(chan []byte, 1)
	rs.pendingMu.Lock()
	rs.pending[k1] = ch1
	rs.pending[k2] = ch2
	rs.pendingMu.Unlock()
	if len(rs.pending) != 2 {
		t.Fatalf("same-(counter,client) requests collapsed to %d entries; per-request seq should keep them distinct", len(rs.pending))
	}

	rs.dispatch(counter, []byte("ack"))
	for i, ch := range []chan []byte{ch1, ch2} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Errorf("waiter %d (same client+counter) was not served — map-overwrite regression", i)
		}
	}
}

// TestRelay_ShortDatagram_NoCrash fences the HIGH finding: a short/empty UDP
// datagram must be rejected by innerCounter (no header-slice panic) and must not
// crash recvLoop — otherwise a single bare datagram is a remote process DoS.
func TestRelay_ShortDatagram_NoCrash(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)

	for _, n := range []int{0, 1, 7, core.HeaderCommonSize - 1} {
		if _, err := rs.innerCounter(make([]byte, n)); err == nil {
			t.Errorf("innerCounter(%d bytes) = nil error, want rejection (no panic)", n)
		}
	}

	// Drive recvLoop with real short datagrams on the socket: an unrecovered
	// goroutine panic would crash the test binary, so reaching the end is the
	// assertion that recvLoop survived.
	sender, err := net.DialUDP("udp", nil, rs.udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial relay socket: %v", err)
	}
	defer func() { _ = sender.Close() }()
	_, _ = sender.Write([]byte{})        // 0-byte (n==0, err==nil)
	_, _ = sender.Write([]byte{1, 2, 3}) // 3-byte
	time.Sleep(50 * time.Millisecond)    // let recvLoop process them
}

func TestRelay_ShortBody_400(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader([]byte{1, 2, 3}))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a 3-byte body (must not panic/500)", w.Code)
	}
}

// TestRelay_StopUnparksHandler fences the Stop-ordering fix: a handler parked
// waiting for an ACK returns 503 promptly when Stop closes stopCh, instead of
// blocking graceful shutdown until the 5s response timeout.
func TestRelay_StopUnparksHandler(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	innerKnock := makeInnerKnock(t, serverPub, 5555)
	// Route to a port with nothing listening: forward's WriteToUDP succeeds, so
	// the handler parks on respCh (no reply ever comes).
	rs := newTestRelay(t, serverPub, 62299, SourceAddrModeRemoteAddr)

	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerKnock))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { rs.handleRelay(w, req); close(done) }()
	time.Sleep(50 * time.Millisecond) // let the handler park
	_ = rs.Stop(context.Background()) // closes stopCh first

	select {
	case <-done:
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503 on stopCh unpark", w.Code)
		}
	case <-time.After(2 * time.Second):
		t.Error("handler did not unpark on stopCh (would stall Shutdown to the 5s timeout)")
	}
}

func TestDeriveSourceAddr(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))

	t.Run("remoteaddr default ignores headers", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "198.51.100.9:5555"
		req.Header.Set("X-Real-IP", "203.0.113.7") // must be IGNORED in default mode
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "198.51.100.9" {
			t.Errorf("ip = %s, want the TCP peer 198.51.100.9 (header must be ignored)", got.IP)
		}
	})

	t.Run("trusted header used when enabled", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "127.0.0.1:5555" // the front door
		req.Header.Set("X-Real-IP", "203.0.113.7")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "203.0.113.7" {
			t.Errorf("ip = %s, want X-Real-IP 203.0.113.7", got.IP)
		}
		if got.Port <= 0 {
			t.Errorf("port = %d, want a non-zero placeholder (validateRelaySourceAddr requires >0)", got.Port)
		}
	})

	t.Run("trusted header falls back to peer when absent", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "198.51.100.9:5555"
		// no X-Real-IP header
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "198.51.100.9" {
			t.Errorf("ip = %s, want fallback to peer 198.51.100.9 when trusted header absent", got.IP)
		}
	})

	// #2622: behind the ALB (X-Forwarded-For append mode) the trusted header is
	// multi-entry. The RIGHTMOST entry is the AWS-attested client IP; entries to
	// its left are attacker-supplied. These fence that deriveSourceAddr takes the
	// rightmost entry only, and fails safe to RemoteAddr if it does not parse.
	t.Run("XFF multi-entry takes rightmost (AWS-attested)", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		rs.config.TrustedHeader = "X-Forwarded-For"
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "10.0.0.1:5555" // the ALB
		req.Header.Set("X-Forwarded-For", "192.0.2.50, 203.0.113.7")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "203.0.113.7" {
			t.Errorf("ip = %s, want rightmost XFF entry 203.0.113.7", got.IP)
		}
	})

	t.Run("XFF forged leftmost is ignored", func(t *testing.T) {
		// An attacker sets X-Forwarded-For before the ALB; the ALB appends the
		// real client IP on the right. The forged leftmost must NOT win.
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		rs.config.TrustedHeader = "X-Forwarded-For"
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "198.51.100.66, 203.0.113.7")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "203.0.113.7" {
			t.Errorf("ip = %s, want AWS-attested rightmost 203.0.113.7 (forged leftmost 198.51.100.66 must be ignored)", got.IP)
		}
	})

	t.Run("XFF unparseable rightmost falls back to peer (no walking left)", func(t *testing.T) {
		// If the rightmost (trusted) entry is garbage, fall back to RemoteAddr —
		// do NOT adopt the left-of-rightmost entry, which is attacker-supplied.
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		rs.config.TrustedHeader = "X-Forwarded-For"
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "198.51.100.9:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7, not-an-ip")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "198.51.100.9" {
			t.Errorf("ip = %s, want fallback to peer 198.51.100.9 (rightmost unparseable; must NOT walk left to 203.0.113.7)", got.IP)
		}
	})

	t.Run("XFF rightmost IPv6", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		rs.config.TrustedHeader = "X-Forwarded-For"
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "192.0.2.50, 2001:db8::1")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "2001:db8::1" {
			t.Errorf("ip = %s, want rightmost IPv6 2001:db8::1", got.IP)
		}
	})

	t.Run("XFF rightmost trims surrounding whitespace", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		rs.config.TrustedHeader = "X-Forwarded-For"
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "192.0.2.50 ,  203.0.113.7  ")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "203.0.113.7" {
			t.Errorf("ip = %s, want trimmed rightmost 203.0.113.7", got.IP)
		}
	})

	t.Run("XFF trailing comma (empty rightmost) falls back to peer", func(t *testing.T) {
		// A trailing comma yields an empty rightmost entry; it must fall back to
		// RemoteAddr, NOT walk left to the preceding entry.
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		rs.config.TrustedHeader = "X-Forwarded-For"
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "198.51.100.9:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7,")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "198.51.100.9" {
			t.Errorf("ip = %s, want fallback to peer 198.51.100.9 (empty rightmost; must NOT walk left to 203.0.113.7)", got.IP)
		}
	})

	t.Run("XFF whitespace-only rightmost falls back to peer", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		rs.config.TrustedHeader = "X-Forwarded-For"
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "198.51.100.9:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7,   ")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "198.51.100.9" {
			t.Errorf("ip = %s, want fallback to peer 198.51.100.9 (whitespace-only rightmost; must NOT walk left)", got.IP)
		}
	})

	t.Run("XFF multiple header lines: global rightmost across all lines wins", func(t *testing.T) {
		// A client can send several X-Forwarded-For header LINES. The ALB appends
		// the attested IP last; deriveSourceAddr joins ALL lines so it's the global
		// rightmost. A bare r.Header.Get would read only the first (attacker) line
		// and return 9.9.9.9 — this fences that we join instead.
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader)
		rs.config.TrustedHeader = "X-Forwarded-For"
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Add("X-Forwarded-For", "9.9.9.9")              // attacker's first line
		req.Header.Add("X-Forwarded-For", "8.8.8.8, 203.0.113.7") // ALB-appended attested last
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "203.0.113.7" {
			t.Errorf("ip = %s, want global rightmost 203.0.113.7 across all XFF lines (attacker first line 9.9.9.9 must NOT win)", got.IP)
		}
	})
}
