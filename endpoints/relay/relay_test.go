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
		ConnData:   &core.ConnectionData{Device: serverDev, RemoteAddr: srcAddr, InitTime: time.Now().UnixNano()},
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

// TestRelay_RoundTrip drives the full path: HTTPS POST -> NHP_RLY to the (fake)
// cell server on the shared socket -> a REAL NHP_ACK, counter-correlated,
// returned to the HTTP response.
func TestRelay_RoundTrip(t *testing.T) {
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
	defer func() { _ = fakeServer.Close() }()

	const counter = uint64(7777)
	innerKnock := makeInnerKnock(t, serverPub, counter)
	realAck := makeRealAck(t, serverDev, innerKnock, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444})

	// Fake server: read the NHP_RLY, reply with the real NHP_ACK to the relay's
	// source addr (the server replies to the packet's source).
	go func() {
		buf := make([]byte, 65536)
		_, from, rerr := fakeServer.ReadFromUDP(buf)
		if rerr != nil {
			return
		}
		_, _ = fakeServer.WriteToUDP(realAck, from)
	}()

	rs := newTestRelay(t, serverPub, fakeServer.LocalAddr().(*net.UDPAddr).Port, SourceAddrModeRemoteAddr)
	rs.cors = newCORSAllowlist(testKnockOrigin) // fence CORS on the production 200 path too

	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerKnock))
	req.RemoteAddr = "203.0.113.7:44444"
	req.Header.Set("Origin", testKnockOrigin)
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)

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
