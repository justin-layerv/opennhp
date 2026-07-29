package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
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

func relayPendingCount(rs *RelayServer) int {
	rs.pendingMu.Lock()
	defer rs.pendingMu.Unlock()
	return len(rs.pending)
}

func waitForRelayCondition(t *testing.T, timeout time.Duration, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition %q not met within %s", what, timeout)
}

func writeTestTLSCert(t *testing.T) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test TLS key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate test TLS serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create test TLS cert: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(priv)

	dir := t.TempDir()
	certFile = dir + "/tls.crt"
	keyFile = dir + "/tls.key"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("write test TLS cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write test TLS key: %v", err)
	}

	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test TLS cert to root pool")
	}
	return certFile, keyFile, roots
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
	return makeInnerAgentPacket(t, serverPub, core.NHP_KNK, counter, &common.AgentKnockMsg{
		HeaderType: core.NHP_KNK, UserId: "u", AuthServiceId: "asp", ResourceId: "res",
	})
}

func makeInnerAgentPacket(t *testing.T, serverPub []byte, headerType int, counter uint64, msg any) []byte {
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
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal knock: %v", err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      conn,
		PeerPk:        serverPub,
		HeaderType:    headerType,
		TransactionId: counter,
		Message:       body,
	})
	return drainSenderContent(t, conn, "inner knock")
}

// drainSenderContent pulls the freshly-encrypted packet off conn's SendQueue and
// returns a copy of its bytes. As the queue's manual consumer it releases the
// sender-owned pool packet before returning. label names the emitter for the
// failure messages.
func drainSenderContent(t *testing.T, conn *core.ConnectionData, label string) []byte {
	t.Helper()
	select {
	case pkt := <-conn.SendQueue:
		if pkt == nil {
			t.Fatalf("%s queue returned nil packet", label)
		}
		defer conn.Device.ReleasePoolPacket(pkt)
		return append([]byte(nil), pkt.Content...)
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout producing %s", label)
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
	rs.closeSockets()
	rs.handlerStartMu.Lock()
	rs.handlerStartMu.Unlock()
	rs.wg.Wait()
	rs.device.Stop()
	rs.metrics.Stop() // New() boots the publisher; reap its flush goroutine (nil-safe), mirroring Stop()
}

type testRelayOption func(*RelayServer)

func withTestRelayTrustedHeader(header string) testRelayOption {
	return func(rs *RelayServer) {
		rs.config.TrustedHeader = header
	}
}

func withTestRelayXForwardedFor() testRelayOption {
	return withTestRelayTrustedHeader("X-Forwarded-For")
}

func withTestRelayResponseTimeout(timeout time.Duration) testRelayOption {
	return func(rs *RelayServer) {
		rs.responseTimeout = timeout
	}
}

func withTestProofRequestLogger(logger func(string)) testRelayOption {
	return func(rs *RelayServer) {
		rs.proofRequestLogger = logger
	}
}

func newTestRelay(t *testing.T, serverPub []byte, serverPort int, mode SourceAddrMode, opts ...testRelayOption) *RelayServer {
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
	for _, opt := range opts {
		opt(rs)
	}
	rs.startBackground()
	t.Cleanup(func() { testStop(rs) })
	return rs
}

func TestProofRequestLoggingIsBoundedAndEnvironmentGated(t *testing.T) {
	t.Setenv("NHP_ENVIRONMENT", proofLoggingEnvironment)
	serverPub := keyBytes(0x40)
	var messages []string
	rs := newTestRelay(
		t,
		serverPub,
		62206,
		SourceAddrModeRemoteAddr,
		withTestProofRequestLogger(func(message string) {
			messages = append(messages, message)
		}),
	)
	if !rs.proofRequestLoggingEnabled {
		t.Fatal("proof request logging disabled in sandbox")
	}

	attackerPath := "/relay/" + strings.Repeat("attacker-controlled-", 1024)
	req := httptest.NewRequest(http.MethodPost, attackerPath, nil)
	req.RemoteAddr = "203.0.113.9:4444"
	rec := httptest.NewRecorder()
	rs.handleRelay(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST unknown route status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if len(messages) != 1 {
		t.Fatalf("proof log count = %d, want 1", len(messages))
	}
	const want = "relay: proof request route=relay source_ip=203.0.113.9"
	if messages[0] != want {
		t.Fatalf("proof log = %q, want %q", messages[0], want)
	}
	if strings.Contains(messages[0], "attacker-controlled") {
		t.Fatalf("proof log contains attacker-controlled path: %q", messages[0])
	}

	serverID := utils.PubKeyFingerprint(serverPub)
	rs.servers[serverID].name = "cell0"
	innerReply := makeInnerKnock(t, serverPub, 2442)
	packet := &core.Packet{Content: innerReply}
	_, payloadSize := packet.HeaderTypeAndSize()
	packet.Header().SetTypeAndPayloadSize(core.NHP_LRT, payloadSize)
	correlation := "nhp-123-1-qurl_go-post_removal-0123456789abcdef0123456789abcdef:relay:cell0:NHP_LRT"
	req = httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerReply))
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set(proofCorrelationHeader, correlation)
	rec = httptest.NewRecorder()
	rs.handleRelay(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST unsupported proof type status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if len(messages) != 3 {
		t.Fatalf("proof log count = %d, want request + rejection logs", len(messages))
	}
	correlationSHA256 := sha256.Sum256([]byte(correlation))
	wantRejection := fmt.Sprintf(
		"relay: proof rejection route=relay source_ip=203.0.113.9 cell_id=cell0 server_id=%s message_type=NHP_LRT correlation_id_sha256=%x outcome=unsupported_type_rejected before_waiter=true before_forward=true before_server_dispatch=true",
		serverID,
		correlationSHA256,
	)
	if messages[2] != wantRejection {
		t.Fatalf("proof rejection log = %q, want %q", messages[2], wantRejection)
	}
	if pending := relayPendingCount(rs); pending != 0 {
		t.Fatalf("pending request count after rejection = %d, want 0", pending)
	}

	rs.proofRequestLoggingEnabled = false
	req = httptest.NewRequest(http.MethodPost, "/relay/another-unknown-route", nil)
	req.RemoteAddr = "203.0.113.10:5555"
	rs.handleRelay(httptest.NewRecorder(), req)
	if len(messages) != 3 {
		t.Fatalf("disabled proof log count = %d, want unchanged 3", len(messages))
	}
}

func TestProofRequestLoggingIsDisabledOutsideSandbox(t *testing.T) {
	t.Setenv("NHP_ENVIRONMENT", "prod")
	serverPub := keyBytes(0x40)
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	if rs.proofRequestLoggingEnabled {
		t.Fatal("proof request logging enabled outside sandbox")
	}
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
	return drainSenderContent(t, conn, "overload cookie")
}

func makeRelayReturnPacket(t *testing.T, serverDev *core.Device, outerPpd *core.PacketParserData, requestID string, inner []byte) []byte {
	t.Helper()
	body, err := json.Marshal(&common.RelayReturnMsg{
		RequestID:   requestID,
		InnerPacket: base64.StdEncoding.EncodeToString(inner),
	})
	if err != nil {
		t.Fatal(err)
	}
	encCh := make(chan *core.MsgAssemblerData, 1)
	md := &core.MsgData{
		HeaderType:     core.NHP_ACK,
		Compress:       false,
		Message:        body,
		PrevParserData: outerPpd,
		ExternalPacket: core.NewRelayPacket(),
		EncryptedPktCh: encCh,
	}
	serverDev.SendMsgToPacket(md)
	select {
	case mad := <-encCh:
		if mad.Error != nil {
			t.Fatalf("encrypt relay return: %v", mad.Error)
		}
		packet := append([]byte(nil), mad.BasePacket.Content...)
		mad.Destroy()
		return packet
	case <-time.After(5 * time.Second):
		t.Fatal("timeout encrypting relay return")
		return nil
	}
}

func makeMaxInnerListRequest(t *testing.T, serverPub []byte, counter uint64) []byte {
	t.Helper()
	targetBody := core.PacketBufferSize - core.NewRelayPacket().MinimalLength() - core.GCMTagSize
	msg := &common.AgentListMsg{
		UserId: "u", DeviceId: "d", AuthServiceId: "asp",
		UserData: map[string]any{"pad": ""},
	}
	empty, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	msg.UserData["pad"] = strings.Repeat("x", targetBody-len(empty))
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != targetBody {
		t.Fatalf("max inner request body = %d, want %d", len(body), targetBody)
	}
	packet := makeInnerAgentPacket(t, serverPub, core.NHP_LST, counter, msg)
	if len(packet) != core.PacketBufferSize {
		t.Fatalf("max inner request = %d bytes, want %d", len(packet), core.PacketBufferSize)
	}
	return packet
}

func makeMaxInnerListResult(t *testing.T, serverDev *core.Device, innerRequest []byte, srcAddr *net.UDPAddr) []byte {
	t.Helper()
	innerPpd, err := serverDev.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: innerRequest},
		ConnData:   &core.ConnectionData{Device: serverDev, RemoteAddr: srcAddr},
		InitTime:   time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("server decrypt max inner request: %v", err)
	}
	targetBody := core.PacketBufferSize - core.NewRelayPacket().MinimalLength() - core.GCMTagSize
	msg := &common.ServerListResultMsg{ErrCode: common.ErrSuccess.ErrorCode(), ListResults: map[string]any{"pad": ""}}
	empty, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	msg.ListResults["pad"] = strings.Repeat("x", targetBody-len(empty))
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != targetBody {
		t.Fatalf("max inner response body = %d, want %d", len(body), targetBody)
	}
	encCh := make(chan *core.MsgAssemblerData, 1)
	serverDev.SendMsgToPacket(&core.MsgData{
		HeaderType:     core.NHP_LRT,
		TransactionId:  innerPpd.SenderTrxId,
		Compress:       false,
		PrevParserData: innerPpd,
		Message:        body,
		EncryptedPktCh: encCh,
	})
	select {
	case mad := <-encCh:
		if mad.Error != nil {
			t.Fatalf("server encrypt max inner response: %v", mad.Error)
		}
		packet := append([]byte(nil), mad.BasePacket.Content...)
		mad.Destroy()
		if len(packet) != core.PacketBufferSize {
			t.Fatalf("max inner response = %d bytes, want %d", len(packet), core.PacketBufferSize)
		}
		return packet
	case <-time.After(5 * time.Second):
		t.Fatal("timeout producing max inner response")
		return nil
	}
}

func TestRelayEnvelopeMaximumSchemaMath(t *testing.T) {
	inner := make([]byte, core.PacketBufferSize)
	requestID := base64.RawURLEncoding.EncodeToString(make([]byte, common.RelayRequestIDBytes))
	forward, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr: &common.NetAddress{
			Ip:   "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			Port: 65535,
		},
		InnerPacket: base64.StdEncoding.EncodeToString(inner),
		RequestID:   requestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	returned, err := json.Marshal(&common.RelayReturnMsg{
		RequestID: requestID, InnerPacket: base64.StdEncoding.EncodeToString(inner),
	})
	if err != nil {
		t.Fatal(err)
	}
	headerAndTag := core.NewRelayPacket().MinimalLength() + core.GCMTagSize
	if got := len(forward); got != 5588 {
		t.Fatalf("maximum RelayForwardMsg JSON = %d bytes, want 5588", got)
	}
	if got := len(returned); got != 5516 {
		t.Fatalf("maximum RelayReturnMsg JSON = %d bytes, want 5516", got)
	}
	if got := headerAndTag + len(forward); got != 5844 || got > core.RelayPacketBufferSize {
		t.Fatalf("maximum forward envelope = %d bytes, want 5844 within %d", got, core.RelayPacketBufferSize)
	}
	if got := headerAndTag + len(returned); got != 5772 || got > core.RelayPacketBufferSize {
		t.Fatalf("maximum return envelope = %d bytes, want 5772 within %d", got, core.RelayPacketBufferSize)
	}
}

// driveRelayRoundTrip exercises the relay's full forward path for one
// server->agent reply type: it POSTs a fresh inner knock to handleRelay while a
// one-shot fake cell server echoes back a real reply built from serverDev. It
// returns the relay, recorded HTTP response, and reply bytes so each test keeps
// only its reply-specific assertions.
func driveRelayRoundTrip(t *testing.T, counter uint64, makeReply func(*testing.T, *core.Device, []byte, *net.UDPAddr) []byte) (*RelayServer, *httptest.ResponseRecorder, []byte) {
	t.Helper()
	serverDev := core.NewDevice(core.NHP_SERVER, keyBytes(0x40), &core.DeviceOptions{DisableAgentPeerValidation: true, DisableRelayPeerValidation: true})
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
	// makeRealCookie temporarily overloads the fake server to mint the inner COK.
	// Clear it before the independent outer NHP_RLY decrypt below; production
	// servers accept the authenticated outer relay envelope before applying
	// overload handling to its inner KNK.
	serverDev.SetOverload(false)

	// Fake server: read the NHP_RLY, reply with the real NHP reply to the relay's
	// source addr (the server replies to the packet's source).
	go func() {
		buf := make([]byte, 65536)
		n, from, rerr := fakeServer.ReadFromUDP(buf)
		if rerr != nil {
			return
		}
		outerPpd, perr := serverDev.PacketToMsg(&core.PacketData{
			BasePacket: &core.Packet{Content: buf[:n]},
			ConnData:   &core.ConnectionData{Device: serverDev, RemoteAddr: from},
			InitTime:   time.Now().UnixNano(),
		})
		if perr != nil || outerPpd == nil {
			return
		}
		var forwarded common.RelayForwardMsg
		if json.Unmarshal(outerPpd.BodyMessage, &forwarded) != nil {
			return
		}
		wrapped := makeRelayReturnPacket(t, serverDev, outerPpd, forwarded.RequestID, reply)
		_, _ = fakeServer.WriteToUDP(wrapped, from)
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

// TestRelay_OverloadCookie_RoundTrip proves an overloaded cell server's NHP_COK
// is returned through the authenticated, request-ID-correlated envelope. The
// inner COK must still carry the original KNK counter for the agent's own
// COK->RKN protocol, but the relay never uses that collision-prone value to
// choose a waiter.
func TestRelay_OverloadCookie_RoundTrip(t *testing.T) {
	const counter = uint64(6611)
	_, w, realCookie := driveRelayRoundTrip(t, counter, makeRealCookie)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q — the overload COK was not dispatched back through the relay", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), realCookie) {
		t.Errorf("relayed NHP_COK bytes mismatch (got %d bytes, want %d)", w.Body.Len(), len(realCookie))
	}
	// Independently confirm the COK retains the inner KNK counter the agent needs
	// to construct its follow-up RKN. Relay dispatch itself uses RequestID.
	cokCounter := (&core.Packet{Content: realCookie}).Counter()
	if cokCounter != counter {
		t.Errorf("COK wire counter = %d, want inner KNK counter %d", cokCounter, counter)
	}
}

// TestRelay_RoundTrip drives the full path: HTTPS POST -> NHP_RLY to the (fake)
// cell server on the shared socket -> an authenticated, random-RequestID-
// correlated REAL NHP_ACK carrying the original agent counter -> HTTP response.
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

// TestRelay_TrustedHeaderForwardStampsAttestedRightmostXFF fences the #1210
// relay trust boundary end to end: in the post-cutover path, the server must see
// the relay-edge client IP in RelayForwardMsg.SourceAddr, not an attacker-supplied
// left XFF entry and not the ALB TCP peer. The deriveSourceAddr unit tests below
// fence parsing; this test proves the derived value survives relay encryption.
// Server-side acceptance is fenced by the TestValidateRelaySourceAddr and
// TestHandleRelayForward tests in the server package.
func TestRelay_TrustedHeaderForwardStampsAttestedRightmostXFF(t *testing.T) {
	const (
		counter        = uint64(1210)
		ackTimeout     = 5 * time.Second
		captureTimeout = ackTimeout + time.Second
	)

	serverDev := core.NewDevice(core.NHP_SERVER, keyBytes(0x40), &core.DeviceOptions{
		DisableAgentPeerValidation: true,
		DisableRelayPeerValidation: true,
	})
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

	expectedSource := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: placeholderSourcePort}
	innerKnock := makeInnerKnock(t, serverPub, counter)
	ackPeer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}
	// makeRealAck only needs a RemoteAddr for decrypt context; the assertion
	// below proves the relay independently derives expectedSource from XFF.
	reply := makeRealAck(t, serverDev, innerKnock, ackPeer)

	rlyCh := make(chan *common.RelayForwardMsg, 1)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 65536)
		n, from, rerr := fakeServer.ReadFromUDP(buf)
		if rerr != nil {
			errCh <- rerr
			return
		}

		ppd, perr := serverDev.PacketToMsg(&core.PacketData{
			BasePacket: &core.Packet{Content: buf[:n]},
			ConnData:   &core.ConnectionData{Device: serverDev, RemoteAddr: from},
			InitTime:   time.Now().UnixNano(),
		})
		if perr != nil {
			errCh <- fmt.Errorf("decrypt outer NHP_RLY: %w", perr)
			return
		}
		if ppd == nil {
			errCh <- fmt.Errorf("decrypt outer NHP_RLY returned nil")
			return
		}
		if ppd.HeaderType != core.NHP_RLY {
			errCh <- fmt.Errorf("outer header = %s, want NHP_RLY", core.HeaderTypeToString(ppd.HeaderType))
			return
		}
		var rlyMsg common.RelayForwardMsg
		if err := json.Unmarshal(ppd.BodyMessage, &rlyMsg); err != nil {
			errCh <- fmt.Errorf("unmarshal RelayForwardMsg: %w", err)
			return
		}
		rlyCh <- &rlyMsg

		wrapped := makeRelayReturnPacket(t, serverDev, ppd, rlyMsg.RequestID, reply)
		_, _ = fakeServer.WriteToUDP(wrapped, from)
	}()

	rs := newTestRelay(
		t,
		serverPub,
		fakeServer.LocalAddr().(*net.UDPAddr).Port,
		SourceAddrModeTrustedHeader,
		withTestRelayXForwardedFor(),
		withTestRelayResponseTimeout(ackTimeout),
	)

	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerKnock))
	req.RemoteAddr = "10.0.0.25:5555"                            // the private ALB hop, not the browser
	req.Header.Add("X-Forwarded-For", "198.51.100.66")           // attacker supplied
	req.Header.Add("X-Forwarded-For", "192.0.2.50, 203.0.113.7") // ALB appends the attested IP last
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)

	if w.Code != http.StatusOK {
		select {
		case err := <-errCh:
			t.Fatalf("fake server failed before relay response: %v", err)
		default:
		}
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}

	select {
	case err := <-errCh:
		t.Fatalf("fake server failed: %v", err)
	case got := <-rlyCh:
		if got.SourceAddr == nil {
			t.Fatal("RelayForwardMsg.SourceAddr = nil")
		}
		if got.SourceAddr.Ip != expectedSource.IP.String() {
			t.Fatalf("RelayForwardMsg.SourceAddr.Ip = %q, want %q (rightmost ALB-attested XFF; forged left entries and ALB RemoteAddr must not win)",
				got.SourceAddr.Ip, expectedSource.IP.String())
		}
		if got.SourceAddr.Port != expectedSource.Port {
			t.Fatalf("RelayForwardMsg.SourceAddr.Port = %d, want placeholder %d", got.SourceAddr.Port, expectedSource.Port)
		}
		gotInner, err := base64.StdEncoding.DecodeString(got.InnerPacket)
		if err != nil {
			t.Fatalf("RelayForwardMsg.InnerPacket is not valid base64: %v", err)
		}
		if !bytes.Equal(gotInner, innerKnock) {
			t.Fatal("RelayForwardMsg.InnerPacket changed while forwarding")
		}
	case <-time.After(captureTimeout):
		t.Fatal("fake server did not capture the RelayForwardMsg")
	}
}

// TestRelay_DispatchTargetsExactRequestIDAndServer fences that colliding agent
// counters or a return from the wrong configured server cannot cross-deliver.
func TestRelay_DispatchTargetsExactRequestIDAndServer(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	// newTestRelay starts a real publisher; stop it before installing the
	// inspectable test publisher so its flush goroutine is not orphaned.
	rs.metrics.Stop()
	rs.metrics = metrics.NewPublisherForTest(t)

	id1 := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, common.RelayRequestIDBytes))
	id2 := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, common.RelayRequestIDBytes))
	ch1 := make(chan []byte, 1)
	ch2 := make(chan []byte, 1)
	serverID := utils.PubKeyFingerprint(serverPub)
	rs.pendingMu.Lock()
	rs.pending[id1] = relayPendingEntry{serverID: serverID, reply: ch1}
	rs.pending[id2] = relayPendingEntry{serverID: serverID, reply: ch2}
	rs.pendingMu.Unlock()

	rs.dispatch(id1, "different-configured-cell", []byte("wrong-cell"))
	select {
	case <-ch1:
		t.Fatal("request accepted a return from the wrong cell")
	default:
	}
	counters, _ := rs.metrics.CountersForTest(t)
	if got := counters[MetricRelayReturnServerMismatch]; got != 1 {
		t.Fatalf("%s counter = %v, want 1", MetricRelayReturnServerMismatch, got)
	}

	rs.dispatch(id1, serverID, []byte("ack-bytes"))

	select {
	case <-ch1:
	case <-time.After(time.Second):
		t.Fatal("matching request-ID waiter did not receive reply")
	}
	select {
	case <-ch2:
		t.Fatal("reply crossed into a different request ID")
	default:
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

	pendingBefore := relayPendingCount(rs)
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
	pendingAfter := relayPendingCount(rs)
	if pendingAfter != pendingBefore {
		t.Errorf("pending grew from %d to %d on a shed request; the cap must shed BEFORE registering a waiter", pendingBefore, pendingAfter)
	}
}

// TestRelay_Shed_IncrementsMetric fences the #2649 shed counter: a backpressure
// 503 must bump the RelayShed metric — the graphable/alertable signal the relay
// alarm (terraform/modules/relay/monitoring.tf) keys on. Asserts BOTH published
// series: the base counter (clean [Environment] dims, what the alarm matches) and
// the per-cell breakdown carrying the target Cell. Replaces rs.metrics with an
// in-memory test publisher so the increment is inspectable via CountersForTest
// without a real CloudWatch client.
func TestRelay_Shed_IncrementsMetric(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	innerKnock := makeInnerKnock(t, serverPub, 4242)
	// Dead port so the handler would PARK absent shedding — makes "did it shed?"
	// unambiguous (same setup as TestRelay_InFlightCap_Sheds).
	rs := newTestRelay(t, serverPub, 62299, SourceAddrModeRemoteAddr)

	// Swap in an inspectable in-memory publisher (no CloudWatch client / flush
	// goroutine). newTestRelay's New() already booted a real publisher; Stop it
	// first so we don't leak its flush goroutine, then install the test one.
	rs.metrics.Stop()
	rs.metrics = metrics.NewPublisherForTest(t)

	serverID := utils.PubKeyFingerprint(serverPub)
	srv := rs.servers[serverID]

	// Saturate the cell's in-flight semaphore so the next POST is shed.
	for i := 0; i < maxInFlightPerServer; i++ {
		srv.inFlight <- struct{}{}
	}

	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerKnock))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (precondition: the request must be shed)", w.Code)
	}

	counters, dimCounters := rs.metrics.CountersForTest(t)
	if got := counters[MetricRelayShed]; got != 1 {
		t.Errorf("base %s counter = %v, want 1 (one shed → one increment)", MetricRelayShed, got)
	}
	// The per-cell breakdown is keyed by "<metric>\x00Cell=<cell name>" (see
	// buildDimCounterKey). srv.name is the routing table's cell name ("test-cell").
	perCellKey := MetricRelayShed + "\x00Cell=" + srv.name
	if got := dimCounters[perCellKey]; got != 1 {
		t.Errorf("per-cell %s counter (key %q) = %v, want 1; got dimCounters=%v", MetricRelayShed, perCellKey, got, dimCounters)
	}
}

// TestRelay_InFlightSlotReleased fences that a slot is returned after the handler
// completes: a request that runs to its (timeout) completion must free its
// in-flight slot so the cap is not permanently consumed by transient load.
func TestRelay_InFlightSlotReleased(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	innerKnock := makeInnerKnock(t, serverPub, 4243)
	rs := newTestRelay(
		t,
		serverPub,
		62299,
		SourceAddrModeRemoteAddr,
		withTestRelayResponseTimeout(50*time.Millisecond),
	) // dead port -> 504
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
		name         string
		mode         SourceAddrMode
		listenAddr   string
		enableTLS    bool
		trustedProxy bool
		wantErr      bool
	}{
		// Dangerous combos — must fail closed.
		{"trusted_header + TLS terminate without trusted_proxy is rejected", SourceAddrModeTrustedHeader, ":8080", true, false, true},
		{"trusted_header + trusted_proxy + public IPv4 bind is rejected", SourceAddrModeTrustedHeader, "203.0.113.7:8080", true, true, true},
		{"trusted_header + trusted_proxy + public IPv4 bind without TLS is rejected", SourceAddrModeTrustedHeader, "203.0.113.7:8080", false, true, true},
		{"trusted_header + public IPv4 bind is rejected", SourceAddrModeTrustedHeader, "203.0.113.7:8080", false, false, true},
		{"trusted_header + public IPv6 bind is rejected", SourceAddrModeTrustedHeader, "[2001:db8::1]:8080", false, false, true},
		// Conservative fail-closed: not IsPrivate/IsLoopback/IsUnspecified, so
		// treated as public and rejected. Locks the posture against accidental
		// broadening of the allowlist (see assertTrustedHeaderBindCoherent doc).
		{"trusted_header + IPv4 link-local bind is rejected", SourceAddrModeTrustedHeader, "169.254.1.1:8080", false, false, true},
		{"trusted_header + CGNAT bind is rejected", SourceAddrModeTrustedHeader, "100.64.0.1:8080", false, false, true},
		{"trusted_header + IPv6 link-local bind is rejected", SourceAddrModeTrustedHeader, "[fe80::1]:8080", false, false, true},
		// Coherent combos — must start.
		{"trusted_header + trusted_proxy + TLS re-encrypt is allowed", SourceAddrModeTrustedHeader, ":8080", true, true, false},
		{"trusted_header + trusted_proxy without TLS is allowed (inert opt-in)", SourceAddrModeTrustedHeader, ":8080", false, true, false},
		{"trusted_header + unspecified host (prod :8080) is allowed", SourceAddrModeTrustedHeader, ":8080", false, false, false},
		{"trusted_header + 0.0.0.0 bind is allowed", SourceAddrModeTrustedHeader, "0.0.0.0:8080", false, false, false},
		{"trusted_header + loopback bind is allowed", SourceAddrModeTrustedHeader, "127.0.0.1:8080", false, false, false},
		{"trusted_header + private bind is allowed", SourceAddrModeTrustedHeader, "10.0.0.5:8080", false, false, false},
		{"trusted_header + hostname bind is allowed (not classifiable)", SourceAddrModeTrustedHeader, "relay.internal:8080", false, false, false},
		// RemoteAddr mode is spoof-proof regardless of bind/TLS — never gated.
		{"remoteaddr + public bind + TLS is allowed", SourceAddrModeRemoteAddr, "203.0.113.7:8080", true, false, false},
		{"remoteaddr + trusted_proxy is allowed (inert opt-in)", SourceAddrModeRemoteAddr, ":8080", false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			cfg.SourceAddrMode = tc.mode
			cfg.ListenAddr = tc.listenAddr
			cfg.EnableTLS = tc.enableTLS
			if tc.enableTLS {
				cfg.TLSCertFile = "/tmp/relay.crt"
				cfg.TLSKeyFile = "/tmp/relay.key"
			}
			cfg.TrustedProxy = tc.trustedProxy
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

func TestNew_RejectsDuplicateServerFingerprint(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	pubKey := base64.StdEncoding.EncodeToString(serverPub)
	cfg := &Config{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(keyBytes(0x80)),
		UDPListenAddr:    "127.0.0.1:0",
		Servers: []ServerConfig{
			{Name: "cell-a", PubKeyBase64: pubKey, Host: "127.0.0.1", Port: 62206},
			{Name: "cell-b", PubKeyBase64: pubKey, Host: "127.0.0.2", Port: 62206},
		},
	}

	rs, err := New(cfg)
	if rs != nil {
		_ = rs.udpConn.Close()
		t.Fatal("New returned a relay after duplicate server fingerprint")
	}
	if err == nil || !strings.Contains(err.Error(), "duplicates public key fingerprint") {
		t.Fatalf("New error = %v, want duplicate fingerprint rejection", err)
	}
}

func TestNew_EnableTLSRequiresCertKeyPaths(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	base := func() *Config {
		return &Config{
			PrivateKeyBase64: base64.StdEncoding.EncodeToString(keyBytes(0x80)),
			ListenAddr:       ":8080",
			UDPListenAddr:    "127.0.0.1:0",
			EnableTLS:        true,
			TLSCertFile:      "/tmp/relay.crt",
			TLSKeyFile:       "/tmp/relay.key",
			Servers:          []ServerConfig{{Name: "c", PubKeyBase64: base64.StdEncoding.EncodeToString(serverPub), Host: "127.0.0.1", Port: 62206}},
		}
	}
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"missing cert path", func(cfg *Config) { cfg.TLSCertFile = "" }},
		{"blank cert path", func(cfg *Config) { cfg.TLSCertFile = " \t" }},
		{"missing key path", func(cfg *Config) { cfg.TLSKeyFile = "" }},
		{"blank key path", func(cfg *Config) { cfg.TLSKeyFile = " \t" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.edit(cfg)
			rs, err := New(cfg)
			if rs != nil {
				_ = rs.udpConn.Close()
			}
			if err == nil {
				t.Fatalf("New accepted enable_tls=true without complete cert/key paths")
			}
			if !strings.Contains(err.Error(), "enable_tls=true requires non-empty tls_cert_file and tls_key_file") {
				t.Fatalf("New error = %v, want cert/key path validation", err)
			}
		})
	}

	t.Run("trims surrounding whitespace before serving", func(t *testing.T) {
		cfg := base()
		cfg.TLSCertFile = " /tmp/relay.crt \t"
		cfg.TLSKeyFile = "\t/tmp/relay.key "
		origCertFile := cfg.TLSCertFile
		origKeyFile := cfg.TLSKeyFile
		rs, err := New(cfg)
		if rs != nil {
			_ = rs.udpConn.Close()
		}
		if err != nil {
			t.Fatalf("New rejected cert/key paths with surrounding whitespace: %v", err)
		}
		if cfg.TLSCertFile != origCertFile || cfg.TLSKeyFile != origKeyFile {
			t.Fatalf("New mutated caller config: cert=%q key=%q", cfg.TLSCertFile, cfg.TLSKeyFile)
		}
		if rs.config.TLSCertFile != "/tmp/relay.crt" || rs.config.TLSKeyFile != "/tmp/relay.key" {
			t.Fatalf("served TLS paths were not trimmed: cert=%q key=%q", rs.config.TLSCertFile, rs.config.TLSKeyFile)
		}
	})
}

func TestRelay_StartServesHealthLiveOverTLS(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	certFile, keyFile, roots := writeTestTLSCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TLS listen addr: %v", err)
	}
	listenAddr := ln.Addr().String()
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release TLS listen addr: %v", err)
	}

	cfg := &Config{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(keyBytes(0x80)),
		ListenAddr:       listenAddr,
		UDPListenAddr:    "127.0.0.1:0",
		EnableTLS:        true,
		TLSCertFile:      certFile,
		TLSKeyFile:       keyFile,
		Servers:          []ServerConfig{{Name: "c", PubKeyBase64: base64.StdEncoding.EncodeToString(serverPub), Host: "127.0.0.1", Port: 62206}},
	}
	rs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- rs.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := rs.Stop(ctx); err != nil {
			t.Errorf("Stop: %v", err)
		}
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("Start returned error after Stop: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("timeout waiting for Start to exit")
		}
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    roots,
				ServerName: "localhost",
			},
		},
		Timeout: time.Second,
	}
	url := "https://localhost:" + strconv.Itoa(port) + "/health/live"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("Start returned before TLS health probe succeeded: %v", err)
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			t.Fatalf("GET %s status = %d, want 200", url, resp.StatusCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for TLS health probe at %s", url)
}

func TestRelay_StartReturnsMissingTLSFileError(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	missingDir := t.TempDir()
	cfg := &Config{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(keyBytes(0x80)),
		ListenAddr:       "127.0.0.1:0",
		UDPListenAddr:    "127.0.0.1:0",
		EnableTLS:        true,
		TLSCertFile:      filepath.Join(missingDir, "missing.crt"),
		TLSKeyFile:       filepath.Join(missingDir, "missing.key"),
		Servers:          []ServerConfig{{Name: "c", PubKeyBase64: base64.StdEncoding.EncodeToString(serverPub), Host: "127.0.0.1", Port: 62206}},
	}
	rs, err := New(cfg)
	if err != nil {
		t.Fatalf("New rejected non-empty TLS paths before Start could validate files: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := rs.Stop(ctx); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})

	err = rs.Start()
	if err == nil {
		t.Fatal("Start succeeded with missing TLS files")
	}
	if !strings.Contains(err.Error(), "missing.crt") {
		t.Fatalf("Start error = %v, want missing cert file path", err)
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
	rs := newTestRelay(
		t,
		serverPub,
		62299,
		SourceAddrModeRemoteAddr,
		withTestRelayResponseTimeout(80*time.Millisecond),
	) // nothing listening -> no ACK; keep the test fast

	req := httptest.NewRequest(http.MethodPost, "/relay/"+utils.PubKeyFingerprint(serverPub), bytes.NewReader(innerKnock))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504 when no ACK arrives", w.Code)
	}
	pendingCount := relayPendingCount(rs)
	if pendingCount != 0 {
		t.Errorf("pending request IDs after timeout = %d, want 0", pendingCount)
	}
}

// Keep the production response window longer than the encryption hand-off
// timeout so a stalled encryption fails before the HTTP waiter times out.
func TestRelay_TimeoutOrdering(t *testing.T) {
	if encryptTimeout >= relayResponseTimeout {
		t.Fatalf("encryptTimeout %s must be shorter than relayResponseTimeout %s", encryptTimeout, relayResponseTimeout)
	}
}

func TestRelay_HTTPSAgentTypeAdmission(t *testing.T) {
	tests := []struct {
		name       string
		headerType int
		allowed    bool
	}{
		{"knock", core.NHP_KNK, true},
		{"reknock", core.NHP_RKN, true},
		{"exit", core.NHP_EXT, true},
		{"otp", core.NHP_OTP, true},
		{"register", core.NHP_REG, true},
		{"list", core.NHP_LST, true},
		{"DHP knock", core.DHP_KNK, false},
		{"ack reply", core.NHP_ACK, false},
		{"cookie reply", core.NHP_COK, false},
		{"reknock ack reply", core.NHP_RAK, false},
		{"list reply", core.NHP_LRT, false},
		{"relay envelope", core.NHP_RLY, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpsAgentTypeAllowed(tc.headerType); got != tc.allowed {
				t.Errorf("HTTPS admission = %v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestRelay_DeviceAllowlistEqualsHTTPSRequestsAndRelayReturns(t *testing.T) {
	relayDevice := core.NewDevice(core.NHP_RELAY, keyBytes(0x91), nil)
	if relayDevice == nil {
		t.Fatal("create relay device")
	}

	for headerType := core.NHP_KPL; core.HeaderTypeToString(headerType) != "UNKNOWN"; headerType++ {
		requestAllowed := httpsAgentTypeAllowed(headerType)
		returnAllowed := relayReturnTypeAllowed(headerType)
		if requestAllowed && returnAllowed {
			t.Errorf("relay inner type %s is admitted as both request and return", core.HeaderTypeToString(headerType))
		}
		want := requestAllowed || returnAllowed
		if got := relayDevice.CheckRecvHeaderType(headerType); got != want {
			t.Errorf(
				"NHP_RELAY device admission for %s = %v, want HTTPS-request-or-return admission %v",
				core.HeaderTypeToString(headerType), got, want,
			)
		}
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

func TestRelay_HTTPSRejectsServerReplyAtEdge(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	innerKnock := makeInnerKnock(t, serverPub, 88_881)
	innerAck := append([]byte(nil), innerKnock...)
	pkt := &core.Packet{Content: innerAck}
	_, payloadSize := pkt.HeaderTypeAndSize()
	pkt.Header().SetTypeAndPayloadSize(core.NHP_ACK, payloadSize)
	rs := newTestRelay(t, serverPub, 62299, SourceAddrModeRemoteAddr)
	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerAck))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for server-reply inner type", w.Code)
	}
}

func TestRelay_RandomRequestIDsDoNotOverwrite(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)

	ch1 := make(chan []byte, 1)
	ch2 := make(chan []byte, 1)
	serverID := utils.PubKeyFingerprint(serverPub)
	k1, err := rs.reservePending(serverID, ch1)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.releasePending(k1)
	k2, err := rs.reservePending(serverID, ch2)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.releasePending(k2)

	pendingCount := relayPendingCount(rs)
	if pendingCount != 2 {
		t.Fatalf("distinct random request IDs collapsed to %d pending entries", pendingCount)
	}

	rs.dispatch(k1, serverID, []byte("ack"))
	select {
	case <-ch1:
	case <-time.After(time.Second):
		t.Fatal("first random request ID was not served")
	}
	select {
	case <-ch2:
		t.Fatal("first reply crossed to second random request ID")
	default:
	}
}

// TestRelay_ShortDatagram_NoCrash proves short private-socket datagrams are
// rejected before decryption and short inner packets cannot panic innerType.
func TestRelay_ShortDatagram_NoCrash(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)

	for _, n := range []int{0, core.HeaderCommonSize, core.RelayPacketMinimalLength - 1} {
		if _, _, _, err := rs.decodeRelayReturn(make([]byte, n), &net.UDPAddr{}); err == nil {
			t.Errorf("decodeRelayReturn(%d bytes) = nil error, want undersized relay-envelope rejection", n)
		}
	}

	for _, n := range []int{0, 1, 7, core.HeaderCommonSize - 1} {
		if _, err := rs.innerType(make([]byte, n)); err == nil {
			t.Errorf("innerType(%d bytes) = nil error, want rejection (no panic)", n)
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

func TestRelay_LateEncryptReaperIsTracked(t *testing.T) {
	rs := &RelayServer{}
	encCh := make(chan *core.MsgAssemblerData, 1)
	rs.reapLateEncryptedPacket(encCh)
	done := make(chan struct{})
	go func() {
		rs.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("shutdown barrier returned before the late encrypt result was reaped")
	case <-time.After(20 * time.Millisecond):
	}
	encCh <- nil
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown barrier did not observe the completed encrypt reaper")
	}
}

func TestRelay_ConsumeEncryptedPacketDestroysErrorResult(t *testing.T) {
	device := core.NewDevice(core.NHP_RELAY, keyBytes(0x80), nil)
	device.Start()
	t.Cleanup(device.Stop)
	encCh := make(chan *core.MsgAssemblerData, 1)
	device.SendMsgToPacket(&core.MsgData{
		HeaderType:     core.NHP_RLY,
		PeerPk:         []byte{1},
		Message:        []byte(`{}`),
		ExternalPacket: device.AllocateRelayPacket(),
		EncryptedPktCh: encCh,
	})
	var mad *core.MsgAssemblerData
	select {
	case mad = <-encCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for forced encryption error")
	}
	if mad == nil || mad.Error == nil {
		t.Fatalf("forced encryption result = %#v, want non-nil MAD error", mad)
	}
	if _, err := core.ConsumeEncryptedPacket(mad); err == nil {
		t.Fatal("ConsumeEncryptedPacket accepted a forced encryption error")
	}
	if mad.BasePacket.Content != nil {
		t.Fatal("error MAD retained its pooled relay packet after consumption")
	}
}

func TestRelay_ReturnRejectsDatagramAboveEnvelopeLimit(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	if _, _, _, err := rs.decodeRelayReturn(make([]byte, core.RelayPacketBufferSize+1), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}); err == nil {
		t.Fatal("private relay return accepted a 6145-byte datagram")
	}
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

func TestRelay_ExpiredShutdownRejectsHandlerThatHasNotRegistered(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62299, SourceAddrModeRemoteAddr)
	rs.cors = newCORSAllowlist(testKnockOrigin)
	rs.handlerStartMu.Lock()
	w := httptest.NewRecorder()
	handlerDone := make(chan struct{})
	go func() {
		req := httptest.NewRequest(http.MethodOptions, "/relay/x", nil)
		req.Header.Set("Origin", testKnockOrigin)
		rs.handleRelay(w, req)
		close(handlerDone)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopDone := make(chan struct{})
	go func() {
		_ = rs.Stop(ctx)
		close(stopDone)
	}()
	waitForRelayCondition(t, time.Second, "relay entered stopping state", func() bool {
		return !rs.running.Load()
	})
	rs.handlerStartMu.Unlock()

	select {
	case <-handlerDone:
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("late handler status = %d, want 503", w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != testKnockOrigin {
			t.Fatalf("late handler CORS origin = %q, want %q", got, testKnockOrigin)
		}
		if got := w.Header().Get("Vary"); got != "Origin" {
			t.Fatalf("late handler Vary = %q, want Origin", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late handler remained blocked after shutdown barrier release")
	}
	select {
	case <-stopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("expired-context Stop did not finish after rejecting the late handler")
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
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader, withTestRelayXForwardedFor())
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
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader, withTestRelayXForwardedFor())
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
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader, withTestRelayXForwardedFor())
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "198.51.100.9:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7, not-an-ip")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "198.51.100.9" {
			t.Errorf("ip = %s, want fallback to peer 198.51.100.9 (rightmost unparseable; must NOT walk left to 203.0.113.7)", got.IP)
		}
	})

	t.Run("XFF rightmost IPv6", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader, withTestRelayXForwardedFor())
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "192.0.2.50, 2001:db8::1")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "2001:db8::1" {
			t.Errorf("ip = %s, want rightmost IPv6 2001:db8::1", got.IP)
		}
	})

	t.Run("XFF rightmost trims surrounding whitespace", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader, withTestRelayXForwardedFor())
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
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader, withTestRelayXForwardedFor())
		req := httptest.NewRequest(http.MethodPost, "/relay/x", nil)
		req.RemoteAddr = "198.51.100.9:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7,")
		got := rs.deriveSourceAddr(req)
		if got.IP.String() != "198.51.100.9" {
			t.Errorf("ip = %s, want fallback to peer 198.51.100.9 (empty rightmost; must NOT walk left to 203.0.113.7)", got.IP)
		}
	})

	t.Run("XFF whitespace-only rightmost falls back to peer", func(t *testing.T) {
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader, withTestRelayXForwardedFor())
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
		rs := newTestRelay(t, serverPub, 62206, SourceAddrModeTrustedHeader, withTestRelayXForwardedFor())
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

// ============================================================================
// qURL v2 relay-routing invariant (regression guards)
//
// The qURL v2 design (docs/design/QURL_V2_KEYED_IDENTITY.md, "Current Code
// Reality -> NHP" and Migration Plan Phase 0) depends on the relay staying
// "boring": POST /relay/{serverId} routes ONLY by the cell NHP-server static
// public-key fingerprint and forwards an OPAQUE inner NHP packet it cannot read.
// These two tests lock the parts of that invariant not already fenced above:
//
//   - TestRelay_RoutesOnlyByPubKeyFingerprint: routing is keyed strictly by the
//     per-cell fingerprint (scope: "routes ONLY by fingerprint" + unknown -> 404).
//   - TestRelay_ReadsOnlyCleartextHeaderNeverDecryptsInner: the relay reads only
//     bounded cleartext header metadata and materially cannot decrypt the inner
//     body.
//
// The complementary halves are already covered and intentionally NOT repeated
// here: verbatim opaque forwarding (RelayForwardMsg.InnerPacket byte-equality)
// is asserted by TestRelay_TrustedHeaderForwardStampsAttestedRightmostXFF, and
// exact request-ID reply dispatch is asserted by
// TestRelay_DispatchTargetsExactRequestIDAndServer.
// ============================================================================

// newTwoCellTestRelay builds a relay configured for two distinct cells, each
// routed to its own UDP backend, and returns the relay plus both backend
// sockets. Cells have distinct static keys, so utils.PubKeyFingerprint gives
// each a distinct {serverId}. It mirrors newTestRelay's variadic-option shape;
// callers pass extra testRelayOptions on top of the shortened ACK-wait below.
func newTwoCellTestRelay(t *testing.T, pubA, pubB []byte, opts ...testRelayOption) (rs *RelayServer, backendA, backendB *net.UDPConn) {
	t.Helper()
	backendA = mustRelayUDPListener(t)
	backendB = mustRelayUDPListener(t)
	cfg := &Config{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(keyBytes(0x80)),
		UDPListenAddr:    "127.0.0.1:0",
		SourceAddrMode:   SourceAddrModeRemoteAddr,
		Servers: []ServerConfig{
			{Name: "cell-a", PubKeyBase64: base64.StdEncoding.EncodeToString(pubA), Host: "127.0.0.1", Port: backendA.LocalAddr().(*net.UDPAddr).Port},
			{Name: "cell-b", PubKeyBase64: base64.StdEncoding.EncodeToString(pubB), Host: "127.0.0.1", Port: backendB.LocalAddr().(*net.UDPAddr).Port},
		},
	}
	rs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Shorten the ACK-wait (these tests assert on the forwarded NHP_RLY datagram,
	// not the ACK leg — no listener replies here — so the handler must not block
	// on the 5s default), then apply caller options. All run before
	// startBackground so the fields are settled before any reader.
	for _, opt := range append([]testRelayOption{withTestRelayResponseTimeout(200 * time.Millisecond)}, opts...) {
		opt(rs)
	}
	rs.startBackground()
	t.Cleanup(func() { testStop(rs) })
	return rs, backendA, backendB
}

// mustRelayUDPListener binds a localhost UDP socket and closes it at test end.
// (relay_test.go has no shared UDP-listener helper; the server package's
// mustUDPListener is in a different package.)
func mustRelayUDPListener(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// gotDatagram reports whether a datagram lands on conn within timeout. A relay
// forward is one NHP_RLY datagram, so its arrival (or absence) on a given
// backend is the ground truth for where handleRelay routed the request.
func gotDatagram(t *testing.T, conn *net.UDPConn, timeout time.Duration) bool {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 65536)
	_, _, err := conn.ReadFromUDP(buf)
	if err == nil {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	t.Fatalf("ReadFromUDP: %v", err)
	return false
}

// TestRelay_RoutesOnlyByPubKeyFingerprint locks the qURL v2 routing invariant:
// POST /relay/{serverId} selects the backend STRICTLY by the per-cell static
// public-key fingerprint. Two cells (A, B) are addressable only by their own
// fingerprints, and a structurally-valid fingerprint for an unconfigured key is
// a 404 (no backend) — the same fail-closed behavior as a garbage serverId.
//
// Concretely this catches a future regression to first-server-wins or any
// cross-cell leak (fp(A) reaching cell B, or vice versa) that the single-cell
// TestRelay_RoundTrip and the garbage-string TestRelay_UnknownServer_404 would
// both still pass. (The map is keyed on the exact fingerprint string, so a
// prefix/substring match isn't a plausible regression to guard separately.)
func TestRelay_RoutesOnlyByPubKeyFingerprint(t *testing.T) {
	pubA := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	pubB := devicePubKey(t, core.NHP_SERVER, keyBytes(0x41))
	fpA := utils.PubKeyFingerprint(pubA)
	fpB := utils.PubKeyFingerprint(pubB)
	if fpA == fpB {
		t.Fatal("distinct cell keys produced the same fingerprint; test cannot discriminate")
	}
	// A structurally-valid fingerprint for a key that is NOT configured.
	fpUnconfigured := utils.PubKeyFingerprint(devicePubKey(t, core.NHP_SERVER, keyBytes(0x42)))

	rs, backendA, backendB := newTwoCellTestRelay(t, pubA, pubB)

	// post drives handleRelay synchronously (it returns within responseTimeout —
	// 200ms here — once it has forwarded and parked on the ACK wait that never
	// arrives, or immediately for a 404) and returns the recorder, so each case
	// can both observe where the datagram landed and assert the final status. The
	// inner knock is built for pubA but its bytes are irrelevant to routing — the
	// relay dispatches on the URL fingerprint, never the packet contents.
	innerKnock := makeInnerKnock(t, pubA, 1234)
	post := func(serverID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerKnock))
		req.RemoteAddr = "203.0.113.7:44444"
		w := httptest.NewRecorder()
		rs.handleRelay(w, req)
		return w
	}

	// noDatagramWait bounds the "expected NO datagram" checks. handleRelay forwards
	// to the backend synchronously BEFORE it parks on the ACK wait, so by the time
	// post() returns any same-request datagram (including a cross-cell leak) is
	// already queued on the backend socket — a short wait is sufficient and avoids
	// burning responseTimeout on every negative assertion. Positive checks below
	// keep a generous ceiling since they only ever wait when something is wrong.
	const noDatagramWait = 50 * time.Millisecond

	// NOTE: these subtests share backendA/backendB and MUST stay sequential —
	// each positive check drains the one datagram its POST produced before the
	// next subtest posts. Do NOT add t.Parallel() here: parallel subtests would
	// race the drains and let one subtest's datagram satisfy another's check.
	t.Run("fingerprint A routes to backend A only", func(t *testing.T) {
		post(fpA)
		if !gotDatagram(t, backendA, time.Second) {
			t.Error("backend A received no datagram for fp(A); request was not routed to cell A")
		}
		if gotDatagram(t, backendB, noDatagramWait) {
			t.Error("backend B received a datagram for fp(A); routing leaked across cells")
		}
	})

	t.Run("fingerprint B routes to backend B only", func(t *testing.T) {
		post(fpB)
		if !gotDatagram(t, backendB, time.Second) {
			t.Error("backend B received no datagram for fp(B); request was not routed to cell B")
		}
		if gotDatagram(t, backendA, noDatagramWait) {
			t.Error("backend A received a datagram for fp(B); routing leaked across cells")
		}
	})

	t.Run("valid but unconfigured fingerprint is 404 and forwards nothing", func(t *testing.T) {
		w := post(fpUnconfigured)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 for a valid fingerprint of an unconfigured key", w.Code)
		}
		// Drain BOTH backends unconditionally — evaluate each before asserting so a
		// datagram on A doesn't short-circuit (||) the read on B and leave B's
		// socket buffered for a later reader.
		leakedA := gotDatagram(t, backendA, noDatagramWait)
		leakedB := gotDatagram(t, backendB, noDatagramWait)
		if leakedA || leakedB {
			t.Errorf("an unconfigured fingerprint forwarded a datagram (A=%v, B=%v); it must select no backend", leakedA, leakedB)
		}
	})
}

// TestRelay_ReadsOnlyCleartextHeaderNeverDecryptsInner locks the second half of
// the qURL v2 opacity invariant: the relay can inspect only bounded CLEARTEXT
// header metadata and CANNOT read the encrypted inner body (the qURL/knock
// semantics). It asserts both directions on the relay's own code paths:
//
//   - innerType(inner) validates the cleartext header and returns its type
//     WITHOUT decryption (RecvPrecheck parses the header only); and
//   - the relay's NHP_RELAY device cannot decrypt the inner packet — it is
//     sealed to the cell SERVER's static key, not the relay's, so PacketToMsg
//     fails. The relay literally lacks the key to read qURL claims.
//
// Verbatim opaque forwarding of those same bytes is fenced by
// TestRelay_TrustedHeaderForwardStampsAttestedRightmostXFF; exact request-ID
// return dispatch by TestRelay_DispatchTargetsExactRequestIDAndServer.
func TestRelay_ReadsOnlyCleartextHeaderNeverDecryptsInner(t *testing.T) {
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)

	const counter = uint64(0xC0FFEE)
	inner := makeInnerKnock(t, serverPub, counter)

	// 1. The relay validates the cleartext header type — no decryption. Inspect
	// the packet header directly to prove the wire counter remains unchanged even
	// though relay dispatch no longer reads or uses it.
	gotType, err := rs.innerType(inner)
	if err != nil {
		t.Fatalf("innerType returned error for a well-formed inner knock: %v", err)
	}
	if gotType != core.NHP_KNK {
		t.Errorf("innerType = %s, want NHP_KNK", core.HeaderTypeToString(gotType))
	}
	if gotCounter := (&core.Packet{Content: inner}).Counter(); gotCounter != counter {
		t.Errorf("wire counter = %#x, want %#x", gotCounter, counter)
	}

	// 2. The relay's NHP_RELAY device cannot decrypt the inner packet: it is
	// sealed agent->server (to serverPub), so the relay key cannot open it. A
	// successful decrypt here would mean the relay could read qURL claims —
	// exactly what the design forbids.
	//
	// Assert the SPECIFIC cryptographic failure (ErrHeaderDigestCheckFailed —
	// "HMAC validation failed", a stable named error). The HMAC is keyed by the
	// agent<->server ECDH secret the relay does not possess, so the integrity
	// check fails before any body decryption. Pinning this error (rather than
	// "any error") proves the relay is rejected at the crypto layer, not by an
	// incidental confound like peer-not-configured.
	pkt := &core.Packet{Content: append([]byte(nil), inner...)}
	ppd, derr := rs.device.PacketToMsg(&core.PacketData{
		BasePacket: pkt,
		ConnData:   &core.ConnectionData{Device: rs.device, RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}},
		InitTime:   time.Now().UnixNano(),
	})
	if derr == nil {
		t.Fatalf("relay device decrypted an inner packet sealed to the server key (header=%s); the relay must NOT be able to read inner qURL/knock semantics",
			core.HeaderTypeToString(ppd.HeaderType))
	}
	if !errors.Is(derr, core.ErrHeaderDigestCheckFailed) {
		t.Errorf("relay decrypt failed with %v, want crypto-layer rejection %v (a non-crypto failure would make the no-decrypt guard pass for the wrong reason)",
			derr, core.ErrHeaderDigestCheckFailed)
	}
}
