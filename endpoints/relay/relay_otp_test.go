package relay

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

// makeInnerOTP produces a real encrypted NHP_OTP (as an agent would emit it to
// the server) — the fire-and-forget registration request a client POSTs to the
// relay. Sibling of makeInnerKnock; only the wire type + body differ.
func makeInnerOTP(t *testing.T, serverPub []byte, counter uint64) []byte {
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
	body, err := json.Marshal(&common.AgentOTPMsg{UserId: "u", DeviceId: "d", AuthServiceId: "asp"})
	if err != nil {
		t.Fatalf("marshal otp: %v", err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      conn,
		PeerPk:        serverPub,
		HeaderType:    core.NHP_OTP,
		TransactionId: counter,
		Message:       body,
	})
	select {
	case pkt := <-conn.SendQueue:
		return append([]byte(nil), pkt.Content...)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout producing inner OTP")
		return nil
	}
}

// TestRelay_InnerOTP_Returns202NoWaiter is the fire-and-forget proof: an inner
// NHP_OTP POST is forwarded to the cell server but the relay registers NO
// pending reply-waiter and returns HTTP 202 Accepted immediately — it does NOT
// park on responseTimeout waiting for a reply that (per spec) never comes.
//
// The fake cell server here deliberately NEVER replies. If the relay wrongly
// parked a waiter, the handler would block until responseTimeout and then 504;
// asserting a fast 202 (with the response-timeout set generously long) proves it
// did not park. rs.pending staying empty proves no waiter was registered.
func TestRelay_InnerOTP_Returns202NoWaiter(t *testing.T) {
	const counter = uint64(1212)
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))

	// Fake cell server that reads the forwarded NHP_RLY and NEVER replies.
	fakeServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("fake server listen: %v", err)
	}
	t.Cleanup(func() { _ = fakeServer.Close() })
	forwarded := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 65536)
		if _, _, rerr := fakeServer.ReadFromUDP(buf); rerr == nil {
			forwarded <- struct{}{}
		}
	}()

	innerOTP := makeInnerOTP(t, serverPub, counter)

	// A LONG response timeout so a wrongly-parked handler would visibly hang
	// (and this test would catch it via the done-channel deadline) rather than
	// racing a short timeout.
	rs := newTestRelay(t, serverPub, fakeServer.LocalAddr().(*net.UDPAddr).Port, SourceAddrModeRemoteAddr,
		withTestRelayResponseTimeout(30*time.Second))

	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerOTP))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { rs.handleRelay(w, req); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleRelay did not return promptly for an OTP — it parked on the reply wait instead of returning 202 (fire-and-forget)")
	}

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 Accepted for a fire-and-forget OTP (body=%q)", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Errorf("202 response carried a %d-byte body; an OTP has no reply to relay back", w.Body.Len())
	}

	// The packet must actually have been forwarded to the cell server.
	select {
	case <-forwarded:
	case <-time.After(2 * time.Second):
		t.Fatal("OTP was not forwarded to the cell server")
	}

	// No pending waiter may have been registered (the whole point — otherwise the
	// map/goroutine would grow and a never-arriving reply would 504).
	n := relayPendingCount(rs)
	if n != 0 {
		t.Errorf("rs.pending has %d entries after an OTP; a fire-and-forget OTP must register NO reply-waiter", n)
	}
}

// TestRelay_InnerOTP_ReleasesInFlightSlotPromptly proves an OTP does not hold an
// in-flight slot for the response-timeout window: after the 202 returns, the
// slot is freed (the handler returned), so the cap is immediately reusable. It
// fills the cap to exactly one below the limit, sends an OTP (which briefly takes
// the last slot and returns it), and confirms the slot count returns to the
// pre-request level. Contrast with a round-trip, which holds its slot for ~5s.
func TestRelay_InnerOTP_ReleasesInFlightSlotPromptly(t *testing.T) {
	const counter = uint64(1213)
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))

	fakeServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("fake server listen: %v", err)
	}
	t.Cleanup(func() { _ = fakeServer.Close() })
	go func() {
		buf := make([]byte, 65536)
		_, _, _ = fakeServer.ReadFromUDP(buf) // consume; never reply
	}()

	innerOTP := makeInnerOTP(t, serverPub, counter)
	rs := newTestRelay(t, serverPub, fakeServer.LocalAddr().(*net.UDPAddr).Port, SourceAddrModeRemoteAddr,
		withTestRelayResponseTimeout(30*time.Second))
	srv := rs.servers[utils.PubKeyFingerprint(serverPub)]

	// Occupy all but one slot so an OTP that failed to release would exhaust the
	// cap and the next acquire would shed.
	for i := 0; i < maxInFlightPerServer-1; i++ {
		srv.inFlight <- struct{}{}
	}
	if got := len(srv.inFlight); got != maxInFlightPerServer-1 {
		t.Fatalf("precondition: in-flight = %d, want %d", got, maxInFlightPerServer-1)
	}

	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerOTP))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { rs.handleRelay(w, req); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("OTP handler parked — it must return promptly and release its slot")
	}
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	// The OTP's slot must be back: still exactly the pre-filled count, proving the
	// OTP did not retain a slot for the (30s) response-timeout window.
	if got := len(srv.inFlight); got != maxInFlightPerServer-1 {
		t.Errorf("in-flight = %d after the OTP returned, want %d (the OTP must release its slot promptly, not park it)", got, maxInFlightPerServer-1)
	}
}

// TestRelay_InnerOTP_ForwardMetric fences MetricRelayOTPForward: a forwarded OTP
// ticks the throughput counter (its only relay-side visibility, since an OTP
// parks nothing observable).
func TestRelay_InnerOTP_ForwardMetric(t *testing.T) {
	const counter = uint64(1214)
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))

	fakeServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("fake server listen: %v", err)
	}
	t.Cleanup(func() { _ = fakeServer.Close() })
	go func() {
		buf := make([]byte, 65536)
		_, _, _ = fakeServer.ReadFromUDP(buf)
	}()

	innerOTP := makeInnerOTP(t, serverPub, counter)
	rs := newTestRelay(t, serverPub, fakeServer.LocalAddr().(*net.UDPAddr).Port, SourceAddrModeRemoteAddr)
	// Swap in an inspectable publisher (reap the real one New() booted first).
	rs.metrics.Stop()
	rs.metrics = metrics.NewPublisherForTest(t)

	serverID := utils.PubKeyFingerprint(serverPub)
	req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(innerOTP))
	req.RemoteAddr = "203.0.113.7:44444"
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	counters, _ := rs.metrics.CountersForTest(t)
	if got := counters[MetricRelayOTPForward]; got != 1 {
		t.Errorf("MetricRelayOTPForward = %v, want 1", got)
	}
}

// TestRelay_InnerKnock_StillParksAndReturnsReply is the contrast case: a normal
// inner KNK still registers a pending waiter and returns the server's dispatched
// reply (200 with the ACK bytes) — proving the OTP fast-path did not disturb the
// round-trip flow. Reuses the round-trip harness.
func TestRelay_InnerKnock_StillParksAndReturnsReply(t *testing.T) {
	const counter = uint64(1215)
	_, w, realAck := driveRelayRoundTrip(t, counter, makeRealAck)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a KNK must still park + return its reply)", w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), realAck) {
		t.Errorf("relayed KNK ACK bytes mismatch (got %d, want %d)", w.Body.Len(), len(realAck))
	}
}
