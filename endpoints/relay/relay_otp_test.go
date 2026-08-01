package relay

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

func makeInnerLifecycle(t *testing.T, serverPub []byte, counter uint64, headerType int) []byte {
	t.Helper()
	inner := makeInnerKnock(t, serverPub, counter)
	packet := &core.Packet{Content: inner}
	_, payloadSize := packet.HeaderTypeAndSize()
	packet.Header().SetTypeAndPayloadSize(headerType, payloadSize)
	return inner
}

func TestRelay_LifecycleTypesRejectedBeforeForwardOrWaiter(t *testing.T) {
	for _, test := range []struct {
		name       string
		headerType int
	}{
		{name: "otp", headerType: core.NHP_OTP},
		{name: "register", headerType: core.NHP_REG},
		{name: "list", headerType: core.NHP_LST},
		{name: "list result", headerType: core.NHP_LRT},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
			fakeServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("fake server listen: %v", err)
			}
			t.Cleanup(func() { _ = fakeServer.Close() })

			rs := newTestRelay(t, serverPub, fakeServer.LocalAddr().(*net.UDPAddr).Port, SourceAddrModeRemoteAddr)
			serverID := utils.PubKeyFingerprint(serverPub)
			inner := makeInnerLifecycle(t, serverPub, 1212, test.headerType)
			req := httptest.NewRequest(http.MethodPost, "/relay/"+serverID, bytes.NewReader(inner))
			req.RemoteAddr = "203.0.113.7:44444"
			w := httptest.NewRecorder()

			rs.handleRelay(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if got := relayPendingCount(rs); got != 0 {
				t.Fatalf("pending waiters = %d, want 0", got)
			}
			if err := fakeServer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatalf("set read deadline: %v", err)
			}
			if _, _, err := fakeServer.ReadFromUDP(make([]byte, 1)); err == nil {
				t.Fatal("retired lifecycle packet was forwarded to the cell")
			}
		})
	}
}

func TestRelay_InnerKnock_StillParksAndReturnsReply(t *testing.T) {
	const counter = uint64(1215)
	_, w, realAck := driveRelayRoundTrip(t, counter, makeRealAck)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), realAck) {
		t.Errorf("relayed KNK ACK bytes mismatch (got %d, want %d)", w.Body.Len(), len(realAck))
	}
}
