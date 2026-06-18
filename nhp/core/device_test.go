package core

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

func TestMsgToPacketRoutineMissingConnDataReturnsError(t *testing.T) {
	silenceGlobalLogger(t)

	for _, tc := range []struct {
		name       string
		headerType int
	}{
		{name: "forward", headerType: NHP_FWD},
		{name: "keepalive", headerType: NHP_KPL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverKey := make([]byte, PrivateKeySize)
			serverKey[0] = 1
			peerKey := make([]byte, PrivateKeySize)
			peerKey[0] = 2

			device := NewDevice(NHP_SERVER, serverKey, nil)
			if device == nil {
				t.Fatal("NewDevice returned nil")
			}
			peer := NewDevice(NHP_SERVER, peerKey, nil)
			if peer == nil {
				t.Fatal("NewDevice(peer) returned nil")
			}

			device.Start()
			t.Cleanup(device.Stop)

			responseCh := make(chan *PacketParserData, 1)
			device.SendMsgToPacket(&MsgData{
				HeaderType:    tc.headerType,
				CipherScheme:  common.CIPHER_SCHEME_CURVE,
				TransactionId: 1,
				PeerPk:        peer.staticEcdh.PublicKey(),
				Message:       []byte(`{"probe":true}`),
				ResponseMsgCh: responseCh,
			})

			select {
			case got := <-responseCh:
				if got == nil || got.Error == nil {
					t.Fatalf("got response %#v, want missing ConnData error", got)
				}
				if !strings.Contains(got.Error.Error(), "missing connection data") {
					t.Fatalf("error = %q, want missing connection data", got.Error.Error())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for missing ConnData error")
			}
		})
	}
}

func TestMsgToPacketRoutineRecoversForwardOutboundPanic(t *testing.T) {
	for _, tc := range []struct {
		name       string
		headerType int
	}{
		{name: "forward-result", headerType: NHP_FRT},
		{name: "forward-transaction", headerType: NHP_FWD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logDir := t.TempDir()
			logger := log.NewLogger("", log.LogLevelError, logDir, "server")
			prevLogger := log.SwapGlobalLogger(logger)
			t.Cleanup(func() {
				log.SwapGlobalLogger(prevLogger)
				logger.Close()
			})

			serverKey := make([]byte, PrivateKeySize)
			serverKey[0] = 1
			peerKey := make([]byte, PrivateKeySize)
			peerKey[0] = 2

			device := NewDevice(NHP_SERVER, serverKey, nil)
			if device == nil {
				t.Fatal("NewDevice returned nil")
			}
			peer := NewDevice(NHP_SERVER, peerKey, nil)
			if peer == nil {
				t.Fatal("NewDevice(peer) returned nil")
			}

			device.Start()
			t.Cleanup(device.Stop)

			sendQueue := make(chan *Packet)
			close(sendQueue)
			connData := &ConnectionData{
				Device:     device,
				RemoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.1.50"), Port: 62206},
				SendQueue:  sendQueue,
				StopSignal: make(chan struct{}),
			}

			responseCh := make(chan *PacketParserData, 1)
			device.SendMsgToPacket(&MsgData{
				HeaderType:    tc.headerType,
				CipherScheme:  common.CIPHER_SCHEME_CURVE,
				TransactionId: 1,
				PeerPk:        peer.staticEcdh.PublicKey(),
				ConnData:      connData,
				Message:       []byte(`{"probe":true}`),
				ResponseMsgCh: responseCh,
			})

			select {
			case got := <-responseCh:
				if got == nil || got.Error == nil {
					t.Fatalf("got response %#v, want recovered panic error", got)
				}
				if !strings.Contains(got.Error.Error(), "runtime panic encountered") {
					t.Fatalf("error = %q, want runtime panic wrapper", got.Error.Error())
				}
				if !strings.Contains(got.Error.Error(), "send on closed channel") {
					t.Fatalf("error = %q, want send-on-closed cause", got.Error.Error())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for recovered panic error")
			}

			deadline := time.After(2 * time.Second)
			for device.LocalTransactionCount() != 0 {
				select {
				case <-deadline:
					t.Fatalf("local transactions still active: %d", device.LocalTransactionCount())
				case <-time.After(10 * time.Millisecond):
				}
			}

			logger.Close()
			logPattern := filepath.Join(logDir, "server-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].log")
			logFiles, err := filepath.Glob(logPattern)
			if err != nil {
				t.Fatalf("glob recovery logs: %v", err)
			}
			if len(logFiles) == 0 {
				t.Fatalf("recovery logs = %v, want at least one server log", logFiles)
			}

			var combinedLog strings.Builder
			for _, logPath := range logFiles {
				logBytes, err := os.ReadFile(logPath)
				if err != nil {
					t.Fatalf("read recovery log %s: %v", logPath, err)
				}
				combinedLog.WriteString(logPath)
				combinedLog.WriteByte('\n')
				combinedLog.Write(logBytes)
				combinedLog.WriteByte('\n')
			}
			logText := combinedLog.String()
			if !strings.Contains(logText, "msgToPacketRoutine") {
				t.Fatalf("recovery log = %q, want msgToPacketRoutine for CloudWatch filter", logText)
			}
			if !strings.Contains(logText, "runtime panic encountered") {
				t.Fatalf("recovery log = %q, want runtime panic encountered for CloudWatch filter", logText)
			}
			foundFilterLine := false
			for _, line := range strings.Split(logText, "\n") {
				if strings.Contains(line, "msgToPacketRoutine") && strings.Contains(line, "runtime panic encountered") {
					foundFilterLine = true
					break
				}
			}
			if !foundFilterLine {
				t.Fatalf("recovery log = %q, want CloudWatch filter terms on one log event", logText)
			}
		})
	}
}
