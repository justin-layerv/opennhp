package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// Credential canaries embedded in the REG/OTP bodies. A single source per
// canary keeps the log-absence assertion in lockstep with the wire value.
const (
	regCanary = "lv_live_REG_CANARY_must_never_reach_logs"
	otpCanary = "lv_live_OTP_CANARY_must_never_reach_logs"
	ackCanary = "lv_live_ACK_CANARY_must_never_reach_logs"
)

// TestDeviceAsyncLogsRedactProtocolBodies drives both asynchronous core
// routines at debug/evaluate level. REG and OTP carry enrollment credentials;
// neither the outbound plaintext nor the recovered inbound plaintext may
// appear in any NHP log file.
func TestDeviceAsyncLogsRedactProtocolBodies(t *testing.T) {
	// Do not call t.Parallel: the global logger swap is process-wide.
	logDir := t.TempDir()
	testLogger := log.NewLogger("NHP-Redaction-Test", log.LogLevelDebug, logDir, "protocol")
	previousLogger := log.SwapGlobalLogger(testLogger)
	loggerRestored := false
	t.Cleanup(func() {
		if !loggerRestored {
			log.SwapGlobalLogger(previousLogger)
			testLogger.Close()
		}
	})

	agent := NewDevice(NHP_AGENT, validatePeerPrivateKey(1), nil)
	server := NewDevice(NHP_SERVER, validatePeerPrivateKey(101), nil)
	if agent == nil || server == nil {
		t.Fatal("create test devices")
	}
	server.AddPeer(&UdpPeer{
		PubKeyBase64: agent.PublicKeyBase64(),
		Ip:           "127.0.0.1",
		Port:         40001,
		Type:         NHP_AGENT,
	})
	agent.Start()
	server.Start()
	devicesStopped := false
	t.Cleanup(func() {
		if !devicesStopped {
			agent.Stop()
			server.Stop()
		}
	})

	tests := []struct {
		name       string
		headerType int
		secret     string
		body       any
	}{
		{
			name:       "reg",
			headerType: NHP_REG,
			secret:     regCanary,
			body: &common.AgentRegisterMsg{
				UserId:        "key_redaction",
				DeviceId:      "device-redaction",
				AuthServiceId: "agent",
				OTP:           regCanary,
			},
		},
		{
			name:       "otp",
			headerType: NHP_OTP,
			secret:     otpCanary,
			body: &common.AgentOTPMsg{
				UserId:        "key_redaction",
				DeviceId:      "device-redaction",
				AuthServiceId: "agent",
				Passcode:      otpCanary,
			},
		},
		{
			name:       "ack",
			headerType: NHP_ACK,
			secret:     ackCanary,
			body: &common.ServerKnockAckMsg{
				ErrCode:           "0",
				AuthProviderToken: ackCanary,
				ACTokens:          map[string]string{"resource-redaction": ackCanary},
			},
		},
	}

	bodies := make([][]byte, len(tests))
	for i, tc := range tests {
		body, err := json.Marshal(tc.body)
		if err != nil {
			t.Fatalf("marshal %s body: %v", tc.name, err)
		}
		bodies[i] = body
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := bodies[i]
			encrypted := make(chan *MsgAssemblerData, 1)
			agent.SendMsgToPacket(&MsgData{
				ConnData:       validatePeerConnectionData(agent, 40001, 62206),
				HeaderType:     tc.headerType,
				CipherScheme:   common.CIPHER_SCHEME_CURVE,
				TransactionId:  uint64(i + 1),
				Compress:       true,
				Message:        body,
				PeerPk:         server.staticEcdh.PublicKey(),
				EncryptedPktCh: encrypted,
			})

			var assembled *MsgAssemblerData
			select {
			case assembled = <-encrypted:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for encrypted packet")
			}
			if assembled == nil || assembled.Error != nil {
				t.Fatalf("encrypt packet: %v", assembled)
			}

			var packetBuffer PacketBuffer
			packetLen := len(assembled.BasePacket.Content)
			copy(packetBuffer[:], assembled.BasePacket.Content)
			assembled.Destroy()
			server.RecvPacketToMsg(&PacketData{
				BasePacket: &Packet{
					Buf:        &packetBuffer,
					Content:    packetBuffer[:packetLen],
					HeaderType: tc.headerType,
				},
				ConnData:       validatePeerConnectionData(server, 62206, 40001),
				InitTime:       time.Now().UnixNano(),
				DecryptedMsgCh: server.DecryptedMsgQueue,
			})

			select {
			case parsed := <-server.DecryptedMsgQueue:
				if parsed == nil || parsed.Error != nil {
					t.Fatalf("decrypt packet: %v", parsed)
				}
				if !bytes.Equal(parsed.BodyMessage, body) {
					t.Fatal("decrypted body differs from input")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for decrypted packet")
			}
		})
	}

	// sendCookie has its own pre-encryption diagnostic. Its cookie is a bearer
	// capability too, so fence that call site alongside the generic routines.
	// It intentionally stays unstarted: sendCookie synchronously enqueues into
	// the buffered response queue, and cleanup Stop only closes those queues.
	cookieDevice := NewDevice(NHP_SERVER, validatePeerPrivateKey(151), nil)
	if cookieDevice == nil {
		t.Fatal("create cookie test device")
	}
	t.Cleanup(cookieDevice.Stop)
	cookieConn := validatePeerConnectionData(cookieDevice, 62206, 40002)
	cookieBytes := bytes.Repeat([]byte{0xa5}, CookieSize)
	copy(cookieConn.CookieStore.CurrCookie[:], cookieBytes)
	cookiePPD := &PacketParserData{
		device:      cookieDevice,
		ConnData:    cookieConn,
		SenderTrxId: 99,
	}
	cookiePPD.sendCookie()
	cookieMessageLen := 0
	select {
	case message := <-cookieDevice.msgToPacketQueue:
		// The test only needs the synchronous diagnostic; no worker is started.
		cookieMessageLen = len(message.Message)
	default:
		t.Fatal("sendCookie did not enqueue a response")
	}
	// Flush before reading the files; the cleanup guards above still handle an
	// earlier t.Fatal without double-stopping devices or closing the logger.
	agent.Stop()
	server.Stop()
	devicesStopped = true
	log.SwapGlobalLogger(previousLogger)
	testLogger.Close()
	loggerRestored = true

	var allLogs []byte
	if err := filepath.WalkDir(logDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		allLogs = append(allLogs, contents...)
		return nil
	}); err != nil {
		t.Fatalf("read test logs: %v", err)
	}

	for i, tc := range tests {
		if bytes.Contains(allLogs, []byte(tc.secret)) {
			t.Errorf("%s credential canary appeared in protocol logs", tc.name)
		}
		body := bodies[i]
		msgType := HeaderTypeToString(tc.headerType)
		for _, want := range []string{
			fmt.Sprintf("encrypting [%s] message (%d bytes)", msgType, len(body)),
			fmt.Sprintf("complete decrypting [%s] message (%d bytes)", msgType, len(body)),
		} {
			if !bytes.Contains(allLogs, []byte(want)) {
				t.Errorf("protocol logs missing redacted metadata %q", want)
			}
		}
	}
	cookieCanary := base64.StdEncoding.EncodeToString(cookieBytes)
	if bytes.Contains(allLogs, []byte(cookieCanary)) {
		t.Error("cookie bearer canary appeared in protocol logs")
	}
	if want := fmt.Sprintf("Send cookie back to %s (%d bytes)", cookieConn.RemoteAddr, cookieMessageLen); !bytes.Contains(allLogs, []byte(want)) {
		t.Errorf("protocol logs missing redacted cookie metadata %q", want)
	}
}
