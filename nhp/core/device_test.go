package core

import (
	"errors"
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

// TestResponseMsgChWrittenExactlyOnce fences the single-writer invariant that
// endpoints/agent's awaitTransactionResponse depends on: because that consumer
// closes ResponseMsgCh on receive and leaves it open (size-1 buffer) on a
// stop-bail, a SECOND write to the same channel would reintroduce a
// send-on-closed panic or a full-buffer deadlock in the agent. The four writer
// sites (transaction.go's completion + error defers, device.go's two
// pre-transaction error paths) are structurally mutually exclusive; this test
// covers the cleanly-drivable device.go pre-transaction error path (missing
// ConnData) and asserts exactly one write, then none. The transaction-owned
// paths route through SendExternalMsg and stay covered by the structure + the
// back-reference comments at those sites.
func TestResponseMsgChWrittenExactlyOnce(t *testing.T) {
	silenceGlobalLogger(t)

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

	// Buffered size 1, matching how endpoints/agent allocates ResponseMsgCh.
	responseCh := make(chan *PacketParserData, 1)
	device.SendMsgToPacket(&MsgData{
		HeaderType:    NHP_FWD,
		CipherScheme:  common.CIPHER_SCHEME_CURVE,
		TransactionId: 1,
		PeerPk:        peer.staticEcdh.PublicKey(),
		Message:       []byte(`{"probe":true}`),
		ResponseMsgCh: responseCh,
	})

	select {
	case got := <-responseCh:
		if got == nil || got.Error == nil {
			t.Fatalf("got response %#v, want an error write", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the single error write")
	}

	// Exactly one write: nothing more must ever land on responseCh. A second
	// writer would break the agent's close-on-receive assumption.
	select {
	case got := <-responseCh:
		t.Fatalf("second write on ResponseMsgCh (%#v) — single-writer invariant broken; see the back-reference comments in transaction.go/device.go", got)
	case <-time.After(200 * time.Millisecond):
		// good: exactly one write
	}
}

// TestEncryptedPktChWrittenExactlyOnce is the EncryptedPktCh sibling of
// TestResponseMsgChWrittenExactlyOnce. endpoints/agent's awaitOrDeadline closes
// EncryptedPktCh on receive (fail-loud tripwire), which is only safe because the
// two msgToPacketRoutine writers (device.go: the success return and the error
// defer) are mutually exclusive — exactly one write per MsgAssemblerData. This
// fences that invariant executably so a future second-writer regression on the
// encrypt path trips here instead of as a send-on-closed panic / device.Stop()
// deadlock in the agent.
func TestEncryptedPktChWrittenExactlyOnce(t *testing.T) {
	silenceGlobalLogger(t)

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

	// Buffered size 1, matching how endpoints/agent allocates EncryptedPktCh
	// (knock.go preAccessRequest). Routing a MsgData through the encrypt pipeline
	// with EncryptedPktCh set writes the assembled packet (or an error) there.
	encCh := make(chan *MsgAssemblerData, 1)
	device.SendMsgToPacket(&MsgData{
		HeaderType:     NHP_FWD,
		CipherScheme:   common.CIPHER_SCHEME_CURVE,
		TransactionId:  1,
		PeerPk:         peer.staticEcdh.PublicKey(),
		Message:        []byte(`{"probe":true}`),
		EncryptedPktCh: encCh,
	})

	select {
	case got := <-encCh:
		if got == nil {
			t.Fatal("got nil MsgAssemblerData, want a single write")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the single encrypt write")
	}

	// Exactly one write: nothing more must ever land on encCh. A second writer
	// would break awaitOrDeadline's close-on-receive assumption.
	select {
	case got := <-encCh:
		t.Fatalf("second write on EncryptedPktCh (%#v) — single-writer invariant broken; see the two writer sites in device.go's msgToPacketRoutine", got)
	case <-time.After(200 * time.Millisecond):
		// good: exactly one write
	}
}

func TestKeepaliveEncryptedPktChCompletesOnSuccessAndError(t *testing.T) {
	silenceGlobalLogger(t)
	device := NewDevice(NHP_AC, append([]byte{1}, make([]byte, PrivateKeySize-1)...), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	device.Start()
	t.Cleanup(device.Stop)

	for _, tc := range []struct {
		name       string
		external   *Packet
		wantErr    bool
		wantPacket bool
	}{
		{name: "success", wantPacket: true},
		{name: "assembly error", external: &Packet{Content: make([]byte, 1)}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encCh := make(chan *MsgAssemblerData, 1)
			device.SendMsgToPacket(&MsgData{
				HeaderType:     NHP_KPL,
				TransactionId:  1,
				ExternalPacket: tc.external,
				EncryptedPktCh: encCh,
			})
			select {
			case mad := <-encCh:
				if mad == nil {
					t.Fatal("keepalive completion returned nil assembler")
				}
				if tc.wantErr && !errors.Is(mad.Error, ErrPacketSizeExceedsBuffer) {
					t.Fatalf("keepalive error = %v, want ErrPacketSizeExceedsBuffer", mad.Error)
				}
				if !tc.wantErr && mad.Error != nil {
					t.Fatalf("keepalive completion error = %v", mad.Error)
				}
				if tc.wantPacket && (mad.BasePacket == nil || mad.BasePacket.HeaderType != NHP_KPL || len(mad.BasePacket.Content) != mad.BasePacket.MinimalLength()) {
					t.Fatalf("keepalive packet = %#v, want assembled NHP_KPL", mad.BasePacket)
				}
				mad.Destroy()
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for keepalive EncryptedPktCh completion")
			}
			select {
			case got := <-encCh:
				t.Fatalf("second keepalive completion %#v", got)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// TestLocalTransactionResponseMsgChWrittenExactlyOnce fences the transaction-OWNED
// ResponseMsgCh writer leg (#3104) — the subtle half that
// TestResponseMsgChWrittenExactlyOnce (the device.go pre-transaction leg) leaves
// to structure + comments. transaction.go's Run() has two mutually-exclusive
// ResponseMsgCh writers: the ExternalMsgCh completion (returns err == nil) and the
// cleanup defer's error write (err != nil). Driving a real completion asserts
// exactly one write and that the error defer skips, so a future change that let
// the completion path also fall through the error defer (or added a third writer)
// trips here instead of as a send-on-closed panic / full-buffer deadlock in
// endpoints/agent's awaitOrDeadline.
func TestLocalTransactionResponseMsgChWrittenExactlyOnce(t *testing.T) {
	silenceGlobalLogger(t)

	key := make([]byte, PrivateKeySize)
	key[0] = 1
	device := NewDevice(NHP_AGENT, key, nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	device.Start()
	t.Cleanup(device.Stop)

	// Buffered size 1, matching endpoints/agent's ResponseMsgCh allocation; Run()
	// reads only connData.StopSignal and mad.device, so a minimal pair suffices.
	responseCh := make(chan *PacketParserData, 1)
	mad := &MsgAssemblerData{device: device, ResponseMsgCh: responseCh}
	connData := &ConnectionData{StopSignal: make(chan struct{})}
	txn := newLocalTransaction(1, connData, mad, 5000)
	device.AddLocalTransaction(txn) // does device.wg.Add(1) + go txn.Run()

	// Complete via the transaction-owned ExternalMsgCh leg. err stays nil, so the
	// cleanup defer's `err != nil` write must skip.
	completed := &PacketParserData{}
	if err := txn.SendExternalMsg(completed); err != nil {
		t.Fatalf("SendExternalMsg: %v", err)
	}

	select {
	case got := <-responseCh:
		if got != completed {
			t.Fatalf("got %#v, want the completion ppd (not an error write)", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the single completion write")
	}

	// Exactly one write: the error defer must NOT also write.
	select {
	case got := <-responseCh:
		t.Fatalf("second write on ResponseMsgCh (%#v) — transaction-owned single-writer invariant broken; see transaction.go's completion vs error-defer writers", got)
	case <-time.After(200 * time.Millisecond):
		// good: exactly one write
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
			if tc.headerType == NHP_FWD {
				// A transaction request uses exactly two packets: the assembler's
				// retained packet and the sender copy. A two-slot pool makes the
				// post-panic capacity check below detect a leak of either owner.
				device.pool = &PacketBufferPool{}
				device.pool.Init(2)
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
			if tc.headerType == NHP_FWD {
				allocatedCh := make(chan [2]*Packet, 1)
				go func() {
					allocatedCh <- [2]*Packet{
						device.AllocatePoolPacket(),
						device.AllocatePoolPacket(),
					}
				}()
				select {
				case packets := <-allocatedCh:
					for _, packet := range packets {
						device.ReleasePoolPacket(packet)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("outbound panic leaked a packet-pool allocation")
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
