package server

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func nativeSessionOperationMaximumWireKnock() common.AgentKnockMsg {
	return common.AgentKnockMsg{
		HeaderType: core.NHP_KNK,
		UserId:     strings.Repeat("a", 256), DeviceId: strings.Repeat("a", 256),
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId:    strings.Repeat("r", 256),
		RunID:         "ffffffffffffffff", RunAttempt: math.MaxUint64,
		NativeSessionOperationID:        strings.Repeat("a", 64),
		NativeSessionOperationBinding:   strings.Repeat("b", 64),
		NativeSessionOperationOwnerID:   strings.Repeat("o", 256),
		NativeSessionOperationPrepared:  math.MaxInt64 - common.NativeSessionOperationMaxCreationWindow.Milliseconds(),
		NativeSessionOperationExpiresAt: math.MaxInt64,
	}
}

func nativeSessionOperationFrameSize(body []byte) int {
	return core.RelayPacketMinimalLength + len(body) + core.GCMTagSize
}

func TestNativeSessionOperationMaximumDirectAndForwardedFramesFitTransport(t *testing.T) {
	knock := nativeSessionOperationMaximumWireKnock()
	knock.UserData = map[string]any{"padding": ""}
	emptyBody, err := json.Marshal(knock)
	if err != nil {
		t.Fatal(err)
	}
	padding := common.NativeSessionOperationMaxKnockJSONBytes - len(emptyBody)
	if padding < 0 {
		t.Fatalf("maximum authority fields already exceed wire ceiling: %d", len(emptyBody))
	}
	knock.UserData["padding"] = strings.Repeat("x", padding)
	knockBody, err := json.Marshal(knock)
	if err != nil {
		t.Fatal(err)
	}
	if len(knockBody) != common.NativeSessionOperationMaxKnockJSONBytes {
		t.Fatalf("maximum operation JSON = %d, want %d", len(knockBody), common.NativeSessionOperationMaxKnockJSONBytes)
	}
	directSize := nativeSessionOperationFrameSize(knockBody)
	if directSize != 2304 || directSize > core.PacketBufferSize {
		t.Fatalf("maximum direct operation frame = %d, want 2304 within %d", directSize, core.PacketBufferSize)
	}
	// Ciphertext is intentionally incompressible here. NHP_FWD currently sends
	// its JSON body without compression, so this is the actual larger bound,
	// not an optimistic compressed estimate.
	directCiphertext := make([]byte, directSize)
	for index := range directCiphertext {
		directCiphertext[index] = byte(index*131 + 17)
	}
	forwardBody, err := json.Marshal(common.ServerForwardMsg{
		KnockData: directCiphertext, SourceServer: strings.Repeat("s", 256),
		UserAddr:      "[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535",
		TransactionId: math.MaxUint64, Timestamp: math.MaxInt64,
		SessionId: math.MaxUint64, SessionIssuedAtNanos: math.MaxInt64,
	})
	if err != nil {
		t.Fatal(err)
	}
	forwardSize := nativeSessionOperationFrameSize(forwardBody)
	if forwardSize != 3811 || forwardSize > core.PacketBufferSize {
		t.Fatalf("maximum forwarded operation frame = %d, want 3811 within %d", forwardSize, core.PacketBufferSize)
	}
	relayBody, err := json.Marshal(common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Port: 65535},
		InnerPacket: base64.StdEncoding.EncodeToString(directCiphertext),
		RequestID:   strings.Repeat("f", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	relaySize := nativeSessionOperationFrameSize(relayBody)
	if relaySize != 3494 || relaySize > core.RelayPacketBufferSize {
		t.Fatalf("maximum relay operation frame = %d, want 3494 within %d", relaySize, core.RelayPacketBufferSize)
	}
}

func TestNativeSessionOperationMaximumRecoveryFrameFitsDirectTransport(t *testing.T) {
	knock := nativeSessionOperationMaximumWireKnock()
	recoveryBody, err := json.Marshal(common.AgentNativeSessionOperationRecoveryMsg{
		HeaderType: core.NHP_EXT, UserID: knock.UserId, DeviceID: knock.DeviceId,
		AuthServiceID: knock.AuthServiceId, ResourceID: knock.ResourceId,
		RunID: knock.RunID, RunAttempt: knock.RunAttempt,
		OperationID: knock.NativeSessionOperationID, BindingSHA256: knock.NativeSessionOperationBinding,
		OwnerID: knock.NativeSessionOperationOwnerID, PreparedAtMS: knock.NativeSessionOperationPrepared,
		ExpiresAtMS: knock.NativeSessionOperationExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if size := nativeSessionOperationFrameSize(recoveryBody); size != 1660 || size > core.PacketBufferSize {
		t.Fatalf("maximum recovery frame = %d, want 1660 within %d", size, core.PacketBufferSize)
	}
}
