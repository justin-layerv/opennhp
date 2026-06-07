package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestForwardHop_SenderRoundTrip exercises the full sender wiring: a
// forwarder configured via EnableForwardHopAttestation produces an
// attestation through forwardToServer that the recipient (a real
// core.Device) verifies. This catches wiring bugs the direct primitive
// tests cannot — wrong selfPubKey, hop-from-context off-by-one, srv.PubKey
// handling, and the marshal/unmarshal round-trip of the envelope.
func TestForwardHop_SenderRoundTrip(t *testing.T) {
	// Recipient identity B.
	bDevice := core.NewDevice(core.NHP_SERVER, hopKey(100), nil)
	if bDevice == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	pubB := bDevice.PublicKeyBase64()

	// Sender identity A.
	aEcdh := hopEcdh(t, 1)
	pubA := aEcdh.PublicKeyBase64()

	// Mock recipient server captures the forwarded envelope.
	captured := make(chan HttpKnockForwardRequest, 1)
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var fwd HttpKnockForwardRequest
		if err := json.NewDecoder(r.Body).Decode(&fwd); err != nil {
			t.Errorf("decode forwarded body: %v", err)
		}
		captured <- fwd
		_ = json.NewEncoder(w).Encode(HttpKnockForwardResponse{
			AckMsg: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()},
		})
	}))
	defer mock.Close()

	_, portStr, _ := net.SplitHostPort(mock.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID:            "ac-test",
		AssignedServers: []ServerInfo{{ID: "srv-b", InternalIP: "127.0.0.1", PubKey: pubB}},
	}

	f := NewHttpKnockForwarder(storage, nil, "10.0.0.99", port, nil, nil)
	f.EnableForwardHopAttestation(aEcdh, pubA)

	req := &common.HttpKnockRequest{
		AuthServiceId: "qurl",
		ResourceId:    "r_test",
		SrcIp:         "10.0.1.50",
	}
	// Incoming hop 0 (origin) → forwarder must emit hop 1.
	ctx := contextWithForwardHop(context.Background(), 0)
	if _, err := f.ForwardHttpKnock(ctx, "ac-test", req, &common.ResourceData{}); err != nil {
		t.Fatalf("ForwardHttpKnock: %v", err)
	}

	var fwd HttpKnockForwardRequest
	select {
	case fwd = <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("recipient never received the forward")
	}

	if fwd.Attestation == nil {
		t.Fatal("forwarder did not attach a hop attestation")
	}
	if fwd.Attestation.SenderPubKey != pubA {
		t.Errorf("attestation sender = %q, want sender A %q", fwd.Attestation.SenderPubKey, pubA)
	}
	if fwd.Attestation.Hop != 1 {
		t.Errorf("attestation hop = %d, want 1 (origin hop 0 + 1)", fwd.Attestation.Hop)
	}

	// The recipient B verifies what the forwarder actually produced,
	// binding the Source it arrived with (empty for a server-to-server hop).
	err := verifyForwardHopAttestation(
		bDevice.GetEcdhByCipherScheme(0),
		fwd.Attestation,
		known(pubA, pubB),
		time.Now(),
		forwardHopMaxSkew,
		fwd.Source,
		fwd.Request,
	)
	if err != nil {
		t.Fatalf("recipient should verify the forwarder's attestation, got %v", err)
	}
}

// TestForwardHop_SenderNoKeypairNoAttestation: a forwarder without
// EnableForwardHopAttestation (legacy/local mode) emits no attestation, so
// pre-rollout senders stay wire-compatible.
func TestForwardHop_SenderNoKeypairNoAttestation(t *testing.T) {
	captured := make(chan HttpKnockForwardRequest, 1)
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var fwd HttpKnockForwardRequest
		_ = json.NewDecoder(r.Body).Decode(&fwd)
		captured <- fwd
		_ = json.NewEncoder(w).Encode(HttpKnockForwardResponse{
			AckMsg: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()},
		})
	}))
	defer mock.Close()

	_, portStr, _ := net.SplitHostPort(mock.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID:            "ac-test",
		AssignedServers: []ServerInfo{{ID: "srv-b", InternalIP: "127.0.0.1", PubKey: "somepub"}},
	}

	f := NewHttpKnockForwarder(storage, nil, "10.0.0.99", port, nil, nil) // attestation NOT enabled
	if _, err := f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{}); err != nil {
		t.Fatalf("ForwardHttpKnock: %v", err)
	}

	select {
	case fwd := <-captured:
		if fwd.Attestation != nil {
			t.Fatalf("legacy forwarder must not attach an attestation, got %+v", fwd.Attestation)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recipient never received the forward")
	}
}
