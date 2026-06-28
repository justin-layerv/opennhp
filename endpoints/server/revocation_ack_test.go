package server

import (
	"encoding/json"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// P4e Slice 3 (#2793): tests for the server NHP_RACK revocation-ack handler.
//
// These exercise HandleRevocationAck against the real acConnectionMap-based
// identity attribution (resolveACIdentityFromPubkey) — not a mock — so "the ack
// was attributed to the right AC slot" is proven by the observable metric
// outcome (RevocationAckReceived on a match, RevocationAckUnresolved on no
// match). The retry-engine tests cover the pending-tracker clear path; these
// fence the receive + attribution wiring it builds on.

func newAckTestServer(t *testing.T) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		device:          core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		acPeerMap:       map[string]*core.UdpPeer{},
		acConnectionMap: map[string][]*ACConn{},
	}
}

// putAckTestConn registers a live AC connection under acID whose pubkey is
// testPubkey(seed) (raw) / testPubkeyB64(seed) (the ACPeer's stored form), so a
// HandleRevocationAck call carrying ppd.RemotePubKey = testPubkey(seed) resolves
// to acID.
func putAckTestConn(s *UdpServer, acID string, seed byte) {
	acPeer := &core.UdpPeer{
		Hostname:     acID,
		PubKeyBase64: testPubkeyB64(seed),
		Type:         core.NHP_AC,
	}
	s.acConnectionMap[acID] = append(s.acConnectionMap[acID], &ACConn{
		ACPeer: acPeer,
		ACId:   acID,
	})
}

func ackPPD(t *testing.T, msg common.ACRevocationAckMsg, serverPubKey []byte) *core.PacketParserData {
	t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal ACRevocationAckMsg: %v", err)
	}
	return &core.PacketParserData{
		HeaderType:   core.NHP_RACK,
		BodyMessage:  body,
		RemotePubKey: serverPubKey,
	}
}

// TestHandleRevocationAck_AttributesAckToAuthenticatedAC: an ack whose
// authenticated pubkey matches a live AC connection is attributed to that AC and
// ticks MetricRevocationAckReceived (proof-of-delivery recorded), NOT the
// unresolved metric.
func TestHandleRevocationAck_AttributesAckToAuthenticatedAC(t *testing.T) {
	s := newAckTestServer(t)
	putAckTestConn(s, "ac-1", 7)

	ppd := ackPPD(t, common.ACRevocationAckMsg{
		Scope: "qurl", ScopeKey: "qurl:qX", RevocationEpoch: 3, EventId: "evt-1",
	}, testPubkey(7))

	if err := s.HandleRevocationAck(ppd); err != nil {
		t.Fatalf("HandleRevocationAck err=%v, want nil", err)
	}

	counters := serverCounters(t, s)
	if c := counters[MetricRevocationAckReceived]; c != 1 {
		t.Fatalf("%s = %v, want 1", MetricRevocationAckReceived, c)
	}
	if c := counters[MetricRevocationAckUnresolved]; c != 0 {
		t.Fatalf("%s = %v, want 0", MetricRevocationAckUnresolved, c)
	}
}

// TestHandleRevocationAck_UnresolvedPubkeyCounted: an ack whose authenticated
// pubkey matches no live AC connection (a drop/reconnect race) is ignored — it
// ticks MetricRevocationAckUnresolved and NOT MetricRevocationAckReceived, and
// returns nil (an unattributable ack is not a handler error). Non-vacuous: a
// DIFFERENT AC is connected, so the map is non-empty but does not contain the
// ack's pubkey.
func TestHandleRevocationAck_UnresolvedPubkeyCounted(t *testing.T) {
	s := newAckTestServer(t)
	putAckTestConn(s, "ac-1", 7)

	// Ack carries a pubkey (seed 9) that no connected AC has.
	ppd := ackPPD(t, common.ACRevocationAckMsg{
		Scope: "qurl", ScopeKey: "qurl:qX", RevocationEpoch: 1,
	}, testPubkey(9))

	if err := s.HandleRevocationAck(ppd); err != nil {
		t.Fatalf("HandleRevocationAck err=%v, want nil for an unattributable ack", err)
	}

	counters := serverCounters(t, s)
	if c := counters[MetricRevocationAckUnresolved]; c != 1 {
		t.Fatalf("%s = %v, want 1", MetricRevocationAckUnresolved, c)
	}
	if c := counters[MetricRevocationAckReceived]; c != 0 {
		t.Fatalf("%s = %v, want 0", MetricRevocationAckReceived, c)
	}
}

// TestHandleRevocationAck_MalformedBodyReturnsError: a body that is not valid
// ACRevocationAckMsg JSON surfaces the unmarshal error (and records no metric).
func TestHandleRevocationAck_MalformedBodyReturnsError(t *testing.T) {
	s := newAckTestServer(t)
	putAckTestConn(s, "ac-1", 7)

	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_RACK,
		BodyMessage:  []byte("{not valid json"),
		RemotePubKey: testPubkey(7),
	}
	if err := s.HandleRevocationAck(ppd); err == nil {
		t.Fatal("malformed body: expected a JSON parse error, got nil")
	}
	counters := serverCounters(t, s)
	if c := counters[MetricRevocationAckReceived]; c != 0 {
		t.Fatalf("%s = %v after malformed body, want 0", MetricRevocationAckReceived, c)
	}
}

// TestResolveACIdentityFromPubkey is the unit-level guard on the attribution
// helper: a matching pubkey resolves to its acId and slot pubkey; a wrong-length
// pubkey and an unknown pubkey both miss.
func TestResolveACIdentityFromPubkey(t *testing.T) {
	s := newAckTestServer(t)
	putAckTestConn(s, "ac-alpha", 3)
	putAckTestConn(s, "ac-beta", 4)

	if gotID, gotPubkey, ok := s.resolveACIdentityFromPubkey(testPubkey(3)); !ok || gotID != "ac-alpha" || gotPubkey != testPubkeyB64(3) {
		t.Fatalf("resolveACIdentityFromPubkey(seed3) = (%q,%q,%v), want (ac-alpha,%q,true)", gotID, gotPubkey, ok, testPubkeyB64(3))
	}
	if gotID, gotPubkey, ok := s.resolveACIdentityFromPubkey(testPubkey(4)); !ok || gotID != "ac-beta" || gotPubkey != testPubkeyB64(4) {
		t.Fatalf("resolveACIdentityFromPubkey(seed4) = (%q,%q,%v), want (ac-beta,%q,true)", gotID, gotPubkey, ok, testPubkeyB64(4))
	}
	// Unknown pubkey.
	if gotID, gotPubkey, ok := s.resolveACIdentityFromPubkey(testPubkey(99)); ok {
		t.Fatalf("resolveACIdentityFromPubkey(seed99) = (%q,%q,true), want miss", gotID, gotPubkey)
	}
	// Wrong-length input is rejected before any scan.
	if gotID, gotPubkey, ok := s.resolveACIdentityFromPubkey([]byte{1, 2, 3}); ok {
		t.Fatalf("resolveACIdentityFromPubkey(short) = (%q,%q,true), want miss", gotID, gotPubkey)
	}
}

// serverCounters snapshots the server metrics publisher's counters for assertion.
func serverCounters(t *testing.T, s *UdpServer) map[string]float64 {
	t.Helper()
	counters, _ := s.metrics.CountersForTest(t)
	return counters
}
