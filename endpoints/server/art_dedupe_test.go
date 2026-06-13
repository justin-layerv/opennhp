package server

import (
	"errors"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func newDedupeTestServer(t *testing.T) (*UdpServer, *metrics.Publisher) {
	t.Helper()
	mp := metrics.NewPublisherForTest(t)
	return &UdpServer{metrics: mp, artReplay: newARTReplayCache()}, mp
}

func artPpd(pub []byte, txid uint64, sendTime int64) *core.PacketParserData {
	return &core.PacketParserData{
		HeaderType:     core.NHP_ART,
		RemotePubKey:   pub,
		SenderTrxId:    txid,
		RemoteSendTime: sendTime,
	}
}

// TestDedupeRecvART_FirstSeenThenReplay is the hook-logic fence for
// #1457: a first ART passes (nil error, no metric); the byte-identical
// replay is rejected with ErrServerDuplicateTransaction and bumps
// MetricARTReplayDetected exactly once.
func TestDedupeRecvART_FirstSeenThenReplay(t *testing.T) {
	s, mp := newDedupeTestServer(t)
	pub := pubkeyN('A')

	if err := s.dedupeRecvART(artPpd(pub, 7, testSendTime)); err != nil {
		t.Fatalf("first ART must pass; got %v", err)
	}
	if err := s.dedupeRecvART(artPpd(pub, 7, testSendTime)); !errors.Is(err, common.ErrServerDuplicateTransaction) {
		t.Fatalf("replayed ART must be rejected; got %v, want ErrServerDuplicateTransaction", err)
	}

	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricARTReplayDetected]; got != 1 {
		t.Fatalf("%s = %v, want 1", MetricARTReplayDetected, got)
	}
}

// TestDedupeRecvART_NonARTSkipped asserts the hook scopes to NHP_ART:
// any other header type returns nil immediately AND is not recorded, so
// it can never make a later ART with the same (pubkey, txid, sendTime)
// look like a duplicate. Without the type guard the hook would key every
// validated packet and a knock could shadow an ART.
func TestDedupeRecvART_NonARTSkipped(t *testing.T) {
	s, mp := newDedupeTestServer(t)
	pub := pubkeyN('A')

	for _, hdr := range []int{core.NHP_KNK, core.NHP_AOL, core.NHP_REG, core.NHP_FRT} {
		ppd := &core.PacketParserData{HeaderType: hdr, RemotePubKey: pub, SenderTrxId: 7, RemoteSendTime: testSendTime}
		if err := s.dedupeRecvART(ppd); err != nil {
			t.Fatalf("non-ART header %s must be skipped (nil); got %v", core.HeaderTypeToString(hdr), err)
		}
	}
	// An ART with the same (pubkey, txid, sendTime) the skipped packets
	// carried must still be first-seen — proof none of them were recorded.
	if err := s.dedupeRecvART(artPpd(pub, 7, testSendTime)); err != nil {
		t.Fatalf("ART must be first-seen after skipped non-ART packets; got %v", err)
	}
	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricARTReplayDetected]; got != 0 {
		t.Fatalf("%s must stay 0 for skipped non-ART packets, got %v", MetricARTReplayDetected, got)
	}
}

// TestDedupeRecvART_MissingPubkeyFailClosed pins the fail-closed guard:
// an ART whose RemotePubKey was not populated to PublicKeySize by
// validatePeer is refused with the DISTINCT ErrServerMissingPeerPubkey
// (not ErrServerDuplicateTransaction, so a duplicate-spike alert isn't
// misled) and is not counted as a replay.
func TestDedupeRecvART_MissingPubkeyFailClosed(t *testing.T) {
	s, mp := newDedupeTestServer(t)

	cases := map[string][]byte{
		"nil":   nil,
		"empty": {},
		"short": make([]byte, core.PublicKeySize-1),
		"long":  make([]byte, core.PublicKeySize+1),
	}
	for label, pub := range cases {
		err := s.dedupeRecvART(artPpd(pub, 7, testSendTime))
		if !errors.Is(err, common.ErrServerMissingPeerPubkey) {
			t.Errorf("%s pubkey: got %v, want ErrServerMissingPeerPubkey", label, err)
		}
	}
	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricARTReplayDetected]; got != 0 {
		t.Fatalf("missing-pubkey rejects must not bump %s; got %v", MetricARTReplayDetected, got)
	}
}

// TestDedupeRecvART_PostRestartCounterCollision is the server-side
// false-reject fence (mirror of the AC's): the server's NextCounterIndex
// resets on restart, so a legitimate post-restart ART can reuse a
// pre-restart (pubkey, txid). The fresh AC send timestamp must let it
// through, while a byte-identical replay of the pre-restart ART is still
// rejected.
func TestDedupeRecvART_PostRestartCounterCollision(t *testing.T) {
	s, _ := newDedupeTestServer(t)
	pub := pubkeyN('A')
	const txid uint64 = 1

	if err := s.dedupeRecvART(artPpd(pub, txid, testSendTime)); err != nil {
		t.Fatalf("pre-restart ART must pass; got %v", err)
	}
	if err := s.dedupeRecvART(artPpd(pub, txid, testSendTime+int64(30_000_000_000))); err != nil {
		t.Fatalf("post-restart ART (same pubkey/txid, fresh sendTime) must pass; got %v", err)
	}
	if err := s.dedupeRecvART(artPpd(pub, txid, testSendTime)); !errors.Is(err, common.ErrServerDuplicateTransaction) {
		t.Fatalf("byte-identical pre-restart replay must still be rejected; got %v", err)
	}
}
