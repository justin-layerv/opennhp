package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestShouldCheckRecvAttack_AOPNoLongerExempt is the regression
// fence for issue #1123. The previous implementation skipped the
// per-connection LastRemoteSendTime monotonic check for NHP_AOP,
// which made the responder a no-op replay-protector for AC-side
// AOP processing within an open connection. The fix removes that
// exemption so AOP rides the same gate as every other AC-bound
// message; the cross-connection cousin lives in
// endpoints/ac/aop_replay_cache.go.
func TestShouldCheckRecvAttack_AOPNoLongerExempt(t *testing.T) {
	if !shouldCheckRecvAttack(NHP_AC, NHP_SERVER, NHP_AOP) {
		t.Fatal("NHP_AOP on AC must be subject to the LastRemoteSendTime gate (#1123)")
	}
}

// TestShouldCheckRecvAttack_ARTNoLongerExempt is the regression fence
// for issue #1457 — the symmetric server-side counterpart of #1123.
// NHP_ART (AC → server response) was previously skipped by the
// per-connection LastRemoteSendTime gate; the fix removes that
// exemption so an in-connection ART timestamp regression is rejected
// at the cryptographic gate, not (only) the transaction-correlation
// layer. The cross-connection cousin lives in
// endpoints/server/art_replay_cache.go. ART remains exempt from the
// 20 ms FLOOD gate (see TestShouldCheckFlood_ARTExempt) — only the
// replay gate changed.
func TestShouldCheckRecvAttack_ARTNoLongerExempt(t *testing.T) {
	if !shouldCheckRecvAttack(NHP_SERVER, NHP_AC, NHP_ART) {
		t.Fatal("NHP_ART on server must be subject to the LastRemoteSendTime gate (#1457)")
	}
}

// TestShouldCheckRecvAttack_DefaultEnforced sanity-checks that an
// unrelated message type still enforces the gate, so a future
// refactor of shouldCheckRecvAttack cannot silently widen the
// exemption set.
func TestShouldCheckRecvAttack_DefaultEnforced(t *testing.T) {
	if !shouldCheckRecvAttack(NHP_SERVER, NHP_AGENT, NHP_KNK) {
		t.Fatal("non-exempt (deviceType, peerType, msgType) must enforce the gate")
	}
}

// TestShouldCheckFlood_AOPExempt fences the round-7 cr finding for
// issue #1123. The flood gate (`MinimalRecvIntervalMs = 20 ms`)
// must NOT apply to NHP_AOP on AC: the server legitimately emits
// AOPs in tight succession during knock bursts, and applying the
// 20 ms floor would false-flood-block a connection past
// `ThreatCountBeforeBlock`. Replay protection is preserved via
// shouldCheckRecvAttack (still enforced on AOP) plus the
// cross-connection cache in endpoints/ac/aop_replay_cache.go.
func TestShouldCheckFlood_AOPExempt(t *testing.T) {
	if shouldCheckFlood(NHP_AC, NHP_SERVER, NHP_AOP) {
		t.Fatal("NHP_AOP on AC must be exempt from the 20 ms flood gate (#1123 round-7)")
	}
}

// TestShouldCheckFlood_ARTExempt pins the ART flood-gate exemption.
// ART (AC → server) stays exempt from the 20 ms rate floor because a
// server knock burst makes the AC emit back-to-back ARTs µs apart, and
// the floor would false-flood-block the trusted AC→server connection.
// This is independent of the replay gate — ART is NO LONGER
// replay-exempt after #1457 (see
// TestShouldCheckRecvAttack_ARTNoLongerExempt); only the rate floor is
// waived.
func TestShouldCheckFlood_ARTExempt(t *testing.T) {
	if shouldCheckFlood(NHP_SERVER, NHP_AC, NHP_ART) {
		t.Fatal("NHP_ART on server must remain exempt from the 20 ms flood gate")
	}
}

// TestShouldCheckFlood_DefaultEnforced asserts the flood gate is
// otherwise enforced, so a future refactor of shouldCheckFlood
// cannot silently widen the exemption set.
func TestShouldCheckFlood_DefaultEnforced(t *testing.T) {
	if !shouldCheckFlood(NHP_SERVER, NHP_AGENT, NHP_KNK) {
		t.Fatal("non-exempt (deviceType, peerType, msgType) must enforce the flood gate")
	}
}

// TestShouldEscalateStale_AOPExempt fences the #1464 decision that a
// stale NHP_AOP (server→AC) is dropped but NOT escalated to
// threat/block. Mirrors the existing shouldCheckFlood AOP exemption:
// AOP must not be able to self-inflict a connection block (here, on a
// clock-skew false-reject; there, on a legitimate burst).
func TestShouldEscalateStale_AOPExempt(t *testing.T) {
	if shouldEscalateStale(NHP_AC, NHP_SERVER, NHP_AOP) {
		t.Fatal("stale NHP_AOP on AC must NOT escalate to threat/block (#1464) — a benign clock-skew drop must not sever the server→AC connection")
	}
}

// TestShouldEscalateStale_DefaultEnforced asserts every other
// (deviceType, peerType, msgType) — including AC→server ART — still
// escalates a stale drop, so the AOP exemption stays narrowly scoped
// and a refactor cannot silently disable the block path fleet-wide.
func TestShouldEscalateStale_DefaultEnforced(t *testing.T) {
	cases := []struct {
		name                          string
		deviceType, peerType, msgType int
	}{
		{"agent knock", NHP_SERVER, NHP_AGENT, NHP_KNK},
		{"AC→server ART", NHP_SERVER, NHP_AC, NHP_ART},
		// AOP on a non-AC device must NOT pick up the AC-scoped exemption.
		{"AOP wrong device scope", NHP_SERVER, NHP_SERVER, NHP_AOP},
	}
	for _, tc := range cases {
		if !shouldEscalateStale(tc.deviceType, tc.peerType, tc.msgType) {
			t.Errorf("%s: stale drop must escalate to threat/block", tc.name)
		}
	}
}

// TestShouldEscalateReplay_ARTExempt fences the #1457 escalation
// exemption: a dropped in-connection ART replay (timestamp regression)
// must NOT escalate toward a connection block. ART send-times are stamped
// by concurrent msgToPacketRoutine workers, so a benign knock-burst
// reorder (reachable without any network reorder) must not be able to
// self-block the trusted AC→server connection.
func TestShouldEscalateReplay_ARTExempt(t *testing.T) {
	if shouldEscalateReplay(NHP_SERVER, NHP_AC, NHP_ART) {
		t.Fatal("dropped NHP_ART replay on server must NOT escalate to threat/block (#1457)")
	}
}

// TestShouldEscalateReplay_AOPExempt fences the #2518 escalation
// exemption — the symmetric server→AC counterpart of #1457. A dropped
// in-connection AOP replay (timestamp regression) must NOT escalate
// toward a connection block: AOP send-times are stamped by the same
// concurrent msgToPacketRoutine workers, so a benign server knock-burst
// reorder (reachable without any network reorder) must not be able to
// self-block the trusted server→AC connection. The drop still rejects the
// replay; the cross-connection cache in endpoints/ac/aop_replay_cache.go
// is the real cross-connection defense.
func TestShouldEscalateReplay_AOPExempt(t *testing.T) {
	if shouldEscalateReplay(NHP_AC, NHP_SERVER, NHP_AOP) {
		t.Fatal("dropped NHP_AOP replay on AC must NOT escalate to threat/block (#2518)")
	}
}

// TestShouldEscalateReplay_DefaultEnforced asserts every other
// (deviceType, peerType, msgType) still escalates a dropped replay, so
// the ART (#1457) and AOP (#2518) exemptions stay narrowly scoped and a
// refactor cannot silently disable the block path fleet-wide.
func TestShouldEscalateReplay_DefaultEnforced(t *testing.T) {
	cases := []struct {
		name                          string
		deviceType, peerType, msgType int
	}{
		{"agent knock", NHP_SERVER, NHP_AGENT, NHP_KNK},
		// ART on a non-server device must NOT pick up the server-scoped exemption.
		{"ART wrong device scope", NHP_AC, NHP_AC, NHP_ART},
		// AOP on a non-AC device must NOT pick up the AC-scoped exemption.
		{"AOP wrong device scope", NHP_SERVER, NHP_SERVER, NHP_AOP},
	}
	for _, tc := range cases {
		if !shouldEscalateReplay(tc.deviceType, tc.peerType, tc.msgType) {
			t.Errorf("%s: dropped replay must escalate to threat/block", tc.name)
		}
	}
}

// TestRecvStalenessFloor_AOPTightened is the regression fence for
// issue #1464. NHP_AOP (server→AC) must use the tighter
// AOPRecvStalenessFloorSeconds floor, not the 600 s default, so the
// cross-restart replay window the AC dedupe cache cannot cover after
// a restart is bounded by the smaller value. A refactor that drops
// the AOP override would silently restore the 600 s window.
func TestRecvStalenessFloor_AOPTightened(t *testing.T) {
	got := recvStalenessFloor(NHP_AC, NHP_SERVER, NHP_AOP)
	want := AOPRecvStalenessFloorSeconds * int64(time.Second)
	if got != want {
		t.Fatalf("NHP_AOP staleness floor = %d ns, want %d ns (tightened for #1464)", got, want)
	}
	// Pin the security invariant the tightening exists to deliver:
	// the AOP floor must be strictly smaller than the default, or the
	// override is doing nothing.
	if got >= DefaultRecvStalenessFloorSeconds*int64(time.Second) {
		t.Fatalf("AOP floor (%d ns) must be strictly tighter than the default (%d ns)", got, DefaultRecvStalenessFloorSeconds*int64(time.Second))
	}
}

// TestRecvStalenessFloor_DefaultPreserved asserts every non-AOP
// (deviceType, peerType, msgType) keeps the historical 600 s floor,
// so #1464's tightening cannot silently narrow the clock-calibration
// tolerance for agent→server knock paths (which may traverse the
// public internet).
func TestRecvStalenessFloor_DefaultPreserved(t *testing.T) {
	want := DefaultRecvStalenessFloorSeconds * int64(time.Second)
	cases := []struct {
		name                          string
		deviceType, peerType, msgType int
	}{
		{"agent knock", NHP_SERVER, NHP_AGENT, NHP_KNK},
		{"AC→server ART", NHP_SERVER, NHP_AC, NHP_ART},
		// AOP on a non-AC device must NOT pick up the AC-scoped
		// override — the tighter floor is keyed on the full triple.
		{"AOP wrong device scope", NHP_SERVER, NHP_SERVER, NHP_AOP},
	}
	for _, tc := range cases {
		if got := recvStalenessFloor(tc.deviceType, tc.peerType, tc.msgType); got != want {
			t.Errorf("%s: staleness floor = %d ns, want default %d ns", tc.name, got, want)
		}
	}
}

type validatePeerFixture struct {
	acPeer        *UdpPeer
	server        *Device
	serverConn    *ConnectionData
	packetContent []byte
	initTime      int64
}

func TestValidatePeerPopulatesRemotePubKey(t *testing.T) {
	fixture := newValidatePeerFixture(t)
	ppd := fixture.parseAndValidate(t)
	defer ppd.Destroy()

	if !bytes.Equal(ppd.RemotePubKey, fixture.acPeer.PublicKey()) {
		t.Fatalf("RemotePubKey mismatch\ngot:  %x\nwant: %x", ppd.RemotePubKey, fixture.acPeer.PublicKey())
	}
}

func TestValidatePeerRemotePubKeySurvivesDestroy(t *testing.T) {
	fixture := newValidatePeerFixture(t)
	ppd := fixture.parseAndValidate(t)
	want := append([]byte(nil), fixture.acPeer.PublicKey()...)

	ppd.Destroy()

	if !bytes.Equal(ppd.RemotePubKey, want) {
		t.Fatalf("RemotePubKey after Destroy mismatch\ngot:  %x\nwant: %x", ppd.RemotePubKey, want)
	}
}

// TestValidatePeer_AOPStalenessFloorWiredAtCallSite is the call-site
// fence requested in cr on #1464. The recvStalenessFloor unit tests
// prove the helper returns the right number, but the behavior that
// ships is its wiring into validatePeer's stale check — a refactor
// could leave the helper correct yet disconnect it from the call site
// and every pure-helper test would stay green. This drives real
// AEAD-authenticated packets through validatePeer and asserts the
// differential the tightening delivers, end to end:
//
//   - an AOP (server→AC) aged past the 120 s AOP floor but within the
//     600 s default is rejected as stale (the tightened floor is wired);
//   - the same AOP just under the floor is accepted (no false-reject);
//   - an ART (AC→server) at the AOP-rejecting age still passes under
//     the unchanged 600 s default (the tightening is AOP-scoped).
//
// The validatePeerFixture helpers already stand up the full
// Device/Peer/ECDH/AEAD chain, so this is the cheap end-to-end fence
// the recvStalenessFloor docstring's "#1468" note assumed was too
// heavy to write before the fixture existed.
func TestValidatePeer_AOPStalenessFloorWiredAtCallSite(t *testing.T) {
	silenceGlobalLogger(t)

	acDevice := NewDevice(NHP_AC, validatePeerPrivateKey(1), nil)
	serverDevice := NewDevice(NHP_SERVER, validatePeerPrivateKey(33), nil)
	if acDevice == nil || serverDevice == nil {
		t.Fatal("failed to create AC/server devices")
	}
	acPeer := &UdpPeer{PubKeyBase64: acDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12345, Type: NHP_AC}
	serverPeer := &UdpPeer{PubKeyBase64: serverDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12346, Type: NHP_SERVER}
	serverDevice.AddPeer(acPeer)
	acDevice.AddPeer(serverPeer)

	// validateAged runs one packet through the receiver's validatePeer
	// on a fresh connection (LastRemoteSendTime == 0, so the replay gate
	// never trips) and returns the error (nil == accepted).
	validateAged := func(receiver *Device, localPort, remotePort int, pkt *Packet, initTime int64) error {
		t.Helper()
		ppd, err := receiver.createPacketParserData(&PacketData{
			BasePacket: pkt,
			ConnData:   validatePeerConnectionData(receiver, localPort, remotePort),
			InitTime:   initTime,
		})
		if err != nil {
			t.Fatalf("createPacketParserData failed: %v", err)
		}
		defer ppd.Destroy()
		return ppd.validatePeer()
	}

	const overAOPFloor = 200 * time.Second // > 120 s AOP floor, < 600 s default
	const underAOPFloor = 60 * time.Second // < 120 s AOP floor

	// AOP (server→AC) aged past the AOP floor → rejected as stale.
	pkt, initTime := buildAgedPacket(t, serverDevice, validatePeerConnectionData(serverDevice, 12346, 12345), acPeer.PublicKey(), NHP_AOP, overAOPFloor)
	if err := validateAged(acDevice, 12345, 12346, pkt, initTime); !errors.Is(err, ErrStalePacketReceived) {
		t.Fatalf("AOP aged %s: got %v, want ErrStalePacketReceived (120 s AOP floor must be wired at the call site)", overAOPFloor, err)
	}

	// AOP (server→AC) just under the AOP floor → accepted.
	pkt, initTime = buildAgedPacket(t, serverDevice, validatePeerConnectionData(serverDevice, 12346, 12345), acPeer.PublicKey(), NHP_AOP, underAOPFloor)
	if err := validateAged(acDevice, 12345, 12346, pkt, initTime); err != nil {
		t.Fatalf("AOP aged %s (under the 120 s floor): got %v, want accepted", underAOPFloor, err)
	}

	// ART (AC→server) at the AOP-rejecting age → still accepted under
	// the unchanged 600 s default floor.
	pkt, initTime = buildAgedPacket(t, acDevice, validatePeerConnectionData(acDevice, 12345, 12346), serverPeer.PublicKey(), NHP_ART, overAOPFloor)
	if err := validateAged(serverDevice, 12346, 12345, pkt, initTime); err != nil {
		t.Fatalf("ART aged %s: got %v, want accepted (default 600 s floor is unchanged for non-AOP)", overAOPFloor, err)
	}
}

// TestValidatePeer_StaleAOPDropsWithoutBlock is the call-site fence
// for the #1464 escalation exemption. It drives a stale AEAD packet
// through validatePeer on an explicit connection and inspects the
// connection's threat/block state afterward:
//
//   - a stale AOP (server→AC) is dropped (ErrStalePacketReceived) but
//     leaves RecvThreatCount at 0 and never fires SendBlockSignal, so a
//     benign clock-skew false-reject can't sever the server→AC link;
//   - a stale ART (AC→server) at the same relative age IS escalated
//     (RecvThreatCount bumped), proving the exemption is AOP-scoped and
//     the block path is otherwise intact.
//
// This is the behavioral counterpart to the shouldEscalateStale unit
// tests — it fences the wiring of the exemption into validatePeer's
// stale branch, which a refactor could disconnect while the predicate
// stays correct.
func TestValidatePeer_StaleAOPDropsWithoutBlock(t *testing.T) {
	silenceGlobalLogger(t)

	acDevice := NewDevice(NHP_AC, validatePeerPrivateKey(1), nil)
	serverDevice := NewDevice(NHP_SERVER, validatePeerPrivateKey(33), nil)
	if acDevice == nil || serverDevice == nil {
		t.Fatal("failed to create AC/server devices")
	}
	acPeer := &UdpPeer{PubKeyBase64: acDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12345, Type: NHP_AC}
	serverPeer := &UdpPeer{PubKeyBase64: serverDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12346, Type: NHP_SERVER}
	serverDevice.AddPeer(acPeer)
	acDevice.AddPeer(serverPeer)

	validateOn := func(receiver *Device, conn *ConnectionData, pkt *Packet, initTime int64) error {
		t.Helper()
		ppd, err := receiver.createPacketParserData(&PacketData{BasePacket: pkt, ConnData: conn, InitTime: initTime})
		if err != nil {
			t.Fatalf("createPacketParserData failed: %v", err)
		}
		defer ppd.Destroy()
		return ppd.validatePeer()
	}

	// Stale AOP (server→AC), aged past the 120 s AOP floor → dropped,
	// NOT escalated. Drive TWO stale AOPs through the SAME connection so
	// the block-suppression is genuinely exercised, not a single-packet
	// no-op: without the exemption the first would bump RecvThreatCount
	// to 1 and the second would cross ThreatCountBeforeBlock (=1) and
	// fire SendBlockSignal. With the exemption RecvThreatCount stays 0
	// and BlockSignal never fires, so BOTH assertions below are
	// load-bearing. (The staleness gate returns before LastRemoteSendTime
	// is updated, so the second packet still reaches the stale branch
	// rather than tripping the replay gate.) RecvThreatCount is read via
	// atomic.LoadInt32 to match how validatePeer writes it.
	acConn := validatePeerConnectionData(acDevice, 12345, 12346)
	for i := 1; i <= 2; i++ {
		pkt, initTime := buildAgedPacket(t, serverDevice, validatePeerConnectionData(serverDevice, 12346, 12345), acPeer.PublicKey(), NHP_AOP, 200*time.Second)
		if err := validateOn(acDevice, acConn, pkt, initTime); !errors.Is(err, ErrStalePacketReceived) {
			t.Fatalf("stale AOP #%d: got %v, want ErrStalePacketReceived", i, err)
		}
	}
	if got := atomic.LoadInt32(&acConn.RecvThreatCount); got != 0 {
		t.Fatalf("two stale AOPs must NOT bump RecvThreatCount (got %d) — AOP is exempt from stale escalation (#1464)", got)
	}
	if len(acConn.BlockSignal) != 0 {
		t.Fatal("two stale AOPs must NOT fire SendBlockSignal — without the exemption the 2nd would cross ThreatCountBeforeBlock and sever the trusted server→AC connection")
	}

	// Stale ART (AC→server), aged past the 600 s default floor → dropped
	// AND escalated (one stale packet bumps RecvThreatCount to 1; a
	// second would cross ThreatCountBeforeBlock and block).
	srvConn := validatePeerConnectionData(serverDevice, 12346, 12345)
	pkt, initTime := buildAgedPacket(t, acDevice, validatePeerConnectionData(acDevice, 12345, 12346), serverPeer.PublicKey(), NHP_ART, 700*time.Second)
	if err := validateOn(serverDevice, srvConn, pkt, initTime); !errors.Is(err, ErrStalePacketReceived) {
		t.Fatalf("stale ART: got %v, want ErrStalePacketReceived", err)
	}
	if got := atomic.LoadInt32(&srvConn.RecvThreatCount); got != 1 {
		t.Fatalf("stale ART must escalate (RecvThreatCount=1); got %d — the AOP exemption must be scoped, not global", got)
	}
}

// TestValidatePeer_ReplayARTDropsWithoutBlock is the call-site fence for
// the #1457 replay-escalation exemption — the replay-gate analog of
// TestValidatePeer_StaleAOPDropsWithoutBlock, and the behavioral fence the
// cr asked for (a pure shouldEscalateReplay unit test would not catch a
// wiring regression). It drives timestamp-regressed packets through
// validatePeer on an explicit connection and inspects threat/block state:
//
//   - two regressed ARTs (AC→server) are each dropped
//     (ErrReplayPacketReceived) but leave RecvThreatCount at 0 and never
//     fire SendBlockSignal — so a benign burst reorder (reachable WITHOUT
//     network reorder, since ART send-times are stamped by concurrent
//     msgToPacketRoutine workers) cannot sever the trusted AC→server link;
//   - two regressed NHP_AAKs (server→AC ack, a non-exempt type) at the
//     same setup ARE escalated (RecvThreatCount clamps to
//     ThreatCountBeforeBlock and SendBlockSignal fires), proving the
//     exemption is ART-scoped and the replay-branch block path is intact.
//     (NHP_AOP is no longer a usable control here — #2518 made it
//     drop-only too; see TestValidatePeer_ReplayAOPDropsWithoutBlock.)
//
// The high-water-mark is seeded directly on LastRemoteSendTime so each
// fresh (age-0) packet regresses deterministically without depending on
// wall-clock ordering between sends — and a dropped replay does not advance
// LastRemoteSendTime, so both packets in a pair regress.
func TestValidatePeer_ReplayARTDropsWithoutBlock(t *testing.T) {
	silenceGlobalLogger(t)

	acDevice := NewDevice(NHP_AC, validatePeerPrivateKey(1), nil)
	serverDevice := NewDevice(NHP_SERVER, validatePeerPrivateKey(33), nil)
	if acDevice == nil || serverDevice == nil {
		t.Fatal("failed to create AC/server devices")
	}
	acPeer := &UdpPeer{PubKeyBase64: acDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12345, Type: NHP_AC}
	serverPeer := &UdpPeer{PubKeyBase64: serverDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12346, Type: NHP_SERVER}
	serverDevice.AddPeer(acPeer)
	acDevice.AddPeer(serverPeer)

	validateOn := func(receiver *Device, conn *ConnectionData, pkt *Packet, initTime int64) error {
		t.Helper()
		ppd, err := receiver.createPacketParserData(&PacketData{BasePacket: pkt, ConnData: conn, InitTime: initTime})
		if err != nil {
			t.Fatalf("createPacketParserData failed: %v", err)
		}
		defer ppd.Destroy()
		return ppd.validatePeer()
	}

	const highWater = time.Hour // far enough that any age-0 send time regresses below it

	// Two regressed ARTs (server is the receiver) → dropped, NOT escalated.
	srvConn := validatePeerConnectionData(serverDevice, 12346, 12345)
	atomic.StoreInt64(&srvConn.LastRemoteSendTime, time.Now().Add(highWater).UnixNano())
	for i := 1; i <= 2; i++ {
		pkt, initTime := buildAgedPacket(t, acDevice, validatePeerConnectionData(acDevice, 12345, 12346), serverPeer.PublicKey(), NHP_ART, 0)
		if err := validateOn(serverDevice, srvConn, pkt, initTime); !errors.Is(err, ErrReplayPacketReceived) {
			t.Fatalf("regressed ART #%d: got %v, want ErrReplayPacketReceived", i, err)
		}
	}
	if got := atomic.LoadInt32(&srvConn.RecvThreatCount); got != 0 {
		t.Fatalf("two regressed ARTs must NOT bump RecvThreatCount (got %d) — ART is exempt from replay escalation (#1457)", got)
	}
	if len(srvConn.BlockSignal) != 0 {
		t.Fatal("two regressed ARTs must NOT fire SendBlockSignal — without the exemption the 2nd would cross ThreatCountBeforeBlock and sever the trusted AC→server connection")
	}

	// Two regressed NHP_AAKs (AC is the receiver) → dropped AND escalated,
	// proving the exemption is ART-scoped. NHP_AAK (server→AC ack) rides
	// the server→AC connection like AOP but is NOT replay-exempt, so it
	// still fences the replay-branch escalation path.
	acConn := validatePeerConnectionData(acDevice, 12345, 12346)
	atomic.StoreInt64(&acConn.LastRemoteSendTime, time.Now().Add(highWater).UnixNano())
	for i := 1; i <= 2; i++ {
		pkt, initTime := buildAgedPacket(t, serverDevice, validatePeerConnectionData(serverDevice, 12346, 12345), acPeer.PublicKey(), NHP_AAK, 0)
		if err := validateOn(acDevice, acConn, pkt, initTime); !errors.Is(err, ErrReplayPacketReceived) {
			t.Fatalf("regressed AAK #%d: got %v, want ErrReplayPacketReceived", i, err)
		}
	}
	if got := atomic.LoadInt32(&acConn.RecvThreatCount); got != ThreatCountBeforeBlock {
		t.Fatalf("two regressed AAKs must escalate (RecvThreatCount clamped to %d); got %d — the ART exemption must be scoped, not global", ThreatCountBeforeBlock, got)
	}
	if len(acConn.BlockSignal) != 1 {
		t.Fatal("two regressed AAKs must fire SendBlockSignal (the 2nd crosses ThreatCountBeforeBlock)")
	}
}

// TestValidatePeer_ReplayAOPDropsWithoutBlock is the call-site fence for
// the #2518 replay-escalation exemption — the symmetric server→AC analog
// of TestValidatePeer_ReplayARTDropsWithoutBlock. It drives
// timestamp-regressed packets through validatePeer on an explicit
// connection and inspects threat/block state:
//
//   - two regressed AOPs (server→AC) are each dropped
//     (ErrReplayPacketReceived) but leave RecvThreatCount at 0 and never
//     fire SendBlockSignal — so a benign server knock-burst reorder
//     (reachable WITHOUT network reorder, since AOP send-times are stamped
//     by concurrent msgToPacketRoutine workers) cannot sever the trusted
//     server→AC link;
//   - two regressed NHP_AOLs (AC→server online, a non-exempt type) at the
//     same setup ARE escalated (RecvThreatCount clamps to
//     ThreatCountBeforeBlock and SendBlockSignal fires), proving the
//     exemption is AOP-scoped and the replay-branch block path is intact.
//
// Seeding matches the ART fence: the high-water-mark is written directly
// to LastRemoteSendTime so each fresh (age-0) packet regresses
// deterministically, and a dropped replay does not advance
// LastRemoteSendTime, so both packets in a pair regress.
func TestValidatePeer_ReplayAOPDropsWithoutBlock(t *testing.T) {
	silenceGlobalLogger(t)

	acDevice := NewDevice(NHP_AC, validatePeerPrivateKey(1), nil)
	serverDevice := NewDevice(NHP_SERVER, validatePeerPrivateKey(33), nil)
	if acDevice == nil || serverDevice == nil {
		t.Fatal("failed to create AC/server devices")
	}
	acPeer := &UdpPeer{PubKeyBase64: acDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12345, Type: NHP_AC}
	serverPeer := &UdpPeer{PubKeyBase64: serverDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12346, Type: NHP_SERVER}
	serverDevice.AddPeer(acPeer)
	acDevice.AddPeer(serverPeer)

	validateOn := func(receiver *Device, conn *ConnectionData, pkt *Packet, initTime int64) error {
		t.Helper()
		ppd, err := receiver.createPacketParserData(&PacketData{BasePacket: pkt, ConnData: conn, InitTime: initTime})
		if err != nil {
			t.Fatalf("createPacketParserData failed: %v", err)
		}
		defer ppd.Destroy()
		return ppd.validatePeer()
	}

	const highWater = time.Hour // far enough that any age-0 send time regresses below it

	// Two regressed AOPs (AC is the receiver) → dropped, NOT escalated.
	acConn := validatePeerConnectionData(acDevice, 12345, 12346)
	atomic.StoreInt64(&acConn.LastRemoteSendTime, time.Now().Add(highWater).UnixNano())
	for i := 1; i <= 2; i++ {
		pkt, initTime := buildAgedPacket(t, serverDevice, validatePeerConnectionData(serverDevice, 12346, 12345), acPeer.PublicKey(), NHP_AOP, 0)
		if err := validateOn(acDevice, acConn, pkt, initTime); !errors.Is(err, ErrReplayPacketReceived) {
			t.Fatalf("regressed AOP #%d: got %v, want ErrReplayPacketReceived", i, err)
		}
	}
	if got := atomic.LoadInt32(&acConn.RecvThreatCount); got != 0 {
		t.Fatalf("two regressed AOPs must NOT bump RecvThreatCount (got %d) — AOP is exempt from replay escalation (#2518)", got)
	}
	if len(acConn.BlockSignal) != 0 {
		t.Fatal("two regressed AOPs must NOT fire SendBlockSignal — without the exemption the 2nd would cross ThreatCountBeforeBlock and sever the trusted server→AC connection")
	}

	// Two regressed NHP_AOLs (server is the receiver) → dropped AND
	// escalated, proving the exemption is AOP-scoped. NHP_AOL (AC→server
	// online status) rides the AC→server connection but is NOT
	// replay-exempt, so it still fences the replay-branch escalation path.
	srvConn := validatePeerConnectionData(serverDevice, 12346, 12345)
	atomic.StoreInt64(&srvConn.LastRemoteSendTime, time.Now().Add(highWater).UnixNano())
	for i := 1; i <= 2; i++ {
		pkt, initTime := buildAgedPacket(t, acDevice, validatePeerConnectionData(acDevice, 12345, 12346), serverPeer.PublicKey(), NHP_AOL, 0)
		if err := validateOn(serverDevice, srvConn, pkt, initTime); !errors.Is(err, ErrReplayPacketReceived) {
			t.Fatalf("regressed AOL #%d: got %v, want ErrReplayPacketReceived", i, err)
		}
	}
	if got := atomic.LoadInt32(&srvConn.RecvThreatCount); got != ThreatCountBeforeBlock {
		t.Fatalf("two regressed AOLs must escalate (RecvThreatCount clamped to %d); got %d — the AOP exemption must be scoped, not global", ThreatCountBeforeBlock, got)
	}
	if len(srvConn.BlockSignal) != 1 {
		t.Fatal("two regressed AOLs must fire SendBlockSignal (the 2nd crosses ThreatCountBeforeBlock)")
	}
}

// BenchmarkValidatePeer replays one byte-identical encrypted ART through
// validatePeer N times. ART is now subject to the replay gate (#1457), but a
// byte-identical replay carries an EQUAL send timestamp, which the strict
// less-than check (remoteSendTime < LastRemoteSendTime) does not trip, and
// ART stays flood-exempt — so the same packet can be re-driven without a
// gate rejection skewing the benchmark.
func BenchmarkValidatePeer(b *testing.B) {
	fixture := newValidatePeerFixture(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ppd := fixture.parseAndValidate(b)
		ppd.Destroy()
	}
}

func newValidatePeerFixture(tb testing.TB) validatePeerFixture {
	tb.Helper()
	silenceGlobalLogger(tb)

	acPrivKey := validatePeerPrivateKey(1)
	serverPrivKey := validatePeerPrivateKey(33)
	acDevice := NewDevice(NHP_AC, acPrivKey, nil)
	if acDevice == nil {
		tb.Fatal("failed to create AC device")
	}
	serverDevice := NewDevice(NHP_SERVER, serverPrivKey, nil)
	if serverDevice == nil {
		tb.Fatal("failed to create server device")
	}

	acPeer := &UdpPeer{
		PubKeyBase64: acDevice.PublicKeyBase64(),
		Ip:           "127.0.0.1",
		Port:         12345,
		Type:         NHP_AC,
	}
	serverPeer := &UdpPeer{
		PubKeyBase64: serverDevice.PublicKeyBase64(),
		Ip:           "127.0.0.1",
		Port:         12346,
		Type:         NHP_SERVER,
	}
	serverDevice.AddPeer(acPeer)
	acDevice.AddPeer(serverPeer)

	acConn := validatePeerConnectionData(acDevice, 12345, 12346)
	mad, err := acDevice.MsgToPacket(&MsgData{
		ConnData:      acConn,
		PeerPk:        serverPeer.PublicKey(),
		HeaderType:    NHP_ART,
		TransactionId: 1,
	})
	if err != nil {
		tb.Fatalf("MsgToPacket failed: %v", err)
	}

	return validatePeerFixture{
		acPeer:        acPeer,
		server:        serverDevice,
		serverConn:    validatePeerConnectionData(serverDevice, 12346, 12345),
		packetContent: append([]byte(nil), mad.BasePacket.Content...),
		initTime:      time.Now().UnixNano(),
	}
}

func (f validatePeerFixture) parseAndValidate(tb testing.TB) *PacketParserData {
	tb.Helper()

	pkt := Packet{
		Content:    f.packetContent,
		HeaderType: NHP_ART,
	}
	pd := PacketData{
		BasePacket: &pkt,
		ConnData:   f.serverConn,
		InitTime:   f.initTime,
	}

	ppd, err := f.server.createPacketParserData(&pd)
	if err != nil {
		tb.Fatalf("createPacketParserData failed: %v", err)
	}
	if err := ppd.validatePeer(); err != nil {
		tb.Fatalf("validatePeer failed: %v", err)
	}

	return ppd
}

func validatePeerPrivateKey(start byte) []byte {
	key := make([]byte, PrivateKeySize)
	for i := range key {
		key[i] = start + byte(i)
	}
	return key
}

func validatePeerConnectionData(device *Device, localPort int, remotePort int) *ConnectionData {
	return &ConnectionData{
		Device:           device,
		LocalAddr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		RemoteAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		InitTime:         time.Now().UnixNano(),
		CookieStore:      &CookieStore{},
		SendQueue:        make(chan *Packet, 1),
		RecvQueue:        make(chan *Packet, 1),
		BlockSignal:      make(chan struct{}, 1),
		SetTimeoutSignal: make(chan struct{}, 1),
		StopSignal:       make(chan struct{}),
	}
}

// buildAgedPacket encrypts one packet from sender→peerPk and returns it
// paired with an InitTime aged `age` past the packet's send timestamp,
// so a later validatePeer sees the packet as `age` old. The send
// timestamp is stamped inside MsgToPacket at ~now; reading now right
// after is accurate to microseconds — far finer than the second-scale
// staleness floors — and any slack only makes the packet marginally
// OLDER, never crossing a boundary for the second-scale ages callers
// use. Shared by the staleness-floor call-site fences.
func buildAgedPacket(tb testing.TB, sender *Device, senderConn *ConnectionData, peerPk []byte, hdr int, age time.Duration) (*Packet, int64) {
	tb.Helper()
	mad, err := sender.MsgToPacket(&MsgData{ConnData: senderConn, PeerPk: peerPk, HeaderType: hdr, TransactionId: 1})
	if err != nil {
		tb.Fatalf("MsgToPacket(hdr=%d) failed: %v", hdr, err)
	}
	return &Packet{Content: append([]byte(nil), mad.BasePacket.Content...), HeaderType: hdr}, time.Now().UnixNano() + int64(age)
}

// overloadKnockFixture builds a real knock packet (NHP_KNK or DHP_KNK) from an
// agent plus the server device that parses it, to exercise the NHP-COK
// early-drop cookie path in validatePeer. registerAgent controls whether the
// agent's pubkey is in the server's peer pool — with agent peer validation on
// (the NHP_SERVER default), that decides whether the knock passes the peer-pool
// gate. These tests fence the behavior the #1131 review confirmed must hold: the
// overload cookie is issued for valid peers but never reflected to a pubkey that
// fails the peer-pool gate.
type overloadKnockFixture struct {
	server        *Device
	serverConn    *ConnectionData
	packetContent []byte
	initTime      int64
	headerType    int
}

func newOverloadKnockFixture(tb testing.TB, registerAgent bool, headerType int) overloadKnockFixture {
	tb.Helper()
	silenceGlobalLogger(tb)

	agentPrivKey := validatePeerPrivateKey(70)
	serverPrivKey := validatePeerPrivateKey(33)
	agentDevice := NewDevice(NHP_AGENT, agentPrivKey, nil)
	if agentDevice == nil {
		tb.Fatal("failed to create agent device")
	}
	serverDevice := NewDevice(NHP_SERVER, serverPrivKey, nil)
	if serverDevice == nil {
		tb.Fatal("failed to create server device")
	}

	serverPeer := &UdpPeer{
		PubKeyBase64: serverDevice.PublicKeyBase64(),
		Ip:           "127.0.0.1",
		Port:         12346,
		Type:         NHP_SERVER,
	}
	agentDevice.AddPeer(serverPeer)

	if registerAgent {
		serverDevice.AddPeer(&UdpPeer{
			PubKeyBase64: agentDevice.PublicKeyBase64(),
			Ip:           "127.0.0.1",
			Port:         12345,
			Type:         NHP_AGENT,
		})
	}

	agentConn := validatePeerConnectionData(agentDevice, 12345, 12346)
	mad, err := agentDevice.MsgToPacket(&MsgData{
		ConnData:      agentConn,
		PeerPk:        serverPeer.PublicKey(),
		HeaderType:    headerType,
		TransactionId: 1,
	})
	if err != nil {
		tb.Fatalf("MsgToPacket(%s) failed: %v", HeaderTypeToString(headerType), err)
	}

	return overloadKnockFixture{
		server:        serverDevice,
		serverConn:    validatePeerConnectionData(serverDevice, 12346, 12345),
		packetContent: append([]byte(nil), mad.BasePacket.Content...),
		initTime:      time.Now().UnixNano(),
		headerType:    headerType,
	}
}

// parse runs createPacketParserData + validatePeer and returns the resulting
// ppd together with the validatePeer error. Unlike validatePeerFixture's
// parseAndValidate, it never t.Fatal()s on that error — these tests assert on
// it directly.
func (f overloadKnockFixture) parse(tb testing.TB) (*PacketParserData, error) {
	tb.Helper()
	pkt := Packet{
		Content:    f.packetContent,
		HeaderType: f.headerType,
	}
	pd := PacketData{
		BasePacket: &pkt,
		ConnData:   f.serverConn,
		InitTime:   f.initTime,
	}
	ppd, err := f.server.createPacketParserData(&pd)
	if err != nil {
		return ppd, err
	}
	return ppd, ppd.validatePeer()
}

// TestValidatePeerOverloadKnockIssuesCookie pins the spec's NHP-COK early-drop
// (NHP.pdf §NHP-COK): under server overload, a registered agent's knock is
// answered with a cookie challenge (ErrServerRejectWithCookie) and the cookie
// is generated, so the agent can re-knock (NHP-RKN) carrying it. Covers both
// knock header types the overload short-circuit handles (NHP_KNK and DHP_KNK).
func TestValidatePeerOverloadKnockIssuesCookie(t *testing.T) {
	for _, headerType := range []int{NHP_KNK, DHP_KNK} {
		t.Run(HeaderTypeToString(headerType), func(t *testing.T) {
			fixture := newOverloadKnockFixture(t, true, headerType)
			fixture.server.SetOverload(true)

			ppd, err := fixture.parse(t)
			defer ppd.Destroy()

			assertNHPError(t, err, ErrServerRejectWithCookie)
			if IsZero(fixture.serverConn.CookieStore.CurrCookie[:]) {
				t.Fatal("overload knock: cookie was not generated (CookieStore.CurrCookie still zero)")
			}
		})
	}
}

// TestValidatePeerOverloadKnockUnregisteredNoCookie is the reflection-safety
// fence flagged by the #1131 review. With agent peer validation on (the
// NHP_SERVER default), an unregistered pubkey must be dropped at the peer-pool
// gate (ErrPeerNotFound) and must NOT elicit a cookie. A COK reply (~1.23x the
// minimal KNK that triggers it) sent to a forged source would be an
// amplification primitive — exactly the vector #1131 item 1 warns about — so a
// future refactor that moves the cookie emit ahead of this gate must fail here.
func TestValidatePeerOverloadKnockUnregisteredNoCookie(t *testing.T) {
	fixture := newOverloadKnockFixture(t, false, NHP_KNK)
	fixture.server.SetOverload(true)

	ppd, err := fixture.parse(t)
	defer ppd.Destroy()

	assertNHPError(t, err, ErrPeerNotFound)
	if !IsZero(fixture.serverConn.CookieStore.CurrCookie[:]) {
		t.Fatal("unregistered overload KNK must not generate a cookie (reflection guard)")
	}
}

// TestValidatePeerKnockNotOverloadCompletesHandshake confirms the cookie
// short-circuit is overload-gated: with the server NOT overloaded, a registered
// agent's KNK runs validatePeer to completion and no cookie is generated.
func TestValidatePeerKnockNotOverloadCompletesHandshake(t *testing.T) {
	fixture := newOverloadKnockFixture(t, true, NHP_KNK)
	// server overload deliberately left false

	ppd, err := fixture.parse(t)
	defer ppd.Destroy()

	if err != nil {
		t.Fatalf("non-overload KNK: validatePeer returned %v, want nil", err)
	}
	if !IsZero(fixture.serverConn.CookieStore.CurrCookie[:]) {
		t.Fatal("non-overload KNK must not generate a cookie")
	}
}

// TestIsAllowedAtOverload pins the server overload allowlist
// (PacketParserData.IsAllowedAtOverload), the gate that decides which packet
// types the server still processes while shedding load.
// NHP_RVA — the qURL v2 revocation proof-of-delivery ack (#2793) — MUST be
// admitted: dropping it under overload would strand the server's pending-revoke
// tracker and age a successfully-delivered revoke out to a false
// RevocationAgedOut. The denied cases fence the allowlist so a future widening
// is deliberate, and assert the asymmetry that only the AC→server ack NHP_RVA
// is admitted, NOT the server→AC revoke push NHP_REV.
func TestIsAllowedAtOverload(t *testing.T) {
	allowed := []int{NHP_KNK, DHP_KNK, NHP_RKN, NHP_EXT, NHP_AOL, NHP_ART, NHP_RLY, NHP_RVA}
	for _, ht := range allowed {
		if !(&PacketParserData{HeaderType: ht}).IsAllowedAtOverload() {
			t.Errorf("IsAllowedAtOverload(%s) = false, want true (must survive overload)", HeaderTypeToString(ht))
		}
	}
	denied := []int{NHP_REV, NHP_ACK, NHP_LST, NHP_AAK, NHP_COK, NHP_OTP, NHP_REG}
	for _, ht := range denied {
		if (&PacketParserData{HeaderType: ht}).IsAllowedAtOverload() {
			t.Errorf("IsAllowedAtOverload(%s) = true, want false (must be shed at overload)", HeaderTypeToString(ht))
		}
	}
}

// TestCreatePacketParserData_RejectsPreBindingProtocolVersion is the
// rollout-diagnosability fence for the protocol 1.1 HeaderCommon AAD binding.
//
// A peer still speaking 1.0 folds a shorter transcript into its body AAD, so its
// body tag can never verify here. Without an explicit gate the operator would see
// "aead decryption failed" — indistinguishable from a wrong key, a corrupted
// datagram, or an attack — instead of a statement that the two ends disagree on
// the protocol version. Both subcases therefore assert the error IDENTITY, not
// merely that the packet was refused.
//
// The gate must also run before the header-digest check and before every key
// agreement: the synthetic subcase carries no valid digest at all, so a gate
// placed later would surface ErrHeaderDigestCheckFailed instead.
func TestCreatePacketParserData_RejectsPreBindingProtocolVersion(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}

	t.Run("real packet downgraded to 1.0", func(t *testing.T) {
		wire := f.sealLST(t, bytes.Repeat([]byte{0xa5}, 64), 7, nil, false)
		if wire[8] != ProtocolVersionMajor || wire[9] != ProtocolVersionMinor {
			t.Fatalf("sealed version = %d.%d, want %d.%d", wire[8], wire[9], ProtocolVersionMajor, ProtocolVersionMinor)
		}
		wire[9] = MinimumRecvProtocolVersionMinor - 1
		// Re-stamp the digest so the digest gate cannot be what rejects this. An
		// off-path attacker can do exactly this with the server's PUBLIC key.
		restampHeaderDigest(t, wire, f.server.staticEcdh.PublicKey())

		_, err := f.parseOnHub(t, wire, source)
		if !errors.Is(err, ErrUnsupportedProtocolVersion) {
			t.Fatalf("downgraded packet error = %v, want ErrUnsupportedProtocolVersion", err)
		}
	})

	t.Run("unsupported major, ahead of the digest check", func(t *testing.T) {
		wire := f.sealLST(t, bytes.Repeat([]byte{0xa5}, 64), 8, nil, false)
		wire[8] = ProtocolVersionMajor + 1
		// Deliberately NOT re-stamped: the digest is now wrong too, and the
		// version error must still be the one reported.
		_, err := f.parseOnHub(t, wire, source)
		if !errors.Is(err, ErrUnsupportedProtocolVersion) {
			t.Fatalf("bad-major packet error = %v, want ErrUnsupportedProtocolVersion", err)
		}
	})

	t.Run("current version still parses", func(t *testing.T) {
		wire := f.sealLST(t, bytes.Repeat([]byte{0xa5}, 64), 9, nil, false)
		if _, err := f.parseOnHub(t, wire, source); !errors.Is(err, ErrHubLSTCookieProofRequired) {
			t.Fatalf("current-version packet error = %v, want the ordinary Hub proof challenge", err)
		}
	})
}

// restampHeaderDigest recomputes the ordinary (cookie-free) header digest over a
// mutated packet, matching MsgAssemblerData.addHeaderDigest. It exists so a
// version subcase can defeat the unkeyed digest gate on purpose and prove the
// version gate is the one that fires.
func restampHeaderDigest(t *testing.T, wire []byte, peerStaticPub []byte) {
	t.Helper()
	h, err := NewHash(HASH_BLAKE2S)
	if err != nil {
		t.Fatalf("NewHash: %v", err)
	}
	h.Write(initialHashBytes)
	h.Write(peerStaticPub)
	h.Write(wire[:curveHeaderDigestOffset])
	copy(wire[curveHeaderDigestOffset:curveHeaderDigestOffset+HashSize], h.Sum(nil))
}

// curveHeaderDigestOffset is the HeaderCurve offset of the digest field: the
// 24-byte common header, the ephemeral key, the identity field, and the sealed
// static and timestamp fields all precede it.
const curveHeaderDigestOffset = HeaderCommonSize + PublicKeySize +
	(PublicKeySizeEx + GCMTagSize) + (PublicKeySize + GCMTagSize) + (TimestampSize + GCMTagSize)

// wireTypeAndSize / setWireTypeAndSize read and rewrite the obfuscated
// type+payload-size word straight on the wire, mirroring
// curve.HeaderCurve.TypeAndPayloadSize / SetTypeAndPayloadSize. The setter takes
// the preamble as a parameter (the real one randomizes it) so a test can hold the
// logical type and size fixed while changing the serialized bytes, or the reverse.
func wireTypeAndSize(wire []byte) (int, int) {
	tns := binary.BigEndian.Uint32(wire[0:4]) ^ binary.BigEndian.Uint32(wire[4:8])
	return int(tns >> 16), int(tns & 0xFFFF)
}

func setWireTypeAndSize(wire []byte, preamble uint32, headerType int, payloadSize int) {
	binary.BigEndian.PutUint32(wire[0:4], preamble)
	binary.BigEndian.PutUint32(wire[4:8], preamble^(uint32(payloadSize&0xFFFF)|uint32((headerType&0xFFFF)<<16)))
}

// headerTamperFixture is a registered agent/server pair that seals an ordinary
// non-empty-body NHP_KNK. Unlike newHubLSTCookieFixture it uses a registered peer
// and a type with no per-type header gate in front of the body open, so a
// mutated HeaderCommon reaches the AEAD instead of tripping the peer-pool check
// or the Hub LST flag validator first.
type headerTamperFixture struct {
	agent  *Device
	server *Device
	body   []byte
}

func newHeaderTamperFixture(t *testing.T) headerTamperFixture {
	t.Helper()
	silenceGlobalLogger(t)

	agent := NewDevice(NHP_AGENT, validatePeerPrivateKey(0x11), nil)
	server := NewDevice(NHP_SERVER, validatePeerPrivateKey(0x51), nil)
	if agent == nil || server == nil {
		t.Fatal("create header-tamper devices")
	}
	agent.AddPeer(&UdpPeer{PubKeyBase64: server.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12346, Type: NHP_SERVER})
	server.AddPeer(&UdpPeer{PubKeyBase64: agent.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12345, Type: NHP_AGENT})

	return headerTamperFixture{
		agent:  agent,
		server: server,
		body:   []byte(`{"type":"knock","resource":"test-service","user":"alice"}`),
	}
}

func (f headerTamperFixture) sealKnock(t *testing.T, counter uint64) []byte {
	t.Helper()
	mad, err := f.agent.MsgToPacket(&MsgData{
		ConnData:      validatePeerConnectionData(f.agent, 12345, 12346),
		PeerPk:        f.server.staticEcdh.PublicKey(),
		HeaderType:    NHP_KNK,
		TransactionId: counter,
		Message:       f.body,
	})
	if err != nil {
		t.Fatalf("seal NHP_KNK: %v", err)
	}
	return bytes.Clone(mad.BasePacket.Content)
}

func (f headerTamperFixture) parseOnServer(t *testing.T, wire []byte) (*PacketParserData, error) {
	t.Helper()
	headerType, _ := wireTypeAndSize(wire)
	return f.server.PacketToMsg(&PacketData{
		BasePacket: &Packet{Content: bytes.Clone(wire), HeaderType: headerType},
		ConnData:   validatePeerConnectionData(f.server, 12346, 12345),
		InitTime:   time.Now().UnixNano(),
	})
}

// TestDecryptBody_RejectsHeaderCommonTamper is the direct fence for the protocol
// 1.1 binding, on a packet that actually carries a body seal.
//
// Every subcase re-stamps the unkeyed header digest, which an off-path attacker
// can do holding nothing but the responder's static PUBLIC key — so the digest
// gate is deliberately defeated and cannot be what rejects the packet. Under 1.0
// all of these were accepted verbatim: HeaderCommon was covered by that digest
// and by nothing else. The body tag is the only thing that rejects them now,
// which is why each subcase asserts ErrAEADDecryptionFailed specifically rather
// than "some error".
//
// The mutations are chosen to reach the AEAD: each leaves the packet
// structurally valid, so RecvPrecheck's type/length checks, the version gate and
// the peer-pool lookup all pass and the body Open is the first thing that can
// object.
func TestDecryptBody_RejectsHeaderCommonTamper(t *testing.T) {
	f := newHeaderTamperFixture(t)

	// Baseline: the untouched packet round-trips. Without it the subcases below
	// could all be passing because the fixture never reached the body seal.
	ppd, err := f.parseOnServer(t, f.sealKnock(t, 20))
	if err != nil {
		t.Fatalf("untampered packet: %v", err)
	}
	if !bytes.Equal(ppd.BodyMessage, f.body) {
		t.Fatalf("untampered body = %q, want %q", ppd.BodyMessage, f.body)
	}

	tests := []struct {
		name   string
		mutate func(t *testing.T, wire []byte)
	}{
		{
			// The original exploit this change closes: raising COMPRESS on a
			// packet sealed uncompressed made the receiver hand its caller a raw
			// zlib stream in place of the plaintext.
			name: "compress flag raised",
			mutate: func(t *testing.T, wire []byte) {
				t.Helper()
				binary.BigEndian.PutUint16(wire[10:12], common.NHP_FLAG_COMPRESS)
			},
		},
		{
			// Payload size held fixed so RecvPrecheck's total-length check still
			// passes, and the swapped type stays inside the server's
			// CheckRecvHeaderType allowlist; the type is the only thing that moves.
			name: "header type swapped, payload size preserved",
			mutate: func(t *testing.T, wire []byte) {
				t.Helper()
				headerType, size := wireTypeAndSize(wire)
				if headerType != NHP_KNK {
					t.Fatalf("fixture header type = %d, want NHP_KNK", headerType)
				}
				setWireTypeAndSize(wire, binary.BigEndian.Uint32(wire[0:4]), NHP_EXT, size)
			},
		},
		{
			// Same logical type and payload size, different serialized bytes.
			// Nothing above the AEAD can even see this edit — it is the proof
			// that the fold covers the header AS SERIALIZED, which is what lets
			// the two implementations interoperate over the masked flag word and
			// the obfuscated type+size field.
			name: "preamble rewritten, type and payload size preserved",
			mutate: func(t *testing.T, wire []byte) {
				t.Helper()
				headerType, size := wireTypeAndSize(wire)
				setWireTypeAndSize(wire, ^binary.BigEndian.Uint32(wire[0:4]), headerType, size)
				if gotType, gotSize := wireTypeAndSize(wire); gotType != headerType || gotSize != size {
					t.Fatalf("re-encoded type/size = %d/%d, want %d/%d", gotType, gotSize, headerType, size)
				}
			},
		},
		{
			// A minor above the floor is admitted by design, so the version gate
			// passes and the fold is what catches it. This is the shape a future
			// 1.2 with a different AAD would take on a deployed 1.1 receiver —
			// see MinimumRecvProtocolVersionMinor in constants.go.
			name: "version minor raised above the floor",
			mutate: func(t *testing.T, wire []byte) {
				t.Helper()
				wire[9] = ProtocolVersionMinor + 1
			},
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire := f.sealKnock(t, uint64(30+i))
			tc.mutate(t, wire)
			restampHeaderDigest(t, wire, f.server.staticEcdh.PublicKey())

			_, err := f.parseOnServer(t, wire)
			assertNHPError(t, err, ErrAEADDecryptionFailed)
		})
	}
}

// TestDecryptBody_EmptyBodyHeaderIsNotAADBound pins the residual gap documented
// at initiator.go encryptBody, so it stays a KNOWN limitation rather than
// quietly becoming an assumed-closed one.
//
// This test asserts that a forgery SUCCEEDS. That is the point: an empty-body
// packet runs no AEAD, so there is no tag to carry the HeaderCommon AAD and the
// header is covered only by the unkeyed digest — which an off-path attacker
// re-stamps with the responder's static PUBLIC key alone. The 1.1 binding does
// not reach these packets, and the version gate in createPacketParserData does
// not either: a minor at or above the floor is admitted by design, so the
// attacker simply picks one. Containment is CheckRecvHeaderType and the counter's
// binding as the GCM nonce.
//
// WHEN THE HEADER-ONLY AEAD LANDS, THIS TEST MUST FAIL and be rewritten to
// assert rejection. Do not relax it to keep it green.
func TestDecryptBody_EmptyBodyHeaderIsNotAADBound(t *testing.T) {
	f := newHeaderTamperFixture(t)
	f.body = nil

	// Header and nothing else: this is the no-AEAD shape decryptBody early-returns
	// on, not the tag-only body that sealEmptyAEADLST builds (which does fold).
	wire := f.sealKnock(t, 40)
	if got, want := len(wire), curveHeaderDigestOffset+HashSize; got != want {
		t.Fatalf("empty-body packet length = %d, want header-only %d", got, want)
	}

	// The documented invariant: an empty-body packet still round-trips.
	ppd, err := f.parseOnServer(t, wire)
	if err != nil {
		t.Fatalf("empty-body packet: %v", err)
	}
	if len(ppd.BodyMessage) != 0 {
		t.Fatalf("empty-body BodyMessage = %q, want empty", ppd.BodyMessage)
	}

	// The documented residual: the same edit that
	// TestDecryptBody_RejectsHeaderCommonTamper proves is caught on a
	// body-carrying packet is accepted here.
	tampered := f.sealKnock(t, 41)
	tampered[9] = ProtocolVersionMinor + 1
	restampHeaderDigest(t, tampered, f.server.staticEcdh.PublicKey())
	if _, err := f.parseOnServer(t, tampered); err != nil {
		t.Fatalf("empty-body header tamper = %v; the residual gap documented in "+
			"initiator.go encryptBody says this is accepted. If a header-only AEAD "+
			"now closes it, update that note and rewrite this test to assert rejection", err)
	}
}
