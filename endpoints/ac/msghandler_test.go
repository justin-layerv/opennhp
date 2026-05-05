package ac

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestHandleUdpACOperations_DedupeRunsBeforeUnmarshal pins the
// ordering invariant from issue #1123: the AOP replay-dedupe gate
// runs ahead of json.Unmarshal and HandleAccessControl, so a
// future refactor that moves the dedupe call below either of them
// fails this test even though every aopReplayCache unit test still
// passes. We verify ordering by handing the function a
// deliberately-malformed BodyMessage: if dedupe runs first, we get
// ErrACDuplicateTransaction; if it runs after Unmarshal, we get a
// parse error first.
//
// The pre-mark and the ppd construction MUST share the same
// sendTime; the cache key is (pubkey, txid, sendTime), so a
// mismatch silently turns this into a first-seen and the
// ordering-invariant assertion would pass for the wrong reason.
func TestHandleUdpACOperations_DedupeRunsBeforeUnmarshal(t *testing.T) {
	a := &UdpAC{
		config:    &Config{ACId: "test-ac"},
		aopReplay: newAOPReplayCache(),
	}

	const txid uint64 = 100
	pub := pubkeyN('A')

	// Pre-mark the (pubkey, txid, sendTime) triple so the call we
	// measure sees it as a duplicate.
	if !a.aopReplay.MarkSeen(pub, txid, testSendTime) {
		t.Fatal("first MarkSeen must succeed")
	}

	ppd := &core.PacketParserData{
		SenderTrxId:    txid,
		RemotePubKey:   pub,
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
		// BodyMessage left nil — json.Unmarshal would error on it.
	}

	err := a.HandleUdpACOperations(ppd)

	if !errors.Is(err, common.ErrACDuplicateTransaction) {
		t.Fatalf("got err=%v, want ErrACDuplicateTransaction (dedupe must run before json.Unmarshal)", err)
	}
}

// TestHandleUdpACOperations_EmptyPubkeyDistinct asserts the
// fail-closed pubkey check returns ErrACMissingPeerPubkey, NOT
// ErrACDuplicateTransaction. Distinguishing these matters for
// oncall: a duplicate-spike alert should not be triggered by an
// upstream invariant violation (validatePeer didn't populate
// RemotePubKey).
func TestHandleUdpACOperations_EmptyPubkeyDistinct(t *testing.T) {
	a := &UdpAC{
		config:    &Config{ACId: "test-ac"},
		aopReplay: newAOPReplayCache(),
	}

	ppd := &core.PacketParserData{
		SenderTrxId:    300,
		RemotePubKey:   nil,
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
	}

	err := a.HandleUdpACOperations(ppd)

	if !errors.Is(err, common.ErrACMissingPeerPubkey) {
		t.Fatalf("got err=%v, want ErrACMissingPeerPubkey (empty pubkey must not masquerade as duplicate)", err)
	}
	if errors.Is(err, common.ErrACDuplicateTransaction) {
		t.Fatal("empty pubkey must not surface as a duplicate transaction")
	}
}

// TestHandleUdpACOperations_WrongLengthPubkeyDistinct fences the
// round-8 cr bug: a hypothetical 31- or 64-byte RemotePubKey
// (future cipher scheme regression, parser bug, fuzz harness) used
// to fall through the handler's zero-length-only check, then get
// rejected at MarkSeen's `len != PublicKeySize` guard, and surface
// as ErrACDuplicateTransaction — exactly the masquerade that
// adding ErrACMissingPeerPubkey was supposed to prevent. The
// handler check now matches the cache's invariant, so wrong-length
// pubkeys take the same Critical-log + ErrACMissingPeerPubkey path
// as zero-length.
func TestHandleUdpACOperations_WrongLengthPubkeyDistinct(t *testing.T) {
	a := &UdpAC{
		config:    &Config{ACId: "test-ac"},
		aopReplay: newAOPReplayCache(),
	}

	for _, n := range []int{1, 16, core.PublicKeySize - 1, core.PublicKeySize + 1, 64} {
		t.Run("len="+strconv.Itoa(n), func(t *testing.T) {
			ppd := &core.PacketParserData{
				SenderTrxId:    400,
				RemotePubKey:   bytes.Repeat([]byte{'X'}, n),
				RemoteSendTime: testSendTime,
				HeaderType:     core.NHP_AOP,
			}
			err := a.HandleUdpACOperations(ppd)

			if !errors.Is(err, common.ErrACMissingPeerPubkey) {
				t.Fatalf("got err=%v, want ErrACMissingPeerPubkey (wrong-length pubkey must not masquerade as duplicate)", err)
			}
			if errors.Is(err, common.ErrACDuplicateTransaction) {
				t.Fatal("wrong-length pubkey must not surface as a duplicate transaction")
			}
		})
	}
}

// TestHandleUdpACOperations_FirstSeenProceedsToUnmarshal is the
// counterpart fence: a fresh (pubkey, txid, sendTime) triple must
// NOT short-circuit at the dedupe gate. With a parseable but empty
// BodyMessage, json.Unmarshal succeeds, HandleAccessControl logs
// ErrACEmptyPassAddress (no src/dst addrs) but the function
// continues and ART-forwarding fails on an empty
// RemoteTransactionMap with ErrTransactionIdNotFound. The test
// asserts the error is the downstream class, NOT
// ErrACDuplicateTransaction — i.e., dedupe let the call through
// and a downstream gate fired.
//
// Hardening over a previous nil-body shape: an explicit
// downstream-error assertion + minimal ConnData fixture means a
// future refactor that reorders device-touching code above
// json.Unmarshal still surfaces loudly (wrong error class) instead
// of relying on parse failure to short-circuit before any
// device-touching call. The fixture deliberately stops at
// ConnData{} (zero-value) — RemoteTransactionMap is nil and a nil
// map read in FindRemoteTransaction returns nil cleanly under the
// mutex.
func TestHandleUdpACOperations_FirstSeenProceedsToUnmarshal(t *testing.T) {
	a := &UdpAC{
		config:    &Config{ACId: "test-ac"},
		aopReplay: newAOPReplayCache(),
	}

	ppd := &core.PacketParserData{
		SenderTrxId:    200,
		RemotePubKey:   pubkeyN('B'),
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
		BodyMessage:    []byte("{}"),
		ConnData:       &core.ConnectionData{},
	}

	err := a.HandleUdpACOperations(ppd)

	if err == nil {
		t.Fatal("first-seen triple with empty body must surface a downstream error, not nil")
	}
	if errors.Is(err, common.ErrACDuplicateTransaction) {
		t.Fatal("first-seen triple must not be reported as duplicate (dedupe short-circuited incorrectly)")
	}
	if !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("got err=%v, want ErrTransactionIdNotFound (empty body reaches HandleAccessControl + ART forwarding; absence of a remote transaction is the deterministic downstream failure)", err)
	}
}

// TestHandleAccessControl_SentinelIP tests that the sentinel IP (SentinelLocalIP)
// is replaced with the AC's DefaultIp. This is used by QURL resources
// where the destination is the AC itself (Traefik proxy).
//
// NOTE: This test duplicates the sentinel replacement logic from HandleAccessControl
// rather than calling the method directly. This is intentional because calling
// HandleAccessControl requires a fully initialized AC with iptables/ipset, which
// isn't practical for unit tests. The logic being tested is simple (string comparison
// and assignment), so duplication risk is low.
func TestHandleAccessControl_SentinelIP(t *testing.T) {
	tests := []struct {
		name        string
		defaultIp   string
		dstIp       string
		expectedIp  string
		description string
	}{
		{
			name:        "sentinel_0.0.0.0_replaced",
			defaultIp:   "10.0.1.50",
			dstIp:       SentinelLocalIP,
			expectedIp:  "10.0.1.50",
			description: "SentinelLocalIP should be replaced with DefaultIp",
		},
		{
			name:        "empty_ip_replaced",
			defaultIp:   "10.0.1.50",
			dstIp:       "",
			expectedIp:  "10.0.1.50",
			description: "empty IP should be replaced with DefaultIp",
		},
		{
			name:        "real_ip_preserved",
			defaultIp:   "10.0.1.50",
			dstIp:       "192.168.1.100",
			expectedIp:  "192.168.1.100",
			description: "real IP should be preserved",
		},
		{
			name:        "no_default_ip_sentinel_unchanged",
			defaultIp:   "",
			dstIp:       SentinelLocalIP,
			expectedIp:  SentinelLocalIP,
			description: "sentinel unchanged when DefaultIp not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create AC with test config
			ac := &UdpAC{
				config: &Config{
					ACId:      "test-ac",
					DefaultIp: tt.defaultIp,
				},
			}

			// Create destination address
			dstAddrs := []*common.NetAddress{
				{
					Ip:   tt.dstIp,
					Port: 443,
				},
			}

			// Apply the sentinel replacement logic (mirrors HandleAccessControl)
			if len(ac.config.DefaultIp) > 0 {
				for _, addr := range dstAddrs {
					if len(addr.Ip) == 0 || addr.Ip == SentinelLocalIP {
						addr.Ip = ac.config.DefaultIp
					}
				}
			}

			// Verify result
			if dstAddrs[0].Ip != tt.expectedIp {
				t.Errorf("%s: got IP %q, want %q", tt.description, dstAddrs[0].Ip, tt.expectedIp)
			}
		})
	}
}

// TestHandleAccessControl_SentinelIP_MultipleAddresses tests sentinel replacement
// with multiple destination addresses.
func TestHandleAccessControl_SentinelIP_MultipleAddresses(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:      "test-ac",
			DefaultIp: "10.0.1.50",
		},
	}

	dstAddrs := []*common.NetAddress{
		{Ip: SentinelLocalIP, Port: 443}, // sentinel - should be replaced
		{Ip: "192.168.1.100", Port: 22},  // real IP - should be preserved
		{Ip: "", Port: 8080},             // empty - should be replaced
	}

	// Apply the sentinel replacement logic (mirrors HandleAccessControl)
	if len(ac.config.DefaultIp) > 0 {
		for _, addr := range dstAddrs {
			if len(addr.Ip) == 0 || addr.Ip == SentinelLocalIP {
				addr.Ip = ac.config.DefaultIp
			}
		}
	}

	// Verify results
	expected := []string{"10.0.1.50", "192.168.1.100", "10.0.1.50"}
	for i, addr := range dstAddrs {
		if addr.Ip != expected[i] {
			t.Errorf("address[%d]: got IP %q, want %q", i, addr.Ip, expected[i])
		}
	}
}
