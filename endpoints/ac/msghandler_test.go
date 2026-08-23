package ac

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

type recordingIPSetAdd struct {
	ipType  utils.IPTYPE
	setType int
	expire  int
	args    []string
}

type recordingIPSet struct {
	adds   []recordingIPSetAdd
	err    error
	events *[]string
}

var _ ipsetWriter = (*recordingIPSet)(nil)

func (r *recordingIPSet) Add(ipType utils.IPTYPE, setType int, expire int, args ...string) (string, error) {
	if r.events != nil {
		*r.events = append(*r.events, "ipset")
	}
	r.adds = append(r.adds, recordingIPSetAdd{
		ipType:  ipType,
		setType: setType,
		expire:  expire,
		args:    append([]string(nil), args...),
	})
	if r.err != nil {
		return "", r.err
	}
	return "", nil
}

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
		config:       &Config{ACId: "test-ac"},
		aopReplay:    newAOPReplayCache(),
		registration: &ACRegistration{metrics: metrics.NewPublisherForTest(t)},
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

	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricAOPReplayDetected]; got != 1 {
		t.Fatalf("%s counter = %v, want 1", MetricAOPReplayDetected, got)
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
// BodyMessage carrying the required 1.2 base fields, strict decode succeeds, HandleAccessControl logs
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
		config:     &Config{ACId: "test-ac"},
		aopReplay:  newAOPReplayCache(),
		tokenStore: common.NewTokenStore[*AccessEntry](),
	}

	ppd := &core.PacketParserData{
		SenderTrxId:    200,
		RemotePubKey:   pubkeyN('B'),
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
		BodyMessage: []byte(fmt.Sprintf(
			`{"sessId":1,"sessOwnerId":"00112233445566778899aabbccddeeff","agentPubKey":%q,"sessIssuedAtMillis":1,"opnTime":1}`,
			base64.StdEncoding.EncodeToString(pubkeyN('A')),
		)),
		ConnData: &core.ConnectionData{},
	}

	err := a.HandleUdpACOperations(ppd)

	if err == nil {
		t.Fatal("first-seen triple with empty body must surface a downstream error, not nil")
	}
	if errors.Is(err, common.ErrACDuplicateTransaction) {
		t.Fatal("first-seen triple must not be reported as duplicate (dedupe short-circuited incorrectly)")
	}
	if !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("got err=%v, want ErrTransactionIdNotFound (valid base fields reach HandleAccessControl + ART forwarding; absence of a remote transaction is the deterministic downstream failure)", err)
	}
}

func TestHandleUdpACOperations_ZeroSessionDoesNotAdmit(t *testing.T) {
	ipset := &recordingIPSet{}
	a := &UdpAC{
		config:     &Config{ACId: "test-ac", DefaultIp: "10.0.0.5", FilterMode: FilterMode_IPTABLES, IpPassMode: PASS_KNOCK_IP},
		ipset:      ipset,
		aopReplay:  newAOPReplayCache(),
		tokenStore: common.NewTokenStore[*AccessEntry](),
	}
	body := []byte(`{"sessId":0,"usrId":"user","aspId":"agent","srcAddrs":[{"ip":"203.0.113.10"}],"dstAddrs":[{"ip":"10.0.0.5","port":443,"protocol":"tcp"}],"opnTime":60}`)
	err := a.HandleUdpACOperations(&core.PacketParserData{
		SenderTrxId:    201,
		RemotePubKey:   pubkeyN('C'),
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
		BodyMessage:    body,
		ConnData:       &core.ConnectionData{},
	})
	if err == nil || !strings.Contains(err.Error(), "canonical nonzero uint64") {
		t.Fatalf("zero-session AOP terminal error = %v, want strict sessId rejection before ART", err)
	}
	if len(ipset.adds) != 0 {
		t.Fatalf("zero-session AOP wrote access rules: %+v", ipset.adds)
	}
}

func TestHandleUdpACOperations_ZeroOpenTimeClosesExactNHPSession(t *testing.T) {
	scheduler := NewScheduler(&NoOpFlusher{}, WithTickInterval(time.Millisecond))
	scheduler.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = scheduler.Shutdown(ctx)
	})
	a := &UdpAC{
		config:      &Config{ACId: "test-ac"},
		aopReplay:   newAOPReplayCache(),
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
		expirySched: scheduler,
	}
	a.sessionFlushComplete.Store(true)
	serverKey := base64.StdEncoding.EncodeToString(pubkeyN('D'))
	agentKey := base64.StdEncoding.EncodeToString(pubkeyN('A'))
	const owner = "00112233445566778899aabbccddeeff"
	issuedAt := time.UnixMilli(1_700_000_000_000)
	target := &AccessEntry{OpenTime: 60, NHPSessionId: 101, NHPServerPublicKey: serverKey, NHPSessionOwnerId: owner, NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: issuedAt.UnixMilli()}
	sibling := &AccessEntry{OpenTime: 60, NHPSessionId: 202, NHPServerPublicKey: serverKey, NHPSessionOwnerId: owner, NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: issuedAt.UnixMilli()}
	crossServerSibling := &AccessEntry{OpenTime: 60, NHPSessionId: 101, NHPServerPublicKey: base64.StdEncoding.EncodeToString(pubkeyN('E')), NHPSessionOwnerId: owner, NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: issuedAt.Add(time.Millisecond).UnixMilli()}
	targetToken := a.GenerateAccessToken(target)
	siblingToken := a.GenerateAccessToken(sibling)
	crossServerToken := a.GenerateAccessToken(crossServerSibling)

	body, err := json.Marshal(&common.ServerACOpsMsg{SessionId: 101, SessionOwnerId: owner, AgentPublicKey: agentKey, SessionIssuedAtMillis: issuedAt.UnixMilli(), OpenTime: 0})
	if err != nil {
		t.Fatal(err)
	}
	err = a.HandleUdpACOperations(&core.PacketParserData{
		SenderTrxId:    202,
		RemotePubKey:   pubkeyN('D'),
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
		BodyMessage:    body,
		ConnData:       &core.ConnectionData{},
	})
	if !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("close-session AOP terminal error = %v, want ART forwarding failure after close", err)
	}
	if _, ok := a.tokenStore.Load(targetToken); ok {
		t.Fatal("target numeric session remained live after opnTime=0 AOP")
	}
	if _, ok := a.tokenStore.Load(siblingToken); !ok {
		t.Fatal("different numeric session was closed")
	}
	if _, ok := a.tokenStore.Load(crossServerToken); !ok {
		t.Fatal("same numeric session from a different authenticated server was closed")
	}
	if got := a.CloseNHPSession(serverKey, owner, 101); got != 0 {
		t.Fatalf("duplicate close count = %d, want idempotent 0", got)
	}
}

func TestHandleUdpACOperations_ZeroOpenTimeRejectsBeforeBootFlushCompletes(t *testing.T) {
	a := &UdpAC{
		config:      &Config{ACId: "test-ac"},
		aopReplay:   newAOPReplayCache(),
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
	}
	agentKey := base64.StdEncoding.EncodeToString(pubkeyN('A'))
	entry := &AccessEntry{
		OpenTime:                 60,
		NHPSessionId:             101,
		NHPServerPublicKey:       base64.StdEncoding.EncodeToString(pubkeyN('D')),
		NHPSessionOwnerId:        "00112233445566778899aabbccddeeff",
		NHPAgentPublicKey:        agentKey,
		NHPSessionIssuedAtMillis: 1_700_000_000_000,
	}
	token := a.GenerateAccessToken(entry)
	body, err := json.Marshal(&common.ServerACOpsMsg{
		SessionId:             entry.NHPSessionId,
		SessionOwnerId:        entry.NHPSessionOwnerId,
		AgentPublicKey:        entry.NHPAgentPublicKey,
		SessionIssuedAtMillis: entry.NHPSessionIssuedAtMillis,
		OpenTime:              0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = a.HandleUdpACOperations(&core.PacketParserData{
		SenderTrxId:    203,
		RemotePubKey:   pubkeyN('D'),
		RemoteSendTime: testSendTime,
		HeaderType:     core.NHP_AOP,
		BodyMessage:    body,
		ConnData:       &core.ConnectionData{},
	})
	if _, ok := a.tokenStore.Load(token); !ok {
		t.Fatal("zero-open-time AOP removed a session before boot flush completed")
	}
	if !a.nhpSessions.admitsSession(sessionFenceEntry(agentKey, entry.NHPSessionId, entry.NHPSessionIssuedAtMillis)) {
		t.Fatal("zero-open-time AOP published a close fence before boot flush completed")
	}
}

func TestHandleUdpACOperations_ZeroOpenTimeKeepsExactFencePendingUntilFlushRetry(t *testing.T) {
	flusher := &failFirstSessionControlFlusher{}
	scheduler := NewScheduler(flusher, WithTickInterval(time.Hour))
	scheduler.Start()
	t.Cleanup(func() { shutdownOrFail(t, scheduler) })
	a := &UdpAC{
		config:      &Config{ACId: "test-ac", FilterMode: FilterMode_IPTABLES},
		aopReplay:   newAOPReplayCache(),
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
		expirySched: scheduler,
	}
	a.sessionFlushComplete.Store(true)
	base := time.Unix(1_700_000_000, 0)
	now := base
	a.nhpSessions.now = func() time.Time { return now }
	serverKey := base64.StdEncoding.EncodeToString(pubkeyN('D'))
	agentKey := base64.StdEncoding.EncodeToString(pubkeyN('A'))
	const owner = "00112233445566778899aabbccddeeff"
	key, err := MakeFlowKey("192.0.2.70", "192.0.2.80", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	target := &AccessEntry{
		OpenTime:                 60,
		NHPSessionId:             101,
		NHPServerPublicKey:       serverKey,
		NHPSessionOwnerId:        owner,
		NHPAgentPublicKey:        agentKey,
		NHPSessionIssuedAtMillis: 1000,
	}
	target.recordScheduledKey(key)
	targetToken := a.GenerateAccessToken(target)
	sibling := &AccessEntry{
		OpenTime:                 60,
		NHPSessionId:             101,
		NHPServerPublicKey:       serverKey,
		NHPSessionOwnerId:        "ffeeddccbbaa99887766554433221100",
		NHPAgentPublicKey:        agentKey,
		NHPSessionIssuedAtMillis: 1001,
	}
	siblingToken := a.GenerateAccessToken(sibling)
	scheduler.Schedule(key, time.Now().Add(time.Hour))
	body, err := json.Marshal(&common.ServerACOpsMsg{
		SessionId:             101,
		SessionOwnerId:        owner,
		AgentPublicKey:        agentKey,
		SessionIssuedAtMillis: 1000,
		OpenTime:              0,
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := func(transactionID uint64, sendTime int64) {
		t.Helper()
		_ = a.HandleUdpACOperations(&core.PacketParserData{
			SenderTrxId:    transactionID,
			RemotePubKey:   pubkeyN('D'),
			RemoteSendTime: sendTime,
			HeaderType:     core.NHP_AOP,
			BodyMessage:    body,
			ConnData:       &core.ConnectionData{},
		})
	}

	handle(300, testSendTime)
	if _, ok := a.tokenStore.Load(targetToken); !ok {
		t.Fatal("failed legacy exact close removed retry state")
	}
	now = base.Add(10 * nhpSessionCloseFenceTTL)
	if a.nhpSessions.admitsSession(sessionFenceEntry(agentKey, 101, 1000)) {
		t.Fatal("failed legacy exact close fence expired before convergence")
	}
	if !a.nhpSessions.admitsSession(sessionFenceEntry(agentKey, 101, 1001)) {
		t.Fatal("failed legacy exact close rejected sibling issuance")
	}

	handle(301, testSendTime+1)
	if got := flusher.count(); got != 2 {
		t.Fatalf("flush calls = %d, want failed attempt plus retry", got)
	}
	if _, ok := a.tokenStore.Load(targetToken); ok {
		t.Fatal("retried legacy exact close retained target")
	}
	if _, ok := a.tokenStore.Load(siblingToken); !ok {
		t.Fatal("retried legacy exact close removed sibling")
	}
	now = now.Add(nhpSessionCloseFenceTTL)
	if !a.nhpSessions.admitsSession(sessionFenceEntry(agentKey, 101, 1000)) {
		t.Fatal("converged legacy exact fence did not expire at replay boundary")
	}
}

// TestAccessEntryFromAOP_StoresQurlV2Metadata proves the AC stores the qURL v2
// revocation metadata (P4a) verbatim from the NHP-AOP onto the AccessEntry it
// admits. P4b's targeted-revocation index match depends on the stored value
// being byte-identical to what the server stamped, so the AC must store the
// hashes as received and MUST NOT recompute them — this asserts pass-through.
func TestAccessEntryFromAOP_StoresQurlV2Metadata(t *testing.T) {
	dop := &common.ServerACOpsMsg{
		SessionId:        0x0123456789abcdef,
		UserId:           "u",
		DeviceId:         "d",
		OrganizationId:   "org",
		AuthServiceId:    "asp",
		SourceAddrs:      []*common.NetAddress{{Ip: "203.0.113.9", Port: 5555}},
		DestinationAddrs: []*common.NetAddress{{Ip: "10.0.0.5", Port: 8443}},
		OpenTime:         60,

		QurlUserPublicKeyHash: "a1b2c3",
		ResourcePublicKeyHash: "d4e5f6",
		QurlSessionId:         "sess_123",
		AdmissionId:           "adm_test123",
		RevocationEpoch:       42,
		Deadline:              1781910300,
	}

	const serverKey = "server-public-key"
	entry := accessEntryFromAOP(dop, serverKey)
	if entry.NHPSessionId != dop.SessionId {
		t.Errorf("NHPSessionId = %#x, want base session %#x", entry.NHPSessionId, dop.SessionId)
	}
	if entry.NHPServerPublicKey != serverKey {
		t.Errorf("NHPServerPublicKey = %q, want %q", entry.NHPServerPublicKey, serverKey)
	}

	if entry.QurlUserPublicKeyHash != "a1b2c3" {
		t.Errorf("QurlUserPublicKeyHash = %q, want %q (verbatim from AOP)", entry.QurlUserPublicKeyHash, "a1b2c3")
	}
	if entry.ResourcePublicKeyHash != "d4e5f6" {
		t.Errorf("ResourcePublicKeyHash = %q, want %q (verbatim from AOP)", entry.ResourcePublicKeyHash, "d4e5f6")
	}
	if entry.QurlSessionId != "sess_123" {
		t.Errorf("QurlSessionId = %q, want %q", entry.QurlSessionId, "sess_123")
	}
	if entry.AdmissionId != "adm_test123" {
		t.Errorf("AdmissionId = %q, want %q", entry.AdmissionId, "adm_test123")
	}
	if entry.RevocationEpoch != 42 {
		t.Errorf("RevocationEpoch = %d, want %d", entry.RevocationEpoch, 42)
	}
	if entry.Deadline != 1781910300 {
		t.Errorf("Deadline = %d, want %d", entry.Deadline, 1781910300)
	}

	// Existing (non-metadata) mapping still holds.
	if entry.User == nil || entry.User.UserId != "u" || entry.User.AuthServiceId != "asp" {
		t.Errorf("User mapping wrong: %#v", entry.User)
	}
	if entry.OpenTime != 60 {
		t.Errorf("OpenTime = %d, want 60", entry.OpenTime)
	}
	// OwnerId stays empty on the AC side by invariant (server-resolved only).
	if entry.User != nil && entry.User.OwnerId != "" {
		t.Errorf("OwnerId = %q, want empty (server-resolved-only invariant)", entry.User.OwnerId)
	}
}

// TestAccessEntryFromAOP_LegacyAOP_NoMetadata proves a legacy / non-qURL-v2 AOP
// (the six fields absent on the wire, so zero after unmarshal) produces an
// AccessEntry with zero-valued revocation metadata — the AC store is unchanged
// for existing knocks.
func TestAccessEntryFromAOP_LegacyAOP_NoMetadata(t *testing.T) {
	dop := &common.ServerACOpsMsg{
		UserId:           "u",
		AuthServiceId:    "asp",
		SourceAddrs:      []*common.NetAddress{{Ip: "203.0.113.9", Port: 5555}},
		DestinationAddrs: []*common.NetAddress{{Ip: "10.0.0.5", Port: 8443}},
		OpenTime:         60,
		// qURL v2 fields intentionally absent — legacy shape.
	}

	entry := accessEntryFromAOP(dop, "server-public-key")

	if entry.QurlUserPublicKeyHash != "" || entry.ResourcePublicKeyHash != "" ||
		entry.QurlSessionId != "" || entry.AdmissionId != "" ||
		entry.RevocationEpoch != 0 || entry.Deadline != 0 {
		t.Errorf("legacy AOP must yield zero revocation metadata, got %#v", entry)
	}
}

// TestApplyDefaultIpSubstitution fences the load-bearing IP-substitution
// invariant on the AC ipset-write path. Two production callers depend
// on this behavior:
//   - QURL resources where the destination is the AC itself (Traefik
//     proxy) — sentinel `0.0.0.0` means "local to this AC."
//   - FRPS-behind-AC overlay (nhp #1977 / SLACK_QURL_ROLLOUT.md §6,
//     2026-05-18) — the resource.toml overlay renders `Addr.Ip = ""`
//     so the ipset entry keys on (agent_ip, port, ac_local_ip), the
//     triple a real customer SYN actually has at the AC kernel. If
//     this substitution stops working, the FRPS-specific knock
//     produces an inert ipset entry no packet ever matches.
//
// The previous form of these tests duplicated the substitution loop
// inline (a tautology — both production and test computed the same
// pattern). Now they call `applyDefaultIpSubstitution` directly so a
// regression in the production helper actually trips this test.
func TestApplyDefaultIpSubstitution(t *testing.T) {
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
			name:        "empty_ip_replaced_frps_behind_ac",
			defaultIp:   "10.0.1.50",
			dstIp:       "",
			expectedIp:  "10.0.1.50",
			description: "empty IP should be replaced with DefaultIp (FRPS-behind-AC overlay path)",
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
			description: "sentinel unchanged when DefaultIp not configured (AC hasn't booted yet)",
		},
		{
			name:        "no_default_ip_empty_unchanged",
			defaultIp:   "",
			dstIp:       "",
			expectedIp:  "",
			description: "empty IP unchanged when DefaultIp not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dstAddrs := []*common.NetAddress{
				{Ip: tt.dstIp, Port: 443},
			}

			applyDefaultIpSubstitution(tt.defaultIp, dstAddrs)

			if dstAddrs[0].Ip != tt.expectedIp {
				t.Errorf("%s: got IP %q, want %q", tt.description, dstAddrs[0].Ip, tt.expectedIp)
			}
		})
	}
}

// TestApplyDefaultIpSubstitution_MultipleAddresses fences the
// per-address branch decision: real IPs preserved, empty + sentinel
// both substituted, mixed correctly across a single slice.
func TestApplyDefaultIpSubstitution_MultipleAddresses(t *testing.T) {
	dstAddrs := []*common.NetAddress{
		{Ip: SentinelLocalIP, Port: 443}, // sentinel - should be replaced
		{Ip: "192.168.1.100", Port: 22},  // real IP - should be preserved
		{Ip: "", Port: 8080},             // empty - should be replaced (FRPS overlay)
	}

	applyDefaultIpSubstitution("10.0.1.50", dstAddrs)

	expected := []string{"10.0.1.50", "192.168.1.100", "10.0.1.50"}
	for i, addr := range dstAddrs {
		if addr.Ip != expected[i] {
			t.Errorf("address[%d]: got IP %q, want %q", i, addr.Ip, expected[i])
		}
	}
}

// TestApplyDefaultIpSubstitution_NilEntries fences the defensive
// nil-skip in the helper. Production callers never pass nil entries,
// but a future refactor that builds dstAddrs from sparse inputs would
// otherwise nil-deref. Asserts both halves of the contract: nil
// entries stay nil (no in-place compaction), and non-nil entries
// receive the substitution.
func TestApplyDefaultIpSubstitution_NilEntries(t *testing.T) {
	dstAddrs := []*common.NetAddress{
		nil,
		{Ip: "", Port: 8080},
		nil,
	}

	applyDefaultIpSubstitution("10.0.1.50", dstAddrs)

	if dstAddrs[0] != nil {
		t.Errorf("dstAddrs[0]: nil entry became %+v — slice must not be compacted in place", dstAddrs[0])
	}
	if dstAddrs[1].Ip != "10.0.1.50" {
		t.Errorf("dstAddrs[1]: non-nil entry not substituted: got %q want %q", dstAddrs[1].Ip, "10.0.1.50")
	}
	if dstAddrs[2] != nil {
		t.Errorf("dstAddrs[2]: nil entry became %+v — slice must not be compacted in place", dstAddrs[2])
	}
	if len(dstAddrs) != 3 {
		t.Errorf("slice length changed: got %d want 3 — slice must not be resized", len(dstAddrs))
	}
}

// TestHandleAccessControl_RejectsNonPositiveOpenTime is the defense-in-depth
// fence for the #1946 cap. ipset.Add (utils/iptables.go) passes the
// timeout verbatim into `ipset add ... timeout N`, and the kernel
// treats `timeout 0` as PERMANENT. The /refresh handler's
// remainingSec<=0 short-circuit (httpac.go) is the primary fence; this
// gate is the secondary fence — a regression that drops the short-
// circuit must still hit this and fail-closed rather than punching a
// permanent firewall hole.
//
// Constructs only the artMsg path (no UdpAC fields touched) because
// the guard fires at the top of HandleAccessControl before any
// ipset/iptables call. A future refactor that moves the guard below
// the first ipset call would still pass this test BUT would also pass
// the live ipset call (which would create the permanent entry) —
// guard placement is documented and not test-fenced. The unit test
// covers the contract; live ipset is in #1950 (Tier 1 smoke).
func TestHandleAccessControl_RejectsNonPositiveOpenTime(t *testing.T) {
	a := &UdpAC{}
	for _, openTimeSec := range []int{0, -1, -1000} {
		artMsg, err := a.HandleAccessControl(&AccessEntry{}, openTimeSec, nil)
		if err == nil {
			t.Errorf("openTimeSec=%d: expected error, got nil", openTimeSec)
			continue
		}
		if !errors.Is(err, common.ErrACInvalidOpenTime) {
			t.Errorf("openTimeSec=%d: error = %v, want ErrACInvalidOpenTime", openTimeSec, err)
		}
		if artMsg == nil {
			t.Errorf("openTimeSec=%d: artMsg must be allocated even on rejection", openTimeSec)
			continue
		}
		if artMsg.ErrCode != common.ErrACInvalidOpenTime.ErrorCode() {
			t.Errorf("openTimeSec=%d: artMsg.ErrCode = %q, want %q", openTimeSec, artMsg.ErrCode, common.ErrACInvalidOpenTime.ErrorCode())
		}
	}
}

func TestHandleAccessControl_EBPFXDPMirrorsDirectTCPAdmissionToIpset(t *testing.T) {
	events := []string{}
	ipset := &recordingIPSet{events: &events}
	var ebpfCalls []struct {
		mapType int
		params  ebpf.EbpfRuleParams
		ttlSec  int
	}
	a := &UdpAC{
		config: &Config{
			DefaultIp:  "10.100.1.11",
			FilterMode: FilterMode_EBPFXDP,
		},
		ipset: ipset,
		ebpfRuleAdd: func(mapType int, params ebpf.EbpfRuleParams, ttlSec int) error {
			if len(ipset.adds) != 0 {
				t.Fatalf("ipset mirror written before eBPF allow-rule: %+v", ipset.adds)
			}
			events = append(events, "ebpf")
			ebpfCalls = append(ebpfCalls, struct {
				mapType int
				params  ebpf.EbpfRuleParams
				ttlSec  int
			}{mapType: mapType, params: params, ttlSec: ttlSec})
			return nil
		},
	}
	entry := &AccessEntry{
		SrcAddrs: []*common.NetAddress{{Ip: "198.51.100.7"}},
		DstAddrs: []*common.NetAddress{{
			Ip:       "",
			Port:     443,
			Protocol: "tcp",
		}},
	}

	artMsg, err := a.HandleAccessControl(entry, 300, nil)
	if err != nil {
		t.Fatalf("HandleAccessControl returned error: %v", err)
	}
	if artMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("artMsg.ErrCode = %q, want success", artMsg.ErrCode)
	}
	if len(ebpfCalls) != 1 {
		t.Fatalf("eBPF calls = %d, want 1: %+v", len(ebpfCalls), ebpfCalls)
	}
	call := ebpfCalls[0]
	if call.mapType != 1 || call.ttlSec != 300 {
		t.Fatalf("eBPF call = mapType %d ttl %d, want mapType 1 ttl 300", call.mapType, call.ttlSec)
	}
	if call.params.SrcIP != "198.51.100.7" || call.params.DstIP != "10.100.1.11" || call.params.DstPort != 443 || call.params.Protocol != "tcp" {
		t.Fatalf("eBPF params = %+v, want direct TCP admission to DefaultIp", call.params)
	}
	if len(ipset.adds) != 1 {
		t.Fatalf("ipset adds = %d, want 1: %+v", len(ipset.adds), ipset.adds)
	}
	add := ipset.adds[0]
	if add.ipType != utils.IPV4 || add.setType != 1 || add.expire != 300 {
		t.Fatalf("ipset add metadata = %+v, want ipv4 defaultset ttl 300", add)
	}
	if len(add.args) != 1 || add.args[0] != "198.51.100.7,443,10.100.1.11" {
		t.Fatalf("ipset add args = %+v, want qURL defaultset tuple", add.args)
	}
	if len(events) != 2 || events[0] != "ebpf" || events[1] != "ipset" {
		t.Fatalf("kernel write order = %+v, want [ebpf ipset]", events)
	}
}

func TestHandleAccessControl_EBPFXDPCIDRICMPMirrorUsesSameTempTTL(t *testing.T) {
	ipset := &recordingIPSet{}
	var ebpfCalls []struct {
		mapType int
		params  ebpf.EbpfRuleParams
		ttlSec  int
	}
	a := &UdpAC{
		config: &Config{
			DefaultIp:  "10.100.1.11",
			FilterMode: FilterMode_EBPFXDP,
			IpPassMode: PASS_KNOCKIP_WITH_RANGE,
		},
		ipset: ipset,
		ebpfRuleAdd: func(mapType int, params ebpf.EbpfRuleParams, ttlSec int) error {
			ebpfCalls = append(ebpfCalls, struct {
				mapType int
				params  ebpf.EbpfRuleParams
				ttlSec  int
			}{mapType: mapType, params: params, ttlSec: ttlSec})
			return nil
		},
	}
	entry := &AccessEntry{
		SrcAddrs: []*common.NetAddress{{Ip: "198.51.100.7"}},
		DstAddrs: []*common.NetAddress{{
			Ip:       "10.100.1.11",
			Port:     0,
			Protocol: "any",
		}},
	}

	artMsg, err := a.HandleAccessControl(entry, 300, nil)
	if err != nil {
		t.Fatalf("HandleAccessControl returned error: %v", err)
	}
	if artMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("artMsg.ErrCode = %q, want success", artMsg.ErrCode)
	}

	foundCIDRICMP := false
	for _, call := range ebpfCalls {
		if call.mapType == 3 && call.ttlSec == TempPortOpenTime {
			foundCIDRICMP = true
			break
		}
	}
	if !foundCIDRICMP {
		t.Fatalf("did not find range-mode ICMP eBPF rule with temp ttl %d in calls %+v", TempPortOpenTime, ebpfCalls)
	}

	icmpMirror := false
	for _, add := range ipset.adds {
		if add.setType != 4 || add.expire != TempPortOpenTime {
			continue
		}
		for _, arg := range add.args {
			if arg == "198.51.100.0/25,icmp:8/0" {
				icmpMirror = true
			}
		}
	}
	if !icmpMirror {
		t.Fatalf("did not find range-mode ICMP ipset mirror with temp ttl %d in adds %+v", TempPortOpenTime, ipset.adds)
	}
}

func TestHandleAccessControl_EBPFXDPCIDRRangeTCPInsertFailureFailsClosed(t *testing.T) {
	ipset := &recordingIPSet{}
	ebpfErr := errors.New("synthetic range insert failure")
	rangeCalls := 0
	a := &UdpAC{
		config: &Config{
			DefaultIp:  "10.100.1.11",
			FilterMode: FilterMode_EBPFXDP,
			IpPassMode: PASS_KNOCKIP_WITH_RANGE,
		},
		ipset: ipset,
		ebpfRuleAdd: func(mapType int, _ ebpf.EbpfRuleParams, _ int) error {
			if mapType == 4 {
				rangeCalls++
				if rangeCalls == 2 {
					return ebpfErr
				}
			}
			return nil
		},
	}
	entry := &AccessEntry{
		SrcAddrs: []*common.NetAddress{{Ip: "198.51.100.7"}},
		DstAddrs: []*common.NetAddress{{
			Ip:       "10.100.1.11",
			Port:     443,
			Protocol: "tcp",
		}},
	}

	_, err := a.HandleAccessControl(entry, 300, nil)
	if !errors.Is(err, ebpfErr) {
		t.Fatalf("error = %v, want synthetic range eBPF failure", err)
	}
	if rangeCalls != 2 {
		t.Fatalf("range eBPF calls = %d, want failure on second call", rangeCalls)
	}
	for _, add := range ipset.adds {
		if add.setType == 4 {
			t.Fatalf("range ipset mirror should not be written after partial eBPF insert failure: %+v", ipset.adds)
		}
	}
}

func TestHandleAccessControl_EBPFXDPDoesNotMirrorWhenEbpfInsertFails(t *testing.T) {
	ipset := &recordingIPSet{}
	ebpfErr := errors.New("synthetic ebpf insert failure")
	a := &UdpAC{
		config: &Config{
			DefaultIp:  "10.100.1.11",
			FilterMode: FilterMode_EBPFXDP,
		},
		ipset: ipset,
		ebpfRuleAdd: func(int, ebpf.EbpfRuleParams, int) error {
			return ebpfErr
		},
	}
	entry := &AccessEntry{
		SrcAddrs: []*common.NetAddress{{Ip: "198.51.100.7"}},
		DstAddrs: []*common.NetAddress{{
			Port:     443,
			Protocol: "tcp",
		}},
	}

	_, err := a.HandleAccessControl(entry, 300, nil)
	if !errors.Is(err, ebpfErr) {
		t.Fatalf("error = %v, want synthetic eBPF failure", err)
	}
	if len(ipset.adds) != 0 {
		t.Fatalf("ipset mirror should not be written after eBPF failure: %+v", ipset.adds)
	}
}

func TestHandleAccessControl_EBPFXDPMirrorFailureFailsAdmission(t *testing.T) {
	ipset := &recordingIPSet{err: errors.New("synthetic ipset mirror failure")}
	ebpfCalls := 0
	a := &UdpAC{
		config: &Config{
			DefaultIp:  "10.100.1.11",
			FilterMode: FilterMode_EBPFXDP,
		},
		ipset: ipset,
		ebpfRuleAdd: func(int, ebpf.EbpfRuleParams, int) error {
			ebpfCalls++
			return nil
		},
	}
	entry := &AccessEntry{
		SrcAddrs: []*common.NetAddress{{Ip: "198.51.100.7"}},
		DstAddrs: []*common.NetAddress{{
			Port:     443,
			Protocol: "tcp",
		}},
	}

	artMsg, err := a.HandleAccessControl(entry, 300, nil)
	if !errors.Is(err, common.ErrACIPSetOperationFailed) {
		t.Fatalf("error = %v, want ErrACIPSetOperationFailed", err)
	}
	if artMsg == nil || artMsg.ErrCode != common.ErrACIPSetOperationFailed.ErrorCode() {
		t.Fatalf("artMsg = %+v, want ErrACIPSetOperationFailed", artMsg)
	}
	if ebpfCalls != 1 {
		t.Fatalf("eBPF calls = %d, want 1 before mirror failure", ebpfCalls)
	}
	if len(ipset.adds) != 1 {
		t.Fatalf("ipset mirror attempts = %d, want 1: %+v", len(ipset.adds), ipset.adds)
	}
	add := ipset.adds[0]
	if len(add.args) != 1 || add.args[0] != "198.51.100.7,443,10.100.1.11" {
		t.Fatalf("ipset mirror args = %+v, want direct TCP qURL tuple", add.args)
	}
}

func TestHandleAccessControl_EBPFXDPRequiresIpsetMirror(t *testing.T) {
	ebpfCalled := false
	a := &UdpAC{
		config: &Config{
			DefaultIp:  "10.100.1.11",
			FilterMode: FilterMode_EBPFXDP,
		},
		ebpfRuleAdd: func(int, ebpf.EbpfRuleParams, int) error {
			ebpfCalled = true
			return nil
		},
	}
	entry := &AccessEntry{
		SrcAddrs: []*common.NetAddress{{Ip: "198.51.100.7"}},
		DstAddrs: []*common.NetAddress{{
			Port:     443,
			Protocol: "tcp",
		}},
	}

	artMsg, err := a.HandleAccessControl(entry, 300, nil)
	if !errors.Is(err, common.ErrACIPSetNotFound) {
		t.Fatalf("error = %v, want ErrACIPSetNotFound", err)
	}
	if artMsg == nil || artMsg.ErrCode != common.ErrACIPSetNotFound.ErrorCode() {
		t.Fatalf("artMsg = %+v, want ErrACIPSetNotFound", artMsg)
	}
	if ebpfCalled {
		t.Fatal("eBPF insert should not run when the iptables mirror is unavailable")
	}
}

// TestHandleAccessControl_AdmissionGate_BreakerOpen fences the L3-only
// security contract: when the flush scheduler's circuit breaker is
// open, HandleAccessControl MUST refuse the NHP-AOP with
// ErrACSchedulerBreakerOpen (53010), not with the previous
// misleading ErrACInvalidOpenTime (53009)
//
// The fail-closed admission is what keeps the post-L7-removal
// boundary intact: a stuck flusher must not admit new sessions
// whose kernel state we cannot later guarantee to tear down.
func TestHandleAccessControl_AdmissionGate_BreakerOpen(t *testing.T) {
	// Construct a real scheduler so IsBreakerOpen is wired correctly.
	// A NoOpFlusher keeps Flush calls from doing anything; we trip
	// the breaker manually via repeated recordBreakerErr.
	sched := NewScheduler(&NoOpFlusher{},
		WithBreakerThreshold(2),
		WithBreakerWindow(60*time.Second),
	)
	sched.Start()
	defer shutdownOrFail(t, sched)
	// Force the breaker open.
	sched.recordBreakerErr()
	sched.recordBreakerErr()
	if !sched.IsBreakerOpen() {
		t.Fatalf("setup: breaker did not open after 2 errors with threshold=2")
	}

	a := &UdpAC{expirySched: sched}
	artMsg, err := a.HandleAccessControl(&AccessEntry{}, 60 /* valid */, nil)
	if !errors.Is(err, common.ErrACSchedulerBreakerOpen) {
		t.Fatalf("got err=%v, want ErrACSchedulerBreakerOpen (admission must refuse when breaker open)", err)
	}
	if artMsg == nil {
		t.Fatal("artMsg must be allocated even on rejection")
	}
	if artMsg.ErrCode != common.ErrACSchedulerBreakerOpen.ErrorCode() {
		t.Errorf("artMsg.ErrCode = %q, want %q", artMsg.ErrCode, common.ErrACSchedulerBreakerOpen.ErrorCode())
	}
	if artMsg.ErrCode == common.ErrACInvalidOpenTime.ErrorCode() {
		t.Error("admission denial must NOT surface as ErrACInvalidOpenTime — that misleads on-call")
	}

	// Second AOP while breaker is still open must ALSO be refused
	//
	artMsg2, err2 := a.HandleAccessControl(&AccessEntry{}, 60, nil)
	if !errors.Is(err2, common.ErrACSchedulerBreakerOpen) {
		t.Errorf("2nd AOP while breaker still open: got err=%v, want ErrACSchedulerBreakerOpen", err2)
	}
	if artMsg2 == nil || artMsg2.ErrCode != common.ErrACSchedulerBreakerOpen.ErrorCode() {
		t.Errorf("2nd AOP artMsg.ErrCode mismatch: %+v", artMsg2)
	}
}

// TestHandleAccessControl_AdmissionGate_FeatureOff_NoBreakerCheck
// fences the no-op-when-disabled contract: with the scheduler nil
// (feature disabled), the admission gate must NOT short-circuit and
// must NOT panic on the nil expirySched read.
func TestHandleAccessControl_AdmissionGate_FeatureOff_NoBreakerCheck(t *testing.T) {
	a := &UdpAC{expirySched: nil}
	// openTimeSec=-1 to short-circuit before any kernel writes — we
	// only want to verify the admission gate doesn't panic on nil and
	// reaches the second (openTimeSec) gate.
	_, err := a.HandleAccessControl(&AccessEntry{}, -1, nil)
	if !errors.Is(err, common.ErrACInvalidOpenTime) {
		t.Errorf("with scheduler nil and openTimeSec=-1, expected ErrACInvalidOpenTime (passes admission gate, fails openTime gate); got %v", err)
	}
}

// TestScheduleFlushIfEnabled_NoOp_WhenNil fences the
// scheduleFlushIfEnabled wrapper's nil-safety: call sites in
// HandleAccessControl sprinkle calls without per-site nil-checks,
// so the wrapper must silently no-op when the feature is off.
func TestScheduleFlushIfEnabled_NoOp_WhenNil(t *testing.T) {
	a := &UdpAC{expirySched: nil}
	// Just verifying no panic.
	a.scheduleFlushIfEnabled(&AccessEntry{}, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP, time.Now().Add(60*time.Second))
}

// TestScheduleFlushIfEnabled_NilEntry_DropsAndDoesNotPanic fences the
// nil-entry guard added in cr round 2: a nil entry would create a
// phantom scheduler entry (Scheduled but not tracked), so the function
// drops the schedule and increments MetricL3FlushScheduleNilEntry
// rather than panicking. Production should never hit this path; the
// metric is the observability signal that a future caller regressed.
func TestScheduleFlushIfEnabled_NilEntry_DropsAndDoesNotPanic(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer shutdownOrFail(t, sched)

	a := &UdpAC{expirySched: sched}
	a.scheduleFlushIfEnabled(nil, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP, time.Now().Add(60*time.Second))

	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after nil-entry schedule attempt = %d, want 0 — nil-entry guard let a phantom scheduler entry through", got)
	}
}

// TestScheduleFlushIfEnabled_BuildsCorrectFlowKey fences the
// FlowKey construction path for each protocol the dispatch table
// in msghandler.go hits (TCP, UDP, ICMP, Any) by routing each call
// through a recording flusher and inspecting the scheduled keys.
func TestScheduleFlushIfEnabled_BuildsCorrectFlowKey(t *testing.T) {
	cases := []struct {
		name      string
		srcIP     string
		dstIP     string
		dstPort   int
		proto     FlowProto
		wantPort  uint16
		wantProto FlowProto
	}{
		{name: "tcp-443", srcIP: "192.0.2.10", dstIP: "192.0.2.20", dstPort: 443, proto: FlowProtoTCP, wantPort: 443, wantProto: FlowProtoTCP},
		{name: "udp-53", srcIP: "10.0.0.5", dstIP: "10.0.0.6", dstPort: 53, proto: FlowProtoUDP, wantPort: 53, wantProto: FlowProtoUDP},
		{name: "icmp-noport", srcIP: "192.0.2.1", dstIP: "192.0.2.2", dstPort: 0, proto: FlowProtoICMP, wantPort: 0, wantProto: FlowProtoICMP},
		{name: "any-noport", srcIP: "203.0.113.5", dstIP: "203.0.113.6", dstPort: 0, proto: FlowProtoAny, wantPort: 0, wantProto: FlowProtoAny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := newRecordingFlusher()
			// Far-future deadline so the entry stays in the index for
			// inspection (doesn't fire during the test).
			sched := NewScheduler(rec, WithTickInterval(5*time.Millisecond), WithWheelSize(1000))
			sched.Start()
			defer shutdownOrFail(t, sched)

			a := &UdpAC{expirySched: sched}
			a.scheduleFlushIfEnabled(&AccessEntry{}, c.srcIP, c.dstIP, c.dstPort, c.proto, time.Now().Add(60*time.Second))

			expected, err := MakeFlowKey(c.srcIP, c.dstIP, c.dstPort, c.proto)
			if err != nil {
				t.Fatalf("MakeFlowKey: %v", err)
			}
			shard := sched.shards[expected.shard()]
			shard.mu.Lock()
			entry, ok := shard.entries[expected]
			shard.mu.Unlock()
			if !ok {
				t.Fatalf("expected entry for FlowKey %+v not found in shard index", expected)
			}
			if entry.FlowKey.DstPort != c.wantPort {
				t.Errorf("DstPort: got %d want %d", entry.FlowKey.DstPort, c.wantPort)
			}
			if entry.FlowKey.Protocol != c.wantProto {
				t.Errorf("Protocol: got %s want %s", entry.FlowKey.Protocol, c.wantProto)
			}
		})
	}
}

// TestScheduleFlushIfEnabled_RejectsMalformedFlowKey fences the
// graceful-skip path: a bogus IP (or 0.0.0.0 wildcard) must not
// trip the scheduler — kernel state was already written by the
// caller; this is best-effort defense-in-depth.
func TestScheduleFlushIfEnabled_RejectsMalformedFlowKey(t *testing.T) {
	rec := newRecordingFlusher()
	sched := NewScheduler(rec, WithTickInterval(5*time.Millisecond), WithWheelSize(1000))
	sched.Start()
	defer shutdownOrFail(t, sched)

	a := &UdpAC{expirySched: sched}
	// Malformed source IP — MakeFlowKey rejects.
	a.scheduleFlushIfEnabled(&AccessEntry{}, "not-an-ip", "192.0.2.2", 443, FlowProtoTCP, time.Now().Add(60*time.Second))
	// Unspecified IP — MakeFlowKey rejects (wildcard fence).
	a.scheduleFlushIfEnabled(&AccessEntry{}, "0.0.0.0", "192.0.2.2", 443, FlowProtoTCP, time.Now().Add(60*time.Second))

	if got := sched.EntryCount(); got != 0 {
		t.Errorf("expected zero entries (malformed inputs rejected at FlowKey boundary); got %d", got)
	}
}

// TestNewFlusherForFilterMode_UnsupportedMode fences the
// fail-loud behavior on an unrecognized FilterMode value. A future
// enum addition (FilterMode=2) that forgets to wire a flusher must
// not silently fall through to a nil flusher; the AC's Start() must
// fail loud at boot rather than schedule no-op flushes forever
func TestNewFlusherForFilterMode_UnsupportedMode(t *testing.T) {
	for _, mode := range []int{2, 3, 99, -1} {
		t.Run(strconv.Itoa(mode), func(t *testing.T) {
			f, err := newFlusherForFilterMode(mode, BackendExec, defaultConntrackNetlinkPoolSize)
			if err == nil {
				t.Errorf("FilterMode=%d: expected error, got nil (flusher=%T)", mode, f)
			}
			if f != nil {
				t.Errorf("FilterMode=%d: expected nil flusher, got %T", mode, f)
			}
		})
	}
}

// TestAllPortsEbpfRuleParams_Sentinel is the pure-Go regression guard for the
// #2843 all-ports sentinel. The two FilterMode_EBPFXDP all-ports branches in
// HandleAccessControl build their port_list EbpfRuleParams via
// allPortsEbpfRuleParams, so pinning the helper's bounds here makes a revert of
// the sentinel back to the pre-#2843 DstPortStart=1 fail this test — without a
// kernel.
//
// WHY DstPortStart MUST be 0: the XDP port_list lookup key is built from the
// compile-time constants `.min_port = MIN_PORT(0), .max_port = MAX_PORT(65535)`
// (nhp/ebpf/xdp/nhp_ebpf_xdp.c), never from the packet. A seed with
// DstPortStart=1 produces the key {src,1,65535}, which never equals the lookup
// {src,0,65535}, so every all-ports admission fail-closes under EBPFXDP. This
// test owns the production-constant half of the proof; the in-kernel
// TestIPv4AdmissionDatapathPortListAllPorts owns the key→verdict half (and
// additionally proves the OLD min=1 value DROPs).
//
// SCOPE: this pins the constant the shared constructor returns, not that every
// call site calls the constructor. The two HandleAccessControl all-ports
// branches were collapsed onto this helper in the same change, so today a revert
// to 1 at the sentinel goes red here.
func TestAllPortsEbpfRuleParams_Sentinel(t *testing.T) {
	const srcIP = "10.1.2.3"
	got := allPortsEbpfRuleParams(srcIP)

	if got.DstPortStart != 0 {
		t.Errorf("all-ports DstPortStart = %d, want 0 — the XDP port_list lookup keys on MIN_PORT=0; a non-zero start (the pre-#2843 bug was 1) makes the seeded key never match and every all-ports admission fail-closes under FilterMode=EBPFXDP (#2843)", got.DstPortStart)
	}
	if got.DstPortEnd != 65535 {
		t.Errorf("all-ports DstPortEnd = %d, want 65535 — the XDP port_list lookup keys on MAX_PORT=65535; any other end makes the seeded key never match the lookup", got.DstPortEnd)
	}
	if got.SrcIP != srcIP {
		t.Errorf("all-ports SrcIP = %q, want %q — the source IP must be threaded through unchanged so the rule is keyed on the admitted source", got.SrcIP, srcIP)
	}
}

// TestIpsetHashHelpers_Format pins the exact entry strings the ipsetHash*
// builders emit. These strings are a kernel-datapath contract, not an internal
// detail: they are handed to ipset.Add for sets created as hash:ip,port,ip
// (defaultset/defaultset_down) and hash:net,port (tempset) in
// docker/iptables_defaults_*.sh. Drift in a separator, a proto prefix, or the
// all-ports range makes the kernel reject or silently mis-key the entry, and the
// admission it was supposed to open fails.
//
// SCOPE: this pins what each builder returns, not that every call site uses the
// builder. All 21 former fmt.Sprintf sites were collapsed onto these helpers in
// the same change, so today a format regression goes red here.
func TestIpsetHashHelpers_Format(t *testing.T) {
	const (
		srcIP  = "10.1.2.3"
		dstIP  = "10.4.5.6"
		netStr = "10.0.0.0/8"
	)

	tests := []struct {
		name string
		got  string
		want string
		// fields is the comma-separated field count the set family requires:
		// 3 for hash:ip,port,ip and 2 for hash:net,port.
		fields int
	}{
		{"tcp", ipsetHashTCP(srcIP, 443, dstIP), "10.1.2.3,443,10.4.5.6", 3},
		{"tcp all ports", ipsetHashTCPAllPorts(srcIP, dstIP), "10.1.2.3,1-65535,10.4.5.6", 3},
		{"udp", ipsetHashUDP(srcIP, 443, dstIP), "10.1.2.3,udp:443,10.4.5.6", 3},
		{"udp all ports", ipsetHashUDPAllPorts(srcIP, dstIP), "10.1.2.3,udp:1-65535,10.4.5.6", 3},
		{"icmp v4", ipsetHashICMP(srcIP, utils.ICMPEchoType(utils.IPV4), dstIP), "10.1.2.3,icmp:8/0,10.4.5.6", 3},
		{"icmp v6", ipsetHashICMP("fd00::1", utils.ICMPEchoType(utils.IPV6), "fd00::2"), "fd00::1,icmpv6:128/0,fd00::2", 3},
		{"net port", ipsetHashNetPort(netStr, 443), "10.0.0.0/8,443", 2},
		{"net all ports", ipsetHashNetAllPorts(netStr), "10.0.0.0/8,1-65535", 2},
		{"net udp port", ipsetHashNetUDPPort(netStr, 443), "10.0.0.0/8,udp:443", 2},
		{"net udp all ports", ipsetHashNetUDPAllPorts(netStr), "10.0.0.0/8,udp:1-65535", 2},
		{"net icmp v4", ipsetHashNetICMP(netStr, utils.ICMPEchoType(utils.IPV4)), "10.0.0.0/8,icmp:8/0", 2},
		// Port 0 reaches the plain builders only when a call site skips its
		// dstAddr.Port == 0 branch; pin the literal so that bug reads as "port
		// 0" in a failure rather than looking like a legitimate all-ports rule.
		{"tcp port zero is not all-ports", ipsetHashTCP(srcIP, 0, dstIP), "10.1.2.3,0,10.4.5.6", 3},
		{"udp port zero is not all-ports", ipsetHashUDP(srcIP, 0, dstIP), "10.1.2.3,udp:0,10.4.5.6", 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("entry = %q, want %q — this string goes straight to ipset.Add; any drift changes what the kernel firewall matches on", tc.got, tc.want)
			}
			if n := len(strings.Split(tc.got, ",")); n != tc.fields {
				t.Errorf("entry %q has %d comma-separated fields, want %d — the set family's grammar is fixed (hash:ip,port,ip is 3, hash:net,port is 2); a gained or lost field is rejected by ipset and also defeats utils.NormalizeIPSetEntry's 3-way split", tc.got, n, tc.fields)
			}
		})
	}
}

// TestIpsetHashHelpers_SurviveIPv6Normalization fences the three-field builders
// against utils.NormalizeIPSetEntry, which rewrites IPv4 components into
// IPv6-mapped form before an entry reaches an inet6 set. That function splits
// with SplitN(entry, ",", 3) and returns the entry UNCHANGED when the split does
// not yield three usable parts — so a builder that gained or lost a comma fails
// silently: the entry is written to the v6 set unmapped instead of being
// rejected. Asserting the mapped output (not just "no error") is what makes that
// failure mode visible.
func TestIpsetHashHelpers_SurviveIPv6Normalization(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "tcp",
			got:  utils.NormalizeIPSetEntry(utils.IPV6, ipsetHashTCP("10.1.2.3", 443, "10.4.5.6")),
			want: "::ffff:10.1.2.3,443,::ffff:10.4.5.6",
		},
		{
			name: "tcp all ports",
			got:  utils.NormalizeIPSetEntry(utils.IPV6, ipsetHashTCPAllPorts("10.1.2.3", "10.4.5.6")),
			want: "::ffff:10.1.2.3,1-65535,::ffff:10.4.5.6",
		},
		{
			name: "udp",
			got:  utils.NormalizeIPSetEntry(utils.IPV6, ipsetHashUDP("10.1.2.3", 443, "10.4.5.6")),
			want: "::ffff:10.1.2.3,udp:443,::ffff:10.4.5.6",
		},
		{
			name: "udp all ports",
			got:  utils.NormalizeIPSetEntry(utils.IPV6, ipsetHashUDPAllPorts("10.1.2.3", "10.4.5.6")),
			want: "::ffff:10.1.2.3,udp:1-65535,::ffff:10.4.5.6",
		},
		{
			name: "icmp",
			got:  utils.NormalizeIPSetEntry(utils.IPV6, ipsetHashICMP("10.1.2.3", utils.ICMPEchoType(utils.IPV6), "10.4.5.6")),
			want: "::ffff:10.1.2.3,icmpv6:128/0,::ffff:10.4.5.6",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("normalized entry = %q, want %q — NormalizeIPSetEntry only rewrites an entry it can split into three parts, so an unmapped IPv4 component here means the builder's field layout drifted and the entry would reach an inet6 set unmapped", tc.got, tc.want)
			}
		})
	}
}
