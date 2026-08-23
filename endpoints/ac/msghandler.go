package ac

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/internal/revocationscope"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

// NHP_REV (qURL v2 immediate-revocation) handler rejection sentinels. Returned
// by HandleUdpACRevocation so the dispatch seam and tests can distinguish a
// validation reject from an apply. All are fail-closed: the event is dropped
// without calling ApplyRevocation, and each reject increments
// MetricRevocationRejected.
var (
	// ErrRevocationUnsupportedScope is returned when an NHP_REV carries a scope
	// that is not one of the wire scopes qurl-service emits (qurl/resource/
	// session) — including the AC-internal-only "admission" dimension.
	ErrRevocationUnsupportedScope = errors.New("unsupported revocation scope")
	// ErrRevocationNegativeEpoch is returned when an NHP_REV carries a negative
	// epoch, which would convert to a near-max uint64 and poison the apply
	// watermark.
	ErrRevocationNegativeEpoch = errors.New("negative revocation epoch")
	// ErrRevocationEmptyScopeKey is returned when an NHP_REV carries an empty or
	// prefix-only scope_key (e.g. "qurl:"). ApplyRevocation already no-ops an
	// empty key, but a well-formed scope with no identity is a malformed event
	// from a correct producer's perspective; rejecting it explicitly (rather than
	// silently no-opping) keeps it on the counted-reject path so a producer bug is
	// visible in the metric, not just absent from the flush counts.
	ErrRevocationEmptyScopeKey = errors.New("empty revocation scope key")
	// ErrRevocationScopeKeyPrefixMismatch is returned when the scope_key's
	// "<scope>:" prefix disagrees with the event's scope field (e.g.
	// scope="qurl" with scope_key="resource:..."). qurl-service builds the prefix
	// from the same scope, so a mismatch is a malformed or forged event.
	ErrRevocationScopeKeyPrefixMismatch = errors.New("revocation scope_key prefix does not match scope")
)

// IP pass mode
const (
	PASS_KNOCK_IP = iota
	PASS_KNOCKIP_WITH_RANGE
	PASS_PRE_ACCESS_IP
)

// flushSafetyMargin extends each L3 flush deadline past the kernel
// ipset / BPF allow-rule's natural expiry so the scheduler always
// sweeps an already-expired entry. Without this margin, the
// conntrack-delete could fire while the ipset entry is still live —
// a new SYN from the allow-listed source in that window would create
// a fresh ESTABLISHED conntrack that survives past intended session
// end
//
// 50ms is comfortably above per-call kernel-write latency (~µs to
// low-ms in iptables mode, similar in eBPF) and well under the
// scheduler's 10ms tick resolution scaled to anything operators care
// about. Tuning down would require benchmarking ipset eviction
// latency under load.
const flushSafetyMargin = 50 * time.Millisecond

// ebpfRuleAddFailClosed wraps ebpf.EbpfRuleAdd to give the eBPF allow-rule
// insert path an explicit, LOUD fail-closed signal when a map is at capacity.
//
// The allow-rule maps are BPF_MAP_TYPE_HASH (#2163): a full map returns kernel
// -E2BIG on insert of a NEW key rather than silently evicting an existing one
// (the LRU_HASH bug). That error already propagates and every caller below acts
// on it (never swallows it). This wrapper adds the security-relevant
// observability the raw helper can't: a dedicated metric (MetricEbpfMapFull) and
// a distinct, unambiguous log line naming the full map, so "an allow-rule map
// hit its ceiling" is visible to operators and not buried under generic
// insert-error noise. The error is returned unchanged so each caller's existing
// control flow is preserved (never swallowed — admitted-but-not-enforced is a
// security hole; never panicked).
//
// What the guarantee IS (and is NOT): the load-bearing property is "no silent
// eviction of an admitted session, and any allow-rule tuple we fail to insert is
// fail-closed at the datapath (no rule => XDP_DROP)." TCP/UDP admission sites
// return on insert failure so callers do not report success for a range whose
// net-level ipset mirror was skipped. Supplementary ICMP diagnostics remain
// warning-only, matching the IPTABLES-mode ICMP path.
//
// Inert under FilterMode_IPTABLES (the maps are never loaded), so this path
// cannot fire in prod until the eBPF FilterMode flip (E5).
func (a *UdpAC) ebpfRuleAddFailClosed(mapType int, params ebpf.EbpfRuleParams, ttlSec int) error {
	add := ebpf.EbpfRuleAdd
	if a != nil && a.ebpfRuleAdd != nil {
		add = a.ebpfRuleAdd
	}
	return a.recordEbpfInsertResult(add(mapType, params, ttlSec), params, mapType)
}

// recordEbpfInsertResult is the detect-and-record half of
// ebpfRuleAddFailClosed, split out so the map-full observability path is unit
// testable without a kernel or pinned maps: a synthetic error wrapping
// syscall.E2BIG drives the same branch the real kernel insert would. It bumps
// MetricEbpfMapFull and emits the distinct fail-closed log on map-full, then
// returns err UNCHANGED (never swallowed, never panicked) so the caller's
// existing fail-closed control flow is preserved.
func (a *UdpAC) recordEbpfInsertResult(err error, params ebpf.EbpfRuleParams, mapType int) error {
	if ebpf.IsMapFull(err) {
		a.incrMetric(MetricEbpfMapFull)
		log.Error("[EbpfRuleAdd] ADMISSION FAIL-CLOSED: allow-rule eBPF map %q (mapType %d) full (-E2BIG) — refusing to insert this NEW allow-rule src: %s dst: %s; EXISTING admitted sessions are NOT evicted (#2163). Map at capacity (max_entries); see SESSION_ENFORCEMENT_ARCHITECTURE.md.", ebpf.MapTypeName(mapType), mapType, params.SrcIP, params.DstIP)
	}
	return err
}

// addEbpfxdpIpsetMirror admits the same tuple through the boot-time iptables
// default-DROP gate after the eBPF allow-rule has already been written.
//
// Sandbox/prod user_data installs iptables + ipset for every AC regardless of
// FilterMode. In FilterMode_EBPFXDP the XDP program returns XDP_PASS for an
// admitted packet, but that packet still traverses INPUT and is dropped unless
// defaultset/tempset contains the matching tuple. Keeping this shadow write
// preserves the existing fail-closed iptables guard instead of loosening the
// firewall for eBPF mode.
func (a *UdpAC) addEbpfxdpIpsetMirror(ipType utils.IPTYPE, setType int, ttlSec int, hashStr, caller string) error {
	if a.ipset == nil {
		log.Error("[%s] eBPF iptables mirror ipset is nil", caller)
		return common.ErrACIPSetNotFound
	}
	if _, err := a.ipset.Add(ipType, setType, ttlSec, hashStr); err != nil {
		log.Error("[%s] add eBPF iptables mirror ipset %s error: %v", caller, hashStr, err)
		return common.ErrACIPSetOperationFailed
	}
	return nil
}

func setArtMsgErrorFromKernelWrite(artMsg *common.ACOpsResultMsg, err error) error {
	var nhpErr *common.Error
	if errors.As(err, &nhpErr) {
		return setArtMsgError(artMsg, nhpErr)
	}
	return err
}

// allPortsEbpfRuleParams builds the EbpfRuleParams for an "all ports"
// (dstAddr.Port == 0) eBPF port_list admission for one source IP. It is the
// SINGLE source of truth for the all-ports min/max sentinel, shared by the TCP
// and UDP FilterMode_EBPFXDP branches in HandleAccessControl (which build
// byte-identical params).
//
// DstPortStart MUST be 0 to match the XDP port_list lookup key, which is built
// from the compile-time constants `.min_port = MIN_PORT(0), .max_port =
// MAX_PORT(65535)` (nhp/ebpf/xdp/nhp_ebpf_xdp.c), NOT from the packet. The
// inserter previously used DstPortStart=1, so the seeded key {src,1,65535} never
// matched the lookup {src,0,65535} and every all-ports admission fail-closed
// under FilterMode=EBPFXDP (#2843, v4 + v6). Centralizing the sentinel here lets
// TestAllPortsEbpfRuleParams_Sentinel pin it so a regression back to 1 fails a
// pure-Go test (the in-kernel TestIPv4AdmissionDatapathPortListAllPorts proves
// the key→verdict half).
//
// ANY new all-ports port_list insert site MUST build its params through this
// helper (not an inline EbpfRuleParams literal): the sentinel guard pins the
// value this constructor returns, so a future site that inlines DstPortStart
// would not be covered. Route it here to keep the guard load-bearing.
func allPortsEbpfRuleParams(srcIPStr string) ebpf.EbpfRuleParams {
	return ebpf.EbpfRuleParams{
		SrcIP:        srcIPStr,
		DstPortStart: 0,
		DstPortEnd:   65535,
	}
}

// computeFlushDeadline returns `now + openTimeSec + flushSafetyMargin`
// — the single source of truth for the L3 flush deadline anchoring.
// Centralizing this here keeps the four call sites in lockstep so a
// future safety-margin retune (post-#2165 netlink latency, etc.)
// is a one-line change rather than a coordinated edit across
// HandleAccessControl + tcp/udpTempAccessHandler + ICMP branch
func computeFlushDeadline(openTimeSec int) time.Time {
	return time.Now().Add(time.Duration(openTimeSec)*time.Second + flushSafetyMargin)
}

// applyDefaultIpSubstitution rewrites empty / SentinelLocalIP destination
// IPs in `dstAddrs` to the AC's `defaultIp` (= LOCAL_IP at boot).
// Two production callers depend on this: QURL resources (sentinel
// `0.0.0.0` = local to this AC) and the FRPS-behind-AC overlay
// (Addr.Ip = "" in resource.toml; see SLACK_QURL_ROLLOUT.md §6).
//
// No-op when `defaultIp == ""`. Mutates `dstAddrs` in place.
//
// Concurrency: callers MUST ensure `dstAddrs` entries are not
// mutated concurrently — the helper writes `addr.Ip` without
// synchronization. Today's caller (HandleAccessControl) is
// knock-local and single-goroutine; see the caller-site comment in
// HandleAccessControl.
func applyDefaultIpSubstitution(defaultIp string, dstAddrs []*common.NetAddress) {
	if len(defaultIp) == 0 {
		return
	}
	for _, addr := range dstAddrs {
		if addr == nil {
			continue
		}
		if len(addr.Ip) == 0 || addr.Ip == SentinelLocalIP {
			addr.Ip = defaultIp
		}
	}
}

// admitAndIssueToken pre-mints + pre-stores the entry in tokenStore,
// runs HandleAccessControl (whose per-tuple Schedule calls record on
// entry.scheduledKeys), and gates token emission on ErrSuccess via
// emitOrCleanupPreMintedToken. The pre-store BEFORE Schedule closes
// the admission-window race in #2201: a concurrent OnExpire firing
// for a peer entry that shares a FlowKey with this new entry must
// observe this entry in tokenStore (via Snapshot) — otherwise
// latestOtherFirewallDeadline returns zero, Cancel fires, and the
// scheduler entry HandleAccessControl is creating gets erased.
//
// The cleaned/defer pattern guarantees the pre-stored entry is torn
// down on any path that doesn't reach emitOrCleanupPreMintedToken
// (panic mid-HandleAccessControl, or a future maintainer who adds an
// early-return). Extracting this into a helper colocates the pairing
// so the cleanup discipline can't drift out of sync with the pre-
// store.
//
// Security invariant: the token is NOT emitted to the server unless
// artMsg.ErrCode == ErrSuccess. On admission failure
// emitOrCleanupPreMintedToken drains partial Schedules + Deletes the
// entry — see its godoc for the post-nhp#1124 threat model.
//
// Pre-mint TOCTOU: the token is in tokenStore from GenerateAccessToken
// onward, BEFORE HandleAccessControl writes any kernel firewall
// state. A concurrent VerifyAccessToken in this window would find a
// valid token whose pinhole hasn't yet been written. Not exploitable
// because the token is 32-byte opaque random and never leaves the
// process until emit (artMsg.ACToken stays empty on the failure
// path; logs use RedactToken). The window's only observable effect
// is in the cross-entry race the pre-store closes by design.
//
// In-process angle: if a future caller adds an in-process trigger
// that can fire /refresh-extend against an in-flight pre-stored
// token (admin endpoint, test harness, internal RPC), an admission
// failure's defer Delete would race against /refresh's Schedule
// calls on the same entry pointer — those keys would orphan
// (entry gone from tokenStore → no OnExpire). Today's only refresh
// trigger is the external HTTP path which cannot reach an in-flight
// pre-mint token (the token isn't on artMsg.ACToken yet). A future
// in-process caller must coordinate with admission completion
// (e.g., gate refresh-extend on a per-entry "admitted" flag) before
// firing.
//
// Defer cleanup is idempotent (drain → nil on second call;
// tokenStore.Delete silent on missing key), so the defer-runs-after-
// emit-already-cleaned path is a benign no-op — fenced by
// TestAdmitAndIssueToken_PanicMidHandleAC_TokenNeverInArtMsg.
func (a *UdpAC) admitAndIssueToken(entry *AccessEntry, openTimeSec int, artMsgIn *common.ACOpsResultMsg) (artMsg *common.ACOpsResultMsg, err error) {
	preMintedToken := a.GenerateAccessToken(entry)
	cleaned := false
	defer func() {
		if !cleaned {
			a.cancelAllScheduledFlows(entry)
			// deleteToken (Delete + revIndex deindex) preserves the
			// cancel-first order; GenerateAccessToken indexed the entry via
			// storeToken, so this panic-cleanup path must deindex too. No-op
			// on the index for legacy / non-qURL-v2 entries.
			a.deleteToken(preMintedToken, entry)
		}
	}()
	artMsg, err = a.HandleAccessControl(entry, openTimeSec, artMsgIn)
	a.emitOrCleanupPreMintedToken(artMsg, preMintedToken, entry)
	cleaned = true
	return
}

// admitOpenAOPWithSessionControlFence serializes registered-agent admission
// against a control-gap flush. If admission owns the fence first, the later
// flush waits and then closes the newly admitted entry; if flush owns it first,
// the post-flush lease check rejects admission until a current AAK arrives.
func (a *UdpAC) admitOpenAOPWithSessionControlFence(dopMsg *common.ServerACOpsMsg, entry *AccessEntry, openTimeSec int, artMsgIn *common.ACOpsResultMsg) (*common.ACOpsResultMsg, error) {
	a.sessionControlFlushMu.Lock()
	defer a.sessionControlFlushMu.Unlock()
	if !a.sessionAdmissionReady() {
		return artMsgIn, common.ErrACSessionControlLeaseClosed
	}
	if dopMsg.AuthServiceId == common.RegisteredAgentAuthServiceID {
		if a.nhpSessions == nil || !a.nhpSessions.admitsSession(entry) {
			return artMsgIn, common.ErrACSessionControlNotReady
		}
		generation := a.sessionFlushGeneration.Load()
		if barrierErr := a.runAttemptBarriers().requireExact(dopMsg.AgentPublicKey, dopMsg.RunID, dopMsg.RunAttempt, generation); barrierErr != nil {
			return artMsgIn, common.ErrACSessionControlNotReady
		}
	}
	return a.admitAndIssueToken(entry, openTimeSec, artMsgIn)
}

// accessEntryFromAOP maps a decoded NHP-AOP message onto the AccessEntry the AC
// admits. Pure (no receiver, no side effects) so the field mapping — including
// the qURL v2 revocation metadata carried by P4a — is unit-testable without the
// kernel-write admission machinery.
//
// OwnerId (the server-resolved tenant identity, see common.AgentUser godoc) is
// INTENTIONALLY not populated on the AC side: the NHP-AOP wire (dopMsg) carries
// only the client-supplied fields, and the AC is not a consumer of
// /nhp/internal/token/validate (which is where server-resolved OwnerId surfaces
// downstream). A future contributor "fixing" this by guessing an OwnerId from
// dopMsg would inject a non-authoritative value into the AC-side AgentUser and
// break the field's "server-resolved-only" invariant. If the AC ever needs
// OwnerId, extend the NHP-AOP wire to carry it from the resolved server state.
func accessEntryFromAOP(dopMsg *common.ServerACOpsMsg, serverPublicKey string) *AccessEntry {
	return &AccessEntry{
		User: &common.AgentUser{
			UserId:         dopMsg.UserId,
			DeviceId:       dopMsg.DeviceId,
			OrganizationId: dopMsg.OrganizationId,
			AuthServiceId:  dopMsg.AuthServiceId,
		},
		SrcAddrs:                 dopMsg.SourceAddrs,
		DstAddrs:                 dopMsg.DestinationAddrs,
		OpenTime:                 int(dopMsg.OpenTime),
		NHPSessionId:             dopMsg.SessionId,
		NHPServerPublicKey:       serverPublicKey,
		NHPSessionOwnerId:        dopMsg.SessionOwnerId,
		NHPAgentPublicKey:        dopMsg.AgentPublicKey,
		NHPSessionIssuedAtMillis: dopMsg.SessionIssuedAtMillis,
		NHPRunID:                 dopMsg.RunID,
		NHPRunAttempt:            dopMsg.RunAttempt,
		// qURL v2 keyed-identity revocation metadata (P4a): stored verbatim from
		// the AOP onto the access entry so P4b can index live flows for immediate
		// revocation. Stored as received — NOT recomputed AC-side (see AccessEntry
		// godoc). Zero-valued for legacy admissions, where the AOP omits them.
		QurlUserPublicKeyHash: dopMsg.QurlUserPublicKeyHash,
		ResourcePublicKeyHash: dopMsg.ResourcePublicKeyHash,
		QurlSessionId:         dopMsg.QurlSessionId,
		AdmissionId:           dopMsg.AdmissionId,
		RevocationEpoch:       dopMsg.RevocationEpoch,
		Deadline:              dopMsg.Deadline,
	}
}

// HandleUdpACOperations processes a single NHP_AOP packet. Synchronous —
// callers own goroutine and wg accounting. The production caller is the
// NHP_AOP arm of recvMessageRoutine in udpac.go, which spawns this in a
// goroutine wrapped by `defer a.wg.Done(); defer a.recoverUDPHandler(...)`.
// Tests call this directly without a wg ceremony.
func (a *UdpAC) HandleUdpACOperations(ppd *core.PacketParserData) (err error) {
	acId := a.config.ACId
	dopMsg := &common.ServerACOpsMsg{}
	artMsg := &common.ACOpsResultMsg{}
	transactionId := ppd.SenderTrxId

	// Fail-closed on missing-or-wrong-length peer pubkey: the
	// dedupe key is scoped per pubkey AND per the fixed-size
	// invariant the cache key construction relies on, so any
	// RemotePubKey that is not exactly core.PublicKeySize means
	// core.responder.validatePeer either didn't run or didn't
	// populate ppd correctly. The threat model treats both
	// zero-length and wrong-length identically — both are
	// upstream invariant violations, not duplicate transactions —
	// so they share the same Critical log + ErrACMissingPeerPubkey
	// return. This branch should never fire in production;
	// returning the distinct error ensures an oncall chasing a
	// duplicate-spike alert isn't misled. Without this match, a
	// hypothetical 31- or 64-byte pubkey from a future cipher
	// scheme regression / parser bug / fuzz harness would fall
	// through to MarkSeen, get rejected by its
	// `len != core.PublicKeySize` guard, and silently surface as
	// ErrACDuplicateTransaction — exactly the masquerade that
	// adding ErrACMissingPeerPubkey was supposed to prevent.
	if len(ppd.RemotePubKey) != core.PublicKeySize {
		log.Critical("ac(%s#%d)[HandleUdpACOperations] missing or wrong-length peer pubkey (len=%d, want %d), drop %s packet", acId, transactionId, len(ppd.RemotePubKey), core.PublicKeySize, core.HeaderTypeToString(ppd.HeaderType))
		return common.ErrACMissingPeerPubkey
	}

	// Reject replays of (sender_pubkey, txid, send_time) triples
	// already processed within the cache TTL. Drop without sending
	// NHP_ART so the response channel cannot be used as a
	// replay-success oracle. No RecvThreatCount bump or SendBlockSignal
	// here — the threat counter lives on ConnData and is meaningless
	// across the connections this cache exists to span. (For AOP the
	// per-connection gate in core.responder is now drop-only too:
	// flood-exempt #1123, stale-escalation-exempt #1464,
	// replay-escalation-exempt #2518 — so this cache is AOP's sole
	// cross-connection replay defense.) See aop_replay_cache.go for the
	// threat model (#1123).
	if !a.aopReplay.MarkSeen(ppd.RemotePubKey, transactionId, ppd.RemoteSendTime) {
		// Warning, not Critical: this fires both on replay attempts
		// (the security signal we care about) and on benign in-flight
		// AOPs that hit the AC after a server restart / AC failover /
		// NAT-table flush (where the same packet is genuinely retried
		// and arrives twice). The duplicate-drop counter in #1458 is
		// the right primary alert surface; the log is the breadcrumb
		// that tells the operator which (acId, txid, pubkey, ts) saw
		// it. The pubkey fingerprint is base64-truncated to keep the
		// line short while remaining sufficient to distinguish one
		// misbehaving server from a fleet-wide signal.
		a.incrMetric(MetricAOPReplayDetected)
		log.Warning("ac(%s#%d)[HandleUdpACOperations] duplicate transaction id, drop replayed %s packet (pubkey=%s, sendTime=%d)", acId, transactionId, core.HeaderTypeToString(ppd.HeaderType), pubkeyFingerprint(ppd.RemotePubKey), ppd.RemoteSendTime)
		return common.ErrACDuplicateTransaction
	}

	err = common.DecodeServerACOpsMsg(ppd.BodyMessage, dopMsg)
	if err != nil {
		log.Error("ac(%s#%d)[HandleUdpACOperations] failed to parse %s message: %v", acId, transactionId, core.HeaderTypeToString(ppd.HeaderType), err)
		artMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
		artMsg.ErrMsg = err.Error()
		return
	}
	// The base NHP session identifier is server-assigned on KNK and must make
	// the complete AOP -> ART -> ACK round trip unchanged. Echo it before any
	// admission work so both success and structured-error ARTs remain
	// correlatable; the server still rejects a missing or mismatched echo.
	artMsg.SessionId = dopMsg.SessionId
	artMsg.SessionOwnerId = dopMsg.SessionOwnerId

	if dopMsg.SessionId == 0 {
		err = common.ErrACOperationFailed
		artMsg.ErrCode = common.ErrACOperationFailed.ErrorCode()
		artMsg.ErrMsg = err.Error()
		log.Warning("ac(%s#%d)[HandleUdpACOperations] rejected AOP with missing NHP session id", acId, transactionId)
	} else if dopMsg.OpenTime == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), bootEnumerationDeadline)
		a.sessionControlFlushMu.Lock()
		var (
			closed   int
			closeErr error
		)
		if !a.sessionFlushComplete.Load() {
			closeErr = errors.New("session-control close rejected while AC flush is incomplete")
		} else {
			closed, closeErr = a.closeNHPExactSessionWithFenceVerified(ctx, dopMsg.AgentPublicKey, dopMsg.SessionId, dopMsg.SessionIssuedAtMillis)
		}
		a.sessionControlFlushMu.Unlock()
		cancel()
		if closeErr != nil {
			artMsg.ErrCode = common.ErrACOperationFailed.ErrorCode()
			artMsg.ErrMsg = closeErr.Error()
			log.Error("ac(%s#%d)[HandleUdpACOperations] exact NHP session close did not converge: %v", acId, transactionId, closeErr)
		} else {
			artMsg.ErrCode = common.ErrSuccess.ErrorCode()
			artMsg.ErrMsg = common.ErrSuccess.Error()
			log.Info("ac(%s#%d)[HandleUdpACOperations] closed exact NHP session %d entries=%d", acId, transactionId, dopMsg.SessionId, closed)
		}
	} else {
		openTimeSec := int(dopMsg.OpenTime)
		entry := accessEntryFromAOP(dopMsg, base64.StdEncoding.EncodeToString(ppd.RemotePubKey))
		artMsg, err = a.admitOpenAOPWithSessionControlFence(dopMsg, entry, openTimeSec, artMsg)
		if err != nil {
			artMsg.ErrCode = common.ErrACOperationFailed.ErrorCode()
			artMsg.ErrMsg = err.Error()
			if errors.Is(err, common.ErrACSessionControlLeaseClosed) {
				artMsg.ErrCode = common.ErrACSessionControlLeaseClosed.ErrorCode()
				log.Warning("ac(%s#%d)[HandleUdpACOperations] registered-agent admission fenced: %v", acId, transactionId, err)
			} else if errors.Is(err, common.ErrACSessionControlNotReady) {
				artMsg.ErrCode = common.ErrACSessionControlNotReady.ErrorCode()
				log.Warning("ac(%s#%d)[HandleUdpACOperations] registered-agent admission fenced: %v", acId, transactionId, err)
			} else {
				log.Error("ac(%s#%d)[HandleUdpACOperations] HandleAccessControl failed, err: %v", acId, transactionId, err)
			}
		}
		// admitAndIssueToken may replace the result object; stamp the exact
		// server-assigned identifier after it returns so ART cannot omit it.
		artMsg.SessionId = dopMsg.SessionId
		artMsg.SessionOwnerId = dopMsg.SessionOwnerId
	}

	// send ac result
	artBytes, marshalErr := json.Marshal(artMsg)
	if marshalErr != nil {
		log.Error("ac(%s#%d)[HandleUdpACOperations] failed to marshal ART message: %v", acId, transactionId, marshalErr)
		return marshalErr
	}
	md := &core.MsgData{
		HeaderType:     core.NHP_ART,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        artBytes,
	}

	// forward to a specific transaction
	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("ac(%s#%d)[HandleUdpACOperations] transaction is not available", acId, transactionId)
		return common.ErrTransactionIdNotFound
	}

	if sendErr := transaction.SendMessage(md); sendErr != nil {
		log.Error("ac(%s#%d)[HandleUdpACOperations] transaction closed before forward: %v", acId, transactionId, sendErr)
		a.recordTransactionClosed(sendErr)
		return sendErr
	}

	return nil
}

// wireRevocationScope maps a qurl-service revocation-event wire scope string to
// the AC's internal revocationScope, returning ok=false for any scope the AC
// does not apply locally. qurl-service emits four scopes ("qurl", "resource",
// "session", "cell"); the AC applies only the first three. "cell" is a
// server-side fanout selector with no AC-local index, so the AC drops it here
// (its job is done once the server fans the event out to the cell's ACs); Slice 3
// folds the explicit cell-drop + epoch conversion into a shared scopeFromWire.
// The string VALUES are identical to the revocationScope constants by
// construction (P4b mirrored qurl-service byte-for-byte, see revocation_index.go),
// so this is an allowlist GATE, not a translation table — equal bytes in,
// validated typed value out.
//
// The ackable set is the SHARED single source of truth in
// endpoints/internal/revocationscope, which the NHP server's proof-tracking gate
// (trackFanout) also derives from — so the AC's apply/ack allowlist and the
// server's "which scopes do I expect an NHP_RVA for" set cannot drift (#2793).
//
// The allowlist is load-bearing, not defensive boilerplate: a raw
// revocationScope(s) cast would also accept "admission", and scopeAdmission is a
// populated index dimension (scopeKeysForEntry stamps every admission with an
// AdmissionId under it). An inbound scope=="admission" would therefore flush by
// admission-id — a capability qurl-service never grants over the wire and the
// design reserves for a future AC-internal cancel seam. Rejecting it (and the
// server-only "cell") here keeps the AC apply path to qurl/resource/session only.
func wireRevocationScope(s string) (revocationScope, bool) {
	if revocationscope.Contains(s) {
		return revocationScope(s), true
	}
	return "", false
}

// bareScopeKey strips the "<scope>:" transport prefix qurl-service puts on its
// scope_key ("<scope>:<identity>", see qurl-service
// internal/revocation/scopekey.go) and returns the bare identity hash/id that
// ApplyRevocation indexes on. The identity itself may legitimately contain ':'
// (a session id is opaque), so only the single leading "<scope>:" is removed via
// TrimPrefix — not a split on the last colon.
//
// It is the single source of truth for the malformed-key classification, so the
// handler does not re-derive the prefix check: a non-nil error is the exact
// reject sentinel to return —
//   - ErrRevocationScopeKeyPrefixMismatch: a non-empty prefix that disagrees with
//     scope (qurl-service always builds the prefix from the same scope, so this is
//     a producer bug / forgery). Checked first so "" classifies as empty, not
//     mismatch.
//   - ErrRevocationEmptyScopeKey: an empty scopeKey or a prefix-only key ("qurl:")
//     — no identity to act on.
func bareScopeKey(scope revocationScope, scopeKey string) (bare string, err error) {
	prefix := string(scope) + ":"
	if scopeKey != "" && !strings.HasPrefix(scopeKey, prefix) {
		return "", ErrRevocationScopeKeyPrefixMismatch
	}
	bare = strings.TrimPrefix(scopeKey, prefix)
	if bare == "" {
		return "", ErrRevocationEmptyScopeKey
	}
	return bare, nil
}

// HandleUdpACRevocation processes a single NHP_REV packet: a qURL v2 immediate-
// revocation event the NHP Server relayed from qurl-service. It unmarshals the
// ACRevocationMsg, validates the scope, strips the "<scope>:" transport prefix
// off scope_key to the bare identity, validates the epoch, and calls the P4b
// apply primitive (*UdpAC).ApplyRevocation, which finds the matching live
// AccessEntries via the secondary revocation index and tears their L3 flow state
// down now (coarse RescheduleEarlier flush — surgical precision is the deferred
// P4c/#2784 follow-up; this handler does NOT touch that path).
//
// Synchronous — the caller owns goroutine + wg accounting, mirroring
// HandleUdpACOperations. The production caller is the NHP_REV arm of
// recvMessageRoutine in udpac.go, which spawns this wrapped by
// `defer a.wg.Done(); defer a.recoverUDPHandler(core.NHP_REV)`. Tests call it
// directly without that ceremony.
//
// No replay/dedupe cache here (unlike the NHP_AOP handler): there is no NHP_ART
// response to be used as a replay-success oracle, and ApplyRevocation is already
// replay-safe — its admitEpoch watermark drops a duplicate/stale epoch and a
// no-live-match event is a no-op without advancing state. A redelivered NHP_REV
// is therefore harmless.
//
// Delivery-guarantee dependency (do not lose across the slice boundary): NHP_REV
// is fire-and-forget UDP with no ack, so a lost packet leaves the entry alive to
// natural expiry — a fail-open outcome. The replay-safety reasoning above assumes
// the sender provides redelivery. depends on: Slice 2 at-least-once send (the
// server→AC fanout must retry); tracked in the P4e plan.
//
// Every reject path is fail-closed (drops without calling ApplyRevocation) and
// increments MetricRevocationRejected so a malformed/forged-event spike is
// alarmable. Errors are logged + returned per the admission-handler convention;
// the dispatch seam does not re-log (the handler's log is richer), matching the
// NHP_ARD/NHP_AOP precedent.
func (a *UdpAC) HandleUdpACRevocation(ppd *core.PacketParserData) error {
	acId := a.config.ACId
	sessionClosePresent, dispatchErr := common.ACSessionCloseKindPresent(ppd.BodyMessage)
	if dispatchErr != nil {
		log.Error("ac(%s)[HandleUdpACRevocation] failed to inspect NHP_REV message: %v", acId, dispatchErr)
		a.incrMetric(MetricRevocationRejected)
		return dispatchErr
	}
	if sessionClosePresent {
		return a.handleUdpACSessionClose(ppd)
	}

	revMsg := &common.ACRevocationMsg{}
	if err := json.Unmarshal(ppd.BodyMessage, revMsg); err != nil {
		log.Error("ac(%s)[HandleUdpACRevocation] failed to parse NHP_REV message: %v", acId, err)
		a.incrMetric(MetricRevocationRejected)
		return err
	}

	scope, ok := wireRevocationScope(revMsg.Scope)
	if !ok {
		// Unknown, server-only ("cell"), or AC-internal-only ("admission") scope.
		// The AC applies only qurl/resource/session; anything else is dropped
		// without applying (a producer bug or a malformed/forged event for
		// unknown/admission, or a correctly-ignored cell selector).
		log.Error("ac(%s)[HandleUdpACRevocation] rejecting NHP_REV with unsupported scope=%q (key=%q epoch=%d eventId=%q)",
			acId, revMsg.Scope, revMsg.ScopeKey, revMsg.RevocationEpoch, revMsg.EventId)
		a.incrMetric(MetricRevocationRejected)
		return fmt.Errorf("%w: scope=%q", ErrRevocationUnsupportedScope, revMsg.Scope)
	}

	// Strip the "<scope>:" transport prefix to the bare identity ApplyRevocation
	// indexes on. This is the load-bearing translation across the slice boundary:
	// qurl-service emits the prefixed form, ApplyRevocation requires the bare hash
	// (its index is keyed on the bare hash stamped onto each AccessEntry at
	// admission), so forwarding the prefixed key verbatim would never match and
	// silently fail revocation open. bareScopeKey is the single source of truth
	// for the malformed-key classification — its returned sentinel
	// (ErrRevocationEmptyScopeKey for empty / prefix-only, or
	// ErrRevocationScopeKeyPrefixMismatch for a prefix that disagrees with scope)
	// is returned verbatim, so the handler does not re-derive the prefix check.
	scopeKey, keyErr := bareScopeKey(scope, revMsg.ScopeKey)
	if keyErr != nil {
		log.Error("ac(%s)[HandleUdpACRevocation] rejecting NHP_REV scope_key=%q: %v (scope=%q epoch=%d eventId=%q)",
			acId, revMsg.ScopeKey, keyErr, revMsg.Scope, revMsg.RevocationEpoch, revMsg.EventId)
		a.incrMetric(MetricRevocationRejected)
		return keyErr
	}

	if revMsg.RevocationEpoch < 0 {
		// A negative wire epoch would convert to a near-max uint64 and, on a
		// matched key, pin lastEpoch so high that every subsequent legitimate
		// revoke is dropped as stale (epoch <= last) — a fail-open
		// watermark-poisoning vector. Reject before the uint64 conversion.
		log.Error("ac(%s)[HandleUdpACRevocation] rejecting NHP_REV with negative epoch=%d (scope=%q key=%q eventId=%q)",
			acId, revMsg.RevocationEpoch, revMsg.Scope, revMsg.ScopeKey, revMsg.EventId)
		a.incrMetric(MetricRevocationRejected)
		return fmt.Errorf("%w: epoch=%d", ErrRevocationNegativeEpoch, revMsg.RevocationEpoch)
	}

	// The receive breadcrumb carries eventId for cross-hop correlation (the
	// qurl-service→server→AC trace), which ApplyRevocation's own outcome log does
	// not. It is at Debug because under cell-wide fan-out every AC receives every
	// revoke — including the keys it never admitted — so at Info this would be the
	// dominant no-op log line (count × AC count). ApplyRevocation is the P4b seam:
	// it epoch-gates, flushes matching live entries' L3 flow state immediately,
	// removes them from tokenStore, and logs the applied / stale-drop / no-match
	// outcome with counts + metrics itself — so this handler never re-logs the
	// count. The single Info below fires only when something was actually torn
	// down, attaching the eventId breadcrumb to the applied case (where an
	// operator wants the correlation id) without inflating the common no-op path.
	// scopeKey is the BARE identity here (prefix already stripped).
	log.Debug("ac(%s)[HandleUdpACRevocation] received NHP_REV scope=%s key=%q epoch=%d eventId=%q",
		acId, scope, scopeKey, revMsg.RevocationEpoch, revMsg.EventId)
	if flushed := a.ApplyRevocation(scope, scopeKey, uint64(revMsg.RevocationEpoch)); flushed > 0 {
		log.Info("ac(%s)[HandleUdpACRevocation] applied NHP_REV scope=%s key=%q epoch=%d eventId=%q",
			acId, scope, scopeKey, revMsg.RevocationEpoch, revMsg.EventId)
	}

	// Proof-of-delivery ack (P4e Slice 3, #2793). Sent AFTER ApplyRevocation on
	// EVERY validated event regardless of flush count — the ack is a convergence
	// claim ("no live flow for this identity at/below this epoch on this AC"),
	// not a work-done claim (see common.ACRevocationAckMsg). The two flushed==0
	// cases (retry after a lost ack; cell-wide reaching a never-admitted AC) MUST
	// still ack or the server would retry to age-out and falsely mark the revoke
	// degraded. Reject paths above return early WITHOUT acking by design: they
	// age out to the server's degraded metric, surfacing server↔AC validation
	// drift instead of masking it. ScopeKey is echoed VERBATIM (the original
	// scope-prefixed wire form, revMsg.ScopeKey — NOT the prefix-stripped
	// scopeKey) so the server can match the ack to its pending tracker by string
	// equality; the bare scopeKey is the AC-internal index form only.
	a.sendRevocationAck(ppd, revMsg)

	return nil
}

func (a *UdpAC) handleUdpACSessionClose(ppd *core.PacketParserData) error {
	if ppd == nil || len(ppd.RemotePubKey) != core.PublicKeySize {
		return common.ErrACMissingPeerPubkey
	}
	var closeMsg common.ACSessionCloseMsg
	if err := common.DecodeACSessionCloseMsg(ppd.BodyMessage, &closeMsg); err != nil {
		a.incrMetric(MetricRevocationRejected)
		return err
	}
	a.sessionControlFlushMu.Lock()
	defer a.sessionControlFlushMu.Unlock()
	if !a.sessionFlushComplete.Load() {
		return errors.New("session-control close rejected while AC flush is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), bootEnumerationDeadline)
	defer cancel()
	var (
		closed   int
		closeErr error
	)
	switch closeMsg.Scope {
	case common.ACSessionCloseScopeExact:
		closed, closeErr = a.closeNHPExactSessionWithFenceVerified(ctx, closeMsg.AgentPublicKey, closeMsg.SessionID, closeMsg.SessionIssuedAtMillis)
	case common.ACSessionCloseScopeAgent:
		if err := a.nhpSessions.beginAgentCloseCutoff(closeMsg.AgentPublicKey, closeMsg.IssuedThroughMillis); err != nil {
			return err
		}
		closed, closeErr = a.closeNHPAgentSessionsThroughVerified(ctx, closeMsg.AgentPublicKey, closeMsg.IssuedThroughMillis)
		if closeErr == nil {
			closeErr = a.nhpSessions.commitAgentCloseCutoff(closeMsg.AgentPublicKey, closeMsg.IssuedThroughMillis)
		}
	case common.ACSessionCloseScopeRun:
		flushGeneration := a.sessionFlushGeneration.Load()
		barriers := a.runAttemptBarriers()
		if err := barriers.record(closeMsg.AgentPublicKey, closeMsg.RunID, closeMsg.RunAttempt, flushGeneration); err != nil {
			return err
		}
		closed, closeErr = a.closeNHPRunBeforeAttemptVerified(ctx, closeMsg.AgentPublicKey, closeMsg.RunID, closeMsg.RunAttempt)
		if closeErr == nil {
			closeErr = barriers.commit(closeMsg.AgentPublicKey, closeMsg.RunID, closeMsg.RunAttempt, flushGeneration)
		}
	default:
		return ErrRevocationUnsupportedScope
	}
	if closeErr != nil {
		return closeErr
	}
	return a.sendSessionControlAck(ppd, &closeMsg, uint64(closed))
}

func (a *UdpAC) sendSessionControlAck(ppd *core.PacketParserData, closeMsg *common.ACSessionCloseMsg, closed uint64) error {
	if a == nil || a.device == nil || ppd == nil || ppd.ConnData == nil ||
		ppd.ConnData.RemoteAddr == nil || len(ppd.RemotePubKey) != core.PublicKeySize || closeMsg == nil {
		return errors.New("session-control acknowledgement envelope is incomplete")
	}
	if !common.ValidNHPACBootID(a.bootID) || a.sessionFlushGeneration.Load() == 0 ||
		!a.sessionFlushComplete.Load() {
		return errors.New("session-control acknowledgement target is not ready")
	}
	ack := common.ACSessionCloseAckMsg{
		Kind:                  closeMsg.Kind,
		Scope:                 closeMsg.Scope,
		EventID:               closeMsg.EventID,
		AgentPublicKey:        closeMsg.AgentPublicKey,
		SessionID:             closeMsg.SessionID,
		SessionIssuedAtMillis: closeMsg.SessionIssuedAtMillis,
		IssuedThroughMillis:   closeMsg.IssuedThroughMillis,
		RunID:                 closeMsg.RunID,
		RunAttempt:            closeMsg.RunAttempt,
		BootID:                a.bootID,
		FlushGeneration:       a.sessionFlushGeneration.Load(),
		Closed:                closed,
	}
	body, err := json.Marshal(&ack)
	if err != nil {
		return err
	}
	md := &core.MsgData{
		// UdpAC.sendMessageRoutine selects or creates the outbound connection by
		// RemoteAddr before it replaces ConnData with the live connection. The
		// address is copied from the authenticated inbound connection; leaving it
		// nil drops the RVA before encryption, while deriving it from message bytes
		// would let an unauthenticated field redirect the acknowledgement.
		RemoteAddr:    cloneACReplyAddr(ppd.ConnData.RemoteAddr),
		ConnData:      ppd.ConnData,
		HeaderType:    core.NHP_RVA,
		CipherScheme:  ppd.CipherScheme,
		TransactionId: a.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        ppd.RemotePubKey,
		Message:       body,
	}
	if !a.IsRunning() {
		return errors.New("AC is stopping before session-control acknowledgement")
	}
	select {
	case a.sendMsgCh <- md:
		return nil
	default:
		return errors.New("AC session-control acknowledgement queue is full")
	}
}

func cloneACReplyAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	clone := *addr
	clone.IP = append(net.IP(nil), addr.IP...)
	return &clone
}

// sendRevocationAck enqueues an NHP_RVA acknowledgement of revMsg back to the
// server that sent the NHP_REV, on the SAME server-initiated connection the
// NHP_REV arrived on (ppd.ConnData) and addressed to that server's
// authenticated pubkey (ppd.RemotePubKey). It is the AC-to-server mirror of the
// server's fanoutRevocation send: an unsolicited push (no ResponseMsgCh, not a
// transaction) — the AC does not block for a reply, since the server's retry
// loop is what provides delivery assurance, not an AC-side wait.
//
// Fire-and-forget with a non-blocking enqueue: if the AC is shutting down or the
// inbound NHP_REV lacked a usable ConnData/pubkey (a malformed-but-validated
// edge that should not occur in production), the ack is dropped with a metric
// (MetricRevocationAckSendFailed) rather than blocking the receive path. A
// dropped ack is not a correctness loss — the server retries the NHP_REV until
// it is acked or ages out — but it IS an observable AC→server-return-path
// impairment, hence the dedicated counter.
//
// The caller MUST gate this on the validated/applied path: reject paths do not
// ack (see HandleUdpACRevocation). revMsg is echoed (scope, scope_key VERBATIM,
// epoch, event_id) per the common.ACRevocationAckMsg wire contract.
func (a *UdpAC) sendRevocationAck(ppd *core.PacketParserData, revMsg *common.ACRevocationMsg) {
	acId := a.config.ACId

	// The connection and the server's authenticated pubkey both come from the
	// inbound NHP_REV's PacketParserData. ppd.RemotePubKey is set by the
	// responder only after validatePeer authenticates it, so it is the trusted
	// server identity to address the ack to. A missing ConnData/pubkey means the
	// receive path handed us an envelope we cannot reply on — drop with a metric.
	if ppd == nil || ppd.ConnData == nil || ppd.ConnData.RemoteAddr == nil || len(ppd.RemotePubKey) != core.PublicKeySize {
		a.incrMetric(MetricRevocationAckSendFailed)
		log.Error("ac(%s)[sendRevocationAck] cannot ack NHP_REV: missing connection or server pubkey (scope=%q key=%q epoch=%d eventId=%q)",
			acId, revMsg.Scope, revMsg.ScopeKey, revMsg.RevocationEpoch, revMsg.EventId)
		return
	}

	ackMsg := &common.ACRevocationAckMsg{
		Scope:           revMsg.Scope,
		ScopeKey:        revMsg.ScopeKey, // VERBATIM (still scope-prefixed)
		RevocationEpoch: revMsg.RevocationEpoch,
		EventId:         revMsg.EventId,
	}
	ackBytes, marshalErr := json.Marshal(ackMsg)
	if marshalErr != nil {
		// A fixed-shape struct of plain fields cannot realistically fail to
		// marshal; treat it as a send failure for observability rather than a
		// panic, and let the server's retry cover the missed ack.
		a.incrMetric(MetricRevocationAckSendFailed)
		log.Error("ac(%s)[sendRevocationAck] failed to marshal NHP_RVA (eventId=%q): %v", acId, revMsg.EventId, marshalErr)
		return
	}

	md := &core.MsgData{
		// Bind the return route to the authenticated inbound connection. The AC
		// send loop requires RemoteAddr even when ConnData is already known.
		RemoteAddr:    cloneACReplyAddr(ppd.ConnData.RemoteAddr),
		ConnData:      ppd.ConnData,
		HeaderType:    core.NHP_RVA,
		CipherScheme:  ppd.CipherScheme,
		TransactionId: a.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        ppd.RemotePubKey,
		Message:       ackBytes,
		// No ResponseMsgCh — unsolicited AC→server push (mirror of NHP_REV).
	}

	if !a.IsRunning() {
		a.incrMetric(MetricRevocationAckSendFailed)
		log.Error("ac(%s#%d)[sendRevocationAck] AC shutting down, skip ack (eventId=%q)", acId, md.TransactionId, revMsg.EventId)
		return
	}

	// Non-blocking enqueue: a full send queue must not stall the revoke receive
	// path. A dropped ack is recovered by the server's retry, so prefer dropping
	// (with a metric) over blocking.
	select {
	case a.sendMsgCh <- md:
		a.incrMetric(MetricRevocationAckSent)
		log.Debug("ac(%s#%d)[sendRevocationAck] enqueued NHP_RVA scope=%q key=%q epoch=%d eventId=%q",
			acId, md.TransactionId, revMsg.Scope, revMsg.ScopeKey, revMsg.RevocationEpoch, revMsg.EventId)
	default:
		a.incrMetric(MetricRevocationAckSendFailed)
		log.Warning("ac(%s#%d)[sendRevocationAck] sendMsgCh full, dropping NHP_RVA (server will retry NHP_REV) eventId=%q",
			acId, md.TransactionId, revMsg.EventId)
	}
}

// HandleAccessControl writes kernel pinhole state for entry's
// (SrcAddrs × DstAddrs) tuples and schedules per-FlowKey flush at
// admission deadline. entry is the tokenStore-bound AccessEntry —
// every successful scheduleFlushIfEnabled call records its FlowKey on
// entry.scheduledKeys so the matching cancelAllScheduledFlows (fired
// from the OnExpire hook or /refresh-shorten) cancels exactly what
// was scheduled. entry MUST be non-nil; tests exercising the early-
// return gates (breaker open, invalid openTime) should pass
// &AccessEntry{} — the gates fail-fast before touching entry's
// fields. The nil-guard at the top is defense-in-depth: a future
// gate added between the breaker check and field-touching code
// could otherwise nil-deref on test inputs.
func (a *UdpAC) HandleAccessControl(entry *AccessEntry, openTimeSec int, artMsgIn *common.ACOpsResultMsg) (artMsg *common.ACOpsResultMsg, err error) {
	if entry == nil {
		log.Error("[HandleAccessControl] called with nil entry — programmer error")
		a.incrMetric(MetricL3FlushAdmissionNilEntry)
		if artMsgIn == nil {
			artMsg = &common.ACOpsResultMsg{}
		} else {
			artMsg = artMsgIn
		}
		err = setArtMsgError(artMsg, common.ErrACNilEntry)
		return
	}
	au := entry.User
	srcAddrs := entry.SrcAddrs
	dstAddrs := entry.DstAddrs
	if artMsgIn == nil {
		artMsg = &common.ACOpsResultMsg{}
	} else {
		artMsg = artMsgIn
	}
	// L3 flush admission gate: when the scheduler's circuit breaker
	// is open, the AC is no longer reliably flushing kernel flow
	// state at session end. Under the L3-only enforcement contract
	// (post-L7-removal) that's a security boundary failure — refuse
	// new NHP-AOPs rather than admit a session whose late-flush
	// would represent unauthorized data flow past expiry. The gate
	// is a no-op when the scheduler isn't constructed (feature off).
	//
	// Distinct error code (ErrACSchedulerBreakerOpen, 53010) so an
	// oncall reading traces gets "scheduler breaker open" instead of
	// the misleading "invalid open time"
	// Non-atomic read is safe today: Stop() intentionally does NOT
	// nil a.expirySched (see udpac.go:371-376 — the field is left
	// in place so an in-flight HandleAccessControl can still
	// observe the IsBreakerOpen state during graceful drain). If a
	// future refactor adds a clear-on-Shutdown, swap to an
	// atomic.Pointer load here
	sched := a.expirySched
	if sched != nil && sched.IsBreakerOpen() {
		log.Error("[HandleAccessControl] L3 flush scheduler breaker OPEN — refusing new NHP-AOP (fail-closed admission)")
		err = setArtMsgError(artMsg, common.ErrACSchedulerBreakerOpen)
		return
	}
	// Defense-in-depth: refuse openTimeSec <= 0. ipset.Add (utils/iptables.go)
	// passes the value verbatim as the ipset `timeout` argument, and the
	// kernel ipset semantics treat `timeout 0` as PERMANENT. The /refresh
	// handler short-circuits at RemainingFirewallSeconds() <= 0 (#1942),
	// so this gate fires only on a regression — but a permanent firewall
	// hole is the worst outcome of such a regression. Fail-closed here too.
	if openTimeSec <= 0 {
		log.Error("[HandleAccessControl] openTimeSec=%d must be > 0 (would create a permanent ipset entry)", openTimeSec)
		err = setArtMsgError(artMsg, common.ErrACInvalidOpenTime)
		return
	}
	// Compute the flush deadline once per call so all per-tuple
	// schedules anchor to the same wall-clock moment as the kernel
	// state writes below. See scheduleFlushIfEnabled for the
	// no-op-when-disabled wrapper.
	//
	// # Caller order — Schedule THEN write (#2168)
	//
	// Every per-tuple block below calls scheduleFlushIfEnabled
	// BEFORE the kernel-rule write (ipset.Add / EbpfRuleAdd).
	// Schedule blocks on any in-flight Flush for the same FlowKey
	// so the new kernel rule lands AFTER the prior teardown
	// completes; the inverse order (write-then-schedule) opens a
	// silent-deny window in BPF mode and a kernel-self-heal lag
	// in iptables mode. If the kernel write subsequently fails,
	// the scheduled flush fires on an already-absent entry and
	// no-ops via the per-flusher ENOENT idempotency contract —
	// schedule-on-write-error is intentional, not a leak.
	//
	// flushDeadline = now + openTimeSec + flushSafetyMargin so the
	// kernel-side ipset/BPF entry has already naturally expired by
	// the time the scheduler fires. Without this margin, the
	// scheduler could conntrack-delete an entry whose ipset allow-
	// rule is still live for a brief window — a new SYN from the
	// allow-listed source in that window would create a fresh
	// conntrack entry, become ESTABLISHED, and survive past the
	// intended session end via the very ESTABLISHED bypass this
	// scheduler exists to defeat
	//
	// Anchoring discipline: this path
	// anchors flushDeadline AND the kernel-write TTL at admission
	// time (HandleAccessControl). The tcp/udp temp-access handlers
	// anchor BOTH at handler-spawn time (which is the kernel-write
	// moment for that path; the handler runs async from admission).
	// Both anchorings are self-consistent — kernel and schedule
	// agree within their own path. A future tightener of
	// flushSafetyMargin must hold this self-consistency on BOTH
	// paths: optimizing one anchor without the other silently breaks
	// the other path's race-window protection.
	flushDeadline := computeFlushDeadline(openTimeSec)
	// process ac operation
	tempOpenTimeSec := TempPortOpenTime
	// CloseWindowOpenTimeSec doubles as the "close everything" signal —
	// see the constant's doc comment and AccessEntry.RemainingFirewallSeconds.
	if openTimeSec == CloseWindowOpenTimeSec {
		tempOpenTimeSec = CloseWindowOpenTimeSec
	}

	// check empty src address
	if len(srcAddrs) == 0 || len(dstAddrs) == 0 {
		log.Error("[HandleAccessControl] no source or destination address specified")
		err = setArtMsgError(artMsg, common.ErrACEmptyPassAddress)
		return
	}

	// ac ipset operations
	//
	// TEST FIXTURE NOTE: this `a.config.FilterMode` read is the
	// load-bearing nil-deref trigger for
	// TestAdmitAndIssueToken_PanicMidHandleAC_TokenNeverInArtMsg in
	// tokenstore_test.go — the test passes a UdpAC with `a.config ==
	// nil` and recovers the panic to verify the pre-mint cleanup
	// defer runs and the token never lands in artMsg.ACToken. If you
	// add an `if a.config == nil { return }` guard above this line,
	// the test fixture breaks and t.Fatalf fires — see the test's
	// PANIC TRIGGER NOTE for guidance on porting the trigger to a
	// new deep-path nil-deref site rather than deleting the test.
	if a.config.FilterMode == FilterMode_IPTABLES || a.config.FilterMode == FilterMode_EBPFXDP {
		if a.ipset == nil {
			log.Error("[HandleAccessControl] ipset is nil")
			err = setArtMsgError(artMsg, common.ErrACIPSetNotFound)
			return
		}
	}

	// Use AC's default IP to override empty or sentinel destination IP.
	// Load-bearing for the FRPS-behind-AC redesign (nhp #1977 /
	// SLACK_QURL_ROLLOUT.md §6, 2026-05-18): the resource.toml overlay
	// renders `Addr.Ip = ""` so the ipset entry written downstream keys
	// on (agent_ip, port, a.config.DefaultIp = ac_local_ip) — the
	// triple a real customer SYN actually has at the AC kernel.
	// Coverage: see `TestApplyDefaultIpSubstitution` for the unit-test
	// fence on this substitution; the live regression test in
	// `endpoints/server/config_test.go::TestFRPSResourceTOMLOverlay_…`
	// asserts the producer side renders `Addr.Ip = ""`.
	//
	// Invariant: dstAddrs is goroutine-local to this call —
	// HandleAccessControl receives a per-packet slice from
	// recvMessageRoutine + json.Unmarshal in `udpac.go`, and nothing
	// caches it across goroutines. The helper's concurrency contract
	// (see its godoc) depends on this. A future refactor that adds
	// upstream caching of `dstAddrs` must add synchronization before
	// calling the helper.
	applyDefaultIpSubstitution(a.config.DefaultIp, dstAddrs)

	ipPassMode := a.IpPassMode()
	switch ipPassMode {
	// pass the knock ip immediately
	case PASS_KNOCKIP_WITH_RANGE:
		fallthrough
	case PASS_KNOCK_IP:
		fallthrough
	default:
		for _, srcAddr := range srcAddrs {
			var ipNet *net.IPNet

			// Detect IP type using proper parsing instead of string matching
			ipType, ipErr := utils.DetectIPType(srcAddr.Ip)
			if ipErr != nil {
				log.Error("[HandleAccessControl] invalid source IP: %s, error: %v", srcAddr.Ip, ipErr)
				continue
			}

			// Use appropriate CIDR mask based on IP type and pass mode
			rangeMode := ipPassMode == PASS_KNOCKIP_WITH_RANGE
			cidrMask := utils.GetCIDRMask(ipType, rangeMode)
			_, ipNet, _ = net.ParseCIDR(srcAddr.Ip + cidrMask)
			log.Debug("src ip is %s, net range is %s", srcAddr, ipNet.String())

			for _, dstAddr := range dstAddrs {
				// for tcp
				if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "tcp" || dstAddr.Protocol == "any" {
					var ipHashStr string
					if dstAddr.Port == 0 {
						ipHashStr = ipsetHashTCPAllPorts(srcAddr.Ip, dstAddr.Ip)
					} else {
						ipHashStr = ipsetHashTCP(srcAddr.Ip, dstAddr.Port, dstAddr.Ip)
					}

					switch a.config.FilterMode {
					case FilterMode_IPTABLES:
						a.scheduleFlushIfEnabled(entry, srcAddr.Ip, dstAddr.Ip, dstAddr.Port, FlowProtoTCP, flushDeadline)
						_, err = a.ipset.Add(ipType, 1, openTimeSec, ipHashStr)
						if err != nil {
							log.Error("[HandleAccessControl] add ipset %s error: %v", ipHashStr, err)
							err = setArtMsgError(artMsg, common.ErrACIPSetOperationFailed)
							return
						}
					//ebpf knock
					case FilterMode_EBPFXDP:
						if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "any" {
							ebpfHashStr := ebpf.EbpfRuleParams{
								SrcIP: srcAddr.Ip,
								DstIP: dstAddr.Ip,
							}
							a.scheduleFlushIfEnabled(entry, srcAddr.Ip, dstAddr.Ip, 0, FlowProtoAny, flushDeadline)
							err = a.ebpfRuleAddFailClosed(2, ebpfHashStr, openTimeSec)
							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
								return
							}
							if err = a.addEbpfxdpIpsetMirror(ipType, 1, openTimeSec, ipHashStr, "HandleAccessControl"); err != nil {
								err = setArtMsgErrorFromKernelWrite(artMsg, err)
								return
							}
						}
						if dstAddr.Protocol == "tcp" {
							ebpfHashStr := ebpf.EbpfRuleParams{
								SrcIP:    srcAddr.Ip,
								DstIP:    dstAddr.Ip,
								DstPort:  dstAddr.Port,
								Protocol: dstAddr.Protocol,
							}
							a.scheduleFlushIfEnabled(entry, srcAddr.Ip, dstAddr.Ip, dstAddr.Port, FlowProtoTCP, flushDeadline)
							err = a.ebpfRuleAddFailClosed(1, ebpfHashStr, openTimeSec)
							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf tcp failed src: %s dst: %s, protocol: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
								return
							}
							if err = a.addEbpfxdpIpsetMirror(ipType, 1, openTimeSec, ipHashStr, "HandleAccessControl"); err != nil {
								err = setArtMsgErrorFromKernelWrite(artMsg, err)
								return
							}
						}
					default:
						log.Error("[HandleAccessControl] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
						return
					}
				}

				// for udp
				if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "udp" || dstAddr.Protocol == "any" {
					var ipHashStr string
					if dstAddr.Port == 0 {
						ipHashStr = ipsetHashUDPAllPorts(srcAddr.Ip, dstAddr.Ip)
					} else {
						ipHashStr = ipsetHashUDP(srcAddr.Ip, dstAddr.Port, dstAddr.Ip)
					}

					switch a.config.FilterMode {
					case FilterMode_IPTABLES:
						a.scheduleFlushIfEnabled(entry, srcAddr.Ip, dstAddr.Ip, dstAddr.Port, FlowProtoUDP, flushDeadline)
						_, err = a.ipset.Add(ipType, 1, openTimeSec, ipHashStr)
						if err != nil {
							log.Error("[HandleAccessControl] add ipset %s error: %v", ipHashStr, err)
							err = setArtMsgError(artMsg, common.ErrACIPSetOperationFailed)
							return
						}
					case FilterMode_EBPFXDP:
						if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "any" {
							ebpfHashStr := ebpf.EbpfRuleParams{
								SrcIP: srcAddr.Ip,
								DstIP: dstAddr.Ip,
							}
							a.scheduleFlushIfEnabled(entry, srcAddr.Ip, dstAddr.Ip, 0, FlowProtoAny, flushDeadline)
							err = a.ebpfRuleAddFailClosed(2, ebpfHashStr, openTimeSec)
							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
								return
							}
							if err = a.addEbpfxdpIpsetMirror(ipType, 1, openTimeSec, ipHashStr, "HandleAccessControl"); err != nil {
								err = setArtMsgErrorFromKernelWrite(artMsg, err)
								return
							}
						}
						if dstAddr.Protocol == "udp" {
							ebpfHashStr := ebpf.EbpfRuleParams{
								SrcIP:    srcAddr.Ip,
								DstIP:    dstAddr.Ip,
								DstPort:  dstAddr.Port,
								Protocol: dstAddr.Protocol,
							}
							a.scheduleFlushIfEnabled(entry, srcAddr.Ip, dstAddr.Ip, dstAddr.Port, FlowProtoUDP, flushDeadline)
							err = a.ebpfRuleAddFailClosed(1, ebpfHashStr, openTimeSec)

							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf udp failed src: %s dst: %s, protocol: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
								return
							}
							if err = a.addEbpfxdpIpsetMirror(ipType, 1, openTimeSec, ipHashStr, "HandleAccessControl"); err != nil {
								err = setArtMsgErrorFromKernelWrite(artMsg, err)
								return
							}
						}
					default:
						log.Error("[HandleAccessControl] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
						return
					}
				}

				// for icmp ping
				if dstAddr.Port == 0 && (len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "any") {
					for _, dstAddr := range dstAddrs {
						ipHashStr := ipsetHashICMP(srcAddr.Ip, utils.ICMPEchoType(ipType), dstAddr.Ip)
						switch a.config.FilterMode {
						case FilterMode_IPTABLES:
							a.scheduleFlushIfEnabled(entry, srcAddr.Ip, dstAddr.Ip, 0, FlowProtoICMP, flushDeadline)
							_, err = a.ipset.Add(ipType, 1, openTimeSec, ipHashStr)
							if err != nil {
								log.Error("[HandleAccessControl] add ipset %s error: %v", ipHashStr, err)
								err = setArtMsgError(artMsg, common.ErrACIPSetOperationFailed)
								return
							}
						case FilterMode_EBPFXDP:
							ebpfHashStr := ebpf.EbpfRuleParams{
								SrcIP: srcAddr.Ip,
								DstIP: dstAddr.Ip,
							}
							a.scheduleFlushIfEnabled(entry, srcAddr.Ip, dstAddr.Ip, 0, FlowProtoICMP, flushDeadline)
							err = a.ebpfRuleAddFailClosed(3, ebpfHashStr, openTimeSec)
							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
								return
							}
							if err = a.addEbpfxdpIpsetMirror(ipType, 1, openTimeSec, ipHashStr, "HandleAccessControl"); err != nil {
								err = setArtMsgErrorFromKernelWrite(artMsg, err)
								return
							}
						default:
							log.Error("[HandleAccessControl] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
							return
						}
					}
				}

				// add tempset for the adjacent 128 (25bit netmask ipv4, 121bit netmask ipv6) addresses derived from the target IP address
				if ipPassMode == PASS_KNOCKIP_WITH_RANGE && ipNet != nil {
					netStr := ipNet.String()
					switch a.config.FilterMode {
					case FilterMode_IPTABLES:
						if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "tcp" || dstAddr.Protocol == "any" {
							var netHashStr string
							if dstAddr.Port == 0 {
								netHashStr = ipsetHashNetAllPorts(netStr)
							} else {
								netHashStr = ipsetHashNetPort(netStr, dstAddr.Port)
							}
							_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, netHashStr)
						}

						if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "udp" || dstAddr.Protocol == "any" {
							var netHashStr string
							if dstAddr.Port == 0 {
								netHashStr = ipsetHashNetUDPAllPorts(netStr)
							} else {
								netHashStr = ipsetHashNetUDPPort(netStr, dstAddr.Port)
							}
							_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, netHashStr)
						}

						if dstAddr.Port == 0 && (len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "any") {
							// ICMP rules are supplementary (ping diagnostics) - failure is non-fatal
							// because the user can still access the protected service via TCP/UDP.
							netHashStr := ipsetHashNetICMP(netStr, utils.ICMPEchoType(ipType))
							_, addErr := a.ipset.Add(ipType, 4, tempOpenTimeSec, netHashStr)
							if addErr != nil {
								log.Warning("[HandleAccessControl] failed to add tempset entry %s: %v", netHashStr, addErr)
							}
						}

					case FilterMode_EBPFXDP:
						srcIp, ipnet, parseErr := net.ParseCIDR(netStr)
						if parseErr != nil {
							log.Error("[HandleAccessControl] failed to parse CIDR %s: %v", netStr, parseErr)
							continue
						}
						if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "tcp" || dstAddr.Protocol == "any" {
							for srcIp := srcIp.Mask(ipnet.Mask); ipnet.Contains(srcIp); incrementIP(srcIp) {
								srcIpStr := srcIp.String()
								if dstAddr.Port != 0 {
									ebpfHashStr := ebpf.EbpfRuleParams{
										SrcIP:   srcIpStr,
										DstPort: dstAddr.Port,
									}
									if addErr := a.ebpfRuleAddFailClosed(4, ebpfHashStr, tempOpenTimeSec); addErr != nil {
										log.Error("[EbpfRuleAdd] add ebpf for tcp dst port src: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstPort, addErr)
										err = setArtMsgErrorFromKernelWrite(artMsg, addErr)
										return
									}

								} else {
									// All-ports sentinel built via the shared helper so the
									// min/max bounds stay in lockstep with the XDP port_list
									// lookup key (#2843); see allPortsEbpfRuleParams.
									ebpfHashStr := allPortsEbpfRuleParams(srcIpStr)
									if addErr := a.ebpfRuleAddFailClosed(5, ebpfHashStr, tempOpenTimeSec); addErr != nil {
										log.Error("[EbpfRuleAdd] add ebpf src: %s  dstportstart: %d,  dstportend: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstPortStart, ebpfHashStr.DstPortEnd, addErr)
										err = setArtMsgErrorFromKernelWrite(artMsg, addErr)
										return
									}
								}
							}
							var netHashStr string
							if dstAddr.Port == 0 {
								netHashStr = ipsetHashNetAllPorts(netStr)
							} else {
								netHashStr = ipsetHashNetPort(netStr, dstAddr.Port)
							}
							if err = a.addEbpfxdpIpsetMirror(ipType, 4, tempOpenTimeSec, netHashStr, "HandleAccessControl"); err != nil {
								err = setArtMsgErrorFromKernelWrite(artMsg, err)
								return
							}
						}
						if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "udp" || dstAddr.Protocol == "any" {
							for srcIp := srcIp.Mask(ipnet.Mask); ipnet.Contains(srcIp); incrementIP(srcIp) {
								srcIpStr := srcIp.String()

								if dstAddr.Port != 0 {
									ebpfHashStr := ebpf.EbpfRuleParams{
										SrcIP:   srcIpStr,
										DstPort: dstAddr.Port,
									}
									if addErr := a.ebpfRuleAddFailClosed(4, ebpfHashStr, tempOpenTimeSec); addErr != nil {
										log.Error("[EbpfRuleAdd] add ebpf for udp dst port src: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstPort, addErr)
										err = setArtMsgErrorFromKernelWrite(artMsg, addErr)
										return
									}
								} else {
									// All-ports sentinel built via the shared helper so the
									// min/max bounds stay in lockstep with the XDP port_list
									// lookup key (#2843); see allPortsEbpfRuleParams.
									ebpfHashStr := allPortsEbpfRuleParams(srcIpStr)
									if addErr := a.ebpfRuleAddFailClosed(5, ebpfHashStr, tempOpenTimeSec); addErr != nil {
										log.Error("[EbpfRuleAdd] add ebpf src: %s  dstportstart: %d,  dstportend: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstPortStart, ebpfHashStr.DstPortEnd, addErr)
										err = setArtMsgErrorFromKernelWrite(artMsg, addErr)
										return
									}
								}
							}
							var netHashStr string
							if dstAddr.Port == 0 {
								netHashStr = ipsetHashNetUDPAllPorts(netStr)
							} else {
								netHashStr = ipsetHashNetUDPPort(netStr, dstAddr.Port)
							}
							if err = a.addEbpfxdpIpsetMirror(ipType, 4, tempOpenTimeSec, netHashStr, "HandleAccessControl"); err != nil {
								err = setArtMsgErrorFromKernelWrite(artMsg, err)
								return
							}
						}
						if dstAddr.Port == 0 && (len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "any") {
							icmpMirrorReady := true
							for srcIp := srcIp.Mask(ipnet.Mask); ipnet.Contains(srcIp); incrementIP(srcIp) {
								srcIpStr := srcIp.String()
								ebpfHashStr := ebpf.EbpfRuleParams{
									SrcIP: srcIpStr,
									DstIP: dstAddr.Ip,
								}
								if addErr := a.ebpfRuleAddFailClosed(3, ebpfHashStr, tempOpenTimeSec); addErr != nil {
									log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, addErr)
									icmpMirrorReady = false
								}
							}
							if icmpMirrorReady {
								netHashStr := ipsetHashNetICMP(netStr, utils.ICMPEchoType(ipType))
								if addErr := a.addEbpfxdpIpsetMirror(ipType, 4, tempOpenTimeSec, netHashStr, "HandleAccessControl"); addErr != nil {
									log.Warning("[HandleAccessControl] failed to add supplementary eBPF iptables mirror tempset ICMP entry %s: %v", netHashStr, addErr)
								}
							}
						}
					default:
						log.Error("[HandleAccessControl] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
						return
					}
				}
			}
		}

		// return temporary listened port(s) and nhp access token, then pass the real ip when agent sends access message
	case PASS_PRE_ACCESS_IP:
		// ac open a temporary tcp or udp port for access
		dstIp := net.ParseIP(dstAddrs[0].Ip)
		if dstIp == nil {
			log.Error("[HandleAccessControl] destination IP %s is invalid", dstAddrs[0].Ip)
			err = setArtMsgError(artMsg, common.ErrInvalidIpAddress)
			return
		}

		var ipType utils.IPTYPE
		var netStr string
		var netStr1 string
		var pickedPort int
		var tcpListener *net.TCPListener
		var udpListener *net.UDPConn

		// Detect IP type using proper parsing instead of string matching
		ipType, ipErr := utils.DetectIPType(dstAddrs[0].Ip)
		if ipErr != nil {
			log.Error("[HandleAccessControl] invalid destination IP for PASS_PRE_ACCESS_IP: %s", dstAddrs[0].Ip)
			err = setArtMsgError(artMsg, common.ErrInvalidIpAddress)
			return
		}
		if ipType == utils.IPV6 {
			netStr = "::/0" // Canonical IPv6 "any" notation
		} else {
			// since ipset does not allow full ip range 0.0.0.0/0, we use two ip ranges
			netStr = "0.0.0.0/1"
			netStr1 = "128.0.0.0/1"
		}

		// openning temp tcp access
		tcpListener, err = net.ListenTCP("tcp", &net.TCPAddr{
			IP:   dstIp,
			Port: 0, // ephemeral port
		})

		if err != nil {
			log.Error("[HandleAccessControl] temporary tcp listening error: %v", err)
			err = setArtMsgError(artMsg, common.ErrACTempPortListenFailed)
			return
		}

		// retrieve local port
		tladdr := tcpListener.Addr()
		tlocalAddr, locErr := net.ResolveTCPAddr(tladdr.Network(), tladdr.String())
		if locErr != nil {
			log.Error("[HandleAccessControl] resolve local TCPAddr error: %v", locErr)
			err = setArtMsgError(artMsg, common.ErrACResolveTempPortFailed)
			return
		}

		log.Debug("open temporary tcp port %s", tlocalAddr.String())
		switch a.config.FilterMode {
		case FilterMode_IPTABLES:
			portHashStr := ipsetHashNetPort(netStr, tlocalAddr.Port)
			_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, portHashStr)

			if err != nil {
				log.Error("[HandleAccessControl] add ipset %s error: %v", portHashStr, err)
				err = setArtMsgError(artMsg, common.ErrACIPSetOperationFailed)
				return
			}
			// IPv4 requires two ranges (0.0.0.0/1 and 128.0.0.0/1) since ipset doesn't allow 0.0.0.0/0
			// IPv6 uses ::/0 directly, so netStr1 is empty for IPv6
			if netStr1 != "" {
				portHashStr = ipsetHashNetPort(netStr1, tlocalAddr.Port)
				_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, portHashStr)
				if err != nil {
					log.Error("[HandleAccessControl] add ipset %s error: %v", portHashStr, err)
					err = setArtMsgError(artMsg, common.ErrACIPSetOperationFailed)
					return
				}
			}
		case FilterMode_EBPFXDP:
			ebpfHashStr := ebpf.EbpfRuleParams{
				Protocol: "tcp",
				DstPort:  tlocalAddr.Port,
			}
			err = a.ebpfRuleAddFailClosed(6, ebpfHashStr, tempOpenTimeSec)
			if err != nil {
				log.Error("[EbpfRuleAdd] add ebpf type 6 protocol: %s, dstport :%d, %v", ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
				return
			}
			portHashStr := ipsetHashNetPort(netStr, tlocalAddr.Port)
			if err = a.addEbpfxdpIpsetMirror(ipType, 4, tempOpenTimeSec, portHashStr, "HandleAccessControl"); err != nil {
				err = setArtMsgErrorFromKernelWrite(artMsg, err)
				return
			}
			if netStr1 != "" {
				portHashStr = ipsetHashNetPort(netStr1, tlocalAddr.Port)
				if err = a.addEbpfxdpIpsetMirror(ipType, 4, tempOpenTimeSec, portHashStr, "HandleAccessControl"); err != nil {
					err = setArtMsgErrorFromKernelWrite(artMsg, err)
					return
				}
			}
		default:
			log.Error("[HandleAccessControl] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
			return
		}

		pickedPort = tlocalAddr.Port
		log.Info("[HandleAccessControl] open temporary tcp port on %s", tladdr.String())

		// for temp udp access
		udpListener, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   dstIp,
			Port: pickedPort, // ephemeral port(0) or continue with previously picked tcp port
		})
		if err != nil {
			log.Error("[HandleAccessControl] temporary udp listening error: %v", err)
			err = setArtMsgError(artMsg, common.ErrACTempPortListenFailed)
			return
		}

		// retrieve local port
		uladdr := udpListener.LocalAddr()
		_, locErr = net.ResolveUDPAddr(uladdr.Network(), uladdr.String())
		if locErr != nil {
			log.Error("[HandleAccessControl] resolve local UDPAddr error: %v", locErr)
			err = setArtMsgError(artMsg, common.ErrACResolveTempPortFailed)
			return
		}

		log.Debug("open temporary udp port %s", tlocalAddr.String())
		pickedPort = tlocalAddr.Port

		switch a.config.FilterMode {
		case FilterMode_IPTABLES:
			portHashStr := ipsetHashNetUDPPort(netStr, tlocalAddr.Port)
			_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, portHashStr)
			if err != nil {
				log.Error("[HandleAccessControl] add ipset %s error: %v", portHashStr, err)
				err = setArtMsgError(artMsg, common.ErrACIPSetOperationFailed)
				return
			}
			// IPv4 requires two ranges (0.0.0.0/1 and 128.0.0.0/1) since ipset doesn't allow 0.0.0.0/0
			// IPv6 uses ::/0 directly, so netStr1 is empty for IPv6
			if netStr1 != "" {
				portHashStr = ipsetHashNetUDPPort(netStr1, tlocalAddr.Port)
				_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, portHashStr)
				if err != nil {
					log.Error("[HandleAccessControl] add ipset %s error: %v", portHashStr, err)
					err = setArtMsgError(artMsg, common.ErrACIPSetOperationFailed)
					return
				}
			}
		case FilterMode_EBPFXDP:
			ebpfHashStr := ebpf.EbpfRuleParams{
				Protocol: "udp",
				DstPort:  tlocalAddr.Port,
			}
			err = a.ebpfRuleAddFailClosed(6, ebpfHashStr, tempOpenTimeSec)
			if err != nil {
				log.Error("[EbpfRuleAdd] add ebpf type 6 protocol: %s, dstport :%d, %v", ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
				return
			}
			portHashStr := ipsetHashNetUDPPort(netStr, tlocalAddr.Port)
			if err = a.addEbpfxdpIpsetMirror(ipType, 4, tempOpenTimeSec, portHashStr, "HandleAccessControl"); err != nil {
				err = setArtMsgErrorFromKernelWrite(artMsg, err)
				return
			}
			if netStr1 != "" {
				portHashStr = ipsetHashNetUDPPort(netStr1, tlocalAddr.Port)
				if err = a.addEbpfxdpIpsetMirror(ipType, 4, tempOpenTimeSec, portHashStr, "HandleAccessControl"); err != nil {
					err = setArtMsgErrorFromKernelWrite(artMsg, err)
					return
				}
			}
		default:
			log.Error("[HandleAccessControl] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
			return
		}
		log.Info("[HandleAccessControl] open temporary udp port on %s", tladdr.String())

		tempEntry := newTempAccessEntry(entry, au, srcAddrs, dstAddrs, tempOpenTimeSec)
		// INVARIANT: this token issuance is not gated by the
		// emitOrCleanupPreMintedToken pattern HandleUdpACOperations uses,
		// because PreAccessAction is reached only after every error return
		// in HandleAccessControl above, and ErrCode is unconditionally set
		// to success at the bottom of this function. Any future error
		// branch added between this line and the `ErrCode = ErrSuccess`
		// assignment below would mint a token paired with a failure code
		// and leak it via the server's `%+v` artMsg logs (the leak-logger
		// predicate uses the strict `ErrCode != ErrSuccess.ErrorCode()`
		// check). Post-nhp#1124 the token is the entire auth secret;
		// preserve the issuance-immediately-before-success pairing or
		// move to a gated helper. Code-level enforcement tracked in #1420.
		artMsg.PreAccessAction = &common.PreAccessInfo{
			AccessPort:     strconv.Itoa(pickedPort),
			ACPubKey:       a.device.PublicKeyBase64(),
			ACToken:        a.GenerateAccessToken(tempEntry),
			ACCipherScheme: a.config.DefaultCipherScheme,
		}

		if tcpListener != nil {
			a.wg.Add(1)
			go a.tcpTempAccessHandler(tcpListener, tempOpenTimeSec, au, srcAddrs, dstAddrs, openTimeSec)
		}

		if udpListener != nil {
			a.wg.Add(1)
			go a.udpTempAccessHandler(udpListener, tempOpenTimeSec, au, srcAddrs, dstAddrs, openTimeSec)
		}
	}

	log.Info("[HandleAccessControl] succeed")

	artMsg.ErrCode = common.ErrSuccess.ErrorCode()
	artMsg.OpenTime = uint32(openTimeSec)

	return
}

func (a *UdpAC) tcpTempAccessHandler(listener *net.TCPListener, timeoutSec int, au *common.AgentUser, srcAddrs, dstAddrs []*common.NetAddress, openTimeSec int) {
	defer a.wg.Done()
	// Spawned from HandleAccessControl on the NHP_AOP path; same
	// blast radius as the per-packet recover seam in
	// recvMessageRoutine — a panic here would crash nhp-acd and
	// take out every in-flight knock transaction. See #1423.
	defer a.recoverUDPHandler(core.NHP_AOP)
	defer func() { _ = listener.Close() }()

	// accept only the first incoming tcp connection
	startTime := time.Now()
	deadlineTime := startTime.Add(time.Duration(timeoutSec) * time.Second)
	localAddrStr := listener.Addr().String()
	err := listener.SetDeadline(deadlineTime)
	if err != nil {
		log.Error("[tcpTempAccessHandler] temporary port on %s failed to set tcp listen timeout", localAddrStr)
		return
	}
	conn, err := listener.Accept()
	if err != nil {
		log.Error("[tcpTempAccessHandler] temporary port on %s tcp listen timeout", localAddrStr)
		return
	}

	defer func() { _ = conn.Close() }()
	err = conn.SetDeadline(deadlineTime)
	if err != nil {
		log.Error("[tcpTempAccessHandler] temporary port on %s failed to set tcp conn timeout", localAddrStr)
		return
	}

	remoteAddrStr := conn.RemoteAddr().String()
	pkt := a.device.AllocatePoolPacket()
	defer a.device.ReleasePoolPacket(pkt)

	// monitor stop signals and quit connection earlier
	ctx, ctxCancel := context.WithDeadline(context.Background(), deadlineTime)
	defer ctxCancel()
	go a.tempConnTerminator(conn, ctx)

	// tcp recv common header first
	n, err := conn.Read(pkt.Buf[:core.HeaderCommonSize])
	if err != nil || n < core.HeaderCommonSize {
		log.Error("[tcpTempAccessHandler] failed to receive tcp packet header from remote address %s (%v)", remoteAddrStr, err)
		return
	}

	pkt.Content = pkt.Buf[:n]
	// check type and payload size
	msgType, msgSize := pkt.HeaderTypeAndSize()
	if msgType != core.NHP_ACC {
		log.Error("[tcpTempAccessHandler] message type is not %s, close connection", core.HeaderTypeToString(core.NHP_ACC))
		return
	}

	packetSize := pkt.Header().Size() + msgSize
	remainingSize := packetSize - n
	n, err = conn.Read(pkt.Buf[n:packetSize])
	if err != nil || n < remainingSize {
		log.Error("[tcpTempAccessHandler] failed to receive tcp message body from remote address %s (%v)", remoteAddrStr, err)
		return
	}

	pkt.Content = pkt.Buf[:packetSize]
	//log.Trace("[tcpTempAccessHandler]receive tcp access packet (%s -> %s): %+v", remoteAddrStr, localAddrStr, pkt.Content)
	log.Info("[tcpTempAccessHandler] receive tcp access message (%s -> %s)", remoteAddrStr, localAddrStr)

	pd := &core.PacketData{
		BasePacket:     pkt,
		ConnData:       &core.ConnectionData{},
		InitTime:       time.Now().UnixNano(),
		DecryptedMsgCh: make(chan *core.PacketParserData),
	}

	if !a.IsRunning() {
		log.Error("[tcpTempAccessHandler] PacketData channel closed or being closed, skip decrypting")
		return
	}

	// start message decryption. A bounded-queue rejection already releases the
	// pooled packet; do not wait forever for a decrypt result that cannot arrive.
	if !a.device.RecvPacketToMsg(pd) {
		log.Warning("[tcpTempAccessHandler] decrypt queue full, shedding message from %s", remoteAddrStr)
		return
	}

	// waiting for message decryption
	accPpd := <-pd.DecryptedMsgCh
	close(pd.DecryptedMsgCh)

	if accPpd.Error != nil {
		log.Error("[tcpTempAccessHandler] failed to decrypt tcp access message: %v", accPpd.Error)
		return
	}

	accMsg := &common.AgentAccessMsg{}
	err = json.Unmarshal(accPpd.BodyMessage, accMsg)
	if err != nil {
		log.Error("[tcpTempAccessHandler] failed to parse %s message: %v", core.HeaderTypeToString(accPpd.HeaderType), err)
		return
	}

	// The kernel rule this handler writes lives for the long outer
	// openTimeSec (often hours), so its scheduled L3 flush must be
	// OWNED by an AccessEntry with a matching lifetime — not recorded
	// on tempEntry (OpenTime ~30s, would Cancel the flush at its ~35s
	// expiry → ESTABLISHED-bypass). registerTempAccessFlushEntry mints
	// that long-lived owner (#2213, retiring the prior orphan path) so
	// the flush is cancelable by an explicit admin Cancel (#2172). The
	// flush deadline is unchanged (computeFlushDeadline(openTimeSec)):
	// only OWNERSHIP changed, not timing. See registerTempAccessFlushEntry
	// godoc for the lifetime-mismatch analysis.
	if parentEntry, admitted := a.lockAdmittedTempAccessParent(accMsg.ACToken); admitted {
		defer a.sessionControlFlushMu.Unlock()
		remoteAddr, _ := net.ResolveTCPAddr(conn.RemoteAddr().Network(), conn.RemoteAddr().String())
		srcAddrIp := remoteAddr.IP.String()

		// Detect IP type using proper parsing instead of string matching
		ipType, ipErr := utils.DetectIPType(dstAddrs[0].Ip)
		if ipErr != nil {
			log.Error("[tcpTempAccessHandler] invalid destination IP: %s", dstAddrs[0].Ip)
			return
		}

		// All per-tuple keys below record on this one entry, mirroring
		// HandleAccessControl's single-entry multi-tuple admission (hence
		// hoisted out of the loop). Ownership/timing rationale: see the
		// block comment above + registerTempAccessFlushEntry godoc.
		flushEntry := a.registerTempAccessFlushEntry(parentEntry, au, srcAddrs, dstAddrs, openTimeSec)

		// Anchor flushDeadline at the moment the temp handler is about
		// to write kernel state — the kernel timer starts NOW, not at
		// HandleAccessControl's earlier admission anchor. Margin
		// rationale: see flushSafetyMargin's comment.
		flushDeadline := computeFlushDeadline(openTimeSec)
		for _, dstAddr := range dstAddrs {
			var ipHashStr string
			if dstAddr.Port == 0 {
				ipHashStr = ipsetHashTCPAllPorts(srcAddrIp, dstAddr.Ip)
			} else {
				ipHashStr = ipsetHashTCP(srcAddrIp, dstAddr.Port, dstAddr.Ip)
			}
			switch a.config.FilterMode {
			case FilterMode_IPTABLES:
				// Wildcard port (Port==0) maps to the FlowKey port=0
				// no-port-filter form; ConntrackFlusher skips --dport
				// in that case, which is the right partial-tuple shape.
				a.scheduleFlushIfEnabled(flushEntry, srcAddrIp, dstAddr.Ip, dstAddr.Port, FlowProtoTCP, flushDeadline)
				_, err = a.ipset.Add(ipType, 1, openTimeSec, ipHashStr)
				if err != nil {
					log.Error("[tcpTempAccessHandler] add ipset %s error: %v", ipHashStr, err)
					return
				}
			case FilterMode_EBPFXDP:
				ebpfHashStr := ebpf.EbpfRuleParams{
					SrcIP: srcAddrIp,
					DstIP: dstAddr.Ip,
				}
				// mapType=2 is the (src,dst) sdwhitelist with no port —
				// FlowProtoAny matches that shape. Intentional
				// asymmetry vs the iptables branch above
				// (FlowProtoTCP + dstAddr.Port): the eBPF temp-
				// access map shape is proto-agnostic by design,
				// while ipset uses `hash:ip,port,ip`. The scheduler
				// must mirror whichever kernel shape was written —
				// schedule-shape MUST match write-shape or the
				// flusher's lookup misses and the entry survives
				// past timeout. A future change that swaps the
				// eBPF mapType here MUST also update the FlowKey
				// shape to match.
				a.scheduleFlushIfEnabled(flushEntry, srcAddrIp, dstAddr.Ip, 0, FlowProtoAny, flushDeadline)
				err = a.ebpfRuleAddFailClosed(2, ebpfHashStr, openTimeSec)
				if err != nil {
					log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
					return
				}
				if err = a.addEbpfxdpIpsetMirror(ipType, 1, openTimeSec, ipHashStr, "tcpTempAccessHandler"); err != nil {
					return
				}
			default:
				log.Error("[tcpTempAccessHandler] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
				return
			}
		}
	}
}

func (a *UdpAC) udpTempAccessHandler(conn *net.UDPConn, timeoutSec int, au *common.AgentUser, srcAddrs, dstAddrs []*common.NetAddress, openTimeSec int) {
	defer a.wg.Done()
	// Same per-packet panic-recover discipline as tcpTempAccessHandler.
	defer a.recoverUDPHandler(core.NHP_AOP)
	defer func() { _ = conn.Close() }()
	// listen to accept and handle only one incoming connection
	startTime := time.Now()
	deadlineTime := startTime.Add(time.Duration(timeoutSec) * time.Second)
	localAddrStr := conn.LocalAddr().String()
	err := conn.SetDeadline(deadlineTime)
	if err != nil {
		log.Error("[udpTempAccessHandler] temporary port on %s failed to set udp conn timeout", localAddrStr)
		return
	}

	pkt := a.device.AllocatePoolPacket()
	defer a.device.ReleasePoolPacket(pkt)

	// monitor stop signals and quit connection earlier
	ctx, ctxCancel := context.WithDeadline(context.Background(), deadlineTime)
	defer ctxCancel()
	go a.tempConnTerminator(conn, ctx)

	// udp recv, blocking until packet arrives or deadline reaches
	n, remoteAddr, err := conn.ReadFromUDP(pkt.Buf[:])
	if err != nil || n < core.HeaderCommonSize {
		log.Error("[udpTempAccessHandler] failed to receive udp packet (%v)", err)
		return
	}

	remoteAddrStr := remoteAddr.String()
	pkt.Content = pkt.Buf[:n]

	// check type and payload size
	msgType, msgSize := pkt.HeaderTypeAndSize()
	if msgType != core.NHP_ACC {
		log.Error("[udpTempAccessHandler] message type is not %s, close connection", core.HeaderTypeToString(core.NHP_ACC))
		return
	}

	packetSize := pkt.Header().Size() + msgSize

	if n != packetSize {
		log.Error("[udpTempAccessHandler] udp packet size incorrect from remote address %s", remoteAddrStr)
		return
	}

	log.Trace("receive udp access packet (%s -> %s): %+v", remoteAddrStr, localAddrStr, pkt.Content)
	log.Info("[udpTempAccessHandler] receive udp access message (%s -> %s)", remoteAddrStr, localAddrStr)

	pd := &core.PacketData{
		BasePacket:     pkt,
		ConnData:       &core.ConnectionData{},
		InitTime:       time.Now().UnixNano(),
		DecryptedMsgCh: make(chan *core.PacketParserData),
	}

	if !a.IsRunning() {
		log.Error("[udpTempAccessHandler] PacketData channel closed or being closed, skip decrypting")
		return
	}

	// start packet decryption. A bounded-queue rejection already releases the
	// pooled packet; do not wait forever for a decrypt result that cannot arrive.
	if !a.device.RecvPacketToMsg(pd) {
		log.Warning("[udpTempAccessHandler] decrypt queue full, shedding message from %s", remoteAddrStr)
		return
	}

	// waiting for packet decryption
	accPpd := <-pd.DecryptedMsgCh
	close(pd.DecryptedMsgCh)

	if accPpd.Error != nil {
		log.Error("[udpTempAccessHandler] failed to decrypt udp access message: %v", accPpd.Error)
		return
	}

	accMsg := &common.AgentAccessMsg{}
	err = json.Unmarshal(accPpd.BodyMessage, accMsg)
	if err != nil {
		log.Error("[udpTempAccessHandler] failed to parse %s message: %v", core.HeaderTypeToString(accPpd.HeaderType), err)
		return
	}

	// Flushes scheduled below are OWNED by a long-lived AccessEntry
	// (registerTempAccessFlushEntry, #2213) instead of the retired
	// orphan path — making them cancelable by an explicit admin Cancel
	// (#2172). See tcpTempAccessHandler's matching note +
	// registerTempAccessFlushEntry godoc for the lifetime-mismatch
	// analysis; timing is unchanged (only OWNERSHIP changed).
	if parentEntry, admitted := a.lockAdmittedTempAccessParent(accMsg.ACToken); admitted {
		defer a.sessionControlFlushMu.Unlock()
		srcAddrIp := remoteAddr.IP.String()

		// Detect IP type using proper parsing instead of string matching
		ipType, ipErr := utils.DetectIPType(dstAddrs[0].Ip)
		if ipErr != nil {
			log.Error("[udpTempAccessHandler] invalid destination IP: %s", dstAddrs[0].Ip)
			return
		}

		// One entry owns every flush scheduled below (TCP/UDP/ANY + the
		// ICMP ping branch), mirroring HandleAccessControl's single-entry
		// admission (hence hoisted out of the loop). Ownership/timing
		// rationale: see the comment above + registerTempAccessFlushEntry
		// godoc.
		flushEntry := a.registerTempAccessFlushEntry(parentEntry, au, srcAddrs, dstAddrs, openTimeSec)

		// Anchor flushDeadline at the moment the temp handler is about
		// to write kernel state — the kernel timer starts NOW, not at
		// HandleAccessControl's earlier admission anchor. Margin
		// rationale: see flushSafetyMargin's comment.
		flushDeadline := computeFlushDeadline(openTimeSec)
		for _, dstAddr := range dstAddrs {
			if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "udp" || dstAddr.Protocol == "any" {
				var ipHashStr string
				if dstAddr.Port == 0 {
					ipHashStr = ipsetHashUDPAllPorts(srcAddrIp, dstAddr.Ip)
				} else {
					ipHashStr = ipsetHashUDP(srcAddrIp, dstAddr.Port, dstAddr.Ip)
				}
				switch a.config.FilterMode {
				case FilterMode_IPTABLES:
					a.scheduleFlushIfEnabled(flushEntry, srcAddrIp, dstAddr.Ip, dstAddr.Port, FlowProtoUDP, flushDeadline)
					_, err = a.ipset.Add(ipType, 1, openTimeSec, ipHashStr)
					if err != nil {
						log.Error("[udpTempAccessHandler] add ipset %s error: %v", ipHashStr, err)
						return
					}
				case FilterMode_EBPFXDP:
					if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "any" {
						ebpfHashStr := ebpf.EbpfRuleParams{
							SrcIP: srcAddrIp,
							DstIP: dstAddr.Ip,
						}
						a.scheduleFlushIfEnabled(flushEntry, srcAddrIp, dstAddr.Ip, 0, FlowProtoAny, flushDeadline)
						err = a.ebpfRuleAddFailClosed(2, ebpfHashStr, openTimeSec)
						if err != nil {
							log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
							return
						}
						if err = a.addEbpfxdpIpsetMirror(ipType, 1, openTimeSec, ipHashStr, "udpTempAccessHandler"); err != nil {
							return
						}
					}
					if dstAddr.Protocol == "udp" {
						ebpfHashStr := ebpf.EbpfRuleParams{
							SrcIP:    srcAddrIp,
							DstIP:    dstAddr.Ip,
							DstPort:  dstAddr.Port,
							Protocol: dstAddr.Protocol,
						}
						a.scheduleFlushIfEnabled(flushEntry, srcAddrIp, dstAddr.Ip, dstAddr.Port, FlowProtoUDP, flushDeadline)
						err = a.ebpfRuleAddFailClosed(1, ebpfHashStr, openTimeSec)

						if err != nil {
							log.Error("[EbpfRuleAdd] add ebpf udp failed src: %s dst: %s, protocol: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
							return
						}
						if err = a.addEbpfxdpIpsetMirror(ipType, 1, openTimeSec, ipHashStr, "udpTempAccessHandler"); err != nil {
							return
						}
					}
				default:
					log.Error("[udpTempAccessHandler] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
					return
				}
			}
			// for ping
			if dstAddr.Port == 0 && (len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "any") {

				// ICMP source IP intentionally uses remoteAddr.IP.String()
				// (the *packet's* source) rather than srcAddrIp (the
				// AOL-declared agent address). Echo replies have to flow
				// back to whatever address the kernel saw on the wire,
				// which under NAT differs from the agent-side declared
				// address. TCP/UDP branches use srcAddrIp because those
				// are session-tied to the AOL declaration
				switch a.config.FilterMode {
				case FilterMode_IPTABLES:
					// ICMP rules are supplementary (ping diagnostics) - failure is non-fatal
					// because the user can still access the protected service via TCP/UDP.
					ipHashStr := ipsetHashICMP(remoteAddr.IP.String(), utils.ICMPEchoType(ipType), dstAddr.Ip)
					// Schedule unconditionally before the write so the
					// in-flight Flush barrier holds; if the
					// non-fatal write below fails the flush is a
					// no-op against an absent entry.
					a.scheduleFlushIfEnabled(flushEntry, remoteAddr.IP.String(), dstAddr.Ip, 0, FlowProtoICMP, flushDeadline)
					_, err = a.ipset.Add(ipType, 1, openTimeSec, ipHashStr)
					if err != nil {
						log.Warning("[udpTempAccessHandler] failed to add ICMP rule %s: %v", ipHashStr, err)
					}
				case FilterMode_EBPFXDP:
					ebpfHashStr := ebpf.EbpfRuleParams{
						SrcIP: remoteAddr.IP.String(),
						DstIP: dstAddr.Ip,
					}
					a.scheduleFlushIfEnabled(flushEntry, remoteAddr.IP.String(), dstAddr.Ip, 0, FlowProtoICMP, flushDeadline)
					err = a.ebpfRuleAddFailClosed(3, ebpfHashStr, openTimeSec)
					if err != nil {
						log.Error("[EbpfRuleAdd] add ebpf icmp src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
						return
					}
					ipHashStr := ipsetHashICMP(remoteAddr.IP.String(), utils.ICMPEchoType(ipType), dstAddr.Ip)
					if err = a.addEbpfxdpIpsetMirror(ipType, 1, openTimeSec, ipHashStr, "udpTempAccessHandler"); err != nil {
						log.Warning("[udpTempAccessHandler] failed to add eBPF iptables mirror ICMP rule %s: %v", ipHashStr, err)
					}
				default:
					log.Error("[udpTempAccessHandler] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
					return
				}
			}
		}
	}
}

func (a *UdpAC) tempConnTerminator(conn net.Conn, ctx context.Context) {
	// Spawned by tcpTempAccessHandler / udpTempAccessHandler on the
	// NHP_AOP path; the body is small and conn.Close() is the only
	// realistic panic site, but the asymmetric "panic-here-kills-the-AC"
	// math from #1423 still applies. The recover keeps the AC alive
	// regardless. (Note: tempConnTerminator is NOT a.wg-tracked today,
	// so it can leak past Stop(); that's tracked in #1658, not this PR.)
	defer a.recoverUDPHandler(core.NHP_AOP)
	select {
	case <-a.signals.stop:
		_ = conn.Close()
		return

	case <-ctx.Done():
		return
	}
}

// setArtMsgError sets the error code and message on an ACOpsResultMsg from
// a common.Error and returns it for use in named return assignment.
func setArtMsgError(artMsg *common.ACOpsResultMsg, nhpErr *common.Error) error {
	artMsg.ErrCode = nhpErr.ErrorCode()
	artMsg.ErrMsg = nhpErr.Error()
	return nhpErr
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ipsetHash* build the ipset entry strings the AC writes to the kernel, and are
// the SINGLE source of truth for the two entry grammars in use. They exist to
// keep the format off the admission hot path's per-src×dst inner loops, and in
// one greppable place.
//
// Each builder makes exactly one heap allocation. The string-only builders
// concatenate directly (a fixed-arity `+` chain lowers to one runtime.concatstring
// call). The port-bearing ones fill a stack buffer with strconv.AppendInt rather
// than concatenating strconv.Itoa's result, because Itoa allocates its own string
// first — that form measures 2 allocs/op and is ~2x slower. See
// msghandler_bench_test.go for the numbers behind both choices.
//
// Two set families, two grammars (created in docker/iptables_defaults_*.sh):
//
//	hash:ip,port,ip  defaultset / defaultset_down  ->  "srcIp,<portspec>,dstIp"
//	hash:net,port    tempset                       ->  "<cidr>,<portspec>"
//
// <portspec> is one of:
//
//	443            bare decimal — ipset assumes TCP when no proto prefix is given
//	udp:443        explicit UDP
//	icmp:8/0       ICMP echo request (icmpv6:128/0 for v6) — see utils.ICMPEchoType
//	1-65535        all ports, TCP (udp:1-65535 for UDP)
//
// The all-ports range is what an AOP's dstAddr.Port == 0 ("any port") lowers to:
// an ipset port field has no wildcard, so the range is written out.
//
// The three-field grammar is load-bearing beyond ipset's own parser:
// utils.NormalizeIPSetEntry splits the hash:ip,port,ip form with
// SplitN(entry, ",", 3) to rewrite IPv4 components into IPv6-mapped form before
// they reach an inet6 set, and returns the entry UNCHANGED when it does not
// split into exactly three parts. A helper that gained or lost a comma would
// therefore fail silently — the entry gets written unmapped rather than
// rejected. TestIpsetHashHelpers_Format pins both the exact strings and the
// field counts.
//
// Deliberate asymmetry with the eBPF datapath: all-ports is 1-65535 here, but
// 0-65535 in the XDP port_list key (see allPortsEbpfRuleParams, whose
// DstPortStart MUST be 0 to match a lookup built from the MIN_PORT compile-time
// constant). The two kernel backends key differently; do not unify the
// constants.
// ipsetEntryBufSize is the stack scratch the port-bearing builders fill so the
// only heap allocation is the returned string. It covers the longest entry the
// AC can emit — two full-length IPv6 addresses (45 bytes each, INET6_ADDRSTRLEN
// minus the NUL), a 5-digit port and two separators, 97 bytes — rounded up.
// Longer input still yields the correct string; append simply spills to the heap
// and costs an extra allocation. This is a performance bound, not a correctness
// one.
const ipsetEntryBufSize = 128

func ipsetHashTCP(srcIp string, port int, dstIp string) string {
	var buf [ipsetEntryBufSize]byte
	b := append(buf[:0], srcIp...)
	b = append(b, ',')
	b = strconv.AppendInt(b, int64(port), 10)
	b = append(b, ',')
	b = append(b, dstIp...)
	return string(b)
}

func ipsetHashTCPAllPorts(srcIp, dstIp string) string {
	return srcIp + ",1-65535," + dstIp
}

func ipsetHashUDP(srcIp string, port int, dstIp string) string {
	var buf [ipsetEntryBufSize]byte
	b := append(buf[:0], srcIp...)
	b = append(b, ",udp:"...)
	b = strconv.AppendInt(b, int64(port), 10)
	b = append(b, ',')
	b = append(b, dstIp...)
	return string(b)
}

func ipsetHashUDPAllPorts(srcIp, dstIp string) string {
	return srcIp + ",udp:1-65535," + dstIp
}

func ipsetHashICMP(srcIp, icmpType, dstIp string) string {
	return srcIp + "," + icmpType + "," + dstIp
}

func ipsetHashNetPort(netStr string, port int) string {
	var buf [ipsetEntryBufSize]byte
	b := append(buf[:0], netStr...)
	b = append(b, ',')
	b = strconv.AppendInt(b, int64(port), 10)
	return string(b)
}

func ipsetHashNetAllPorts(netStr string) string {
	return netStr + ",1-65535"
}

func ipsetHashNetUDPPort(netStr string, port int) string {
	var buf [ipsetEntryBufSize]byte
	b := append(buf[:0], netStr...)
	b = append(b, ",udp:"...)
	b = strconv.AppendInt(b, int64(port), 10)
	return string(b)
}

func ipsetHashNetUDPAllPorts(netStr string) string {
	return netStr + ",udp:1-65535"
}

func ipsetHashNetICMP(netStr, icmpType string) string {
	return netStr + "," + icmpType
}
