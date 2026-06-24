package ac

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/OpenNHP/opennhp/nhp/utils/ebpf"
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
			a.tokenStore.Delete(preMintedToken)
		}
	}()
	artMsg, err = a.HandleAccessControl(entry, openTimeSec, artMsgIn)
	a.emitOrCleanupPreMintedToken(artMsg, preMintedToken, entry)
	cleaned = true
	return
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
func accessEntryFromAOP(dopMsg *common.ServerACOpsMsg) *AccessEntry {
	return &AccessEntry{
		User: &common.AgentUser{
			UserId:         dopMsg.UserId,
			DeviceId:       dopMsg.DeviceId,
			OrganizationId: dopMsg.OrganizationId,
			AuthServiceId:  dopMsg.AuthServiceId,
		},
		SrcAddrs: dopMsg.SourceAddrs,
		DstAddrs: dopMsg.DestinationAddrs,
		OpenTime: int(dopMsg.OpenTime),
		// qURL v2 keyed-identity revocation metadata (P4a): stored verbatim from
		// the AOP onto the access entry so P4b can index live flows for immediate
		// revocation. Stored as received — NOT recomputed AC-side (see AccessEntry
		// godoc). Zero-valued for legacy admissions, where the AOP omits them.
		QurlUserPublicKeyHash: dopMsg.QurlUserPublicKeyHash,
		ResourcePublicKeyHash: dopMsg.ResourcePublicKeyHash,
		SessionId:             dopMsg.SessionId,
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

	err = json.Unmarshal(ppd.BodyMessage, dopMsg)
	if err != nil {
		log.Error("ac(%s#%d)[HandleUdpACOperations] failed to parse %s message: %v", acId, transactionId, core.HeaderTypeToString(ppd.HeaderType), err)
		artMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
		artMsg.ErrMsg = err.Error()
		return
	}

	openTimeSec := int(dopMsg.OpenTime)
	entry := accessEntryFromAOP(dopMsg)
	artMsg, err = a.admitAndIssueToken(entry, openTimeSec, artMsg)
	if err != nil {
		log.Error("ac(%s#%d)[HandleUdpACOperations] HandleAccessControl failed, err: %v", acId, transactionId, err)
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
	if a.config.FilterMode == FilterMode_IPTABLES {
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
					ipHashStr := fmt.Sprintf("%s,%d,%s", srcAddr.Ip, dstAddr.Port, dstAddr.Ip)
					if dstAddr.Port == 0 {
						ipHashStr = fmt.Sprintf("%s,1-65535,%s", srcAddr.Ip, dstAddr.Ip)
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
							err = ebpf.EbpfRuleAdd(2, ebpfHashStr, openTimeSec)
							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
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
							err = ebpf.EbpfRuleAdd(1, ebpfHashStr, openTimeSec)
							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf tcp failed src: %s dst: %s, protocol: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
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
					ipHashStr := fmt.Sprintf("%s,udp:%d,%s", srcAddr.Ip, dstAddr.Port, dstAddr.Ip)
					if dstAddr.Port == 0 {
						ipHashStr = fmt.Sprintf("%s,udp:1-65535,%s", srcAddr.Ip, dstAddr.Ip)
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
							err = ebpf.EbpfRuleAdd(2, ebpfHashStr, openTimeSec)
							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
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
							err = ebpf.EbpfRuleAdd(1, ebpfHashStr, openTimeSec)

							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf udp failed src: %s dst: %s, protocol: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
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
						ipHashStr := fmt.Sprintf("%s,%s,%s", srcAddr.Ip, utils.ICMPEchoType(ipType), dstAddr.Ip)
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
							err = ebpf.EbpfRuleAdd(3, ebpfHashStr, openTimeSec)
							if err != nil {
								log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
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
							netHashStr := fmt.Sprintf("%s,%d", netStr, dstAddr.Port)
							if dstAddr.Port == 0 {
								netHashStr = fmt.Sprintf("%s,1-65535", netStr)
							}
							_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, netHashStr)
						}

						if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "udp" || dstAddr.Protocol == "any" {
							netHashStr := fmt.Sprintf("%s,udp:%d", netStr, dstAddr.Port)
							if dstAddr.Port == 0 {
								netHashStr = fmt.Sprintf("%s,udp:1-65535", netStr)
							}
							_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, netHashStr)
						}

						if dstAddr.Port == 0 && (len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "any") {
							// ICMP rules are supplementary (ping diagnostics) - failure is non-fatal
							// because the user can still access the protected service via TCP/UDP.
							netHashStr := fmt.Sprintf("%s,%s", netStr, utils.ICMPEchoType(ipType))
							_, addErr := a.ipset.Add(ipType, 4, tempOpenTimeSec, netHashStr)
							if addErr != nil {
								log.Warning("[HandleAccessControl] failed to add tempset entry %s: %v", netHashStr, addErr)
							}
						}

					case FilterMode_EBPFXDP:
						srcIp, ipnet, err := net.ParseCIDR(netStr)
						if err != nil {
							log.Error("[HandleAccessControl] failed to parse CIDR %s: %v", netStr, err)
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
									err = ebpf.EbpfRuleAdd(4, ebpfHashStr, tempOpenTimeSec)
									if err != nil {
										log.Error("[EbpfRuleAdd] add ebpf for tcp dst port src: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstPort, err)
									}

								} else {
									ebpfHashStr := ebpf.EbpfRuleParams{
										SrcIP:        srcIpStr,
										DstPortStart: 1,
										DstPortEnd:   65535,
									}
									err = ebpf.EbpfRuleAdd(5, ebpfHashStr, tempOpenTimeSec)
									if err != nil {
										log.Error("[EbpfRuleAdd] add ebpf src: %s  dstportstart: %d,  dstportend: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstPortStart, ebpfHashStr.DstPortEnd, err)
									}
								}
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
									err = ebpf.EbpfRuleAdd(4, ebpfHashStr, tempOpenTimeSec)
									if err != nil {
										log.Error("[EbpfRuleAdd] add ebpf for udp dst port src: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstPort, err)
									}
								} else {
									ebpfHashStr := ebpf.EbpfRuleParams{
										SrcIP:        srcIpStr,
										DstPortStart: 1,
										DstPortEnd:   65535,
									}
									err = ebpf.EbpfRuleAdd(5, ebpfHashStr, tempOpenTimeSec)
									if err != nil {
										log.Error("[EbpfRuleAdd] add ebpf src: %s  dstportstart: %d,  dstportend: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstPortStart, ebpfHashStr.DstPortEnd, err)
									}
								}
							}
						}
						if dstAddr.Port == 0 && (len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "any") {
							for srcIp := srcIp.Mask(ipnet.Mask); ipnet.Contains(srcIp); incrementIP(srcIp) {
								srcIpStr := srcIp.String()
								ebpfHashStr := ebpf.EbpfRuleParams{
									SrcIP: srcIpStr,
									DstIP: dstAddr.Ip,
								}
								err = ebpf.EbpfRuleAdd(3, ebpfHashStr, openTimeSec)
								if err != nil {
									log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
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
			portHashStr := fmt.Sprintf("%s,%d", netStr, tlocalAddr.Port)
			_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, portHashStr)

			if err != nil {
				log.Error("[HandleAccessControl] add ipset %s error: %v", portHashStr, err)
				err = setArtMsgError(artMsg, common.ErrACIPSetOperationFailed)
				return
			}
			// IPv4 requires two ranges (0.0.0.0/1 and 128.0.0.0/1) since ipset doesn't allow 0.0.0.0/0
			// IPv6 uses ::/0 directly, so netStr1 is empty for IPv6
			if netStr1 != "" {
				portHashStr = fmt.Sprintf("%s,%d", netStr1, tlocalAddr.Port)
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
			err = ebpf.EbpfRuleAdd(6, ebpfHashStr, tempOpenTimeSec)
			if err != nil {
				log.Error("[EbpfRuleAdd] add ebpf type 6 protocol: %s, dstport :%d, %v", ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
				return
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
			portHashStr := fmt.Sprintf("%s,udp:%d", netStr, tlocalAddr.Port)
			_, err = a.ipset.Add(ipType, 4, tempOpenTimeSec, portHashStr)
			if err != nil {
				log.Error("[HandleAccessControl] add ipset %s error: %v", portHashStr, err)
				err = setArtMsgError(artMsg, common.ErrACIPSetOperationFailed)
				return
			}
			// IPv4 requires two ranges (0.0.0.0/1 and 128.0.0.0/1) since ipset doesn't allow 0.0.0.0/0
			// IPv6 uses ::/0 directly, so netStr1 is empty for IPv6
			if netStr1 != "" {
				portHashStr = fmt.Sprintf("%s,udp:%d", netStr1, tlocalAddr.Port)
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
			err = ebpf.EbpfRuleAdd(6, ebpfHashStr, tempOpenTimeSec)
			if err != nil {
				log.Error("[EbpfRuleAdd] add ebpf type 6 protocol: %s, dstport :%d, %v", ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
				return
			}
		default:
			log.Error("[HandleAccessControl] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
			return
		}
		log.Info("[HandleAccessControl] open temporary udp port on %s", tladdr.String())

		tempEntry := &AccessEntry{
			User:     au,
			SrcAddrs: srcAddrs,
			DstAddrs: dstAddrs,
			OpenTime: tempOpenTimeSec,
		}
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

	// start message decryption
	a.device.RecvPacketToMsg(pd)

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
	if a.VerifyAccessToken(accMsg.ACToken) != nil {
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
		flushEntry := a.registerTempAccessFlushEntry(au, srcAddrs, dstAddrs, openTimeSec)

		// Anchor flushDeadline at the moment the temp handler is about
		// to write kernel state — the kernel timer starts NOW, not at
		// HandleAccessControl's earlier admission anchor. Margin
		// rationale: see flushSafetyMargin's comment.
		flushDeadline := computeFlushDeadline(openTimeSec)
		for _, dstAddr := range dstAddrs {
			ipHashStr := fmt.Sprintf("%s,%d,%s", srcAddrIp, dstAddr.Port, dstAddr.Ip)
			if dstAddr.Port == 0 {
				ipHashStr = fmt.Sprintf("%s,1-65535,%s", srcAddrIp, dstAddr.Ip)
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
				err = ebpf.EbpfRuleAdd(2, ebpfHashStr, openTimeSec)
				if err != nil {
					log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
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

	// start packet decryption
	a.device.RecvPacketToMsg(pd)

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
	if a.VerifyAccessToken(accMsg.ACToken) != nil {
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
		flushEntry := a.registerTempAccessFlushEntry(au, srcAddrs, dstAddrs, openTimeSec)

		// Anchor flushDeadline at the moment the temp handler is about
		// to write kernel state — the kernel timer starts NOW, not at
		// HandleAccessControl's earlier admission anchor. Margin
		// rationale: see flushSafetyMargin's comment.
		flushDeadline := computeFlushDeadline(openTimeSec)
		for _, dstAddr := range dstAddrs {
			if len(dstAddr.Protocol) == 0 || dstAddr.Protocol == "udp" || dstAddr.Protocol == "any" {
				ipHashStr := fmt.Sprintf("%s,udp:%d,%s", srcAddrIp, dstAddr.Port, dstAddr.Ip)
				if dstAddr.Port == 0 {
					ipHashStr = fmt.Sprintf("%s,udp:1-65535,%s", srcAddrIp, dstAddr.Ip)
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
						err = ebpf.EbpfRuleAdd(2, ebpfHashStr, openTimeSec)
						if err != nil {
							log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
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
						err = ebpf.EbpfRuleAdd(1, ebpfHashStr, openTimeSec)

						if err != nil {
							log.Error("[EbpfRuleAdd] add ebpf udp failed src: %s dst: %s, protocol: %s, dstport: %d, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, ebpfHashStr.Protocol, ebpfHashStr.DstPort, err)
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
					ipHashStr := fmt.Sprintf("%s,%s,%s", remoteAddr.IP.String(), utils.ICMPEchoType(ipType), dstAddr.Ip)
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
					err = ebpf.EbpfRuleAdd(3, ebpfHashStr, openTimeSec)
					if err != nil {
						log.Error("[EbpfRuleAdd] add ebpf icmp src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
						return
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
