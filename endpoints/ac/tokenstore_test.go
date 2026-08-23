package ac

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestGenerateAccessToken_DecodesTo32Bytes pins the cross-component
// wire contract: a token issued by GenerateAccessToken, when decoded
// as base64.StdEncoding, must yield exactly 32 bytes. The HTTP /refresh
// handler at endpoints/ac/httpac.go enforces `len(buf) == 32` after
// decode, so a regression that flips the encoding to RawURLEncoding
// (43 chars, no padding) or changes the byte budget would pass every
// other test in this PR but fail at runtime when an agent presents a
// real token. Smoke-tier coverage of the live wire shape is tracked
// in #1417.
func TestGenerateAccessToken_DecodesTo32Bytes(t *testing.T) {
	a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	entry := &AccessEntry{User: &common.AgentUser{UserId: "u"}, OpenTime: 60}

	token := a.GenerateAccessToken(entry)
	buf, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token does not decode as base64.StdEncoding: %v (token=%q)", err, token)
	}
	if len(buf) != 32 {
		// Wire contract: the AC's /refresh handler in endpoints/ac/httpac.go
		// rejects tokens whose base64-StdEncoding decode is not 32 bytes.
		// (Line number deliberately omitted — line numbers drift; the
		// `len(buf) != 32` check is the searchable invariant.)
		t.Fatalf("decoded token length = %d, want 32 (token=%q) — wire contract with httpac.go broken",
			len(buf), token)
	}
}

// TestGenerateAccessToken_Uniqueness asserts that 10_000 AC tokens issued
// for the same User are all unique and round-trip through VerifyAccessToken.
// Token generation must not depend on entry metadata; setting only
// tokenStore here is deliberate — adding a config field would mask a
// future regression that re-introduces metadata into the token derivation.
func TestGenerateAccessToken_Uniqueness(t *testing.T) {
	a := &UdpAC{
		tokenStore: common.NewTokenStore[*AccessEntry](),
	}

	const n = 10_000
	user := &common.AgentUser{
		UserId:         "user-1",
		DeviceId:       "device-1",
		OrganizationId: "org-1",
		AuthServiceId:  "asp-1",
	}

	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		entry := &AccessEntry{User: user, OpenTime: 60}
		token := a.GenerateAccessToken(entry)
		if _, dup := seen[token]; dup {
			t.Fatalf("collision after %d tokens: %q", i, token)
		}
		seen[token] = struct{}{}

		got := a.VerifyAccessToken(token)
		if got != entry {
			t.Fatalf("VerifyAccessToken did not return the issued entry for token %d", i)
		}
		if got.User != user {
			t.Fatalf("VerifyAccessToken returned an entry with the wrong User pointer for token %d", i)
		}
	}
}

// TestEmitOrCleanupPreMintedToken_GatesOnErrCode fences the
// post-admission gate paired with the pre-mint-then-pre-store pattern
// in HandleUdpACOperations (#2201). Post-nhp#1124 the access token is
// the entire auth secret, so a token issued alongside ErrCode !=
// success would only ever appear in leaky %+v error logs on the
// server (endpoints/server/udpserver.go:1862, :2150). The gate uses
// STRICT success-code equality, not the more permissive
// common.IsSuccessErrCode (which treats empty string as success) —
// bare-return paths in HandleAccessControl can leave ErrCode == ""
// with err != nil, and the server's leak logger treats those as
// failures. Emitting a token under those conditions would re-open
// the exact path the gate exists to close. Additionally: on the
// non-success path the pre-stored entry MUST be Deleted from
// tokenStore, otherwise an unemitted token would linger and a
// concurrent /refresh consult would resolve to a stranded entry.
func TestEmitOrCleanupPreMintedToken_GatesOnErrCode(t *testing.T) {
	cases := []struct {
		name        string
		errCode     string
		wantIssued  bool
		description string
	}{
		{
			name:        "empty_errcode_no_token",
			errCode:     "",
			wantIssued:  false,
			description: "empty ErrCode is the bare-return / err-set-but-no-errcode case from HandleAccessControl — server's leak logger treats it as failure, gate must too",
		},
		{
			name:        "explicit_success_code_emits",
			errCode:     common.ErrSuccess.ErrorCode(),
			wantIssued:  true,
			description: "the only ErrCode value that should emit the pre-minted token",
		},
		{
			name:        "failure_code_cleans_up",
			errCode:     "5001",
			wantIssued:  false,
			description: "any explicit non-success code suppresses emit AND Deletes the pre-stored entry",
		},
		{
			name:        "ac_op_failed_no_token",
			errCode:     common.ErrACOperationFailed.ErrorCode(),
			wantIssued:  false,
			description: "ErrACOperationFailed — the most common AC failure surface",
		},
		{
			name:        "ac_empty_pass_address_no_token",
			errCode:     common.ErrACEmptyPassAddress.ErrorCode(),
			wantIssued:  false,
			description: "ErrACEmptyPassAddress — fired by setArtMsgError at msghandler.go's empty-srcAddrs path",
		},
		{
			name:        "ac_ipset_not_found_no_token",
			errCode:     common.ErrACIPSetNotFound.ErrorCode(),
			wantIssued:  false,
			description: "ErrACIPSetNotFound — fired when iptables ipset is nil",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
			artMsg := &common.ACOpsResultMsg{ErrCode: tc.errCode}
			entry := &AccessEntry{
				User:     &common.AgentUser{UserId: "u"},
				OpenTime: 60,
			}
			// Simulate the pre-mint-then-pre-store pattern in
			// HandleUdpACOperations.
			preMintedToken := a.GenerateAccessToken(entry)
			if a.tokenStore.Size() != 1 {
				t.Fatalf("precondition: pre-store should put 1 entry in tokenStore, got %d", a.tokenStore.Size())
			}

			a.emitOrCleanupPreMintedToken(artMsg, preMintedToken, entry)

			if tc.wantIssued {
				if artMsg.ACToken == "" {
					t.Fatalf("%s: expected ACToken to be populated", tc.description)
				}
				if got := a.VerifyAccessToken(artMsg.ACToken); got != entry {
					t.Fatalf("%s: token did not round-trip through tokenStore", tc.description)
				}
				if a.tokenStore.Size() != 1 {
					t.Fatalf("%s: success path must keep the pre-stored entry; tokenStore size = %d, want 1", tc.description, a.tokenStore.Size())
				}
			} else {
				if artMsg.ACToken != "" {
					t.Fatalf("%s: expected ACToken to stay empty, got %q", tc.description, artMsg.ACToken)
				}
				if a.tokenStore.Size() != 0 {
					t.Fatalf("%s: expected tokenStore to be cleaned up to empty, got size %d", tc.description, a.tokenStore.Size())
				}
			}
		})
	}
}

// PANIC TRIGGER NOTE for TestAdmitAndIssueToken_PanicMidHandleAC_TokenNeverInArtMsg:
//
// The test triggers panic by passing a UdpAC with `a.config == nil` —
// HandleAccessControl reads `a.config.FilterMode` at the IPTABLES
// gate (msghandler.go) and nil-derefs. That deref site is the SINGLE
// load-bearing trigger; a `TEST FIXTURE NOTE` comment at the deref
// itself flags the dependency for any contributor adding an `if
// a.config == nil { return }` guard above it.
//
// We deliberately do NOT use `a.ipset == nil` as a backup trigger:
// HandleAccessControl already has an explicit `if a.ipset == nil {
// return err }` graceful-fallback check immediately AFTER the
// FilterMode read, so nil ipset doesn't panic — it returns
// gracefully and the test's t.Fatalf("expected panic …") fires.
//
// If the FilterMode trigger gains a graceful guard (returns without
// panicking), the test fixture fails loud — it does NOT silently
// pass — because `paniced == nil` hits t.Fatalf. The maintainer's
// required response:
//
//   - Find a NEW deterministic panic trigger that fires deep inside
//     HandleAccessControl AFTER admitAndIssueToken's pre-store-and-defer
//     setup AND BEFORE emitOrCleanupPreMintedToken sets cleaned=true.
//     Candidates: malformed `entry.SrcAddrs[0]` (nil pointer in slot),
//     panicking *Device on AC keypair lookup, or a synchronous panic
//     injected via a refactored admitAndIssueToken hook.
//   - Update this test with the new trigger.
//   - **Do NOT delete the test.** The token-leak path it fences
//     (post-nhp#1124: token == entire auth secret; leaked to
//     `artMsg.ACToken` via panic path bypasses the post-success gate)
//     is the explicit security invariant for the pre-mint pattern.
//     Deleting the test removes the only synthetic fence on that
//     invariant.
//
// TestAdmitAndIssueToken_PanicMidHandleAC_TokenNeverInArtMsg fences
// the post-nhp#1124 security invariant under the panic path: even
// if HandleAccessControl panics after the pre-mint-then-pre-store
// completes, the pre-minted token MUST NOT reach artMsg.ACToken
// (the only field the server reads it from). The defer cleanup in
// admitAndIssueToken also drops the entry from tokenStore so the
// token cannot be /refresh'd.
//
// This is the explicit fence for cr round 3 item 5; brittleness
// trade-off discussed in cr round 19/20 — a panicking-flusher-via-
// scheduler-option-chain trigger would be ideal but requires
// refactoring admitAndIssueToken to take an injectable HandleAccessControl
// hook (out of scope for this PR; tracked as a follow-up if the
// single-trigger fixture proves insufficient in practice).
func TestAdmitAndIssueToken_PanicMidHandleAC_TokenNeverInArtMsg(t *testing.T) {
	a := &UdpAC{
		tokenStore: common.NewTokenStore[*AccessEntry](),
		// a.config left nil — HandleAccessControl panics on the
		// FilterMode read (msghandler.go's TEST FIXTURE NOTE marks
		// the load-bearing deref site). a.ipset is also nil here but
		// the existing `if a.ipset == nil` graceful guard inside
		// HandleAccessControl means that field is NOT a panic
		// trigger; see PANIC TRIGGER NOTE above.
	}
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u-panic"},
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime: 60,
	}
	artMsg := &common.ACOpsResultMsg{}

	var paniced any
	func() {
		defer func() { paniced = recover() }()
		_, _ = a.admitAndIssueToken(entry, 60, artMsg)
	}()

	if paniced == nil {
		t.Fatalf("expected panic from HandleAccessControl with nil a.config — FilterMode-deref trigger guarded. " +
			"DO NOT DELETE THIS TEST: it fences a load-bearing security invariant (post-nhp#1124 token-leak via " +
			"panic path bypasses post-success gate). Find a new deep-path panic trigger that fires after " +
			"admitAndIssueToken's pre-store-and-defer setup — see PANIC TRIGGER NOTE above the test for guidance.")
	}
	if artMsg.ACToken != "" {
		t.Errorf("ACToken after panic = %q, want empty (pre-mint token leaked through panic path)", artMsg.ACToken)
	}
	if a.tokenStore.Size() != 0 {
		t.Errorf("tokenStore size after panic = %d, want 0 (defer cleanup did not run)", a.tokenStore.Size())
	}
}

// TestEmitOrCleanupPreMintedToken_DrainsPartiallyScheduledKeys
// fences the cleanup-path drain (cr round 2 finding): if
// HandleAccessControl ran N successful scheduleFlushIfEnabled calls
// before a downstream kernel write failed, the pre-stored entry
// holds those keys in its scheduledKeys set. tokenStore.Delete
// alone is silent (no OnExpire hook), so cancelAllScheduledFlows
// MUST run explicitly to drop the scheduler entries — otherwise
// they fire Flush against kernel state that the failed write
// never created, ticking the breaker error counter on every
// failure and (at sustained rate) opening the admission gate.
//
// Pre-fix: only tokenStore.Delete ran on the failure branch →
// scheduler EntryCount stays at N after the cleanup.
// Post-fix: drain + Delete → scheduler EntryCount drops to 0.
func TestEmitOrCleanupPreMintedToken_DrainsPartiallyScheduledKeys(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}

	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u-partial"},
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime: 60,
	}
	preMintedToken := a.GenerateAccessToken(entry)

	// Simulate "HandleAccessControl ran 2 successful Schedule calls
	// before a third kernel write failed and set ErrCode to
	// ErrACIPSetOperationFailed." The entry's scheduledKeys holds
	// both keys; the scheduler holds 2 entries.
	a.scheduleFlushIfEnabled(entry, "1.2.3.4", "10.0.0.1", 80, FlowProtoTCP, time.Now().Add(1*time.Hour))
	a.scheduleFlushIfEnabled(entry, "1.2.3.4", "10.0.0.1", 80, FlowProtoUDP, time.Now().Add(1*time.Hour))
	if got := sched.EntryCount(); got != 2 {
		t.Fatalf("precondition: EntryCount = %d, want 2 (2 successful Schedule calls)", got)
	}

	artMsg := &common.ACOpsResultMsg{ErrCode: common.ErrACIPSetOperationFailed.ErrorCode()}
	a.emitOrCleanupPreMintedToken(artMsg, preMintedToken, entry)

	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after cleanup of partial-admission failure = %d, want 0 — scheduler entries leaked (cr round 2 regression)", got)
	}
	if a.tokenStore.Size() != 0 {
		t.Errorf("tokenStore size after cleanup = %d, want 0", a.tokenStore.Size())
	}
	if artMsg.ACToken != "" {
		t.Errorf("ACToken after failed admission = %q, want empty (token-emit gate violated)", artMsg.ACToken)
	}
}

// TestEmitOrCleanupPreMintedToken_PeerReschedulesAcrossCleanup fences
// the cancel-before-Delete ordering in emitOrCleanupPreMintedToken:
// when a failed admission triggers cleanup AND a peer entry holds the
// same FlowKey with a live firewall deadline, the cleanup walk must
// observe the peer and re-Schedule the shared scheduler entry
// (preserving peer coverage) rather than Cancel-and-erase.
//
// Pre-fix risk (cr round 22 concern #8): both Cancel-then-Delete and
// Delete-then-Cancel happen to produce the right outcome today via
// different self-filter mechanisms (pointer-equality self-skip vs
// Delete-induced self-absence). A future Delete-first reorder leaves
// the surrounding godocs accurate-but-vestigial. This fence ensures
// the peer-reschedule path actually fires; a reorder regression
// would leak a peer's coverage AND fail this test, surfacing the
// regression at CI rather than at runtime.
func TestEmitOrCleanupPreMintedToken_PeerReschedulesAcrossCleanup(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}

	const srcIP, dstIP, dstPort = "1.2.3.4", "10.0.0.1", 80

	// Peer entry T1: already admitted, live firewall (FirstKnockTime
	// + OpenTime well in the future). Holds shared FlowKey K.
	peer := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-peer-live"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       3600,
		FirstKnockTime: time.Now(),
	}
	peerToken := a.GenerateAccessToken(peer)
	a.scheduleFlushIfEnabled(peer, srcIP, dstIP, dstPort, FlowProtoTCP, time.Now().Add(1*time.Hour))

	// Failing-admission entry T2: pre-stored + partially-scheduled,
	// then cleanup fires. Shares FlowKey K with peer.
	failing := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-failing"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       3600,
		FirstKnockTime: time.Now(),
	}
	failingToken := a.GenerateAccessToken(failing)
	a.scheduleFlushIfEnabled(failing, srcIP, dstIP, dstPort, FlowProtoTCP, time.Now().Add(2*time.Hour))

	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1 (longest-wins absorbs both Schedules to one entry)", got)
	}

	artMsg := &common.ACOpsResultMsg{ErrCode: common.ErrACIPSetOperationFailed.ErrorCode()}
	a.emitOrCleanupPreMintedToken(artMsg, failingToken, failing)

	// Post-cleanup invariants:
	//  - failing's tokenStore entry is deleted
	//  - failing's scheduledKeys is drained
	//  - peer's tokenStore entry is still present
	//  - scheduler EntryCount stays at 1 (rescheduled to peer's deadline)
	if got := sched.EntryCount(); got != 1 {
		t.Errorf("EntryCount after cleanup with live peer = %d, want 1 — peer-reschedule lost (cleanup-order regression: peer's coverage was orphaned)", got)
	}
	if a.tokenStore.Size() != 1 {
		t.Errorf("tokenStore size after cleanup = %d, want 1 (peer entry only)", a.tokenStore.Size())
	}
	if !peer.holdsScheduledKey(mustFlowKey(t, srcIP, dstIP, dstPort, FlowProtoTCP)) {
		t.Errorf("peer no longer holds shared FlowKey — drain leaked across entries")
	}
	if artMsg.ACToken != "" {
		t.Errorf("ACToken after failed admission = %q, want empty", artMsg.ACToken)
	}
	_ = peerToken
}

func mustFlowKey(t *testing.T, srcIP, dstIP string, dstPort int, proto FlowProto) FlowKey {
	t.Helper()
	k, err := MakeFlowKey(srcIP, dstIP, dstPort, proto)
	if err != nil {
		t.Fatalf("MakeFlowKey(%s, %s, %d, %v): %v", srcIP, dstIP, dstPort, proto, err)
	}
	return k
}

// TestAccessTokenLatePacketBufferConstantMatchesServer pins the AC's
// late-packet buffer constant against the shared common-package source
// of truth. The server's ACK-path entries (NewACKTokenEntry) consume
// the same constant; a future edit that touches one side without the
// other would drift the contract — the test ensures the AC value is
// read from common.AccessTokenLatePacketBufferSeconds, which catches
// the drift at compile/test time on either side.
func TestAccessTokenLatePacketBufferConstantMatchesServer(t *testing.T) {
	if accessTokenLatePacketBufferSeconds != common.AccessTokenLatePacketBufferSeconds {
		t.Fatalf("ac accessTokenLatePacketBufferSeconds drifted from common: got %d, want %d", accessTokenLatePacketBufferSeconds, common.AccessTokenLatePacketBufferSeconds)
	}
	if common.AccessTokenLatePacketBufferSeconds != 5 {
		t.Fatalf("common.AccessTokenLatePacketBufferSeconds drift: got %d, want 5 (AC and server both consume this — see endpoints/server/tokenstore.go's NewACKTokenEntry)", common.AccessTokenLatePacketBufferSeconds)
	}
}

// TestGenerateAccessToken_LatePacketBuffer fences the
// accessTokenLatePacketBufferSeconds extension. The AC issues tokens with
// ExpireTime = now + OpenTime + buffer to keep iptables/ipset entries
// matchable for late-arriving packets after the client thinks the window
// is closed. A regression that drops the +buffer (a tempting "tighten
// the contract" cleanup) would silently shorten the late-packet window
// and cause sporadic refused-traffic incidents that don't reproduce
// outside production timing.
func TestGenerateAccessToken_LatePacketBuffer(t *testing.T) {
	a := &UdpAC{
		tokenStore: common.NewTokenStore[*AccessEntry](),
	}

	const openTime = 60
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "user-1"},
		OpenTime: openTime,
	}

	before := time.Now()
	a.GenerateAccessToken(entry)
	after := time.Now()

	wantMin := before.Add(time.Duration(openTime+accessTokenLatePacketBufferSeconds) * time.Second)
	wantMax := after.Add(time.Duration(openTime+accessTokenLatePacketBufferSeconds) * time.Second)

	if entry.ExpireTime.Before(wantMin) {
		t.Fatalf("ExpireTime %v earlier than expected lower bound %v (lost late-packet buffer?)",
			entry.ExpireTime, wantMin)
	}
	if entry.ExpireTime.After(wantMax) {
		t.Fatalf("ExpireTime %v later than expected upper bound %v",
			entry.ExpireTime, wantMax)
	}

	// Strictly-non-zero buffer assertion: catches a regression that drops
	// BOTH the constant AND the addition (e.g., a "simplification" that
	// rewrites the entire ExpireTime line to `before.Add(OpenTime * sec)`).
	// The bracket assertions above catch a buffer-shrinks-to-N regression;
	// this one catches a buffer-disappears-entirely regression.
	expireAtOpenTimeBoundary := before.Add(time.Duration(openTime) * time.Second)
	if !entry.ExpireTime.After(expireAtOpenTimeBoundary) {
		t.Fatalf("ExpireTime %v is not strictly later than now+OpenTime %v — late-packet buffer is zero",
			entry.ExpireTime, expireAtOpenTimeBoundary)
	}
}

// TestGenerateAccessToken_SetsFirstKnockTime pins the absolute-deadline
// anchor (#1942). FirstKnockTime must be populated at issue time so the
// downstream RemainingFirewallSeconds + VerifyAccessToken cap can compute
// the deadline. A regression that creates AccessEntry without going
// through GenerateAccessToken would leave FirstKnockTime at zero —
// callers reading the cap would see a deadline in 1970 and refuse to
// extend (fail-closed, which is the right default for a security gate).
func TestGenerateAccessToken_SetsFirstKnockTime(t *testing.T) {
	a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	entry := &AccessEntry{User: &common.AgentUser{UserId: "u"}, OpenTime: 60}

	before := time.Now()
	a.GenerateAccessToken(entry)
	after := time.Now()

	if entry.FirstKnockTime.IsZero() {
		t.Fatalf("FirstKnockTime not set — absolute-deadline cap will fail-closed incorrectly")
	}
	if entry.FirstKnockTime.Before(before) || entry.FirstKnockTime.After(after) {
		t.Fatalf("FirstKnockTime %v outside expected range [%v, %v]",
			entry.FirstKnockTime, before, after)
	}
}

// TestGenerateAccessToken_TempEntryShapeSetsFirstKnockTime exercises
// GenerateAccessToken with the SAME field shape used by the PreAccessAction
// path at msghandler.go:604-609 (User + SrcAddrs + DstAddrs + OpenTime).
// While that path is transitively covered by
// TestGenerateAccessToken_SetsFirstKnockTime, a direct fence on the
// temp-entry shape catches a future refactor that bypassed
// GenerateAccessToken on that path (e.g., a hand-rolled
// `tokenStore.Store(token, tempEntry)` with no FirstKnockTime population).
//
// Cannot exercise HandleAccessControl's PreAccessAction branch directly here —
// that requires a fully-initialized AC with iptables/ipset (see
// msghandler_test.go:174). This test pins the structural contract: any
// AccessEntry that flows through GenerateAccessToken gets FirstKnockTime
// populated, regardless of the entry's field shape at construction. (#1942)
func TestGenerateAccessToken_TempEntryShapeSetsFirstKnockTime(t *testing.T) {
	a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}

	// Mirror msghandler.go:604-609's tempEntry construction shape.
	const tempOpenTimeSec = 5
	tempEntry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u-tempentry"},
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}},
		OpenTime: tempOpenTimeSec,
	}

	before := time.Now()
	token := a.GenerateAccessToken(tempEntry)
	after := time.Now()

	if token == "" {
		t.Fatal("GenerateAccessToken returned empty token")
	}
	if tempEntry.FirstKnockTime.IsZero() {
		t.Fatalf("tempEntry.FirstKnockTime not set after GenerateAccessToken — PreAccessAction path would produce year-1970 absolute deadline and fail-closed (#1942 contract regression)")
	}
	if tempEntry.FirstKnockTime.Before(before) || tempEntry.FirstKnockTime.After(after) {
		t.Fatalf("tempEntry.FirstKnockTime %v outside expected range [%v, %v]",
			tempEntry.FirstKnockTime, before, after)
	}
	// And the deadline cap actually fires for this shape: verify that
	// the firewall-deadline math is anchored on the tempEntry's
	// FirstKnockTime and uses the temp OpenTime.
	if got := tempEntry.RemainingFirewallSeconds(); got > tempOpenTimeSec {
		t.Errorf("RemainingFirewallSeconds = %d > OpenTime %d — tempEntry deadline math wrong", got, tempOpenTimeSec)
	}
}

// TestVerifyAccessToken_AbsoluteDeadlineCap pins the central #1942 fix:
// the per-verify sliding window may not push ExpireTime past
// FirstKnockTime + OpenTime + buffer, no matter how many times
// VerifyAccessToken is called. Without the cap, every successful verify
// extended ExpireTime by OpenTime and the token's lifetime grew
// unbounded.
func TestVerifyAccessToken_AbsoluteDeadlineCap(t *testing.T) {
	a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	const openTime = 10
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u"},
		OpenTime: openTime,
	}
	token := a.GenerateAccessToken(entry)
	deadline := entry.absoluteTokenDeadline()

	for i := 0; i < 100; i++ {
		got := a.VerifyAccessToken(token)
		if got == nil {
			t.Fatalf("verify %d returned nil before deadline", i)
		}
		if got.ExpireTime.After(deadline) {
			t.Fatalf("verify %d slid ExpireTime to %v, past absolute deadline %v (#1942 regression)",
				i, got.ExpireTime, deadline)
		}
		// First verify slides ExpireTime by OpenTime, which is exactly
		// the buffer past `now + OpenTime`. That overshoots the deadline
		// (`now + OpenTime + buffer`) by `OpenTime - buffer` seconds (5
		// in this test setup), so the cap fires and clamps to deadline
		// EXACTLY. Every subsequent verify also clamps to deadline. A
		// regression that capped at `deadline - 1ns` would pass the
		// !After check above but fail this exact-equality assertion.
		if !got.ExpireTime.Equal(deadline) {
			t.Fatalf("verify %d: ExpireTime = %v, want exactly %v (cap should clamp to deadline, not deadline-ε)",
				i, got.ExpireTime, deadline)
		}
	}
}

// TestVerifyAccessToken_ReturnsNilPastAbsoluteDeadline simulates the
// post-deadline state by rewinding FirstKnockTime. Once
// FirstKnockTime + OpenTime + buffer has elapsed, VerifyAccessToken
// must return nil regardless of ExpireTime's current value — otherwise
// a stale entry whose ExpireTime was previously slid forward would
// remain validatable indefinitely.
func TestVerifyAccessToken_ReturnsNilPastAbsoluteDeadline(t *testing.T) {
	a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	const openTime = 10
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u"},
		OpenTime: openTime,
	}
	token := a.GenerateAccessToken(entry)

	// Rewind to one second past the absolute deadline. ExpireTime is
	// kept far in the future to prove the cap is on FirstKnockTime,
	// not ExpireTime.
	entry.FirstKnockTime = time.Now().Add(-time.Duration(openTime+accessTokenLatePacketBufferSeconds+1) * time.Second)
	entry.ExpireTime = time.Now().Add(1 * time.Hour)
	a.tokenStore.Store(token, entry)

	if got := a.VerifyAccessToken(token); got != nil {
		t.Fatalf("verify past absolute deadline returned entry %v — #1942 regression (sliding-window cap not enforced)", got)
	}
}

// TestGenerateAccessToken_FirstKnockTimeRetainsMonotonic pins the
// monotonic-clock invariant the absolute-deadline cap relies on. Per
// time.Time semantics, time.Now() returns a time.Time carrying both a
// wall reading and a monotonic reading; Add/Until preserve the
// monotonic component, and time.Time-equality `t == t.Round(0)` is
// false iff a monotonic reading is present (Round(0) strips it).
//
// Why this matters: the absolute-deadline cap relies on `time.Until(...)`
// against `FirstKnockTime + OpenTime` being computed via the monotonic
// clock, so an NTP step-back cannot extend the deadline. A future
// refactor that serializes AccessEntry (Redis, disk, JSON round-trip)
// or applies a method that strips monotonic (`.UTC()`, `.Truncate`,
// `.Round`) would silently restore the bug this PR closes.
func TestGenerateAccessToken_FirstKnockTimeRetainsMonotonic(t *testing.T) {
	a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	entry := &AccessEntry{User: &common.AgentUser{UserId: "u"}, OpenTime: 60}

	a.GenerateAccessToken(entry)

	// Round(0) strips the monotonic reading; if FirstKnockTime carries
	// a monotonic component (it must, per time.Now() semantics on
	// supported platforms), `entry.FirstKnockTime != entry.FirstKnockTime.Round(0)`.
	if entry.FirstKnockTime == entry.FirstKnockTime.Round(0) {
		t.Fatal("FirstKnockTime has no monotonic clock reading — NTP step-backs would extend the absolute deadline cap. Check that GenerateAccessToken stores `time.Now()` directly (not `.UTC()` / `.Truncate()` / serialized round-trip).")
	}
}

// TestRemainingFirewallSeconds_StrictNoBuffer pins the firewall-side
// (no-buffer) deadline. The buffer applies to the AC token's tokenStore
// lifetime (late-packet handling); the firewall ipset entry MUST close
// at exactly FirstKnockTime + OpenTime per the mint's session_duration
// contract. A regression that adds the buffer here would leak
// `buffer` seconds of firewall window past the security boundary.
func TestRemainingFirewallSeconds_StrictNoBuffer(t *testing.T) {
	const openTime = 10
	before := time.Now()
	entry := &AccessEntry{
		OpenTime:       openTime,
		FirstKnockTime: before,
	}

	// Compute the deadline-arithmetic bracket directly rather than the
	// previous magic-number `openTime-2` slop. The lower bound is
	// `int(time.Until(deadline))` measured AFTER the call returns; the
	// upper bound is `openTime` (the strict no-buffer contract). This
	// catches a 1s premature shortening that the previous 2s slop hid.
	remaining := entry.RemainingFirewallSeconds()
	deadline := before.Add(time.Duration(openTime) * time.Second)
	lowerBound := int(time.Until(deadline).Seconds())
	if lowerBound < 0 {
		lowerBound = 0
	}

	if remaining > openTime {
		t.Fatalf("remaining %d > OpenTime %d — buffer leaked into firewall deadline (#1942)", remaining, openTime)
	}
	if remaining < lowerBound {
		t.Fatalf("remaining %d < deadline-arithmetic lower bound %d — firewall window prematurely shortened", remaining, lowerBound)
	}
}

// TestRemainingFirewallSeconds_SubSecondTruncatesToZero pins the
// truncate-toward-zero behavior in the sub-second dead zone. When the
// remaining window is in (0, 1)s, int(remaining.Seconds()) returns 0
// and httpac.go's deadline-passed branch treats 0 as "refuse re-open."
// This shortens the firewall window by up to ~1s vs the strict math
// deadline — intentional, favors earlier close (safe direction for a
// security gate). A regression that switched to Round (banker's
// rounding) or Ceil would silently extend the window into the
// sub-second-past-deadline zone.
func TestRemainingFirewallSeconds_SubSecondTruncatesToZero(t *testing.T) {
	const openTime = 10
	// 500ms before the strict deadline: remaining is in (0, 1)s.
	entry := &AccessEntry{
		OpenTime:       openTime,
		FirstKnockTime: time.Now().Add(-time.Duration(openTime)*time.Second + 500*time.Millisecond),
	}

	if got := entry.RemainingFirewallSeconds(); got != 0 {
		t.Fatalf("sub-second remaining (got %d) must truncate to 0 — refresh in this window must refuse re-open per the strict-no-buffer contract", got)
	}
}

// TestRemainingFirewallSeconds_OpenTimeOneBoundary fences the
// degenerate-floor case made hot by qurl-service#498 (which dropped
// SessionDuration min from 5min to 1s to support Discord-bot
// self-destruct presets; the bot rounds its 0.5s preset up to 1s
// because the wire and DDB shape are int seconds — see #498's "Why
// 1 second, not 500 ms" section). At OpenTime=1 the dead zone is
// effectively the entire window post-issue: any moment past
// FirstKnockTime leaves remaining < 1s, truncate-toward-zero
// returns 0, and the handler's deadline-passed branch refuses re-
// open. The session expires naturally at the absolute deadline.
//
// A regression that shifted truncation to Round / Ceil would let a
// 1s session refresh once and keep its firewall open for ~2s,
// defeating the marketed self-destruct window the post-#498 floor
// exists to support.
func TestRemainingFirewallSeconds_OpenTimeOneBoundary(t *testing.T) {
	const openTime = 1
	// 1µs past issue: remaining is just under 1s. Test stability:
	// any test-runtime slop between Add() and the call below only
	// reduces remaining further, strengthening the assertion.
	entry := &AccessEntry{
		OpenTime:       openTime,
		FirstKnockTime: time.Now().Add(-1 * time.Microsecond),
	}

	if got := entry.RemainingFirewallSeconds(); got != 0 {
		t.Fatalf("OpenTime=1, 1µs past issue (got %d): refresh must refuse re-open — qurl-service#498 self-destruct floor depends on this", got)
	}
}

// TestRemainingFirewallSeconds_ZeroPastDeadline confirms the post-
// deadline return value is 0, which httpac.go uses as the
// "refuse-to-reopen" signal. A non-zero return after the deadline
// would let HandleAccessControl re-issue the ipset rule with a
// stale-or-negative timeout, defeating the cap.
func TestRemainingFirewallSeconds_ZeroPastDeadline(t *testing.T) {
	const openTime = 10
	entry := &AccessEntry{
		OpenTime:       openTime,
		FirstKnockTime: time.Now().Add(-time.Duration(openTime+1) * time.Second),
	}

	if got := entry.RemainingFirewallSeconds(); got != 0 {
		t.Fatalf("remaining = %d past firewall deadline, want 0 (#1942 — must refuse to re-open)", got)
	}
}

// TestAccessEntry_JSONOmitsFirstKnockTime pins the json:"-" tag on
// FirstKnockTime. httpac.go's /refresh handler returns the AccessEntry
// to the caller via c.JSON; without the tag the precise token-issue
// timestamp would leak to anyone presenting a valid refresh token. A
// regression that drops the tag (e.g. struct refactor) silently
// re-introduces the leak.
func TestAccessEntry_JSONOmitsFirstKnockTime(t *testing.T) {
	entry := &AccessEntry{
		User:           &common.AgentUser{UserId: "u"},
		OpenTime:       60,
		FirstKnockTime: time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC),
		ExpireTime:     time.Date(2026, 5, 13, 12, 1, 0, 0, time.UTC),
	}
	buf, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Unmarshal back into a map and assert no key (case-insensitive)
	// names FirstKnockTime. More durable than substring-matching the
	// rendered timestamp, which would false-pass if Go's time.Time
	// JSON format ever changed.
	var m map[string]any
	if err := json.Unmarshal(buf, &m); err != nil {
		t.Fatalf("Unmarshal back: %v (body=%s)", err, buf)
	}
	for k := range m {
		if strings.EqualFold(k, "FirstKnockTime") {
			t.Fatalf("AccessEntry JSON leaks FirstKnockTime as key %q — json:\"-\" tag removed? body=%s", k, buf)
		}
	}
}

// TestAccessEntry_JSONOmitsEmptyOwnerId pins the json:",omitempty"
// tag on common.AgentUser.OwnerId for the AC /refresh wire shape.
//
// The AC msghandler intentionally does NOT populate OwnerId
// (msghandler.go:120-128 — the AC has no application-layer
// authorization use for tenant identity; only the server-side
// /nhp/internal/token/validate consumer needs it). httpac.go's
// /refresh handler returns the entire AccessEntry via c.JSON;
// without the tag, every AC refresh response would emit
// `"OwnerId":""` — present-but-empty, which a strict downstream
// consumer could read as "AC asserts identity unknown" rather than
// "AC doesn't carry this field."
//
// Matches the omitempty contract on the server-side
// internalTokenValidateResponse.OwnerId — both endpoints surface
// the absence of OwnerId identically (key-absent), so a consumer
// observing one shape across both APIs sees the same fail-safe
// semantics.
func TestAccessEntry_JSONOmitsEmptyOwnerId(t *testing.T) {
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u"}, // OwnerId left empty
		OpenTime: 60,
	}
	buf, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// The omitempty tag lives on the embedded *common.AgentUser. The
	// flattened User shape is rendered as a nested object under the
	// "User" key in AccessEntry's JSON; assert no OwnerId key appears
	// anywhere in the rendered body.
	if strings.Contains(string(buf), `"OwnerId"`) {
		t.Errorf("AccessEntry JSON contains OwnerId key with empty value (json:\",omitempty\" tag removed?); body=%s", buf)
	}

	// Positive control: when OwnerId IS set, the field DOES appear.
	// A regression that mis-spelled the tag (e.g. `json:\"owner_id,omitempty\"`
	// would also pass the negative check above) would surface here
	// because the field would now render as `\"owner_id\"`, not `\"OwnerId\"`.
	entryWithOwner := &AccessEntry{
		User:     &common.AgentUser{UserId: "u", OwnerId: "tenant-X"},
		OpenTime: 60,
	}
	buf2, err := json.Marshal(entryWithOwner)
	if err != nil {
		t.Fatalf("Marshal entryWithOwner: %v", err)
	}
	if !strings.Contains(string(buf2), `"OwnerId":"tenant-X"`) {
		t.Errorf("AccessEntry JSON with OwnerId set is missing the expected key/value pair; body=%s", buf2)
	}
}

// TestAccessEntry_JSONOmitsQurlV2Metadata pins the json:"-" tag on all six
// P4a qURL v2 revocation-metadata fields. httpac.go's /refresh handler returns
// the whole AccessEntry via c.JSON; these are internal revocation-index fields
// with no client consumer, so they must never ride out on the /refresh wire —
// not even as present-but-zero PascalCase keys on legacy entries. This mirrors
// the FirstKnockTime json:"-" and OwnerId omitempty fences. The test sets every
// field to a non-zero value so a dropped tag is caught (a zero value would be
// absent under ,omitempty but PascalCase-present under no tag; json:"-" keeps it
// absent either way).
func TestAccessEntry_JSONOmitsQurlV2Metadata(t *testing.T) {
	entry := &AccessEntry{
		User:                  &common.AgentUser{UserId: "u"},
		OpenTime:              60,
		QurlUserPublicKeyHash: "a1b2c3",
		ResourcePublicKeyHash: "d4e5f6",
		QurlSessionId:         "sess_123",
		AdmissionId:           "adm_test123",
		RevocationEpoch:       42,
		Deadline:              1781910300,
	}
	buf, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf, &m); err != nil {
		t.Fatalf("Unmarshal back: %v (body=%s)", err, buf)
	}
	for _, field := range []string{
		"QurlUserPublicKeyHash",
		"ResourcePublicKeyHash",
		"QurlSessionId",
		"AdmissionId",
		"RevocationEpoch",
		"Deadline",
	} {
		for k := range m {
			if strings.EqualFold(k, field) {
				t.Fatalf("AccessEntry /refresh JSON leaks %q as key %q — json:\"-\" tag removed? body=%s", field, k, buf)
			}
		}
	}
}

func TestGenerateAccessToken_IgnoresQurlV2DeadlineForExpiry(t *testing.T) {
	a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	const openTime = 3
	before := time.Now()
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u"},
		OpenTime: openTime,
		Deadline: before.Add(24 * time.Hour).Unix(),
	}

	a.GenerateAccessToken(entry)

	wantMax := before.Add(time.Duration(openTime+accessTokenLatePacketBufferSeconds+1) * time.Second)
	if entry.ExpireTime.After(wantMax) {
		t.Fatalf("ExpireTime = %v, want bounded by OpenTime + late-packet buffer (<= %v), not qURL Deadline %d",
			entry.ExpireTime, wantMax, entry.Deadline)
	}
	if got := entry.Deadline; got != before.Add(24*time.Hour).Unix() {
		t.Fatalf("Deadline = %d, want stored metadata preserved", got)
	}
}

// TestBufferAsymmetry_TokenStillValidButFirewallClosed pins the
// asymmetry between the two #1942 deadlines: there is a window after
// FirstKnockTime + OpenTime but before FirstKnockTime + OpenTime + buffer
// where VerifyAccessToken still returns the entry (late-packet handling)
// but RemainingFirewallSeconds returns 0 (refuse to re-open the ipset
// rule). A future "simplification" that shares one constant between
// the two helpers would collapse this asymmetry — silently restoring
// the leak this PR closes. The httpac.go refresh handler MUST observe
// the firewall-zero signal and short-circuit before HandleAccessControl.
func TestBufferAsymmetry_TokenStillValidButFirewallClosed(t *testing.T) {
	a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	const openTime = 10
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u"},
		OpenTime: openTime,
	}
	token := a.GenerateAccessToken(entry)

	// Rewind FirstKnockTime so we land in the asymmetry window:
	// past FirstKnockTime + OpenTime but before + buffer.
	entry.FirstKnockTime = time.Now().Add(-time.Duration(openTime+1) * time.Second)
	a.tokenStore.Store(token, entry)

	if got := a.VerifyAccessToken(token); got == nil {
		t.Fatalf("VerifyAccessToken returned nil inside the late-packet buffer window — token deadline cap too tight (#1942 over-correction)")
	}
	if got := entry.RemainingFirewallSeconds(); got != 0 {
		t.Fatalf("RemainingFirewallSeconds = %d past firewall deadline, want 0 — buffer leaked into firewall (#1942 regression)", got)
	}
}

// TestRemainingFirewallSeconds_ShrinksOverTime confirms the deadline
// is anchored on FirstKnockTime, not "now". As wall-clock advances,
// the remaining window must monotonically decrease — this is the
// "no sliding" property #1942 enforces. A regression that re-anchors
// on the verify time would re-introduce the bug.
func TestRemainingFirewallSeconds_ShrinksOverTime(t *testing.T) {
	const openTime = 10
	entry := &AccessEntry{
		OpenTime:       openTime,
		FirstKnockTime: time.Now().Add(-3 * time.Second),
	}

	r1 := entry.RemainingFirewallSeconds()
	// Mutate FirstKnockTime backward to simulate 2s of wall-clock
	// passing — no real sleep. Indirect fence: if RemainingFirewallSeconds
	// were re-anchored on time.Now() at call time, mutating FirstKnockTime
	// wouldn't change the result. A direct wall-clock test would more
	// tightly fence "no re-anchoring AND no caching of `now`" — the
	// mutation test covers the first half. Saves ~1.5s per CI run; the
	// missing half is fenced indirectly by AbsoluteDeadlineCap (which
	// would fail if `now` were cached at issue time).
	entry.FirstKnockTime = entry.FirstKnockTime.Add(-2 * time.Second)
	r2 := entry.RemainingFirewallSeconds()

	if r2 >= r1 {
		t.Fatalf("remaining did not shrink: r1=%d r2=%d — deadline re-anchored on each call (#1942 regression)", r1, r2)
	}
}

// TestUdpAC_InstallExpiryHook_WiresCancelAllScheduledFlows fences the
// production wire-up: (*UdpAC).Start calls installExpiryHook, which
// must register the cancelAllScheduledFlows callback. A regression
// that drops the installExpiryHook call from Start (or its body)
// would silently disable the entire #2202 mechanism — this test
// fires the hook indirectly via CleanExpired and asserts the
// scheduler entry was canceled.
//
// Routes the Schedule through scheduleFlushIfEnabled (the production
// path) so the key is recorded on entry.scheduledKeys; per-entry
// tracking (#2201/#2205) means cancelAllScheduledFlows walks exactly
// what was scheduled rather than recomputing a fan-out.
func TestUdpAC_InstallExpiryHook_WiresCancelAllScheduledFlows(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}
	a.installExpiryHook() // exact wiring (*UdpAC).Start uses.

	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u-wire-fence"},
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime: 1,
	}
	token := a.GenerateAccessToken(entry)
	entry.ExpireTime = time.Now().Add(-1 * time.Minute)
	a.tokenStore.Store(token, entry)

	a.scheduleFlushIfEnabled(entry, "1.2.3.4", "10.0.0.1", 80, FlowProtoTCP, time.Now().Add(1*time.Hour))
	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1", got)
	}

	if got := a.tokenStore.CleanExpired(); got != 1 {
		t.Fatalf("CleanExpired removed %d, want 1", got)
	}
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after CleanExpired = %d, want 0 (installExpiryHook wiring broken)", got)
	}
}

// TestTokenStore_CleanExpired_CancelsScheduledFlows fences the
// end-to-end SetOnExpire → cancelAllScheduledFlows → Scheduler.Cancel
// chain. Without the hook, expired token entries would leave
// scheduler bookkeeping that fires Flush on already-gone kernel state.
// Two scheduled FlowKey variants (TCP + UDP) on the same entry
// exercise per-entry-set drain (#2201/#2205) in one assertion: both
// keys are recorded on entry.scheduledKeys at Schedule time, and
// cancelAllScheduledFlows must drain both.
func TestTokenStore_CleanExpired_CancelsScheduledFlows(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}
	a.tokenStore.SetOnExpire(func(_ string, entry *AccessEntry) {
		a.cancelAllScheduledFlows(entry)
	})

	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u-clean-cancels"},
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime: 1,
	}
	token := a.GenerateAccessToken(entry)
	// Rewind ExpireTime so CleanExpired removes it.
	entry.ExpireTime = time.Now().Add(-1 * time.Minute)
	a.tokenStore.Store(token, entry)

	// Schedule both TCP and UDP variants for this tuple through the
	// production wrapper so each key is recorded on entry.scheduledKeys.
	deadline := time.Now().Add(1 * time.Hour)
	a.scheduleFlushIfEnabled(entry, "1.2.3.4", "10.0.0.1", 80, FlowProtoTCP, deadline)
	a.scheduleFlushIfEnabled(entry, "1.2.3.4", "10.0.0.1", 80, FlowProtoUDP, deadline)
	if got := sched.EntryCount(); got != 2 {
		t.Fatalf("precondition: EntryCount = %d, want 2", got)
	}

	removed := a.tokenStore.CleanExpired()
	if removed != 1 {
		t.Fatalf("CleanExpired removed %d, want 1", removed)
	}
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after CleanExpired = %d, want 0 (SetOnExpire hook did not drain both variants)", got)
	}
}

// TestMakeFlowKey_ValidatesIPAndPortRange pins the MakeFlowKey
// contract scheduleFlushIfEnabled depends on: validates srcIP, dstIP,
// AND port ∈ [0, 65535]. A regression that loosened any of these
// would silently allow garbage FlowKeys into the scheduler index.
//
// Placement: generic MakeFlowKey unit tests live in
// expiry_scheduler_test.go; this lives here because the invariant
// underpins the scheduleFlushIfEnabled wrapper at the AC seam.
func TestMakeFlowKey_ValidatesIPAndPortRange(t *testing.T) {
	// Port=0 with valid IPs must succeed — wildcard / Any shape.
	if _, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 0, FlowProtoAny); err != nil {
		t.Fatalf("MakeFlowKey(..., port=0, Any): want nil, got %v", err)
	}
	// Out-of-range port must fail.
	if _, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 100_000, FlowProtoTCP); err == nil {
		t.Errorf("MakeFlowKey(..., port=100000): want error, got nil — port range no longer validated")
	}
	if _, err := MakeFlowKey("1.2.3.4", "10.0.0.1", -1, FlowProtoTCP); err == nil {
		t.Errorf("MakeFlowKey(..., port=-1): want error, got nil — port range no longer validated")
	}
	// Bad IP must fail regardless of port.
	if _, err := MakeFlowKey("not-an-ip", "10.0.0.1", 0, FlowProtoAny); err == nil {
		t.Errorf("MakeFlowKey(badIP, port=0): want error, got nil — IP validation regressed")
	}
}

// TestLatestOtherFirewallDeadline_SelfOnly_ReturnsZero fences the
// pointer-equality self-skip in latestOtherFirewallDeadline directly,
// without routing through cancelAllScheduledFlows. A future regression
// that broke `other == self` (e.g., swapped to ID-based equality, or
// a pooled-pointer refactor that lets self appear multiple times in
// the snapshot) would cause this test to return a non-zero deadline
// for a snapshot containing only self — locking down the invariant.
//
// Companion to TestUdpAC_CancelAllScheduledFlows_LoneEntryStillCancels
// which exercises the same property via the cancel path.
func TestLatestOtherFirewallDeadline_SelfOnly_ReturnsZero(t *testing.T) {
	a := &UdpAC{}
	entry := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-self"},
		SrcAddrs:       []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs:       []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime:       60,
		FirstKnockTime: time.Now(),
	}
	key, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 80, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}
	entry.recordScheduledKey(key)

	// Snapshot contains only self. The self-skip via pointer equality
	// must filter it out and the function must return the zero time.
	got := a.latestOtherFirewallDeadline([]*AccessEntry{entry}, entry, key, time.Now())
	if !got.IsZero() {
		t.Errorf("self-only snapshot returned non-zero deadline %v; want zero (self-skip broken)", got)
	}
}

// TestScheduler_Cancel_OnNeverScheduledKey_IsNoOp fences the
// no-op-on-non-existent-key contract that scheduleFlushIfEnabled's
// "acceptable degradation" godoc relies on. The full chain is:
// recordScheduledKey runs but Scheduler.Schedule never does (e.g.,
// breaker open, shutdown, panic between record and Schedule) →
// next cancelAllScheduledFlows walks the recorded key → calls
// Scheduler.Cancel(K) for a key the scheduler has no entry for.
// The contract: Cancel is idempotently a no-op, no panic, no
// scheduler-state corruption, no spurious metric ticks.
//
// Direct test on Scheduler.Cancel rather than indirect via
// cancelAllScheduledFlows so a regression in the scheduler
// (rather than in the wrapper) is caught at the right level.
func TestScheduler_Cancel_OnNeverScheduledKey_IsNoOp(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	never, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 80, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}
	if got := sched.EntryCount(); got != 0 {
		t.Fatalf("precondition: EntryCount = %d, want 0", got)
	}

	// Cancel a key that was never Scheduled — must not panic.
	sched.Cancel(never)
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after Cancel of never-Scheduled key = %d, want 0 (Scheduler.Cancel mutated state on non-existent key)", got)
	}

	// Schedule + Cancel + Cancel-again — second Cancel must also be a no-op.
	sched.Schedule(never, time.Now().Add(1*time.Hour))
	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("after Schedule: EntryCount = %d, want 1", got)
	}
	sched.Cancel(never)
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("after first Cancel: EntryCount = %d, want 0", got)
	}
	sched.Cancel(never) // double-Cancel is a no-op
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("after second Cancel (double-Cancel): EntryCount = %d, want 0", got)
	}
}

// TestUdpAC_CancelAllScheduledFlows_RescheduledMetricTicks fences the
// new MetricL3FlushCancelRescheduledForPeer counter — the
// positive-signal counter that the #2201 multi-session reschedule path
// is actually firing. Without this assertion, a regression that
// silently broke holdsScheduledKey (returning false where it should
// return true) would pass every other test (scheduler EntryCount
// would stay correct because Cancel-then-no-reschedule-then-Schedule
// happens to converge) but the dashboard counter would stop ticking
// unobserved.
func TestUdpAC_CancelAllScheduledFlows_RescheduledMetricTicks(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}

	now := time.Now()
	const srcIP, dstIP, dstPort = "1.2.3.4", "10.0.0.1", 80
	t1 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t1"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       1,
		FirstKnockTime: now.Add(-5 * time.Second),
	}
	t2 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t2"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       60,
		FirstKnockTime: now,
	}
	a.tokenStore.Store("tok-t1", t1)
	a.tokenStore.Store("tok-t2", t2)
	a.scheduleFlushIfEnabled(t1, srcIP, dstIP, dstPort, FlowProtoTCP, now.Add(2*time.Second))
	a.scheduleFlushIfEnabled(t2, srcIP, dstIP, dstPort, FlowProtoTCP, now.Add(60*time.Second))

	// Baseline: metric is zero before T1's cancel.
	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricL3FlushCancelRescheduledForPeer]; got != 0 {
		t.Fatalf("precondition: counter = %v, want 0", got)
	}

	a.cancelAllScheduledFlows(t1) // T2 holds K → reschedule, must tick

	counters, _ = a.registration.metrics.CountersForTest(t)
	if got := counters[MetricL3FlushCancelRescheduledForPeer]; got != 1 {
		t.Errorf("MetricL3FlushCancelRescheduledForPeer = %v, want 1 (reschedule path didn't tick)", got)
	}

	// LoneEntry case: t2 has no peer, must NOT tick.
	a.tokenStore.Delete("tok-t2")
	a.cancelAllScheduledFlows(t2)
	counters, _ = a.registration.metrics.CountersForTest(t)
	if got := counters[MetricL3FlushCancelRescheduledForPeer]; got != 1 {
		t.Errorf("MetricL3FlushCancelRescheduledForPeer = %v after lone-entry cancel, want 1 (no extra tick)", got)
	}
}

// TestHandleAccessControl_NilEntry_TicksMetric fences the
// MetricL3FlushAdmissionNilEntry counter mirroring the
// MetricL3FlushScheduleNilEntry pattern. Programmer-error signal:
// if a future caller drops the entry pointer, this surfaces loudly
// rather than silently nil-derefing.
func TestHandleAccessControl_NilEntry_TicksMetric(t *testing.T) {
	a := &UdpAC{
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}
	artMsg, err := a.HandleAccessControl(nil, 60, nil)
	if err == nil {
		t.Fatal("expected error from nil-entry guard")
	}
	if artMsg == nil || artMsg.ErrCode != common.ErrACNilEntry.ErrorCode() {
		t.Errorf("artMsg.ErrCode = %v, want ErrACNilEntry", artMsg)
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricL3FlushAdmissionNilEntry]; got != 1 {
		t.Errorf("MetricL3FlushAdmissionNilEntry = %v, want 1", got)
	}
}

// TestUdpAC_CancelAllScheduledFlows_NilTokenStore_TicksMetric fences
// the MetricL3FlushCancelNilTokenStore Critical-log + counter path.
// Programmer-error signal: a future DI refactor that drops
// a.tokenStore would silently lose the multi-session protection
// (degraded to lone-entry behavior); this metric is the only
// observable signal of that regression.
func TestUdpAC_CancelAllScheduledFlows_NilTokenStore_TicksMetric(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		expirySched: sched, // tokenStore intentionally nil
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}
	entry := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-nil-store"},
		SrcAddrs:       []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs:       []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime:       60,
		FirstKnockTime: time.Now(),
	}
	a.scheduleFlushIfEnabled(entry, "1.2.3.4", "10.0.0.1", 80, FlowProtoTCP, time.Now().Add(1*time.Hour))

	a.cancelAllScheduledFlows(entry)

	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricL3FlushCancelNilTokenStore]; got != 1 {
		t.Errorf("MetricL3FlushCancelNilTokenStore = %v, want 1 (degraded-to-lone-entry path didn't tick)", got)
	}
}

// TestScheduleFlushIfEnabled_NilEntry_TicksMetric fences the
// MetricL3FlushScheduleNilEntry counter (already wired; this is the
// missing test coverage cr round 18 flagged).
func TestScheduleFlushIfEnabled_NilEntry_TicksMetric(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		expirySched: sched,
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}
	a.scheduleFlushIfEnabled(nil, "1.2.3.4", "10.0.0.1", 80, FlowProtoTCP, time.Now().Add(1*time.Hour))

	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricL3FlushScheduleNilEntry]; got != 1 {
		t.Errorf("MetricL3FlushScheduleNilEntry = %v, want 1 (nil-entry guard didn't tick)", got)
	}
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount = %v, want 0 (phantom scheduler entry created)", got)
	}
}

// TestLatestOtherFirewallDeadline_DifferentPointersSameFields_BothCount
// fences the pointer-equality self-skip's invariant that "self" is
// distinguished by POINTER identity, not by address-field equality. If
// a future refactor pools or reuses AccessEntry pointers (e.g.,
// connection-pool style optimization), two entries with identical
// fields but different pointers must EACH count the other as a peer
// holder — they're not the same logical session.
//
// Companion to TestLatestOtherFirewallDeadline_SelfOnly_ReturnsZero
// which fences the opposite direction (self IS skipped).
func TestLatestOtherFirewallDeadline_DifferentPointersSameFields_BothCount(t *testing.T) {
	a := &UdpAC{}
	key, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 80, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}

	now := time.Now()
	// Two distinct entries with identical address-field shapes.
	// Self-skip must NOT collapse them via field equality — only
	// pointer identity skips.
	e1 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-shared"},
		SrcAddrs:       []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs:       []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime:       60,
		FirstKnockTime: now,
	}
	e2 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-shared"},
		SrcAddrs:       []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs:       []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime:       60,
		FirstKnockTime: now,
	}
	e1.recordScheduledKey(key)
	e2.recordScheduledKey(key)

	// From e1's perspective, e2 must register as a peer holder.
	got := a.latestOtherFirewallDeadline([]*AccessEntry{e1, e2}, e1, key, now)
	if got.IsZero() {
		t.Errorf("with two distinct entries holding K, latestOtherFirewallDeadline from e1's view = zero; want e2's deadline (pointer-equality self-skip collapsed by field equality?)")
	}

	// Symmetric: from e2's perspective, e1 must register as a peer.
	got = a.latestOtherFirewallDeadline([]*AccessEntry{e1, e2}, e2, key, now)
	if got.IsZero() {
		t.Errorf("with two distinct entries holding K, latestOtherFirewallDeadline from e2's view = zero; want e1's deadline (pointer-equality self-skip collapsed by field equality?)")
	}
}

// TestLatestOtherFirewallDeadline_NowCapturedOnceDuringWalk fences the
// snapshot-now semantic in cancelAllScheduledFlows: `now` is captured
// once before the per-key loop and reused, so a peer entry whose
// firewall closes DURING the walk (between snapshot and the per-key
// consult) is still treated as live for the captured `now`. The
// rationale (udpac.go) is "late Flush is ENOENT-idempotent on the
// flusher side" — we accept a sub-second reschedule overshoot in
// exchange for sequential consistency across the K-loop.
//
// Concrete fence: construct a peer whose firewallDeadline = capturedNow
// + 1ns. From the perspective of capturedNow, the peer is live
// (1ns in the future), and latestOtherFirewallDeadline returns the
// peer's deadline. By the time the assertion runs (well after
// capturedNow), the peer's actual firewall has closed in wall time —
// but the function still returns the deadline because it consults
// the captured `now`, not time.Now(). Regression where the loop
// re-captures now per-key would return zero here, failing the test.
//
// Companion to cr round 23 observation #2.
func TestLatestOtherFirewallDeadline_NowCapturedOnceDuringWalk(t *testing.T) {
	a := &UdpAC{}
	key, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 80, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}

	// capturedNow precedes the peer's firewall close by exactly 1ns.
	// Real wall time during the test will be well past peer's close.
	capturedNow := time.Now().Add(-1 * time.Hour) // anchor capturedNow in the past
	peer := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-edge-firewall"},
		SrcAddrs:       []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs:       []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime:       0, // firewallDeadline = FirstKnockTime + 0s
		FirstKnockTime: capturedNow.Add(1 * time.Nanosecond),
	}
	peer.recordScheduledKey(key)

	self := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-self"},
		SrcAddrs:       []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs:       []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime:       60,
		FirstKnockTime: capturedNow,
	}

	// From self's perspective with the captured `now`, peer's firewall
	// is 1ns in the future — must register as a live holder.
	got := a.latestOtherFirewallDeadline([]*AccessEntry{self, peer}, self, key, capturedNow)
	if got.IsZero() {
		t.Errorf("peer with firewallDeadline = capturedNow+1ns treated as past; want returned-as-live (regression: now re-captured per-key)")
	}

	// Sanity: with a captured `now` AFTER peer's firewallDeadline, peer
	// is correctly past and returns zero.
	got = a.latestOtherFirewallDeadline([]*AccessEntry{self, peer}, self, key, capturedNow.Add(1*time.Second))
	if !got.IsZero() {
		t.Errorf("peer past firewall returned %v; want zero (liveness check broken)", got)
	}
}

// TestUdpAC_CancelAllScheduledFlows_DoesNotCancelUntrackedKeys fences
// the per-entry tracking contract (#2201/#2205): cancelAllScheduledFlows
// drains exactly entry.scheduledKeys and touches no other scheduler
// entries. A regression that accidentally re-introduced a fan-out from
// SrcAddrs × DstAddrs would Cancel keys this entry never scheduled
// (the multi-session race #2201 was about). Pre-fix code with the
// probe-based fan-out canceled any FlowKey shape derivable from the
// entry's address fields; post-fix code can only touch keys the
// entry's own Schedule calls recorded.
func TestUdpAC_CancelAllScheduledFlows_DoesNotCancelUntrackedKeys(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{expirySched: sched}

	// Pre-schedule a "foreign" key that no AccessEntry tracks. Under
	// the old fan-out implementation, calling cancelAllScheduledFlows
	// with an entry covering the same (src, dst, port=80) would have
	// canceled this via the TCP fan-out. Post-tracking, the foreign
	// key has no owning entry and must survive.
	//
	// Direct sched.Schedule (bypassing scheduleFlushIfEnabled) is
	// INTENTIONAL — this test is specifically modeling a foreign
	// key that no AccessEntry tracks. A future "fix" that routes
	// this call through scheduleFlushIfEnabled would defeat the
	// test by recording the key on some entry, removing the
	// untracked condition the assertion needs.
	foreignKey, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 80, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}
	sched.Schedule(foreignKey, time.Now().Add(1*time.Hour))

	// Build an entry covering the same address space and call Cancel
	// — its empty scheduledKeys means nothing should be canceled.
	a.cancelAllScheduledFlows(&AccessEntry{
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
	})

	if got := sched.EntryCount(); got != 1 {
		t.Errorf("EntryCount = %d, want 1 — Cancel touched a key the entry never scheduled (fan-out leaked back in?)", got)
	}
}

// TestUdpAC_CancelAllScheduledFlows_NilSafe pins both early-return
// guards: nil-scheduler (feature disabled) and nil-entry. Each
// branch asserts no scheduler state changes; without nil-entry,
// an entry-shape regression could hide behind the nil-scheduler
// short-circuit.
func TestUdpAC_CancelAllScheduledFlows_NilSafe(t *testing.T) {
	// Branch 1: scheduler disabled, non-nil entry.
	noSched := &UdpAC{}
	noSched.cancelAllScheduledFlows(&AccessEntry{
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
	})

	// Branch 2: scheduler enabled, nil entry. Pre-stage one
	// unrelated scheduled entry and assert EntryCount is
	// unchanged after the nil-entry call — guards against a
	// regression that silently iterates a nil dereference and
	// somehow disturbs scheduler state.
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()
	unrelatedKey, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 80, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}
	sched.Schedule(unrelatedKey, time.Now().Add(1*time.Hour))
	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1", got)
	}

	withSched := &UdpAC{expirySched: sched}
	withSched.cancelAllScheduledFlows(nil)

	if got := sched.EntryCount(); got != 1 {
		t.Errorf("EntryCount after nil-entry call = %d, want 1 (nil-entry guard touched unrelated state)", got)
	}
}

// TestAccessEntry_RecordScheduledKey_IdempotentOnReSchedule fences the
// set-dedup contract on /refresh extension: re-Schedule of the same
// FlowKey (longest-wins semantics handle the deadline side) records
// once on the tracking side, so drainScheduledKeys returns one key
// and cancelAllScheduledFlows issues exactly one Cancel.
func TestAccessEntry_RecordScheduledKey_IdempotentOnReSchedule(t *testing.T) {
	entry := &AccessEntry{}
	key, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 80, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}
	entry.recordScheduledKey(key)
	entry.recordScheduledKey(key) // /refresh re-Schedule
	entry.recordScheduledKey(key) // second /refresh re-Schedule

	keys := entry.drainScheduledKeys()
	if len(keys) != 1 {
		t.Errorf("drained %d keys after 3 records of same key, want 1 (set-dedup regression)", len(keys))
	}
	if got := entry.drainScheduledKeys(); got != nil {
		t.Errorf("second drain returned %v, want nil (drain did not reset the set)", got)
	}
}

// TestAccessEntry_DrainScheduledKeys_NilSafe fences the empty-entry
// drain: a fresh AccessEntry that was never scheduled must drain
// nil without allocating the underlying map. Closes a regression
// path where cancelAllScheduledFlows is called on an entry that
// went through HandleAccessControl's early-return gates (breaker
// open, malformed openTime) and never reached a Schedule call.
func TestAccessEntry_DrainScheduledKeys_NilSafe(t *testing.T) {
	entry := &AccessEntry{}
	if got := entry.drainScheduledKeys(); got != nil {
		t.Errorf("fresh entry drained %v, want nil", got)
	}
}

// TestUdpAC_CancelAllScheduledFlows_MultiSessionRaceKeepsKeyAlive
// fences #2201's actual acceptance criterion: two live AccessEntries
// share a FlowKey, T1 expires, T2's scheduler coverage MUST survive.
//
// Pre-fix code (probe-based fan-out) canceled the shared FlowKey on
// T1's expire, orphaning T2. The fix is the tokenStore consult in
// cancelAllScheduledFlows: when T1 drains key K, scan tokenStore for
// any other entry that holds K with a still-future firewall deadline
// (T2 does), and re-Schedule rather than Cancel so longest-wins
// absorb keeps the scheduler entry at T2's deadline.
//
// The assertions check both the scheduler keeps the entry alive
// AND its deadline reflects T2's window (via T2's subsequent
// Cancel actually removing the entry).
func TestUdpAC_CancelAllScheduledFlows_MultiSessionRaceKeepsKeyAlive(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}

	now := time.Now()
	const srcIP, dstIP, dstPort = "1.2.3.4", "10.0.0.1", 80

	// T1 admitted earlier with a shorter OpenTime; the live firewall
	// has already closed naturally for T1 (deadline in past), which
	// triggers OnExpire's cancelAllScheduledFlows(t1). T2 admitted
	// later with a long OpenTime — still live, scheduler must keep
	// its FlowKey coverage.
	t1 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t1"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       1,
		FirstKnockTime: now.Add(-5 * time.Second), // T1's firewall closed 4s ago
	}
	t2 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t2"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       60, // T2's firewall still open for ~60s
		FirstKnockTime: now,
	}
	// Store both in tokenStore so the snapshot in cancelAllScheduledFlows
	// sees T2 as a candidate for the multi-session check.
	a.tokenStore.Store("tok-t1", t1)
	a.tokenStore.Store("tok-t2", t2)

	// Both scheduled the same FlowKey; longest-wins absorb keeps the
	// scheduler at T2's deadline.
	a.scheduleFlushIfEnabled(t1, srcIP, dstIP, dstPort, FlowProtoTCP, now.Add(1*time.Second))
	a.scheduleFlushIfEnabled(t2, srcIP, dstIP, dstPort, FlowProtoTCP, now.Add(60*time.Second))
	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1 (longest-wins should absorb to one entry)", got)
	}

	// T1 expires — must NOT remove the scheduler entry because T2
	// still needs it. Pre-#2201 fix this dropped EntryCount to 0.
	a.cancelAllScheduledFlows(t1)
	if got := sched.EntryCount(); got != 1 {
		t.Errorf("EntryCount after T1 Cancel = %d, want 1 — T2's scheduler coverage orphaned (#2201 regression)", got)
	}

	// T2 expires — now no other entry holds the key, the scheduler
	// entry must be removed.
	a.tokenStore.Delete("tok-t2") // simulate T2's tokenStore removal
	a.cancelAllScheduledFlows(t2)
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after T2 Cancel (no other holders) = %d, want 0", got)
	}
}

// TestUdpAC_CancelAllScheduledFlows_LoneEntryStillCancels fences the
// inverse of the multi-session case: when only one AccessEntry holds
// a key, that entry's Cancel must actually cancel — the #2201
// tokenStore consult should not accidentally treat the entry's own
// key as a "held by other" signal (the latestOtherFirewallDeadline
// helper skips self).
func TestUdpAC_CancelAllScheduledFlows_LoneEntryStillCancels(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}

	entry := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-lone"},
		SrcAddrs:       []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs:       []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime:       60,
		FirstKnockTime: time.Now(),
	}
	a.tokenStore.Store("tok-lone", entry)
	a.scheduleFlushIfEnabled(entry, "1.2.3.4", "10.0.0.1", 80, FlowProtoTCP, time.Now().Add(1*time.Hour))

	a.cancelAllScheduledFlows(entry)
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after lone-entry Cancel = %d, want 0 (self-skip in tokenStore consult broken)", got)
	}
}

// TestUdpAC_CancelAllScheduledFlows_OtherEntryPastFirewall fences the
// liveness check in latestOtherFirewallDeadline: when the only other
// entry holding the key has a firewall deadline already in the past
// (kernel state self-expired), we still Cancel rather than re-Schedule.
// Otherwise an entry in the late-packet buffer window would keep
// scheduler bookkeeping alive past the natural kernel expiry.
func TestUdpAC_CancelAllScheduledFlows_OtherEntryPastFirewall(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}

	now := time.Now()
	const srcIP, dstIP, dstPort = "1.2.3.4", "10.0.0.1", 80

	// Both entries' firewalls closed naturally; T2 is still in the
	// late-packet buffer window so it's in tokenStore.
	t1 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t1"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       1,
		FirstKnockTime: now.Add(-10 * time.Second),
	}
	t2 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t2"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       1,
		FirstKnockTime: now.Add(-3 * time.Second), // also past
	}
	a.tokenStore.Store("tok-t1", t1)
	a.tokenStore.Store("tok-t2", t2)

	a.scheduleFlushIfEnabled(t1, srcIP, dstIP, dstPort, FlowProtoTCP, now.Add(1*time.Hour))
	a.scheduleFlushIfEnabled(t2, srcIP, dstIP, dstPort, FlowProtoTCP, now.Add(1*time.Hour))

	a.cancelAllScheduledFlows(t1)
	// T2 is still in the snapshot AND holds the key, but its firewall
	// is past — must Cancel rather than re-Schedule (no live cover).
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after Cancel with only-past-firewall other holders = %d, want 0 — liveness check missed", got)
	}
}

// Shared temp-access fixture coordinates. natIP is the kernel-observed
// (NAT'd) source the temp handler Schedules with; aolIP is the
// AOL-declared agent address carried on the entry's SrcAddrs.
const (
	tempAccessAolIP   = "10.99.0.5"
	tempAccessNatIP   = "203.0.113.42"
	tempAccessDstIP   = "10.0.0.1"
	tempAccessDstPort = 443
	// Long outer openTimeSec written to the kernel. Large so its
	// firewallDeadline/OnExpire sit far past the test's wall clock.
	tempAccessOpenTimeSec = 3600
)

// newTempAccessTestAC builds a UdpAC with a live scheduler + tokenStore
// for the temp-access ownership tests, registering the scheduler
// shutdown on cleanup.
func newTempAccessTestAC(t *testing.T) (*UdpAC, *Scheduler) {
	t.Helper()
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	})
	return &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}, sched
}

// TestUdpAC_RegisterTempAccessFlushEntry_OwnsAndIsCancelable fences the
// #2213 fix that retires the orphan flush path: temp-handler-written
// kernel rules are scheduled against a long-lived AccessEntry minted by
// registerTempAccessFlushEntry, so the scheduled flush is OWNED and an
// explicit admin Cancel (#2172) — modeled here by cancelAllScheduledFlows
// on that same entry — terminates it early. The pre-#2213 orphan path had
// no owner to walk to, so its scheduler entry could never be canceled
// before its deadline.
func TestUdpAC_RegisterTempAccessFlushEntry_OwnsAndIsCancelable(t *testing.T) {
	a, sched := newTempAccessTestAC(t)

	dstAddrs := []*common.NetAddress{{Ip: tempAccessDstIP, Port: tempAccessDstPort}}
	flushEntry := a.registerTempAccessFlushEntry(
		nil,
		&common.AgentUser{UserId: "u-temp-nat"},
		[]*common.NetAddress{{Ip: tempAccessAolIP}},
		dstAddrs,
		tempAccessOpenTimeSec,
	)

	// The entry must carry the kernel rule's actual lifetime so its
	// expiry (and thus OnExpire's cancel) lands after the flush deadline
	// — see the timing-preservation test below.
	if flushEntry.OpenTime != tempAccessOpenTimeSec {
		t.Fatalf("flushEntry.OpenTime = %d, want %d", flushEntry.OpenTime, tempAccessOpenTimeSec)
	}
	// Registered in tokenStore so OnExpire self-cleans it AND an admin
	// Cancel walking tokenStore.Snapshot() can reach it.
	if got := a.tokenStore.Size(); got != 1 {
		t.Fatalf("tokenStore.Size after register = %d, want 1 (entry must be stored for OnExpire/admin-Cancel reachability)", got)
	}

	// Temp handler Schedules using the kernel-observed natIP and the
	// LONG openTimeSec deadline — exactly the path the rewired
	// tcp/udpTempAccessHandler take.
	a.scheduleFlushIfEnabled(flushEntry, tempAccessNatIP, tempAccessDstIP, tempAccessDstPort, FlowProtoTCP, time.Now().Add(time.Hour))
	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1", got)
	}

	// Explicit admin Cancel: cancelAllScheduledFlows on the OWNING entry
	// drains its tracked key and cancels the scheduler entry. This is the
	// capability the orphan path lacked.
	a.cancelAllScheduledFlows(flushEntry)
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after cancelAllScheduledFlows(flushEntry) = %d, want 0 — owned temp-access flush must be cancelable (#2172/#2213)", got)
	}
}

// TestUdpAC_RegisterTempAccessFlushEntry_TempEntryExpiryDoesNotCancel
// fences the ESTABLISHED-bypass protection the orphan path provided and
// the #2213 fix preserves: the flush is owned by the LONG-lived entry,
// NOT by the short auth-gate tempEntry (OpenTime ~30s). When tempEntry's
// ~35s tokenStore expiry fires OnExpire, cancelAllScheduledFlows(tempEntry)
// must NOT cancel the temp-access flush — tempEntry holds no scheduled
// keys, so the long entry's scheduler entry survives until its own
// deadline. Recording the key on tempEntry instead (the abandoned #2205
// design) would Cancel here, leaving the kernel rule live with no queued
// flush.
func TestUdpAC_RegisterTempAccessFlushEntry_TempEntryExpiryDoesNotCancel(t *testing.T) {
	a, sched := newTempAccessTestAC(t)

	dstAddrs := []*common.NetAddress{{Ip: tempAccessDstIP, Port: tempAccessDstPort}}

	// tempEntry as constructed at msghandler.go's PASS_PRE_ACCESS_IP
	// branch: short TempPortOpenTime, AOL-declared SrcAddrs, no scheduled
	// keys of its own.
	tempEntry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u-temp-nat"},
		SrcAddrs: []*common.NetAddress{{Ip: tempAccessAolIP}},
		DstAddrs: dstAddrs,
		OpenTime: TempPortOpenTime,
	}

	// Long-lived owner mints + Schedules the flush, exactly as the
	// rewired temp handler does.
	flushEntry := a.registerTempAccessFlushEntry(
		nil,
		tempEntry.User,
		tempEntry.SrcAddrs,
		dstAddrs,
		tempAccessOpenTimeSec,
	)
	a.scheduleFlushIfEnabled(flushEntry, tempAccessNatIP, tempAccessDstIP, tempAccessDstPort, FlowProtoTCP, time.Now().Add(time.Hour))
	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1", got)
	}

	// Simulate OnExpire(tempEntry) firing at tempEntry's tokenStore
	// expiry. The flush is owned by flushEntry, so this must be a no-op
	// for the scheduler entry.
	a.cancelAllScheduledFlows(tempEntry)
	if got := sched.EntryCount(); got != 1 {
		t.Errorf("EntryCount after cancelAllScheduledFlows(tempEntry) = %d, want 1 — temp flush is owned by the long entry; tempEntry expiry must not cancel it (ESTABLISHED-bypass regression)", got)
	}
}

// TestUdpAC_RegisterTempAccessFlushEntry_NaturalExpiryAfterFlushDeadline
// fences the timing-preservation guarantee of #2213: the change is
// OWNERSHIP, not timing. The OnExpire hook that drives
// cancelAllScheduledFlows fires from TokenStore.CleanExpired when
// now.After(entry.GetExpireTime()) — i.e. at ExpireTime ==
// absoluteTokenDeadline (FirstKnockTime + openTimeSec + late-packet
// buffer), NOT at firewallDeadline. That OnExpire moment must land
// AFTER the flush deadline computeFlushDeadline(openTimeSec) the handler
// schedules, so OnExpire only ever drains an already-fired scheduler
// entry (idempotent no-op Cancel). The buffer (5s) dominates the flush
// safety margin (50ms) and the sub-ms ε between GenerateAccessToken
// stamping FirstKnockTime and computeFlushDeadline running, so the
// ordering holds with comfortable slack. A regression that shortened the
// owning entry's OpenTime would pull ExpireTime before the flush and
// re-open the ESTABLISHED-bypass.
func TestUdpAC_RegisterTempAccessFlushEntry_NaturalExpiryAfterFlushDeadline(t *testing.T) {
	a, _ := newTempAccessTestAC(t)

	dstAddrs := []*common.NetAddress{{Ip: tempAccessDstIP, Port: tempAccessDstPort}}
	flushEntry := a.registerTempAccessFlushEntry(
		nil,
		&common.AgentUser{UserId: "u-temp-nat"},
		[]*common.NetAddress{{Ip: tempAccessAolIP}},
		dstAddrs,
		tempAccessOpenTimeSec,
	)

	// The handler anchors the flush at computeFlushDeadline(openTimeSec)
	// immediately after registering the entry; reproduce that ordering.
	flushDeadline := computeFlushDeadline(tempAccessOpenTimeSec)

	// ExpireTime (what CleanExpired/OnExpire fire on) must be at/after the
	// flush deadline so the flush always fires first. absoluteTokenDeadline
	// is the immutable formula behind ExpireTime; assert on it directly.
	onExpireMoment := flushEntry.absoluteTokenDeadline()
	if onExpireMoment.Before(flushDeadline) {
		t.Errorf("OnExpire moment (absoluteTokenDeadline) %v is before flushDeadline %v — tokenStore expiry could cancel the temp flush before it fires (timing regression)",
			onExpireMoment, flushDeadline)
	}
	// Slack must be ~the late-packet buffer minus the safety margin (5s -
	// 50ms), give or take the sub-ms stamp ε. Assert a healthy lower bound
	// so a future buffer/margin retune that erases the slack is caught.
	if slack := onExpireMoment.Sub(flushDeadline); slack < 4*time.Second {
		t.Errorf("OnExpire-vs-flush slack = %v, want ≥ 4s (buffer %ds dominates margin %v) — slack erosion risks an early cancel",
			slack, accessTokenLatePacketBufferSeconds, flushSafetyMargin)
	}
}

// TestUdpAC_RegisterTempAccessFlushEntry_OneEntryOwnsAllTuples fences
// the "single entry owns every per-tuple key" contract the temp handlers
// rely on (one flushEntry is hoisted out of the dstAddrs loop and all
// TCP/UDP/ANY/ICMP keys record on it). A single cancelAllScheduledFlows
// on that entry must drain ALL of them — the property that makes an admin
// Cancel terminate the whole flow, not just one tuple. The unit covers
// the multi-tuple ownership wiring that the handlers' au/srcAddrs
// threading exercises only under Linux CI integration.
func TestUdpAC_RegisterTempAccessFlushEntry_OneEntryOwnsAllTuples(t *testing.T) {
	a, sched := newTempAccessTestAC(t)

	dstAddrs := []*common.NetAddress{
		{Ip: tempAccessDstIP, Port: tempAccessDstPort},
		{Ip: "10.0.0.2", Port: 8443},
	}
	flushEntry := a.registerTempAccessFlushEntry(
		nil,
		&common.AgentUser{UserId: "u-temp-nat"},
		[]*common.NetAddress{{Ip: tempAccessAolIP}},
		dstAddrs,
		tempAccessOpenTimeSec,
	)

	deadline := time.Now().Add(time.Hour)
	// Distinct keys spanning the per-tuple shapes the handlers schedule:
	// TCP+port, UDP+port, the port=0 ANY form, and ICMP — all on the one
	// entry, as the handler loop does.
	a.scheduleFlushIfEnabled(flushEntry, tempAccessNatIP, dstAddrs[0].Ip, dstAddrs[0].Port, FlowProtoTCP, deadline)
	a.scheduleFlushIfEnabled(flushEntry, tempAccessNatIP, dstAddrs[1].Ip, dstAddrs[1].Port, FlowProtoUDP, deadline)
	a.scheduleFlushIfEnabled(flushEntry, tempAccessNatIP, dstAddrs[0].Ip, 0, FlowProtoAny, deadline)
	a.scheduleFlushIfEnabled(flushEntry, tempAccessNatIP, dstAddrs[0].Ip, 0, FlowProtoICMP, deadline)
	if got := sched.EntryCount(); got != 4 {
		t.Fatalf("precondition: EntryCount = %d, want 4 (one per distinct FlowKey)", got)
	}

	// One cancel drains every key the entry owns.
	a.cancelAllScheduledFlows(flushEntry)
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after one cancelAllScheduledFlows(flushEntry) = %d, want 0 — a single admin Cancel must terminate ALL tuples the entry owns", got)
	}
}

// TestUdpAC_RegisterTempAccessFlushEntry_NoSchedulerStoresNothing fences
// the disabled-scheduler short-circuit: when EnableL3FlushOnExpiry is off
// (a.expirySched == nil) there is no flush to own and no admin-Cancel
// target, so registerTempAccessFlushEntry must store NOTHING — matching
// the retired orphan path, which stored nothing in either config. A
// regression that minted+stored an entry here would park a useless
// long-lived tokenStore entry per temp flow. The returned nil must also
// be safe to feed to scheduleFlushIfEnabled (no Critical / metric tick),
// since the handlers pass it unconditionally.
func TestUdpAC_RegisterTempAccessFlushEntry_NoSchedulerStoresNothing(t *testing.T) {
	a := &UdpAC{
		tokenStore: common.NewTokenStore[*AccessEntry](),
		// expirySched intentionally nil (feature disabled).
	}

	dstAddrs := []*common.NetAddress{{Ip: tempAccessDstIP, Port: tempAccessDstPort}}
	flushEntry := a.registerTempAccessFlushEntry(
		nil,
		&common.AgentUser{UserId: "u-temp-nat"},
		[]*common.NetAddress{{Ip: tempAccessAolIP}},
		dstAddrs,
		tempAccessOpenTimeSec,
	)

	if flushEntry != nil {
		t.Errorf("registerTempAccessFlushEntry returned non-nil with scheduler disabled — must store nothing (orphan-path parity)")
	}
	if got := a.tokenStore.Size(); got != 0 {
		t.Errorf("tokenStore.Size with scheduler disabled = %d, want 0 — no entry should be parked", got)
	}
	// Feeding the nil entry to scheduleFlushIfEnabled must be a silent
	// no-op (disabled-scheduler short-circuit precedes the nil-entry
	// guard), not a Critical/metric tick.
	a.scheduleFlushIfEnabled(flushEntry, tempAccessNatIP, tempAccessDstIP, tempAccessDstPort, FlowProtoTCP, time.Now().Add(time.Hour))
}

// TestUdpAC_RegisterTempAccessFlushEntry_KeysOnNatIPNotSrcAddrs fences
// the #2205 NAT'd-vs-AOL divergence at the helper boundary the temp
// handlers use: the owning entry carries the AOL-declared SrcAddrs (for
// log/refresh parity), but the scheduled FlowKey must be keyed on the
// kernel-observed (NAT'd) source IP — the address the kernel rule was
// written for — NOT the AOL IP. Keying on SrcAddrs would make the
// flusher's lookup miss the NAT'd kernel rule and the entry would
// survive past timeout (the whole point of #2205).
//
// COVERAGE NOTE: this asserts the contract at the registerTempAccessFlushEntry
// + scheduleFlushIfEnabled seam — it does NOT drive tcp/udpTempAccessHandler
// end-to-end (deriving srcAddrIp from a live conn.RemoteAddr() needs the
// device/crypto/decrypt path, which the package deliberately leaves to the
// Linux smoke suite, #1656; see udp_handler_panic_test.go's preamble for
// the same boundary). The handler-level wiring that au/srcAddrs are threaded
// in and that srcAddrIp == remoteAddr.IP.String() is keyed (not SrcAddrs)
// is tracked for smoke coverage in #1656. This unit locks the half that CAN
// be exercised hermetically: given the NAT'd IP, the key lands on it.
func TestUdpAC_RegisterTempAccessFlushEntry_KeysOnNatIPNotSrcAddrs(t *testing.T) {
	a, _ := newTempAccessTestAC(t)

	// natIP (kernel-observed) deliberately differs from aolIP (declared).
	if tempAccessNatIP == tempAccessAolIP {
		t.Fatalf("test fixture broken: natIP must differ from aolIP to exercise the divergence")
	}

	dstAddrs := []*common.NetAddress{{Ip: tempAccessDstIP, Port: tempAccessDstPort}}
	flushEntry := a.registerTempAccessFlushEntry(
		nil,
		&common.AgentUser{UserId: "u-temp-nat"},
		[]*common.NetAddress{{Ip: tempAccessAolIP}},
		dstAddrs,
		tempAccessOpenTimeSec,
	)

	// The entry carries the AOL-declared source (parity/log shape)...
	if len(flushEntry.SrcAddrs) != 1 || flushEntry.SrcAddrs[0].Ip != tempAccessAolIP {
		t.Fatalf("flushEntry.SrcAddrs = %+v, want the AOL IP %s", flushEntry.SrcAddrs, tempAccessAolIP)
	}

	// ...but the flush is scheduled on the NAT'd IP, exactly as the
	// handler does (srcAddrIp = remoteAddr.IP.String()).
	a.scheduleFlushIfEnabled(flushEntry, tempAccessNatIP, tempAccessDstIP, tempAccessDstPort, FlowProtoTCP, time.Now().Add(time.Hour))

	natKey, err := MakeFlowKey(tempAccessNatIP, tempAccessDstIP, tempAccessDstPort, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(natIP): %v", err)
	}
	aolKey, err := MakeFlowKey(tempAccessAolIP, tempAccessDstIP, tempAccessDstPort, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(aolIP): %v", err)
	}

	if !flushEntry.holdsScheduledKey(natKey) {
		t.Errorf("entry does not hold the NAT'd-IP FlowKey — flush must key on the kernel-observed source (#2205)")
	}
	if flushEntry.holdsScheduledKey(aolKey) {
		t.Errorf("entry holds the AOL-IP FlowKey — flush must NOT key on SrcAddrs (would miss the NAT'd kernel rule, #2205)")
	}
}

// TestAccessEntry_ScheduledKeys_NoRaceDetectorTrip fences the
// AccessEntry.mu discipline: many goroutines concurrently calling
// recordScheduledKey, holdsScheduledKey, and drainScheduledKeys on
// the same entry must not trip the race detector. This is the
// entry.mu correctness fence, decoupled from the scheduler-side
// races (which never occur on the SAME entry pointer in production
// — HandleAccessControl admits one entry in one goroutine; that
// entry's OnExpire fires only after CleanExpired removed it from
// tokenStore, so no concurrent Schedule for that entry can fire).
//
// Cross-entry races on shared FlowKeys are fenced separately by
// TestUdpAC_CancelAllScheduledFlows_MultiSessionRaceKeepsKeyAlive,
// which exercises the sequential Snapshot+holdsScheduledKey
// reschedule logic.
func TestAccessEntry_ScheduledKeys_NoRaceDetectorTrip(t *testing.T) {
	entry := &AccessEntry{}
	const goroutines, iterations = 8, 200

	keys := make([]FlowKey, iterations)
	for i := range keys {
		k, err := MakeFlowKey("1.2.3.4", fmt.Sprintf("10.0.%d.1", i%256), 80, FlowProtoTCP)
		if err != nil {
			t.Fatalf("MakeFlowKey[%d]: %v", i, err)
		}
		keys[i] = k
	}

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)
	for g := 0; g < goroutines; g++ {
		// Recorders.
		go func() {
			defer wg.Done()
			for _, k := range keys {
				entry.recordScheduledKey(k)
			}
		}()
		// Drainers.
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = entry.drainScheduledKeys()
			}
		}()
		// Readers.
		go func() {
			defer wg.Done()
			for _, k := range keys {
				_ = entry.holdsScheduledKey(k)
			}
		}()
	}
	wg.Wait()
	// No assertion on final state — concurrent record/drain interleavings
	// can leave any subset of keys. The race detector is the contract.
}

// TestUdpAC_CancelAllScheduledFlows_RecordBeforeScheduleClosesAdmissionRace fences the
// cross-entry race the record-then-Schedule order in
// scheduleFlushIfEnabled exists to close.
//
// Scenario: T2 is in the middle of HandleUdpACOperations admission.
// Pre-mint stored T2 in tokenStore. T2's HandleAccessControl is
// running per-tuple Schedule calls. After T2 records key K on its
// scheduledKeys (recordScheduledKey runs FIRST in
// scheduleFlushIfEnabled), but BEFORE T2's Scheduler.Schedule call
// completes — the scheduler doesn't yet hold K from T2.
//
// In this exact window, T1's OnExpire fires
// cancelAllScheduledFlows(t1). T1 holds K too (older session, longest-
// wins absorbed). T1 drains {K}. Snapshot sees t2 (pre-stored).
// holdsScheduledKey(t2, K) returns TRUE (record happened first).
// latestOtherFirewallDeadline returns t2's deadline → re-Schedule K
// rather than Cancel.
//
// If the order were Schedule-then-record (the reverse), T2's record
// hasn't happened yet, holdsScheduledKey returns FALSE, T1 Cancels K,
// and T2's coverage is orphaned. This test simulates the partial-
// completion state (record done, Schedule not yet) by manually
// calling recordScheduledKey on T2 before T1's cancel — verifying
// the multi-session reschedule path absorbs the race.
//
// Combined with the inline implementation of record-before-Schedule
// in scheduleFlushIfEnabled (and the pre-store-before-Schedule in
// HandleUdpACOperations), this fences the actual #2201 acceptance
// criterion: T2's L3 coverage survives T1's expiry.
func TestUdpAC_CancelAllScheduledFlows_RecordBeforeScheduleClosesAdmissionRace(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}

	now := time.Now()
	const srcIP, dstIP, dstPort = "1.2.3.4", "10.0.0.1", 80
	key, err := MakeFlowKey(srcIP, dstIP, dstPort, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}

	// T1 is in steady state: in tokenStore, fully scheduled (record +
	// Scheduler.Schedule both done).
	t1 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t1"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       1,
		FirstKnockTime: now.Add(-5 * time.Second),
	}
	a.tokenStore.Store("tok-t1", t1)
	a.scheduleFlushIfEnabled(t1, srcIP, dstIP, dstPort, FlowProtoTCP, now.Add(2*time.Second))

	// T2 is in the admission window: pre-stored in tokenStore (closes
	// the wider admission-window race fixed in HandleUdpACOperations),
	// has called recordScheduledKey on its entry, but has NOT YET
	// completed Scheduler.Schedule. This is the partial-completion
	// state achievable ONLY under record-then-Schedule order.
	t2 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t2"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       60,
		FirstKnockTime: now,
	}
	a.tokenStore.Store("tok-t2", t2)
	t2.recordScheduledKey(key) // record-step of t2's scheduleFlushIfEnabled

	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1 (only T1's Schedule has completed)", got)
	}

	// T1's OnExpire fires NOW (the race window). cancelAllScheduledFlows
	// must detect t2 holds K and re-Schedule rather than Cancel.
	a.cancelAllScheduledFlows(t1)

	if got := sched.EntryCount(); got != 1 {
		t.Errorf("EntryCount after T1 Cancel in admission window = %d, want 1 — T2's coverage orphaned (record-then-Schedule order broken or multi-session reschedule missing)", got)
	}

	// T2 now completes Scheduler.Schedule (no-op via longest-wins
	// absorb since the rescheduled deadline is at or beyond T2's).
	a.expirySched.Schedule(key, now.Add(60*time.Second).Add(flushSafetyMargin))
	if got := sched.EntryCount(); got != 1 {
		t.Errorf("EntryCount after T2 Schedule completes = %d, want 1", got)
	}
}

// TestScheduleFlushIfEnabled_RecordWithoutSchedule_NextCancelNoOps
// fences the documented degradation in scheduleFlushIfEnabled's
// godoc: when the key is recorded on entry.scheduledKeys but
// Scheduler.Schedule never created a scheduler entry (because of
// breaker open, scheduler Shutdown, or a future failure mode), the
// next cancelAllScheduledFlows walks K and Scheduler.Cancel is
// idempotently a no-op (does not panic, does not corrupt scheduler
// state, no metric ticks).
//
// The "record-only" state is simulated by calling recordScheduledKey
// directly without going through scheduleFlushIfEnabled — a direct
// proxy for "Schedule failed after record." We don't actually open
// the breaker (which would require firing flusher errors and racing
// the timer wheel); the simulation captures the same end state more
// reliably.
func TestScheduleFlushIfEnabled_RecordWithoutSchedule_NextCancelNoOps(t *testing.T) {
	sched := NewScheduler(&NoOpFlusher{},
		WithTickInterval(5*time.Millisecond),
		WithWheelSize(100),
	)
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}

	entry := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-breaker"},
		SrcAddrs:       []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs:       []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime:       60,
		FirstKnockTime: time.Now(),
	}

	// Simulate "record completed, Schedule effectively no-op'd"
	// state by calling recordScheduledKey directly without going
	// through scheduleFlushIfEnabled.
	key, err := MakeFlowKey("1.2.3.4", "10.0.0.1", 80, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}
	entry.recordScheduledKey(key)
	if !entry.holdsScheduledKey(key) {
		t.Fatalf("precondition: recordScheduledKey should have added the key")
	}
	if got := sched.EntryCount(); got != 0 {
		t.Fatalf("precondition: scheduler should not hold key (record-only state)")
	}

	// Now Cancel should: drain {K}, walk it, Scheduler.Cancel(K)
	// idempotently no-ops. No panic, no scheduler-state change.
	a.cancelAllScheduledFlows(entry)
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after no-op Cancel = %d, want 0", got)
	}
	// drainScheduledKeys reset the map — confirm entry no longer
	// holds the key, so a future Cancel is a clean no-op too.
	if entry.holdsScheduledKey(key) {
		t.Error("scheduledKeys not drained after cancelAllScheduledFlows")
	}
}

// TestUdpAC_CancelAllScheduledFlows_RecordBeforeScheduleClosesAdmissionRace_Concurrent
// is the goroutine variant of the cross-entry race fence — both T1
// and T2 share FlowKey K and BOTH cycle through schedule + cancel in
// parallel. The race detector exercises the actual interleavings of
// recordScheduledKey, Scheduler.Schedule, drainScheduledKeys, and
// the per-key latestOtherFirewallDeadline walk.
//
// The previous shape of this test stored T1 in tokenStore without
// scheduling on it, so cancelAllScheduledFlows(t1) drained nil and
// short-circuited — never reaching latestOtherFirewallDeadline.
// This variant has both entries actively cycling, so every
// iteration runs the multi-session reschedule path and a regression
// that reorders record/Schedule or skips the snapshot consult would
// trip the race detector and/or the final scheduler-clean assert.
//
// Final assertion: after both goroutines stop cycling and a final
// drain on each entry runs, EntryCount must be 0. A regression that
// orphans the shared scheduler entry leaves a stray.
func TestUdpAC_CancelAllScheduledFlows_RecordBeforeScheduleClosesAdmissionRace_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("goroutine stress test; skipped under -short")
	}
	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(1000))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}

	now := time.Now()
	const srcIP, dstIP, dstPort = "1.2.3.4", "10.0.0.1", 80

	// Both T1 and T2 have live firewall deadlines so each peer
	// shows up as a live candidate in the other's
	// latestOtherFirewallDeadline walk. Both stored in tokenStore so
	// Snapshot returns them.
	t1 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t1"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       60,
		FirstKnockTime: now,
	}
	t2 := &AccessEntry{
		User:           &common.AgentUser{UserId: "u-t2"},
		SrcAddrs:       []*common.NetAddress{{Ip: srcIP}},
		DstAddrs:       []*common.NetAddress{{Ip: dstIP, Port: dstPort}},
		OpenTime:       60,
		FirstKnockTime: now,
	}
	a.tokenStore.Store("tok-t1", t1)
	a.tokenStore.Store("tok-t2", t2)

	cycle := func(e *AccessEntry, iterations int) {
		for i := 0; i < iterations; i++ {
			// Each iteration: record + schedule, then cancel. Mirrors
			// the cycle of admission → expiry happening repeatedly
			// for an entry. Concurrent with the peer's same cycle,
			// each Cancel hits the latestOtherFirewallDeadline path
			// (peer is live + holds the shared K).
			a.scheduleFlushIfEnabled(e, srcIP, dstIP, dstPort, FlowProtoTCP, time.Now().Add(60*time.Second).Add(flushSafetyMargin))
			a.cancelAllScheduledFlows(e)
		}
	}

	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); cycle(t1, iterations) }()
	go func() { defer wg.Done(); cycle(t2, iterations) }()
	wg.Wait()

	// TL;DR: re-Schedule on both entries, then run two manual Cancels
	// that exercise the real reschedule-vs-Cancel choice — this is
	// what makes the final EntryCount assertions load-bearing.
	//
	// Post-cycle quiesced phase: intentionally leave each entry's set
	// populated by Scheduling-without-Cancel ONCE, then assert the
	// final manual cancels actually catch real keys. Without this
	// intentional residue, the cycle goroutines' final iteration
	// would have drained both sets and the final cancels would
	// no-op via early-return — making the EntryCount==0 assertion
	// pass for any state, not just the correct one.
	//
	// With residue: latestOtherFirewallDeadline runs (each entry
	// holds K, peer is live), so the per-key reschedule path
	// executes once per intentional Schedule. The final manual
	// cancels then drain both sets, and the scheduler entries are
	// only released when neither side holds K — testing the real
	// drain + Cancel pair.
	deadline := time.Now().Add(60 * time.Second).Add(flushSafetyMargin)
	a.scheduleFlushIfEnabled(t1, srcIP, dstIP, dstPort, FlowProtoTCP, deadline)
	a.scheduleFlushIfEnabled(t2, srcIP, dstIP, dstPort, FlowProtoTCP, deadline)
	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("post-residue EntryCount = %d, want 1 (both entries scheduled K; longest-wins absorbs)", got)
	}

	a.cancelAllScheduledFlows(t1) // t2 still holds K → reschedule, EntryCount stays 1
	if got := sched.EntryCount(); got != 1 {
		t.Errorf("EntryCount after t1 cancel with t2 still holding = %d, want 1 (multi-session reschedule broken)", got)
	}
	a.cancelAllScheduledFlows(t2) // no other holders → Cancel, EntryCount drops to 0
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after t2 cancel (no other holders) = %d, want 0", got)
	}
}
