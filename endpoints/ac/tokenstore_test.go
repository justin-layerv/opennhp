package ac

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

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

// TestIssueACTokenIfSuccess_GatesOnErrCode fences the threat-model fix:
// post-nhp#1124 the access token is the entire auth secret, so a token
// issued alongside ErrCode != success would only ever appear in leaky
// %+v error logs on the server (endpoints/server/udpserver.go:1862,
// :2150). The gate must use STRICT success-code equality, not the more
// permissive common.IsSuccessErrCode (which treats empty string as
// success) — bare-return paths in HandleAccessControl can leave ErrCode
// == "" with err != nil, and the server's leak logger treats those as
// failures. Issuing a token under those conditions would re-open the
// exact path the gate exists to close.
func TestIssueACTokenIfSuccess_GatesOnErrCode(t *testing.T) {
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
			description: "empty ErrCode is the bare-return / err-set-but-no-errcode case from HandleAccessControl (e.g. EBPFXDP EbpfRuleAdd failure at msghandler.go:478) — server's leak logger treats it as failure, gate must too",
		},
		{
			name:        "explicit_success_code_issues",
			errCode:     common.ErrSuccess.ErrorCode(),
			wantIssued:  true,
			description: "the only ErrCode value that should mint a token",
		},
		{
			name:        "failure_code_no_token",
			errCode:     "5001",
			wantIssued:  false,
			description: "any explicit non-success code suppresses issuance",
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

			a.IssueACTokenIfSuccess(artMsg, entry)

			if tc.wantIssued {
				if artMsg.ACToken == "" {
					t.Fatalf("%s: expected ACToken to be populated", tc.description)
				}
				if got := a.VerifyAccessToken(artMsg.ACToken); got != entry {
					t.Fatalf("%s: token did not round-trip through tokenStore", tc.description)
				}
			} else {
				if artMsg.ACToken != "" {
					t.Fatalf("%s: expected ACToken to stay empty, got %q", tc.description, artMsg.ACToken)
				}
				if a.tokenStore.Size() != 0 {
					t.Fatalf("%s: expected tokenStore to stay empty, got size %d", tc.description, a.tokenStore.Size())
				}
			}
		})
	}
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
