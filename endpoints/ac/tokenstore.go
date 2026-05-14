package ac

import (
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// accessTokenLatePacketBufferSeconds extends AC token retention beyond
// AccessEntry.OpenTime to handle requests that arrive after the AC has
// already torn down the iptables/ipset entry but before the client knows
// to re-knock.
//
// The value lives in nhp/common so the AC and server cannot drift —
// see common.AccessTokenLatePacketBufferSeconds for the full rationale
// (including the asymmetry: server-issued tokens keep strict OpenTime
// retention, while ACK-path entries on the server side DO extend by
// the same buffer so a delayed /nhp/internal/token/validate request
// still resolves while the AC would still accept a packet).
const accessTokenLatePacketBufferSeconds = common.AccessTokenLatePacketBufferSeconds

// AccessEntry represents an access token entry. FirstKnockTime anchors
// the absolute-deadline cap (#1942). The `json:"-"` tag is a STRUCTURAL
// fence only — it blocks a future serialization path from exposing the
// raw field as a top-level JSON key. It does NOT close the timing-leak
// angle: post-first-refresh `ExpireTime == FirstKnockTime + OpenTime +
// buffer` exactly, so `FirstKnockTime` is recoverable to nanosecond
// precision from the JSON shape regardless of the tag. Response-shape
// mitigation (slim DTO that drops ExpireTime + User + SrcAddrs) is
// tracked in #1959.
type AccessEntry struct {
	User           *common.AgentUser
	SrcAddrs       []*common.NetAddress
	DstAddrs       []*common.NetAddress
	OpenTime       int
	FirstKnockTime time.Time `json:"-"`
	ExpireTime     time.Time
}

// GetExpireTime implements the common.TokenEntry interface.
func (e *AccessEntry) GetExpireTime() time.Time {
	return e.ExpireTime
}

// GenerateAccessToken creates a new access token for the given entry. The
// token is opaque random bytes (see common.GenerateOpaqueToken) — not a hash
// of metadata. This closes nhp#1124: the prior SHA-256-over-public-inputs
// construction was offline-grindable given any timing signal.
//
// Token retention is OpenTime + accessTokenLatePacketBufferSeconds.
func (a *UdpAC) GenerateAccessToken(entry *AccessEntry) string {
	token := common.GenerateOpaqueToken()
	now := time.Now()
	entry.FirstKnockTime = now
	entry.ExpireTime = now.Add(time.Duration(entry.OpenTime+accessTokenLatePacketBufferSeconds) * time.Second)
	a.tokenStore.Store(token, entry)
	return token
}

// absoluteTokenDeadline returns the latest moment the token may validate:
// FirstKnockTime + OpenTime + buffer. Includes the late-packet buffer.
//
// FirstKnockTime carries time.Now()'s monotonic reading; Add / time.Until
// preserve it, so NTP step-backs and wall-clock skew cannot extend the
// cap. A future change that serializes the entry through Redis / disk
// would strip the monotonic component — re-anchor on Unix epoch then.
func (e *AccessEntry) absoluteTokenDeadline() time.Time {
	return e.FirstKnockTime.Add(time.Duration(e.OpenTime+accessTokenLatePacketBufferSeconds) * time.Second)
}

// RemainingFirewallSeconds returns seconds left until the AC firewall
// must close: FirstKnockTime + OpenTime, NO buffer. 0 = deadline passed;
// caller must refuse to re-open rather than call HandleAccessControl
// with a no-op timeout.
//
// Edge case: a return value of CloseWindowOpenTimeSec (1) trips
// HandleAccessControl's tempset-collapse branch (msghandler.go:152-158).
// On the /refresh path that branch is reached via PASS_KNOCKIP_WITH_RANGE
// (msghandler.go:336-417), so the adjacent-IP-range tempset entries
// also collapse to a 1s window — the desired behavior at this
// remainder. Issue #1962 tracks breaking the coupling by widening
// the dead zone to (0, 2)s.
func (e *AccessEntry) RemainingFirewallSeconds() int {
	deadline := e.FirstKnockTime.Add(time.Duration(e.OpenTime) * time.Second)
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	// Truncate-toward-zero (not Round): favors earlier firewall close.
	return int(remaining.Seconds())
}

// IssueACTokenIfSuccess populates artMsg.ACToken with a freshly issued
// token iff artMsg's ErrCode is the explicit success code. On success
// it overwrites any existing artMsg.ACToken without checking; on
// non-success it leaves artMsg untouched. Issuing a token for a failed
// operation would do nothing useful (the agent path discards it in
// processACOperationBroadcast at endpoints/server/udpserver.go:2127),
// but post-nhp#1124 the token IS the entire auth secret, so storing
// one in tokenStore + emitting it to the server (where %+v error logs
// at udpserver.go:1862 / :2150 would serialize it in plaintext) is a
// real exposure.
//
// The gate intentionally uses the strict equality check (not
// common.IsSuccessErrCode) so it stays aligned with the server's
// failure-log predicate at udpserver.go:1861. The two predicates differ
// on the empty-string case: IsSuccessErrCode treats "" as success, but
// the server-side log treats "" as failure and would still leak the
// token. Several bare-return paths in HandleAccessControl (e.g. the
// EBPFXDP EbpfRuleAdd failure at msghandler.go:478, the unsupported
// FilterMode default branch at msghandler.go:482) leave ErrCode == ""
// with err != nil — those must NOT mint a token.
//
// Open thread: forward.go:387 still uses IsSuccessErrCode and so will
// build a "success" ackMsg with an empty ACToken on the same bare-return
// paths the gate suppresses. Functionally safe (the empty token fails
// httpac.go:190's len-check) but produces a confusing user-visible
// failure mode. Tracked for cleanup in #1422 (preferred fix: route the
// bare returns through setArtMsgError so ErrCode is always populated).
func (a *UdpAC) IssueACTokenIfSuccess(artMsg *common.ACOpsResultMsg, entry *AccessEntry) {
	if artMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		return
	}
	artMsg.ACToken = a.GenerateAccessToken(entry)
}

// VerifyAccessToken validates a token and extends its expiry time if
// valid. Sliding extension is capped at absoluteTokenDeadline (#1942).
//
// Concurrent verifies write ExpireTime without a per-entry lock; the
// tokenStore mutex protects the map, not the struct fields. This is a
// genuine Go memory-model data race — `go test -race` could surface it
// — not just a logical race. It's pre-existing and unrelated to the
// #1942 cap. Lost updates are benign at the value level because every
// write is bounded by the same immutable deadline, but a future
// contributor should NOT treat the comment as a claim that the race
// is race-detector-safe. CleanExpired (nhp/common/tokenstore.go)
// reading ExpireTime concurrently is the torn-read counterpart; in
// the worst case it removes a still-valid entry one cleanup cycle
// early — acceptable because the firewall close is the actual
// security boundary, not the tokenStore retention.
func (a *UdpAC) VerifyAccessToken(token string) *AccessEntry {
	entry, found := a.tokenStore.Load(token)
	if !found {
		return nil
	}
	deadline := entry.absoluteTokenDeadline()
	// Use !Before (not After) so the exact-instant t==deadline is rejected.
	// A "simplification" to After() silently widens the cap by a nanosecond;
	// TestVerifyAccessToken_AbsoluteDeadlineCap fences the cap value but
	// not this comparator choice.
	if !time.Now().Before(deadline) {
		return nil
	}
	// Slide ExpireTime forward by OpenTime, capped at the absolute deadline.
	// Under current constants (ExpireTime initialized to deadline at issue
	// time, buffer > 0) the slide ALWAYS overshoots and the clamp ALWAYS
	// fires — so this is functionally equivalent to `entry.ExpireTime =
	// deadline`. Kept as slide-then-clamp for clarity (the call site reads
	// as a sliding window that's just been capped, which matches the
	// design narrative) and to remain correct under a future constant
	// flip (e.g., buffer = 0 or ExpireTime initialized to OpenTime only).
	newExpire := entry.ExpireTime.Add(time.Duration(entry.OpenTime) * time.Second)
	if newExpire.After(deadline) {
		newExpire = deadline
	}
	entry.ExpireTime = newExpire
	a.tokenStore.Store(token, entry)
	return entry
}
