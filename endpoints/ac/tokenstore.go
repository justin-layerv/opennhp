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

// AccessEntry represents an access token entry with user and access information.
type AccessEntry struct {
	User       *common.AgentUser
	SrcAddrs   []*common.NetAddress
	DstAddrs   []*common.NetAddress
	OpenTime   int
	ExpireTime time.Time
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
	entry.ExpireTime = time.Now().Add(time.Duration(entry.OpenTime+accessTokenLatePacketBufferSeconds) * time.Second)
	a.tokenStore.Store(token, entry)
	return token
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

// VerifyAccessToken validates a token and extends its expiry time if valid.
// Returns the AccessEntry if found, nil otherwise.
func (a *UdpAC) VerifyAccessToken(token string) *AccessEntry {
	entry, found := a.tokenStore.Load(token)
	if found {
		// Extend expiry time on successful verification
		entry.ExpireTime = entry.ExpireTime.Add(time.Duration(entry.OpenTime) * time.Second)
		// Re-store to commit the updated expiry (ensures thread-safe update)
		a.tokenStore.Store(token, entry)
		return entry
	}
	return nil
}
