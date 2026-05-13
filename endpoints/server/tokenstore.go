package server

import (
	"maps"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ACTokenEntry represents a server access token entry with user and AC token information.
//
// KnockSrcIP is the IP the agent knocked from. PR-2b's
// /nhp/internal/token/validate exposes this so a downstream FRP login can
// be cross-checked against the IP that earned the pinhole.
//
// Source-of-truth varies by code path:
//   - UDP knock (handleNhpOpenResource): the real UDP packet source IP
//     observed by the listener (trustworthy — adversary cannot spoof
//     without a UDP send-spoof primitive, which doesn't survive the
//     return-path handshake).
//   - HTTP knock (handleHttpOpenResource): ctx.ClientIP() under gin's
//     SetTrustedProxies configuration (see httpserver.go). Production
//     either trusts a CIDR list (NHP_TRUSTED_PROXY_CIDRS, e.g.
//     CloudFront origin) or trusts nobody, in which case ClientIP
//     returns the TCP RemoteAddr — both trustworthy. X-Forwarded-For
//     from an untrusted hop is ignored.
//   - Forward receiver (forward.go): forwarder-supplied via
//     fwdMsg.UserAddr. Trusted transitively through the forwarder's
//     Noise authentication (forwarders are peers, not arbitrary
//     clients), not from-the-wire verified. A compromised forwarder
//     could put anything here; that's a strictly broader threat model
//     than the cross-check this field feeds.
//
// RunID is the agent's run-scope identifier (nullable; populated by PR-2c
// via the agent registration path). Backwards-compat: legacy ACK paths
// that do not carry a RunID write the empty string here.
type ACTokenEntry struct {
	User       *common.AgentUser
	ResourceId string
	ACTokens   map[string]string
	KnockSrcIP string
	RunID      string
	OpenTime   int
	ExpireTime time.Time
}

// accessTokenLatePacketBufferSeconds matches the AC's identically-named
// constant in endpoints/ac/tokenstore.go. The value lives in nhp/common
// so the AC and server cannot drift — see
// common.AccessTokenLatePacketBufferSeconds for the rationale
// (late-arrival packet handling between AC tear-down and client re-knock).
//
// Tokens issued via GenerateAccessToken keep strict OpenTime retention —
// the buffer applies only to entries written via the ACK path
// (NewACKTokenEntry), which are what the AC then validates packets
// against.
const accessTokenLatePacketBufferSeconds = common.AccessTokenLatePacketBufferSeconds

// NewACKTokenEntry builds an ACTokenEntry for the ACK-construction path
// (UDP knock, HTTP knock, forward receiver). The three call sites differ
// only in resource-id source (knkMsg.ResourceId vs the loop name) and
// the src-IP shape (NetAddress.Ip vs the request's already-parsed string),
// which the caller passes in directly.
//
// ExpireTime is now + (openTime + accessTokenLatePacketBufferSeconds)s so
// a delayed PR-2b validate request still resolves while the AC's pinhole
// is still open. RunID is not yet wired (PR-2c) and stays the empty
// string here; KnockSrcIP feeds the cross-check against the FRP login IP.
//
// acTokens is shallow-copied with maps.Clone so each entry holds its
// own snapshot. The local-knock paths (PublishACKTokens) only call
// this after acWg.Wait(), so the source map is no longer being
// mutated — but a defensive copy isolates entries from any future
// post-publish mutation of ackMsg.ACTokens and frees the eventual
// PR-2b reader from depending on the implicit "no concurrent writes
// after publish" contract. The map is small (one entry per resource
// the agent knocked, typically 1–3) and the copy happens on a slow
// path (per-knock, not per-packet).
func NewACKTokenEntry(
	knkMsg *common.AgentKnockMsg,
	resourceId string,
	acTokens map[string]string,
	srcIp string,
	openTime int,
) *ACTokenEntry {
	// maps.Clone returns nil for a nil input; normalize to an empty map
	// so PR-2b's reader (and any future caller) never has to handle a
	// nil-vs-empty distinction on stored entries. The branch only fires
	// for callers that passed nil — the local-knock path always
	// initializes ackMsg.ACTokens before this is reached, so the cost
	// is one comparison on a slow path.
	clonedTokens := maps.Clone(acTokens)
	if clonedTokens == nil {
		clonedTokens = map[string]string{}
	}
	return &ACTokenEntry{
		User: &common.AgentUser{
			UserId:         knkMsg.UserId,
			DeviceId:       knkMsg.DeviceId,
			OrganizationId: knkMsg.OrganizationId,
			AuthServiceId:  knkMsg.AuthServiceId,
		},
		ResourceId: resourceId,
		ACTokens:   clonedTokens,
		KnockSrcIP: srcIp,
		OpenTime:   openTime,
		ExpireTime: time.Now().Add(time.Duration(openTime+accessTokenLatePacketBufferSeconds) * time.Second),
	}
}

// GetExpireTime implements the common.TokenEntry interface.
func (e *ACTokenEntry) GetExpireTime() time.Time {
	return e.ExpireTime
}

// GenerateAccessToken issues an opaque random access token for the given
// entry, stores the entry under that token, and returns the token.
//
// The token is opaque random bytes (see common.GenerateOpaqueToken) — not a
// hash of metadata. This closes nhp#1124: the prior SHA-256-over-public-inputs
// construction was offline-grindable given any timing signal.
//
// Token retention is exactly OpenTime — the server is the issuer, not the
// gate, so it has no equivalent of the AC's accessTokenLatePacketBufferSeconds.
func (s *UdpServer) GenerateAccessToken(entry *ACTokenEntry) string {
	token := common.GenerateOpaqueToken()
	entry.ExpireTime = time.Now().Add(time.Duration(entry.OpenTime) * time.Second)
	s.tokenStore.Store(token, entry)
	return token
}

// VerifyAccessToken validates a token at the moment of the call. Returns
// the ACTokenEntry if the token exists in the store AND its ExpireTime
// is still in the future, nil otherwise.
//
// Expiry is checked here, not deferred to CleanExpired's periodic sweep.
// CleanExpired runs every TokenStoreRefreshInterval seconds (10s; see
// nhp/common/constants.go), so a token whose ExpireTime is in the past
// can sit in the store for up to that interval before being reaped.
// PR-2b's /nhp/internal/token/validate calls this method and must NOT
// resolve such an entry — the AC's pinhole (sized by OpenTime + the
// shared late-packet buffer) has already torn down, and approving a
// post-pinhole token would let an FRP login through to an AC that
// would drop the traffic.
//
// Two responsibilities, intentionally split:
//   - Point-in-time validity: this method (caller observes "is the
//     token usable right now?").
//   - Memory reclamation: tokenStore.CleanExpired (sweep that frees
//     map slots back to the runtime).
//
// Note: Unlike AC, server does not extend expiry on verify.
func (s *UdpServer) VerifyAccessToken(token string) *ACTokenEntry {
	entry, found := s.tokenStore.Load(token)
	if !found {
		return nil
	}
	if time.Now().After(entry.ExpireTime) {
		return nil
	}
	return entry
}

// storeACToken persists the given ACTokenEntry under token in the server
// tokenStore. Package-private chokepoint for the ACK-construction path
// (PublishACKTokens, which the local UDP/HTTP knock handlers and the
// forward receiver all flow through) so PR-2b's
// /nhp/internal/token/validate can resolve AC-issued tokens.
//
// Empty tokens are silently ignored at the top — guarded here rather
// than relying on common.TokenStore.Store's empty-key semantics, so a
// future in-package caller can't accidentally bypass the
// MetricACTokenStored increment by working around an underlying
// contract this method nominally owns.
//
// Unexported on purpose. Callers outside the server package must reach
// this through PublishACKTokens (which owns the NewACKTokenEntry +
// maps.Clone snapshot dance). Exporting would let a future caller hand
// in an *ACTokenEntry they still hold a reference to, defeating the
// snapshot isolation PR-2b's reader depends on.
//
// metrics.Publisher.IncrCounter is nil-safe (see
// endpoints/metrics/publisher.go), so no s.metrics nil-guard is needed
// here — matching the unguarded posture in ac_pubkey_cap_gate.go and
// license_pubkey_gate.go. Test fixtures that construct UdpServer
// without metrics rely on that nil-safety.
//
// Token-space disjointness: the tokenStore is a flat map keyed on the
// token string. Server-issued tokens (GenerateAccessToken) and
// AC-issued tokens (this method) share the same keyspace. Both come
// from common.GenerateOpaqueToken — 256 bits of crypto/rand entropy
// each — so the collision floor is well below any practical concern.
// A future change to either issuer's format that shortens the entropy
// budget or introduces structure (e.g. an embedded customer ID prefix)
// must keep the keyspace disjoint or this method silently overwrites.
func (s *UdpServer) storeACToken(token string, entry *ACTokenEntry) {
	if token == "" {
		return
	}
	s.tokenStore.Store(token, entry)
	s.metrics.IncrCounter(MetricACTokenStored)
}

// PublishACKTokens persists every AC token recorded in ackMsg.ACTokens.
// The local-knock handlers (UDP, HTTP) must call this AFTER acWg.Wait()
// returns — once the AC goroutines have completed, ackMsg.ACTokens is
// no longer being mutated and iteration here is race-free with the
// writers. The forward receiver is single-goroutine (one resource per
// forward) and is unaffected — it calls PublishACKTokens with the same
// shape so the chokepoint (storeACToken) and the maps.Clone snapshot
// from NewACKTokenEntry apply uniformly.
//
// Publishing from inside the AC goroutine (as PR-2a's first cut did)
// raced: iteration of ackMsg.ACTokens overlapped sibling goroutines'
// writes to the same map under artMsgsMutex, and PR-2b's reader would
// see the write/read race per the Go memory model. NewACKTokenEntry's
// maps.Clone additionally isolates stored entries from any future
// post-publish mutation of ackMsg.ACTokens (defense in depth).
//
// openTime is loop-invariant in both local-knock handlers (it's computed
// from res.OpenTime and knkMsg.HeaderType, which are call-scoped), so
// the caller hoists it above the resource loop and passes the shared
// value here.
func (s *UdpServer) PublishACKTokens(knkMsg *common.AgentKnockMsg, ackMsg *common.ServerKnockAckMsg, srcIp string, openTime int) {
	for name, token := range ackMsg.ACTokens {
		if token == "" {
			continue
		}
		s.storeACToken(token, NewACKTokenEntry(knkMsg, name, ackMsg.ACTokens, srcIp, openTime))
	}
}
