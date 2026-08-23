package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/endpoints/internal/acktoken"
	"github.com/OpenNHP/opennhp/nhp/common"
)

// ACTokenEntry is the server-side alias of the shared acktoken.ACTokenEntry.
// The canonical struct, its GetExpireTime method, and the DynamoDB
// marshalers/hasher live in endpoints/internal/acktoken so the AC daemon can
// read the shared store without importing package server. This is a true
// type alias (=), so server.ACTokenEntry and acktoken.ACTokenEntry are the
// same type — common.TokenStore[*ACTokenEntry] and every existing call site
// are unchanged. nhp-server remains the sole WRITER of these entries (it
// stamps the fields the AC cannot derive); see the acktoken.ACTokenEntry
// godoc for the RunID + no-post-store-mutation invariants.
//
// KnockSrcIP source-of-truth (kept on the writer side, since that is where
// the field is stamped): /nhp/internal/token/validate exposes it so a
// downstream FRP login can be cross-checked against the IP that earned the
// pinhole. Trustworthiness varies by write path:
//   - UDP knock (handleNhpOpenResource): the real UDP packet source IP
//     observed by the listener (trustworthy — an adversary cannot spoof
//     without a UDP send-spoof primitive, which doesn't survive the
//     return-path handshake).
//   - Forward receiver (forward.go): forwarder-supplied via fwdMsg.UserAddr,
//     trusted transitively through the forwarder's Noise authentication
//     (forwarders are peers, not arbitrary clients), not from-the-wire
//     verified. A compromised forwarder could put anything here — a strictly
//     broader threat model than the cross-check this field feeds.
type ACTokenEntry = acktoken.ACTokenEntry

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

// NewACKTokenEntry builds an ACTokenEntry for native UDP and forwarded-knock
// ACK construction. The call sites differ only in catalog-token key source and
// the src-IP shape (NetAddress.Ip vs the request's already-parsed string),
// which the caller passes in directly.
//
// ExpireTime is now + (openTime + accessTokenLatePacketBufferSeconds)s so
// a delayed PR-2b validate request still resolves while the AC's pinhole
// is still open. RunID is copied byte-for-byte from the AEAD-authenticated
// knock body; the registered-agent native UDP boundary guarantees that it is
// canonical and nonempty before this constructor can be reached. Legacy/HTTP
// callers retain the empty value. KnockSrcIP feeds the cross-check against the
// FRP login IP.
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
//
// ownerId is the server-resolved tenant identity from the pubkey-bound
// agent registry lookup (`agentPeerLookup.CachedOwnerID(req.PublicKey)`
// on the UDP knock path, populated by `LookupAgentByPubKey` during knock
// validation). Distinct from `knkMsg.OrganizationId`, which carries the
// client-supplied label per the NHP-KNK spec; OrganizationId stays on
// AgentUser unchanged so downstream consumers that expected client-
// supplied semantics keep working. OwnerId is the new server-stamped
// identity field — see `common.AgentUser` docstring for the spec
// rationale. Empty remains valid for legacy entries created before strict
// pubkey-bound ownership was required.
//
// RunID is copied only when AuthServiceId is the registered-agent service.
// Legacy flows remain deliberately unbound even if a generic client supplies
// a syntactically valid runId extension.
func NewACKTokenEntry(
	knkMsg *common.AgentKnockMsg,
	resourceId string,
	acTokens map[string]string,
	srcIp string,
	openTime int,
	ownerId string,
	sessionId uint64,
	sessionExpireTime time.Time,
) *ACTokenEntry {
	if knkMsg == nil || knkMsg.ResourceId == "" || sessionId == 0 || openTime <= 0 || sessionExpireTime.IsZero() {
		return nil
	}
	protectedResourceID := ""
	if knkMsg.AuthServiceId == common.RegisteredAgentAuthServiceID {
		protectedResourceID = knkMsg.ProtectedResourceId
		if !validProtectedResourceID(protectedResourceID) || protectedResourceID == knkMsg.ResourceId {
			return nil
		}
	}
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
	runID := ""
	if knkMsg.AuthServiceId == common.RegisteredAgentAuthServiceID {
		runID = knkMsg.RunID
	}
	return &ACTokenEntry{
		User: &common.AgentUser{
			UserId:         knkMsg.UserId,
			DeviceId:       knkMsg.DeviceId,
			OrganizationId: knkMsg.OrganizationId,
			AuthServiceId:  knkMsg.AuthServiceId,
			OwnerId:        ownerId,
		},
		ResourceId:          resourceId,
		ProtectedResourceId: protectedResourceID,
		ACTokens:            clonedTokens,
		KnockSrcIP:          srcIp,
		RunID:               runID,
		SessionId:           sessionId,
		OpenTime:            openTime,
		SessionExpireTime:   sessionExpireTime,
		ExpireTime:          sessionExpireTime.Add(accessTokenLatePacketBufferSeconds * time.Second),
	}
}

// validProtectedResourceID applies the Connector resource contract's canonical
// P-256 DER SPKI/base64url grammar. A knock/catalog routing key or Connector
// routing ID cannot pass this gate and therefore cannot be misrepresented as
// the public resource subject signed into token-validation responses.
func validProtectedResourceID(value string) bool {
	return conformance.ValidateConnectorResourceLSTV1ResourceID(value) == nil
}

// bindRegisteredAgentProtectedResource copies the public resource identity
// only from the already-resolved server catalog row. The client-authenticated
// AgentKnockMsg.ResourceId remains the distinct KnockResourceID/catalog lookup
// key and is never promoted into authorization metadata.
func bindRegisteredAgentProtectedResource(knkMsg *common.AgentKnockMsg, res *common.ResourceData) error {
	if knkMsg == nil {
		return errors.New("bind protected resource: missing knock")
	}
	knkMsg.ProtectedResourceId = ""
	if knkMsg.AuthServiceId != common.RegisteredAgentAuthServiceID {
		return nil
	}
	if res == nil || !validProtectedResourceID(res.ResourcePublicKeyB64) {
		return errors.New("bind protected resource: resolved catalog public resource id is missing or malformed")
	}
	if res.ResourcePublicKeyB64 == knkMsg.ResourceId {
		return errors.New("bind protected resource: public resource id is cross-wired to knock resource id")
	}
	knkMsg.ProtectedResourceId = res.ResourcePublicKeyB64
	return nil
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
// (PublishACKTokens, which the native UDP handler and forward receiver flow
// through) so PR-2b's
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
func (s *UdpServer) storeACToken(ctx context.Context, token string, entry *ACTokenEntry) error {
	if token == "" {
		return nil
	}
	if s.ackTokenStore != nil {
		if err := s.ackTokenStore.StoreACToken(ctx, token, entry); err != nil {
			s.metrics.IncrCounter(MetricACKTokenSharedStoreWriteFailure)
			return fmt.Errorf("persist ACK token metadata: %w", err)
		}
	}
	s.storeLocalACToken(token, entry)
	return nil
}

func (s *UdpServer) storeLocalACToken(token string, entry *ACTokenEntry) {
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
// ownerId is forwarded into each entry's User.OwnerId so downstream
// consumers of /nhp/internal/token/validate (tunnel-server's tunnel-auth
// plugin) can recover the server-resolved tenant identity without
// trusting client-supplied labels. Callers obtain ownerId from the
// pubkey-bound lookup (e.g., agentPeerLookup.CachedOwnerID(pubKeyB64)
// on the UDP knock path); pass "" when no pubkey-resolved identity is
// available on a legacy path.
//
// When the shared ACK-token store is configured, publication is fail-closed
// for the whole ACK: every non-empty token must persist to the fleet-visible
// store before any local tokenStore entry is installed. That all-or-nothing
// order prevents a knock response from carrying a token that only validates
// on the issuing process and fails when FRPS lands on a peer NHP instance.
// Shared-store publication uses one aggregate DynamoDBOperationTimeout budget
// across the ACK, not one full timeout per token, so a degraded table cannot
// add N*timeout latency to a multi-resource knock before failing closed.
func (s *UdpServer) PublishACKTokens(ctx context.Context, knkMsg *common.AgentKnockMsg, ackMsg *common.ServerKnockAckMsg, srcIp string, openTime int, ownerId string) error {
	if ackMsg == nil || ackMsg.SessionId == 0 {
		return errors.New("persist ACK token metadata: missing NHP session id")
	}
	if openTime <= 0 {
		return errors.New("persist ACK token metadata: invalid open time")
	}
	if knkMsg == nil || knkMsg.NHPSessionIssuedAt.IsZero() {
		return errors.New("persist ACK token metadata: missing NHP session issuance time")
	}
	if knkMsg.NHPSessionId == 0 || ackMsg.SessionId != knkMsg.NHPSessionId {
		return errors.New("persist ACK token metadata: NHP session id mismatch")
	}
	if knkMsg.AuthServiceId == common.RegisteredAgentAuthServiceID &&
		(!validProtectedResourceID(knkMsg.ProtectedResourceId) || knkMsg.ProtectedResourceId == knkMsg.ResourceId) {
		return errors.New("persist ACK token metadata: invalid protected resource binding")
	}
	sessionExpireTime := knkMsg.NHPSessionIssuedAt.Add(time.Duration(openTime) * time.Second)
	if !time.Now().Before(sessionExpireTime) {
		return errors.New("persist ACK token metadata: NHP session expired")
	}
	type ackTokenPublication struct {
		token string
		entry *ACTokenEntry
	}
	publications := make([]ackTokenPublication, 0, len(ackMsg.ACTokens))
	for name, token := range ackMsg.ACTokens {
		if token == "" {
			continue
		}
		publications = append(publications, ackTokenPublication{
			token: token,
			entry: NewACKTokenEntry(knkMsg, name, ackMsg.ACTokens, srcIp, openTime, ownerId, ackMsg.SessionId, sessionExpireTime),
		})
	}
	for _, publication := range publications {
		if publication.entry == nil {
			return errors.New("persist ACK token metadata: invalid token subject")
		}
	}
	if s.ackTokenStore != nil {
		publishCtx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
		defer cancel()
		for _, publication := range publications {
			if err := s.ackTokenStore.StoreACToken(publishCtx, publication.token, publication.entry); err != nil {
				s.metrics.IncrCounter(MetricACKTokenSharedStoreWriteFailure)
				s.metrics.IncrCounter(MetricKnockPinholeOrphaned)
				// Do not best-effort delete any prior rows from this ACK:
				// the agent never receives these opaque tokens, entries are
				// TTL-bounded, and cleanup writes during a DDB fault add a
				// second failure mode to the fail-closed path.
				return fmt.Errorf("persist ACK token metadata: %w", err)
			}
		}
	}
	for _, publication := range publications {
		s.storeLocalACToken(publication.token, publication.entry)
	}
	return nil
}
