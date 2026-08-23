package server

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func mustStoreACToken(t *testing.T, s *UdpServer, token string, entry *ACTokenEntry) {
	t.Helper()
	if err := s.storeACToken(context.Background(), token, entry); err != nil {
		t.Fatalf("storeACToken(%q): %v", token, err)
	}
}

func mustPublishACKTokens(t *testing.T, s *UdpServer, knkMsg *common.AgentKnockMsg, ackMsg *common.ServerKnockAckMsg, srcIp string, openTime int, ownerId string) {
	t.Helper()
	if knkMsg.NHPSessionIssuedAt.IsZero() {
		knkMsg.NHPSessionIssuedAt = time.Now()
	}
	if knkMsg.NHPSessionId == 0 {
		knkMsg.NHPSessionId = ackMsg.SessionId
	}
	if err := s.PublishACKTokens(context.Background(), knkMsg, ackMsg, srcIp, openTime, ownerId); err != nil {
		t.Fatalf("PublishACKTokens: %v", err)
	}
}

// TestGenerateAccessToken_Uniqueness asserts that 10_000 server tokens
// issued for the same User + ResourceId are all unique and round-trip
// through VerifyAccessToken. Token generation must not depend on entry
// metadata; setting only tokenStore here is deliberate — adding a
// config field would mask a future regression that re-introduces
// metadata into the token derivation.
func TestGenerateAccessToken_Uniqueness(t *testing.T) {
	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
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
		entry := &ACTokenEntry{User: user, ResourceId: "r-1", OpenTime: 60}
		token := s.GenerateAccessToken(entry)
		if _, dup := seen[token]; dup {
			t.Fatalf("collision after %d tokens: %q", i, token)
		}
		seen[token] = struct{}{}

		got := s.VerifyAccessToken(token)
		if got != entry {
			t.Fatalf("VerifyAccessToken did not return the issued entry for token %d", i)
		}
		if got.User != user {
			t.Fatalf("VerifyAccessToken returned an entry with the wrong User pointer for token %d", i)
		}
	}
}

// TestStoreACToken_RoundTrip fences PR-2a's load-bearing invariant: a
// token written to the store via the ACK-construction path
// (storeACToken) must be resolvable via VerifyAccessToken. Before
// PR-2a, ACK construction wrote
// ackMsg.ACTokens[name] = artMsg.ACToken without any corresponding
// store call — every token issued via the ACK path returned nil from
// VerifyAccessToken, which made PR-2b's /nhp/internal/token/validate
// a black hole. Deleting this test means the store-on-issue contract
// is no longer checked at unit level.
func TestStoreACToken_RoundTrip(t *testing.T) {
	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}

	user := &common.AgentUser{
		UserId:         "user-1",
		DeviceId:       "device-1",
		OrganizationId: "org-1",
		AuthServiceId:  "asp-1",
	}
	entry := &ACTokenEntry{
		User:       user,
		ResourceId: "r-1",
		ACTokens:   map[string]string{"r-1": "ac-token-abc"},
		KnockSrcIP: "203.0.113.7",
		RunID:      "run-xyz",
		OpenTime:   60,
		ExpireTime: time.Now().Add(65 * time.Second),
	}

	mustStoreACToken(t, s, "ac-token-abc", entry)

	got := s.VerifyAccessToken("ac-token-abc")
	if got == nil {
		t.Fatal("VerifyAccessToken returned nil for a stored ACK-path token; before PR-2a this was the bug — every ACK-path token was unverifiable")
	}
	if got != entry {
		t.Fatal("VerifyAccessToken did not return the same entry pointer that storeACToken wrote")
	}
	if got.KnockSrcIP != "203.0.113.7" {
		t.Errorf("KnockSrcIP not preserved through round-trip: got %q want %q", got.KnockSrcIP, "203.0.113.7")
	}
	if got.RunID != "run-xyz" {
		t.Errorf("RunID not preserved through round-trip: got %q want %q", got.RunID, "run-xyz")
	}
}

// TestStoreACToken_RunIDDefaultEmpty fences the intentional legacy/HTTP
// contract on RunID: callers outside the registered-agent native UDP path may
// still store the empty string, and the entry must round-trip cleanly.
func TestStoreACToken_RunIDDefaultEmpty(t *testing.T) {
	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}

	entry := &ACTokenEntry{
		ResourceId: "r-1",
		KnockSrcIP: "198.51.100.4",
		OpenTime:   30,
		ExpireTime: time.Now().Add(35 * time.Second),
		// RunID intentionally left as zero value
	}
	mustStoreACToken(t, s, "tok-no-runid", entry)

	got := s.VerifyAccessToken("tok-no-runid")
	if got == nil {
		t.Fatal("VerifyAccessToken returned nil for an entry with empty RunID")
	}
	if got.RunID != "" {
		t.Errorf("RunID expected to round-trip as empty string, got %q", got.RunID)
	}
}

// TestStoreACToken_ExpiresAfterOpenTimePlusBuffer fences the +5s
// late-packet buffer the three ACK-construction sites apply when
// they call storeACToken with `ExpireTime: now + (OpenTime + 5)s`.
// The +5s mirrors the AC's accessTokenLatePacketBufferSeconds: the
// server-side entry must outlive the AC's pinhole so a delayed
// validate request still resolves.
//
// VerifyAccessToken now consults ExpireTime directly so an expired
// entry returns nil even before CleanExpired's periodic sweep removes
// it — the sweep runs every TokenStoreRefreshInterval seconds (10s),
// and without this check a token could sit ~10s past ExpireTime and
// still resolve, letting an FRP login through to an AC whose pinhole
// has already torn down. ExpireTime is set in the past so the boundary
// is observed deterministically without sleeping.
func TestStoreACToken_ExpiresAfterOpenTimePlusBuffer(t *testing.T) {
	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}

	// Construct an entry the way the ACK sites do: ExpireTime is now
	// + (OpenTime + accessTokenLatePacketBufferSeconds) seconds. To
	// avoid a real sleep, set ExpireTime in the past — the
	// post-expiry state is the same as if (OpenTime + 5s) had elapsed.
	openTime := 30
	entry := &ACTokenEntry{
		ResourceId: "r-1",
		KnockSrcIP: "192.0.2.10",
		OpenTime:   openTime,
		ExpireTime: time.Now().Add(-time.Second), // already past
	}
	mustStoreACToken(t, s, "tok-expired", entry)

	// Pre-sweep: VerifyAccessToken must return nil for the expired
	// entry. This is the load-bearing property — PR-2b's
	// /nhp/internal/token/validate calls this method, and without the
	// expiry check it would approve a token whose AC pinhole has
	// already been torn down.
	if got := s.VerifyAccessToken("tok-expired"); got != nil {
		t.Fatal("VerifyAccessToken returned an expired entry before the sweep ran; the point-in-time validity check is broken")
	}

	// CleanExpired still has work to do — the entry is reachable via
	// the raw Load until the sweep reaps it. See
	// TestVerifyAccessToken_ExpiryDoesNotEvict for the dedicated fence
	// on the responsibility split (point-in-time validity vs. memory
	// reclamation).
	removed := s.tokenStore.CleanExpired()
	if removed != 1 {
		t.Fatalf("expected CleanExpired to remove 1 entry, got %d", removed)
	}

	if got := s.VerifyAccessToken("tok-expired"); got != nil {
		t.Fatal("VerifyAccessToken should return nil after the entry expired and was swept")
	}
}

// TestVerifyAccessToken_ExpiryDoesNotEvict fences the responsibility
// split introduced when VerifyAccessToken started consulting
// ExpireTime: the method returns nil for an expired entry, but does
// NOT remove it from the store. Memory reclamation stays with
// CleanExpired so the sweep counter (and any future
// MetricTokenStoreSize gauge) reflects the actual store population,
// not the read-rate of expired tokens.
//
// A future regression that "fixes" the split by deleting the entry on
// expired-Load would silently break the sweep accounting (CleanExpired
// would see fewer entries to remove than were written) and any
// observability built on the store size.
func TestVerifyAccessToken_ExpiryDoesNotEvict(t *testing.T) {
	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}

	entry := &ACTokenEntry{
		ResourceId: "r-1",
		OpenTime:   30,
		ExpireTime: time.Now().Add(-time.Second), // already past
	}
	mustStoreACToken(t, s, "tok-expired-load", entry)

	// Point-in-time validity: nil.
	if got := s.VerifyAccessToken("tok-expired-load"); got != nil {
		t.Fatal("VerifyAccessToken should return nil for an expired entry")
	}

	// Raw Load still sees the entry — CleanExpired hasn't run yet.
	got, found := s.tokenStore.Load("tok-expired-load")
	if !found {
		t.Fatal("tokenStore.Load should still return the expired entry pre-sweep; VerifyAccessToken must not evict")
	}
	if got != entry {
		t.Fatal("tokenStore.Load returned a different entry pointer than was stored")
	}

	// CleanExpired is what reclaims the slot.
	if removed := s.tokenStore.CleanExpired(); removed != 1 {
		t.Fatalf("expected CleanExpired to remove 1 entry, got %d", removed)
	}
	if _, found := s.tokenStore.Load("tok-expired-load"); found {
		t.Fatal("tokenStore.Load should return not-found after CleanExpired ran")
	}
}

// TestStoreACToken_BufferConstantMatchesAC pins the asymmetry
// documented in endpoints/ac/tokenstore.go: server-side ACK entries
// extend by exactly accessTokenLatePacketBufferSeconds (5s), not 0
// and not the AC's full OpenTime. The constant is now sourced from
// nhp/common, so both AC and server consume the same symbol — this
// test fences the local server alias against the shared source AND
// pins the shared value itself, so a future edit on either side
// fails this test (and its AC-side twin in
// endpoints/ac/tokenstore_test.go).
func TestStoreACToken_BufferConstantMatchesAC(t *testing.T) {
	if accessTokenLatePacketBufferSeconds != common.AccessTokenLatePacketBufferSeconds {
		t.Fatalf("server accessTokenLatePacketBufferSeconds drifted from common: got %d, want %d", accessTokenLatePacketBufferSeconds, common.AccessTokenLatePacketBufferSeconds)
	}
	if common.AccessTokenLatePacketBufferSeconds != 5 {
		t.Fatalf("common.AccessTokenLatePacketBufferSeconds drift: got %d, want 5 (AC and server both consume this — see endpoints/ac/tokenstore.go and NewACKTokenEntry)", common.AccessTokenLatePacketBufferSeconds)
	}
}

// TestNewACKTokenEntry_ProducesShapeAllACKSitesShare fences the
// shape contract every ACK site relies on. Native UDP and forwarded-knock
// publication both flow through
// PublishACKTokens, which in turn calls NewACKTokenEntry per token.
//
// Adding direct tests at all three sites would require driving the
// full HandleKnockRequest / HandleForwardRequest paths (which need
// real cipher state). Testing the helper instead covers them
// transitively: a regression in NewACKTokenEntry's mapping (e.g.,
// AuthServiceId stops flowing through, or ExpireTime drops the +5s
// buffer) breaks every call site identically and fails this test.
//
// Specifically pins:
//   - All four AgentUser fields (UserId, DeviceId, OrganizationId,
//     AuthServiceId) flow from knkMsg into entry.User (PR-2b's
//     validate response shape consumes UserId + OrganizationId).
//   - ResourceId comes from the explicit caller arg, not knkMsg.
//     (udpserver/httpserver pass per-resource loop var `name`,
//     forward passes knkMsg.ResourceId; the asymmetry is intentional
//     and the helper preserves it.)
//   - KnockSrcIP is the caller's parsed IP, not anything from knkMsg
//     (the wire knock has no source-IP field — it's recovered from
//     the UDP packet at the call site).
//   - ACTokens map is shallow-copied via maps.Clone (defensive
//     isolation; callers may mutate the source map post-publish
//     without corrupting stored entries).
//   - OpenTime is the caller's int conversion of the resource's
//     openTime (uint32 truncation is the caller's problem).
//   - SessionExpireTime is the caller-computed session deadline and
//     ExpireTime is exactly five seconds later for late token resolution.
//   - RunID is copied exactly from a registered-agent authenticated knock body.
func TestNewACKTokenEntry_ProducesShapeAllACKSitesShare(t *testing.T) {
	knkMsg := &common.AgentKnockMsg{
		UserId:              "user-1",
		DeviceId:            "device-2",
		OrganizationId:      "org-3",
		AuthServiceId:       common.RegisteredAgentAuthServiceID,
		ResourceId:          "wire-resource", // intentionally distinct from caller arg
		ProtectedResourceId: testProtectedResourceID,
		RunID:               "0123456789abcdef",
	}
	acTokens := map[string]string{"r-1": "ac-tok-abc"}

	const openTime = 60
	sessionExpireTime := time.Now().Add(openTime * time.Second)
	entry := NewACKTokenEntry(knkMsg, "r-1", acTokens, "203.0.113.7", openTime, "", 1, sessionExpireTime)

	if entry == nil {
		t.Fatal("NewACKTokenEntry returned nil")
	}
	if entry.User == nil {
		t.Fatal("entry.User is nil")
	}

	// User-field mapping — fences PR-2b's validate response contract.
	if entry.User.UserId != "user-1" {
		t.Errorf("User.UserId = %q, want %q", entry.User.UserId, "user-1")
	}
	if entry.User.DeviceId != "device-2" {
		t.Errorf("User.DeviceId = %q, want %q", entry.User.DeviceId, "device-2")
	}
	if entry.User.OrganizationId != "org-3" {
		t.Errorf("User.OrganizationId = %q, want %q", entry.User.OrganizationId, "org-3")
	}
	if entry.User.AuthServiceId != common.RegisteredAgentAuthServiceID {
		t.Errorf("User.AuthServiceId = %q, want %q", entry.User.AuthServiceId, common.RegisteredAgentAuthServiceID)
	}

	// ResourceId comes from caller arg, NOT knkMsg.ResourceId.
	// udpserver/httpserver pass the per-resource loop var; forward
	// happens to pass knkMsg.ResourceId. Helper preserves the
	// caller's choice.
	if entry.ResourceId != "r-1" {
		t.Errorf("ResourceId = %q, want %q (must come from caller arg, not knkMsg.ResourceId %q)",
			entry.ResourceId, "r-1", knkMsg.ResourceId)
	}
	if entry.ProtectedResourceId != testProtectedResourceID {
		t.Errorf("ProtectedResourceId = %q, want resolved public subject %q (knock key is %q, catalog token key is %q)", entry.ProtectedResourceId, testProtectedResourceID, knkMsg.ResourceId, entry.ResourceId)
	}

	// ACTokens plumbed (snapshot via maps.Clone — entries are
	// isolated from post-publish mutation of the source map).
	if got := entry.ACTokens["r-1"]; got != "ac-tok-abc" {
		t.Errorf("ACTokens[r-1] = %q, want %q", got, "ac-tok-abc")
	}
	// Isolation fence: mutating the caller's map after construction
	// must NOT alter the stored entry's ACTokens. A regression that
	// drops the maps.Clone (or aliases the field) silently re-opens
	// the cross-mutex aliasing the helper exists to defend against.
	acTokens["fence-key"] = "fence-value"
	if _, leaked := entry.ACTokens["fence-key"]; leaked {
		t.Error("entry.ACTokens shares the caller's map (lost maps.Clone defense — PR-2b would see post-publish mutations)")
	}

	if entry.KnockSrcIP != "203.0.113.7" {
		t.Errorf("KnockSrcIP = %q, want %q", entry.KnockSrcIP, "203.0.113.7")
	}
	if entry.OpenTime != openTime {
		t.Errorf("OpenTime = %d, want %d", entry.OpenTime, openTime)
	}

	if !entry.SessionExpireTime.Equal(sessionExpireTime) {
		t.Errorf("SessionExpireTime = %v, want %v", entry.SessionExpireTime, sessionExpireTime)
	}
	wantTokenExpiry := sessionExpireTime.Add(accessTokenLatePacketBufferSeconds * time.Second)
	if !entry.ExpireTime.Equal(wantTokenExpiry) {
		t.Errorf("ExpireTime = %v, want %v", entry.ExpireTime, wantTokenExpiry)
	}

	if entry.RunID != knkMsg.RunID {
		t.Errorf("RunID = %q, want authenticated knock RunID %q", entry.RunID, knkMsg.RunID)
	}
}

func TestNewACKTokenEntry_LegacySuppliedRunIDStaysUnbound(t *testing.T) {
	entry := NewACKTokenEntry(&common.AgentKnockMsg{
		AuthServiceId: "legacy",
		ResourceId:    "public-resource",
		RunID:         "0123456789abcdef",
	}, "resource", map[string]string{"resource": "token"}, "203.0.113.7", 60, "", 1, time.Now().Add(time.Minute))
	if entry.RunID != "" {
		t.Fatalf("legacy entry.RunID = %q, want empty", entry.RunID)
	}
}

// TestNewACKTokenEntry_OwnerIdPropagates pins the spec-compliant
// identity-propagation contract: ownerId passed by the caller
// lands on entry.User.OwnerId (NOT on entry.User.OrganizationId,
// which carries the client-supplied label per the NHP-KNK spec).
//
// Per CSA Stealth Mode SDP §"NHP Workflow", the
// NHP-Server's pubkey-based authentication is the authoritative
// identity signal; OwnerId surfaces that resolution through the
// ACK-path so downstream consumers (e.g. the tunnel-auth plugin
// in qurl-reverse-tunnel-server) can authorize without re-resolving
// from potentially-spoofable client labels.
//
// Three cases:
//  1. Non-empty ownerId → User.OwnerId == that string.
//     OrganizationId stays untouched (client-supplied value).
//  2. Empty ownerId → User.OwnerId == "". Mirrors legacy entries where
//     pubkey-resolved identity is unavailable.
//     Downstream consumers MUST treat empty as "identity not
//     resolved at this hop."
//  3. ownerId and knkMsg.OrganizationId differ → both land
//     independently. Cross-contamination would silently degrade
//     either the server-resolved or the client-supplied value.
func TestNewACKTokenEntry_OwnerIdPropagates(t *testing.T) {
	knkMsg := &common.AgentKnockMsg{
		UserId:         "agent-1",
		DeviceId:       "device-1",
		OrganizationId: "client-supplied-org", // per NHP-KNK spec, client-supplied label
		AuthServiceId:  "asp",
		ResourceId:     "r-1",
	}

	t.Run("non-empty ownerId lands on User.OwnerId", func(t *testing.T) {
		entry := NewACKTokenEntry(knkMsg, "r-1", map[string]string{"r-1": "tok"}, "203.0.113.7", 60, "owner-from-pubkey-lookup", 1, time.Now().Add(time.Minute))
		if entry.User == nil {
			t.Fatal("entry.User is nil")
		}
		if entry.User.OwnerId != "owner-from-pubkey-lookup" {
			t.Errorf("User.OwnerId = %q, want %q", entry.User.OwnerId, "owner-from-pubkey-lookup")
		}
		// Client-supplied OrganizationId must stay untouched —
		// they're semantically distinct fields (client claim vs
		// server-resolved tenant identity).
		if entry.User.OrganizationId != "client-supplied-org" {
			t.Errorf("OrganizationId clobbered: got %q, want %q", entry.User.OrganizationId, "client-supplied-org")
		}
	})

	t.Run("empty ownerId surfaces as empty User.OwnerId", func(t *testing.T) {
		entry := NewACKTokenEntry(knkMsg, "r-1", map[string]string{"r-1": "tok"}, "203.0.113.7", 60, "", 1, time.Now().Add(time.Minute))
		if entry.User.OwnerId != "" {
			t.Errorf("User.OwnerId = %q, want \"\" (empty marks identity-not-resolved-at-this-hop)", entry.User.OwnerId)
		}
	})

	t.Run("ownerId and OrganizationId are independent", func(t *testing.T) {
		entry := NewACKTokenEntry(knkMsg, "r-1", map[string]string{"r-1": "tok"}, "203.0.113.7", 60, "different-owner", 1, time.Now().Add(time.Minute))
		// Pin both fields to explicit values, not just !=. A swap-bug
		// (OwnerId populated from knkMsg.OrganizationId and vice-versa)
		// would still produce two different strings — only explicit
		// per-field assertions catch the swap.
		if entry.User.OwnerId != "different-owner" {
			t.Errorf("User.OwnerId = %q, want %q (server-resolved ownerId param must populate User.OwnerId)",
				entry.User.OwnerId, "different-owner")
		}
		if entry.User.OrganizationId != "client-supplied-org" {
			t.Errorf("User.OrganizationId = %q, want %q (client-supplied knkMsg.OrganizationId must populate User.OrganizationId untouched)",
				entry.User.OrganizationId, "client-supplied-org")
		}
	})
}

func TestNewACKTokenEntry_ZeroOpenTime(t *testing.T) {
	knkMsg := &common.AgentKnockMsg{UserId: "u", ResourceId: "public-resource"}
	if entry := NewACKTokenEntry(knkMsg, "r", nil, "127.0.0.1", 0, "", 1, time.Now()); entry != nil {
		t.Fatalf("NewACKTokenEntry with zero open time = %+v, want nil", entry)
	}
}

func TestNewACKTokenEntry_RejectsInvalidSession(t *testing.T) {
	knkMsg := &common.AgentKnockMsg{UserId: "u", ResourceId: "public-resource"}
	if entry := NewACKTokenEntry(knkMsg, "r", nil, "127.0.0.1", 60, "", 0, time.Now().Add(time.Minute)); entry != nil {
		t.Fatalf("NewACKTokenEntry with zero session id = %+v, want nil", entry)
	}
	if entry := NewACKTokenEntry(knkMsg, "r", nil, "127.0.0.1", 60, "", 1, time.Time{}); entry != nil {
		t.Fatalf("NewACKTokenEntry with zero session deadline = %+v, want nil", entry)
	}
}

func TestNewACKTokenEntry_RejectsMissingProtectedResource(t *testing.T) {
	if entry := NewACKTokenEntry(nil, "q_catalog", nil, "127.0.0.1", 60, "", 1, time.Now().Add(time.Minute)); entry != nil {
		t.Fatalf("NewACKTokenEntry with nil knock = %+v, want nil", entry)
	}
	if entry := NewACKTokenEntry(&common.AgentKnockMsg{AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "connector-knock-1"}, "q_catalog", nil, "127.0.0.1", 60, "", 1, time.Now().Add(time.Minute)); entry != nil {
		t.Fatalf("NewACKTokenEntry with missing protected resource = %+v, want nil", entry)
	}
	if entry := NewACKTokenEntry(&common.AgentKnockMsg{AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "connector-knock-1", ProtectedResourceId: "malformed"}, "q_catalog", nil, "127.0.0.1", 60, "", 1, time.Now().Add(time.Minute)); entry != nil {
		t.Fatalf("NewACKTokenEntry with malformed protected resource = %+v, want nil", entry)
	}
	if entry := NewACKTokenEntry(&common.AgentKnockMsg{AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: testProtectedResourceID, ProtectedResourceId: testProtectedResourceID}, "q_catalog", nil, "127.0.0.1", 60, "", 1, time.Now().Add(time.Minute)); entry != nil {
		t.Fatalf("NewACKTokenEntry with cross-wired knock/public resource = %+v, want nil", entry)
	}
	legacy := NewACKTokenEntry(&common.AgentKnockMsg{AuthServiceId: "legacy", ResourceId: "legacy-catalog-key"}, "q_catalog", nil, "127.0.0.1", 60, "", 1, time.Now().Add(time.Minute))
	if legacy == nil || legacy.ProtectedResourceId != "" {
		t.Fatalf("generic entry = %+v, want stored without a public protected-resource assertion", legacy)
	}
}

func TestPublishACKTokens_RejectsInvalidLifetime(t *testing.T) {
	s := &UdpServer{tokenStore: common.NewTokenStore[*ACTokenEntry]()}
	validKnock := func() *common.AgentKnockMsg {
		return &common.AgentKnockMsg{UserId: "u", AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "connector-knock-1", ProtectedResourceId: testProtectedResourceID, NHPSessionId: 123, NHPSessionIssuedAt: time.Now()}
	}
	validACK := func() *common.ServerKnockAckMsg {
		return &common.ServerKnockAckMsg{SessionId: 123, ACTokens: map[string]string{"r": "token"}}
	}
	tests := map[string]struct {
		knock    *common.AgentKnockMsg
		ack      *common.ServerKnockAckMsg
		openTime int
	}{
		"missing session id":         {knock: validKnock(), ack: &common.ServerKnockAckMsg{ACTokens: map[string]string{"r": "token"}}, openTime: 60},
		"mismatched session id":      {knock: validKnock(), ack: &common.ServerKnockAckMsg{SessionId: 456, ACTokens: map[string]string{"r": "token"}}, openTime: 60},
		"zero open time":             {knock: validKnock(), ack: validACK(), openTime: 0},
		"negative open time":         {knock: validKnock(), ack: validACK(), openTime: -1},
		"missing issuance time":      {knock: &common.AgentKnockMsg{UserId: "u", AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "connector-knock-1", ProtectedResourceId: testProtectedResourceID, NHPSessionId: 123}, ack: validACK(), openTime: 60},
		"missing protected resource": {knock: &common.AgentKnockMsg{UserId: "u", AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "connector-knock-1", NHPSessionId: 123, NHPSessionIssuedAt: time.Now()}, ack: validACK(), openTime: 60},
		"expired session lifetime":   {knock: &common.AgentKnockMsg{UserId: "u", AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "connector-knock-1", ProtectedResourceId: testProtectedResourceID, NHPSessionId: 123, NHPSessionIssuedAt: time.Now().Add(-time.Minute)}, ack: validACK(), openTime: 30},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := s.PublishACKTokens(context.Background(), test.knock, test.ack, "203.0.113.5", test.openTime, "owner"); err == nil {
				t.Fatal("PublishACKTokens accepted invalid lifetime")
			}
			if got := s.VerifyAccessToken("token"); got != nil {
				t.Fatalf("invalid publication persisted token: %+v", got)
			}
		})
	}
}

// TestPublishACKTokens_PersistsAfterWait fences the load-bearing
// invariant Option A of PR-2a's concurrency fix introduced: the native UDP
// knock handler must publish AC-issued tokens to tokenStore
// AFTER acWg.Wait() returns, not from inside an AC goroutine. Before
// the fix the publication happened while sibling goroutines for other
// resources were still mutating ackMsg.ACTokens under artMsgsMutex, so
// PR-2b's /nhp/internal/token/validate could race the writers.
// NewACKTokenEntry's maps.Clone now also isolates stored entries from
// any future post-publish mutation (defense in depth). Driving the
// full handleNhpOpenResource handler from a unit test requires real cipher
// state; this test fences the post-Wait
// publication property directly on the helper instead.
//
// Specifically pins:
//   - Every non-empty entry in ackMsg.ACTokens becomes a tokenStore
//     entry resolvable via VerifyAccessToken.
//   - Empty tokens are skipped (matches tokenStore.Store semantics
//     and the artMsg.ACToken=="" defensive layer at the call sites).
//   - The shared openTime (loop-invariant in both handlers) flows
//     through to every entry's OpenTime.
//   - The KnockSrcIP and User fields land identically on every entry
//     for the same call (only ResourceId differs per entry).
//
// Deleting this test means the post-Wait publication contract is no
// longer checked at unit level.
func TestPublishACKTokens_PersistsAfterWait(t *testing.T) {
	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}

	knkMsg := &common.AgentKnockMsg{
		UserId:         "u-1",
		DeviceId:       "d-1",
		OrganizationId: "o-1",
		AuthServiceId:  "asp-1",
		ResourceId:     "public-resource",
	}
	ackMsg := &common.ServerKnockAckMsg{
		SessionId: 1,
		ACTokens: map[string]string{
			"resource-a": "ac-token-a",
			"resource-b": "ac-token-b",
			"resource-c": "", // empty must be skipped (e.g., AC suppressed via IssueACTokenIfSuccess)
		},
	}

	mustPublishACKTokens(t, s, knkMsg, ackMsg, "203.0.113.42", 60, "")

	entryA := s.VerifyAccessToken("ac-token-a")
	if entryA == nil {
		t.Fatal("PublishACKTokens did not persist ac-token-a; the post-Wait publication contract is broken")
	}
	if entryA.ResourceId != "resource-a" {
		t.Errorf("entryA.ResourceId = %q, want %q", entryA.ResourceId, "resource-a")
	}
	if entryA.ProtectedResourceId != "" {
		t.Errorf("entryA.ProtectedResourceId = %q, want no public-resource assertion for generic auth service", entryA.ProtectedResourceId)
	}
	if entryA.KnockSrcIP != "203.0.113.42" {
		t.Errorf("entryA.KnockSrcIP = %q, want %q", entryA.KnockSrcIP, "203.0.113.42")
	}
	if entryA.OpenTime != 60 {
		t.Errorf("entryA.OpenTime = %d, want %d", entryA.OpenTime, 60)
	}
	if entryA.User == nil || entryA.User.UserId != "u-1" {
		t.Errorf("entryA.User = %+v, want UserId=u-1", entryA.User)
	}

	entryB := s.VerifyAccessToken("ac-token-b")
	if entryB == nil {
		t.Fatal("PublishACKTokens did not persist ac-token-b")
	}
	if entryB.ResourceId != "resource-b" {
		t.Errorf("entryB.ResourceId = %q, want %q", entryB.ResourceId, "resource-b")
	}
	if !entryA.SessionExpireTime.Equal(entryB.SessionExpireTime) {
		t.Fatalf("multi-resource session deadlines differ: %v != %v", entryA.SessionExpireTime, entryB.SessionExpireTime)
	}

	// Empty-token case: VerifyAccessToken on "" must return nil.
	if got := s.VerifyAccessToken(""); got != nil {
		t.Fatalf("PublishACKTokens persisted an empty-token entry; want skip, got %+v", got)
	}

	// Stored entries must be isolated from post-publish mutation of
	// ackMsg.ACTokens. The helper-shape test fences the maps.Clone
	// at the NewACKTokenEntry level; this confirms PublishACKTokens
	// preserves the isolation through to tokenStore so PR-2b's
	// reader can rely on the entry surviving any future mutation
	// of the source ackMsg by the call sites.
	ackMsg.ACTokens["fence"] = "post-publish-mutation"
	if _, leaked := entryA.ACTokens["fence"]; leaked {
		t.Error("entryA observed post-publish mutation of ackMsg.ACTokens (lost maps.Clone isolation)")
	}
	if _, leaked := entryB.ACTokens["fence"]; leaked {
		t.Error("entryB observed post-publish mutation of ackMsg.ACTokens (lost maps.Clone isolation)")
	}
}

// TestPublishACKTokens_PersistsEveryNonEmptyToken_AtFanInScale
// fences the production shape of the native UDP knock handler:
// many AC goroutines mutate ackMsg.ACTokens under artMsgsMutex in
// parallel, the handler calls acWg.Wait(), then PublishACKTokens
// runs once. The property under test is "every non-empty token gets
// persisted"; the 32-resource fan-in is just the setup that exercises
// it under realistic write contention.
//
// This is a positive fence on the safe shape, not a regression test
// for the inverse: it will pass under -race even if a future
// regression moves PublishACKTokens back inside the AC goroutine,
// because that buggy interleaving is not constructed here. The
// actual fence against the race is structural — PublishACKTokens is
// called from a single goroutine after Wait() in three known sites,
// covered by TestHandleNhpOpenResource_PublishACKTokens_RoundTrip
// (UDP) and TestHandleHttpOpenResource_PublishACKTokens_RoundTrip
// (HTTP), so a future PR that drops the call from either handler
// will fail those tests.
func TestPublishACKTokens_PersistsEveryNonEmptyToken_AtFanInScale(t *testing.T) {
	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}
	knkMsg := &common.AgentKnockMsg{UserId: "u-multi", ResourceId: "public-resource-multi"}
	ackMsg := &common.ServerKnockAckMsg{
		SessionId: 1,
		ACTokens:  make(map[string]string),
	}

	const resourceCount = 32
	resName := func(i int) string { return "r-" + strconv.Itoa(i) }
	acTok := func(i int) string { return "ac-tok-" + strconv.Itoa(i) }

	var wg sync.WaitGroup
	var mu sync.Mutex // mirrors artMsgsMutex's role in the production handlers
	for i := 0; i < resourceCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock()
			ackMsg.ACTokens[resName(i)] = acTok(i)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// All writers complete before publish runs — this is the production
	// shape after Option A. PublishACKTokens iterates the map without
	// holding mu because there are no concurrent writers.
	mustPublishACKTokens(t, s, knkMsg, ackMsg, "198.51.100.1", 30, "")

	for i := 0; i < resourceCount; i++ {
		entry := s.VerifyAccessToken(acTok(i))
		if entry == nil {
			t.Fatalf("PublishACKTokens missed token for resource %d", i)
		}
		if entry.ResourceId != resName(i) {
			t.Errorf("entry[%d].ResourceId = %q, want %q", i, entry.ResourceId, resName(i))
		}
	}
}
