package server

import (
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ACTokenEntry represents a server access token entry with user and AC token information.
type ACTokenEntry struct {
	User       *common.AgentUser
	ResourceId string
	ACTokens   map[string]string
	OpenTime   int
	ExpireTime time.Time
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

// VerifyAccessToken validates a token.
// Returns the ACTokenEntry if found, nil otherwise.
// Note: Unlike AC, server does not extend expiry on verify.
func (s *UdpServer) VerifyAccessToken(token string) *ACTokenEntry {
	entry, found := s.tokenStore.Load(token)
	if found {
		return entry
	}
	return nil
}
