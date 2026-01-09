package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

// GenerateAccessToken creates a new access token for the given entry.
func (s *UdpServer) GenerateAccessToken(entry *ACTokenEntry) string {
	var tsBytes [8]byte
	currTime := time.Now().UnixNano()

	hash := sha256.New()
	binary.BigEndian.PutUint64(tsBytes[:], uint64(currTime))
	au := entry.User
	hash.Write([]byte(s.config.Hostname + au.UserId + au.DeviceId + au.OrganizationId + au.AuthServiceId))
	hash.Write(tsBytes[:])
	token := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	hash.Reset()

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
