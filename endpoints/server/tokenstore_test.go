package server

import (
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

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
