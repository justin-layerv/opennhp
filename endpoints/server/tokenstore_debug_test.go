//go:build nhp_debug

package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestACTokenEntry_Debug_StoreUnderTwoTokens_Panics is the server-side
// symmetric of endpoints/ac.TestAccessEntry_Debug_StoreUnderTwoTokens_Panics:
// the pointer-uniqueness fence at common.TokenStore.Store (#2214) must
// trip on the server's *ACTokenEntry instantiation too. The fence lives
// in nhp/common and runs for every TokenStore[E] caller; this fences
// the second production pointer-typed instantiation so a future
// server-side pool/reuse refactor that aliases *ACTokenEntry across
// tokens is caught in CI before merge.
func TestACTokenEntry_Debug_StoreUnderTwoTokens_Panics(t *testing.T) {
	ts := common.NewTokenStore[*ACTokenEntry]()
	entry := &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u-1"},
		ResourceId: "res-1",
		OpenTime:   60,
		ExpireTime: time.Now().Add(time.Hour),
	}
	ts.Store("AAAAtoken1", entry)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("Store of same *ACTokenEntry under second token did not panic; #2214 fence regressed")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "#2214") {
			t.Fatalf("panic message did not carry the #2214 anchor; got: %s", msg)
		}
	}()
	ts.Store("BBBBtoken2", entry)
}

// TestACTokenEntry_Debug_DistinctPointersSameFields_NoPanic fences the
// negative side: NewACKTokenEntry allocates a fresh *ACTokenEntry per
// (token, resource) pair (see PublishACKTokens), so byte-identical
// entries under different tokens are the steady state. That MUST NOT
// trip the assertion.
func TestACTokenEntry_Debug_DistinctPointersSameFields_NoPanic(t *testing.T) {
	ts := common.NewTokenStore[*ACTokenEntry]()
	user := &common.AgentUser{UserId: "u-1"}
	expire := time.Now().Add(time.Hour)

	ts.Store("AAAAtoken1", &ACTokenEntry{User: user, ResourceId: "res-1", OpenTime: 60, ExpireTime: expire})
	ts.Store("BBBBtoken2", &ACTokenEntry{User: user, ResourceId: "res-1", OpenTime: 60, ExpireTime: expire})
}
