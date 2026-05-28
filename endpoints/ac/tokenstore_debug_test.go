//go:build nhp_debug

package ac

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestAccessEntry_Debug_StoreUnderTwoTokens_Panics fences the actual
// failure mode #2214 exists to catch: a future *AccessEntry
// pool/reuse refactor stores the same pointer under two tokens, and
// latestOtherFirewallDeadline's `other == self` self-skip silently
// degrades — keeping scheduler entries alive past their genuine
// firewall deadlines (a silent security regression, not a panic).
//
// The mechanism-level test lives in
// nhp/common/tokenstore_debug_test.go with *fakeEntry; this test is
// the AccessEntry-typed positive case the issue body asks for so
// the regression-catcher is exercised against the real type whose
// invariant is at stake.
func TestAccessEntry_Debug_StoreUnderTwoTokens_Panics(t *testing.T) {
	ts := common.NewTokenStore[*AccessEntry]()
	entry := &AccessEntry{
		User:       &common.AgentUser{UserId: "u-1"},
		OpenTime:   60,
		ExpireTime: time.Now().Add(time.Hour),
	}
	ts.Store("AAAAtoken1", entry)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("Store of same *AccessEntry under second token did not panic; #2214 fence regressed")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "#2214") {
			t.Fatalf("panic message did not carry the #2214 anchor; got: %s", msg)
		}
	}()
	ts.Store("BBBBtoken2", entry)
}

// TestAccessEntry_Debug_DistinctPointersSameFields_NoPanic fences
// the negative side: the real production code path
// (HandleUdpACOperations allocates a fresh &AccessEntry{} per
// admission) stores byte-identical entries under different tokens
// every time the same agent re-knocks. That MUST NOT trip the
// assertion — only pointer reuse does.
func TestAccessEntry_Debug_DistinctPointersSameFields_NoPanic(t *testing.T) {
	ts := common.NewTokenStore[*AccessEntry]()
	user := &common.AgentUser{UserId: "u-1"}
	expire := time.Now().Add(time.Hour)

	ts.Store("AAAAtoken1", &AccessEntry{User: user, OpenTime: 60, ExpireTime: expire})
	ts.Store("BBBBtoken2", &AccessEntry{User: user, OpenTime: 60, ExpireTime: expire})
}
