package agent

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestPreAccessPathsRejectNilKnockUser(t *testing.T) {
	a := &UdpAgent{}

	if err := a.preAccessRequest(&common.ServerKnockAckMsg{}); !errors.Is(err, common.ErrKnockUserNotSpecified) {
		t.Fatalf("preAccessRequest() error = %v, want %v", err, common.ErrKnockUserNotSpecified)
	}
	if err := a.processPreAccessAction(&common.PreAccessInfo{}); !errors.Is(err, common.ErrKnockUserNotSpecified) {
		t.Fatalf("processPreAccessAction() error = %v, want %v", err, common.ErrKnockUserNotSpecified)
	}
}

func TestSetKnockUserInitializesNilState(t *testing.T) {
	a := &UdpAgent{}
	a.SetKnockUser("user", "org", map[string]any{"role": "tester"})
	a.SetDeviceId("device")
	a.SetCheckResults(map[string]any{"posture": "ok"})

	state := a.snapshotKnockUserState()
	if state.user.UserId != "user" || state.user.OrganizationId != "org" || state.deviceID != "device" {
		t.Fatalf("snapshotKnockUserState() = %+v, want initialized user/org/device", state)
	}
	if got := state.user.UserData["role"]; got != "tester" {
		t.Fatalf("snapshot user data role = %v, want tester", got)
	}
	if got := state.checkResults["posture"]; got != "ok" {
		t.Fatalf("snapshot check result posture = %v, want ok", got)
	}
}

// TestKnockUserStateConcurrentAccess fences the DHP/request-path lock gap: all
// user, device, and check-result reads must flow through one mutex-consistent
// snapshot while the public setters replace that state concurrently.
func TestKnockUserStateConcurrentAccess(t *testing.T) {
	a := &UdpAgent{}
	target := &KnockTarget{}

	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range iterations {
			a.SetKnockUser(fmt.Sprintf("user-%d", i), fmt.Sprintf("org-%d", i), map[string]any{"iteration": i})
			a.SetDeviceId(fmt.Sprintf("device-%d", i))
			a.SetCheckResults(map[string]any{"iteration": i})
		}
	}()
	go func() {
		defer wg.Done()
		for range iterations {
			_ = a.snapshotKnockUserState()
			_ = a.buildAgentKnockMsg(target, 0)
			// No server is configured, so KnockDHP returns after resolving the
			// snapshotted user ID and never touches the WASM/device paths.
			_, _ = a.KnockDHP()
		}
	}()
	wg.Wait()
}
