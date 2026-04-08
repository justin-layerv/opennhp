package ac

import (
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestACRegistration_HandleRedispatch_RejectsHostnameOnlyDrain is the regression
// test for issue #832.
//
// Root cause: The server's graceful-drain code in endpoints/server/udpserver.go
// constructed an NHP_ARD message with a RedirectTarget that had Hostname set
// but IP empty. The AC's HandleRedispatch validation condition was
// (target.IP == "" && target.Hostname == ""), so a hostname-only target passed
// validation. HandleRedispatch then replaced r.assignedServers with the
// 1-entry hostname-only slice. Downstream consumer code
// (refreshAssignedServerRegistrations, IsServerAddress, log lines) used
// Target.IP as a stable identifier — with IP empty those lookups silently
// failed forever and the AC never recovered.
//
// Existing HandleRedispatch tests only exercise the early error paths and
// recovery mechanisms, not the specific failure mode — this test targets the
// exact shape of the message the buggy server drain emitted.
//
// The regression test must FAIL on main (accepts the hostname-only target,
// corrupts r.assignedServers) and PASS after the RedirectTarget.Validate()
// contract is enforced.
func TestACRegistration_HandleRedispatch_RejectsHostnameOnlyDrain(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		sendMsgCh: make(chan *core.MsgData, 10),
	}

	reg := mustNewACRegistration(t, ac)

	// Pre-populate assignedServers with 3 healthy entries to represent a
	// fully-connected AC at the time the drain ARD arrives.
	original := []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.1",
				Port:         DefaultServerPort,
				PubKeyBase64: "key1",
				AZ:           "us-east-2a",
				ServerID:     "srv-1",
			},
			Connected: true,
		},
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.2",
				Port:         DefaultServerPort,
				PubKeyBase64: "key2",
				AZ:           "us-east-2b",
				ServerID:     "srv-2",
			},
			Connected: true,
		},
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.3",
				Port:         DefaultServerPort,
				PubKeyBase64: "key3",
				AZ:           "us-east-2c",
				ServerID:     "srv-3",
			},
			Connected: true,
		},
	}
	reg.mu.Lock()
	reg.assignedServers = original
	reg.mu.Unlock()

	// Construct the EXACT shape of the ARD message the buggy server drain
	// code emits — hostname populated, IP empty, valid port and pubkey.
	ardMsg := &common.ACRedispatchMsg{
		ErrCode: common.ErrSuccess.ErrorCode(),
		Targets: []common.RedirectTarget{
			{
				Hostname:     "nlb.example.com",
				Port:         62206,
				PubKeyBase64: "c2hhcmVkLWtleQ==", // "shared-key"
				// IP intentionally unset — this is the #832 bug
			},
		},
	}

	// HandleRedispatch MUST reject the drain ARD rather than accept it and
	// corrupt r.assignedServers with a hostname-only entry that downstream
	// consumers can never use. The specific error we expect is the
	// "no valid targets after filtering" path — RedirectTarget.Validate()
	// rejects the hostname-only target, the invalid target is skipped with
	// a warning, and the filter ends up empty.
	err := reg.HandleRedispatch(ardMsg)
	if err == nil {
		t.Fatal("HandleRedispatch accepted hostname-only drain target (#832 regression): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no valid targets") {
		t.Errorf("expected error to mention 'no valid targets', got: %v", err)
	}

	// Verify r.assignedServers was NOT mutated: still 3 entries with their
	// original IPs. Before the fix this slice was corrupted to a 1-entry
	// hostname-only slice (Target.IP == "") and the AC was stuck forever.
	reg.mu.Lock()
	got := reg.assignedServers
	reg.mu.Unlock()

	if len(got) != 3 {
		t.Fatalf("r.assignedServers was mutated: expected 3 entries, got %d", len(got))
	}
	expectedIPs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, server := range got {
		if server.Target.IP != expectedIPs[i] {
			t.Errorf("server[%d].Target.IP = %q, want %q (slice was mutated)",
				i, server.Target.IP, expectedIPs[i])
		}
		if !server.Connected {
			t.Errorf("server[%d].Connected = false, want true (slice was mutated)", i)
		}
	}
}
