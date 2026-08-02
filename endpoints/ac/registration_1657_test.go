package ac

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// testPubKeyBase64 is base64(0x00..0x1f) — a structurally valid
// 32-byte pubkey shape used uniformly across all #1657 test fixtures.
const testPubKeyBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// TODO(#1672): once metrics.Publisher exposes a counter reader, fence
// the "stopped" failure-metric increment in register's receive case
// here directly. The classifyResponseError test below covers the
// dispatch logic; the IncrCounterWithDims call path itself is still
// uncovered by automated regression tests.

// TestACRegistration_HandleRedispatch_RejectsAfterStop fences the
// use-after-stop window in #1657. Without the gate, an NHP_ARD
// goroutine scheduled before Stop could re-enter HandleRedispatch
// during teardown, mutate r.assignedServers, and spawn connectToServer
// goroutines after the manager was supposed to be done. The narrow
// in-flight TOCTOU (caller passes the gate while Stop's first
// instructions are running) is covered transitively by
// connectToServer's IsRunning check and the stopCh selects in its
// downstream blocking ops; a direct race fence on that seam is
// deferred to issue #1670, which also tracks the pre-existing
// Peer-field race surfaced when driving the TOCTOU under -race.
//
// TODO(#1670): once the connectToServer peer-leak and AssignedServer.Peer
// race ship a structural fix, add TestACRegistration_HandleRedispatch_RaceWithStop
// here to fence the in-flight TOCTOU seam (#1657's other half).
func TestACRegistration_HandleRedispatch_RejectsAfterStop(t *testing.T) {
	reg := newStoppedTestRegistration(t)

	ardMsg := &common.ACRedispatchMsg{
		Targets: []common.RedirectTarget{
			{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: testPubKeyBase64},
		},
	}

	err := reg.HandleRedispatch(ardMsg)
	if !errors.Is(err, ErrRegistrationStopped) {
		t.Fatalf("HandleRedispatch err = %v, want ErrRegistrationStopped", err)
	}
}

// TestACRegistration_HandleRegistrationResponse_NHPARDPropagatesSentinel
// fences two regression classes for the NHP_ARD branch of
// handleRegistrationResponse:
//  1. Removal of the gate at HandleRedispatch entry — the test
//     drives a stopped manager and expects ErrRegistrationStopped to
//     surface end-to-end.
//  2. Non-%w wrapping of the sentinel (e.g., a refactor that
//     switches to fmt.Errorf("%v", err) or errors.New(err.Error())) —
//     breaks errors.Is at every caller. (%w-style wrapping is fine,
//     since it preserves errors.Is.)
func TestACRegistration_HandleRegistrationResponse_NHPARDPropagatesSentinel(t *testing.T) {
	reg := newStoppedTestRegistration(t)

	ardMsg := common.ACRedispatchMsg{
		Targets: []common.RedirectTarget{
			{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: testPubKeyBase64},
		},
	}
	body, err := json.Marshal(ardMsg)
	if err != nil {
		t.Fatalf("marshal ardMsg: %v", err)
	}

	// Hostname is intentionally empty so SendAddr/ResolveHost skips a
	// real DNS lookup and falls back to Ip.
	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: testPubKeyBase64,
		Type:         core.NHP_SERVER,
	}
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_ARD,
		BodyMessage: body,
	}

	got := reg.handleRegistrationResponse(ppd, registrationPeer)
	if !errors.Is(got, ErrRegistrationStopped) {
		t.Fatalf("handleRegistrationResponse err = %v, want errors.Is(ErrRegistrationStopped)", got)
	}
}

// TestACRegistration_HandleRegistrationResponse_NHPAAKPropagatesSentinel
// fences the parallel wrapping invariant on the NHP_AAK + peer-list
// branch — a future refactor that wraps the sentinel with fmt.Errorf
// would break errors.Is at every caller. The NHP_ARD branch's
// parallel test would stay green on this regression, so this fence
// stands on its own.
//
// Scope note: this only fences sentinel preservation. The cr round 6
// invariant (don't record success on ErrRegistrationStopped) is
// orthogonal — a regression that dropped the early return and still
// returned the sentinel would pass this assertion. Adding a metric
// recorder for that fence would need an exported reader on the
// metrics.Publisher; deferred.
//
// Precondition chain to reach the gate (any future hardening that
// fails fast before HandleRedispatch should add its own stop-check
// rather than rely on this fence):
//  1. aakMsg.ErrCode passes IsSuccessErrCode.
//  2. aakMsg.Registered is true.
//  3. aakMsg.ServerAddr/ServerPubKey absent → falls back to registrationPeer.
//  4. registrationPeer.SendAddr() resolves (Hostname empty + valid Ip).
//  5. len(aakMsg.Peers) > 0 reaches the HandleRedispatch call.
func TestACRegistration_HandleRegistrationResponse_NHPAAKPropagatesSentinel(t *testing.T) {
	reg := newStoppedTestRegistration(t)

	aakMsg := common.ServerACAckMsg{
		ErrCode:    common.ErrSuccess.ErrorCode(),
		Registered: true,
		Peers: []common.RedirectTarget{
			{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: testPubKeyBase64},
		},
	}
	body, err := json.Marshal(aakMsg)
	if err != nil {
		t.Fatalf("marshal aakMsg: %v", err)
	}

	// Hostname is intentionally empty so SendAddr/ResolveHost skips a
	// real DNS lookup and falls back to Ip.
	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: testPubKeyBase64,
		Type:         core.NHP_SERVER,
	}
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: body,
	}

	got := reg.handleRegistrationResponse(ppd, registrationPeer)
	if !errors.Is(got, ErrRegistrationStopped) {
		t.Fatalf("handleRegistrationResponse err = %v, want errors.Is(ErrRegistrationStopped)", got)
	}
}

// TestClassifyResponseError_DispatchOnly fences the dispatch logic
// that maps register's post-response error onto the MetricRegistrationFailure
// ErrorCode dimension string. The "_DispatchOnly" suffix is intentional:
// this does not fence the IncrCounterWithDims call path itself (#1672
// tracks adding a counter reader to metrics.Publisher for that). A
// future refactor that removes the call to classifyResponseError
// entirely from register's receive case would still pass this test.
//
// Wrapped errors must still resolve via errors.Is — the test exercises
// both bare and errors.Join-wrapped sentinels.
func TestClassifyResponseError_DispatchOnly(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"bare sentinel", ErrRegistrationStopped, "stopped"},
		{"wrapped sentinel", errors.Join(errors.New("upstream"), ErrRegistrationStopped), "stopped"},
		{"unrelated error", errors.New("connection refused"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyResponseError(tt.err); got != tt.want {
				t.Errorf("classifyResponseError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// newStoppedTestRegistration returns an ACRegistration that has already
// completed Stop. The helper relies on Stop remaining safe without a
// prior Start — adding a started.Load() assertion in Stop would mask
// the bug this fence surfaces. A real device is provided so the helper
// can be reused as-is by future tests that drive HandleRedispatch past
// its gate (e.g., the in-flight TOCTOU fence deferred to #1670).
//
// No t.Cleanup(device.Stop) is needed: core.NewDevice does not spawn
// goroutines until Start is called, so there's nothing to drain.
// A future helper variant that calls device.Start must register a
// cleanup that calls device.Stop.
func newStoppedTestRegistration(t *testing.T) *ACRegistration {
	t.Helper()
	device := core.NewDevice(core.NHP_AC, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("failed to create device")
	}
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device:    device,
		sendMsgCh: make(chan *core.MsgData, 10),
	}
	reg := mustNewACRegistration(t, ac)
	reg.Stop()
	return reg
}
