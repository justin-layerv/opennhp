package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// This file fences the agent-lifecycle concurrency/crash fixes ported from
// OpenNHP PR #1552 (issue #3084): send-on-closed-channel panics on the
// SDK/knock/DHP send paths, a double-close of knockTargetStop, a spent
// sync.Once surviving a Stop()->Start() restart, and a nil-deref in Knock.
// Run under -race (make test / go test -race) — several assertions are the
// absence of a panic in a deliberately-raced teardown.

// testAgentPrivKey is a valid 32-byte X25519 private key (all-zero is a valid
// clamped scalar); the agent only validates base64-decodability + length. Same
// material as TestStart_InitializesPerStartMaps.
const testAgentPrivKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// newStartedTestAgent starts a real agent against a minimal tmp-dir config and
// returns it plus its working dir (for a RestartAgent-style second Start).
func newStartedTestAgent(t *testing.T) (a *UdpAgent, dir string) {
	t.Helper()
	dir = t.TempDir()
	etc := filepath.Join(dir, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	cfg := `PrivateKeyBase64 = "` + testAgentPrivKey + `"` + "\n"
	if err := os.WriteFile(filepath.Join(etc, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}
	a = &UdpAgent{}
	if err := a.Start(dir, 1); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return a, dir
}

// testServerPeer builds a loopback NHP_SERVER peer whose Host()
// ("127.0.0.1:62206") matches a KnockResource with the same ServerIp/ServerPort,
// and whose SendAddr() resolves, so request methods reach their sendMsgCh send.
func testServerPeer() *core.UdpPeer {
	return &core.UdpPeer{
		Type:         core.NHP_SERVER,
		PubKeyBase64: testAgentPrivKey, // any decodable 32-byte key; used only as a map key here
		Ip:           "127.0.0.1",
		Port:         62206,
	}
}

// stopWithin runs a.Stop() with a deadlock watchdog and a panic trap, so a
// double-close panic or a wg.Wait() deadlock surfaces as a test failure rather
// than crashing or hanging the whole run.
func stopWithin(t *testing.T, a *UdpAgent, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	var panicked atomic.Value
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked.Store(fmt.Sprint(r))
			}
			close(done)
		}()
		a.Stop()
	}()
	select {
	case <-done:
		if v := panicked.Load(); v != nil {
			t.Fatalf("Stop() panicked: %v", v)
		}
	case <-time.After(d):
		t.Fatalf("Stop() did not return within %s — likely wg.Wait() deadlock (knockTargetStopOnce not re-armed in Start())", d)
	}
}

// TestStopKnockLoopThenStop_NoDoubleClosePanic fences the double-close half of
// 8e983f1d: StopKnockLoop() (exported via sdk.KnockloopStop) and Stop() both
// close knockTargetStop, and the documented RestartAgent flow calls the former
// before the latter. Without the shared knockTargetStopOnce, Stop()'s close is a
// second close of an already-closed channel and panics.
func TestStopKnockLoopThenStop_NoDoubleClosePanic(t *testing.T) {
	a, _ := newStartedTestAgent(t)
	a.StartKnockLoop() // launch knockResourceRoutine, as an SDK knock user would
	a.StopKnockLoop()  // closes knockTargetStop via the Once
	stopWithin(t, a, 5*time.Second)
}

// TestStartAfterStop_ReArmsKnockStopOnce fences the Once re-arm half of bf3e5efe.
// RestartAgent reuses the same *UdpAgent (Stop() -> Start()). A sync.Once is
// spent after its first Do, so without re-arming knockTargetStopOnce in Start()
// the second cycle's stopKnockLoop() no-ops, the freshly-created knockTargetStop
// is never closed, the second knockResourceRoutine never returns, and the second
// Stop() deadlocks on wg.Wait().
func TestStartAfterStop_ReArmsKnockStopOnce(t *testing.T) {
	a, dir := newStartedTestAgent(t)
	a.StartKnockLoop()
	stopWithin(t, a, 5*time.Second) // cycle 1

	if err := a.Start(dir, 1); err != nil {
		t.Fatalf("re-Start (RestartAgent reuse): %v", err)
	}
	a.StartKnockLoop()
	stopWithin(t, a, 5*time.Second) // cycle 2 — deadlocks without the re-arm
}

// TestStop_ConcurrentRequestOtp_NoSendOnClosedPanic fences af931432 (and, by the
// identical select-on-stop pattern, the ExitKnockRequest send in bf3e5efe). It
// hammers the untracked, send-only RequestOtp path against a concurrent Stop().
// RequestOtp is chosen because its sibling methods (RegisterPublicKey /
// ListResource / ExitKnockRequest) block on a response channel after the same
// guarded send, which would exercise the transaction layer rather than the send
// race. The fix (sendMsgCh is never closed + select on signals.stop) keeps every
// send safe; re-introducing close(sendMsgCh) would make this panic under -race.
func TestStop_ConcurrentRequestOtp_NoSendOnClosedPanic(t *testing.T) {
	a, _ := newStartedTestAgent(t)
	peer := testServerPeer()
	a.AddServer(peer)
	target := &KnockTarget{
		KnockResource: KnockResource{
			AuthServiceId: "asp",
			ResourceId:    "res",
			ServerIp:      "127.0.0.1",
			ServerPort:    62206,
		},
		ServerPeer: peer,
	}

	const workers = 64
	var wg sync.WaitGroup
	release := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			for j := 0; j < 20; j++ {
				// A send-on-closed panic here would crash the process (an
				// unrecovered panic in a goroutine fails the test run).
				_ = a.RequestOtp(target)
			}
		}()
	}
	close(release)
	a.Stop() // race teardown against the in-flight sends
	wg.Wait()
}

// TestStop_LeavesSendChannelOpen is the deterministic counterpart to the
// probabilistic race test above: it directly asserts the invariant that makes
// those untracked sends safe. Every untracked sender (request.go and the DHP
// DAR/DAV sends) selects on signals.stop but still names sendMsgCh as a
// select case, so if Stop() closed the channel the send could still be chosen and
// panic. Perform the raw send those methods make and assert it does not panic —
// re-introducing close(sendMsgCh) in Stop() makes this fail every run.
func TestStop_LeavesSendChannelOpen(t *testing.T) {
	a, _ := newStartedTestAgent(t)
	stopWithin(t, a, 5*time.Second)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("send on sendMsgCh after Stop() panicked — Stop() must not close sendMsgCh: %v", r)
		}
	}()
	// sendMessageRoutine has exited on signals.stop, so a send now lands in the
	// (size-SendQueueSize) buffer; the only way it panics is a closed channel,
	// which is the regression this fences (a send case on a closed channel is
	// still selected, then panics — caught by the defer above). Non-blocking so a
	// never-observed full buffer fails loudly instead of hanging the test.
	select {
	case a.sendMsgCh <- &core.MsgData{}:
	default:
		t.Fatal("sendMsgCh buffer unexpectedly full after Stop(); cannot exercise the send-on-closed path")
	}
}

// TestResourceSignal_AfterStop_NoSendOnClosedPanic fences the knockTargetMapUpdated
// close in 8e983f1d together with the non-blocking AddResource/RemoveResource
// signals in 568cb53f. Stop() must leave knockTargetMapUpdated open so a late
// signal send (here from AddResource/RemoveResource after Stop) lands in the
// buffer instead of panicking on a closed channel.
func TestResourceSignal_AfterStop_NoSendOnClosedPanic(t *testing.T) {
	a, _ := newStartedTestAgent(t)
	a.AddServer(testServerPeer())
	stopWithin(t, a, 5*time.Second)

	res := &KnockResource{AuthServiceId: "asp", ResourceId: "res", ServerIp: "127.0.0.1", ServerPort: 62206}
	if err := a.AddResource(res); err != nil {
		t.Fatalf("AddResource after Stop: %v", err) // must reach the signal send, not error early
	}
	a.RemoveResource("asp", "res") // signals on the same channel again
}

// TestUpdateResourcesSignal_AfterStop_NoSendOnClosedPanic fences the config.go
// site of 8e983f1d: the resource-config file-watcher's debounced callback fires
// via an untracked time.AfterFunc that can land after Stop(). Invoking
// updateResources directly stands in for that late callback — it must not panic
// signaling on the (now-not-closed) knockTargetMapUpdated channel.
func TestUpdateResourcesSignal_AfterStop_NoSendOnClosedPanic(t *testing.T) {
	a, dir := newStartedTestAgent(t)
	// Write OUTSIDE the watched etc/ dir. updateResources reads whatever path it
	// is handed, so pointing it at a non-watched file exercises the same signal
	// send without triggering the etc/resource.toml file-watcher — whose
	// debounced time.AfterFunc callback would otherwise fire ~100ms later (after
	// Stop() closed the watcher, which does NOT cancel a scheduled AfterFunc)
	// and race the shared global logger against the next test's Start().
	resourceFile := filepath.Join(dir, "resource-direct.toml")
	if err := os.WriteFile(resourceFile, []byte("# no resources\n"), 0o600); err != nil {
		t.Fatalf("write resource file: %v", err)
	}
	stopWithin(t, a, 5*time.Second)

	if err := a.updateResources(resourceFile); err != nil {
		t.Fatalf("updateResources after Stop: %v", err)
	}
}

// TestDeviceKey_NilDevice fences the nil-safety of the log identifier. The
// address-parse Criticals in SendDAR/DAVMsgToServer call deviceKey() before the
// IsRunning() gate, so on a never-Start()ed agent (a.device == nil) a bare
// a.device.PublicKeyBase64() would nil-panic. deviceKey() must return "" instead.
func TestDeviceKey_NilDevice(t *testing.T) {
	a := &UdpAgent{} // never Started: a.device is nil
	if got := a.deviceKey(); got != "" {
		t.Fatalf("deviceKey() on a nil device = %q, want empty string (no nil-deref)", got)
	}
}

// TestAwaitTransactionResponse_ReceivesAndCloses fences the normal path of the
// receive-side teardown guard: a response present on the channel is returned and
// the channel is closed (its single transaction write consumed).
func TestAwaitTransactionResponse_ReceivesAndCloses(t *testing.T) {
	a := &UdpAgent{}
	a.signals.stop = make(chan struct{}) // open — not stopping
	ch := make(chan *core.PacketParserData, 1)
	want := &core.PacketParserData{}
	ch <- want

	got, ok := a.awaitTransactionResponse(ch)
	if !ok || got != want {
		t.Fatalf("awaitTransactionResponse = (%v, %v), want (response, true)", got, ok)
	}
	if _, open := <-ch; open {
		t.Fatal("awaitTransactionResponse must close ch on the receive path")
	}
}

// TestAwaitTransactionResponse_BailsOnStop fences the teardown path: when
// signals.stop is closed and no response is pending, the receive bails cleanly
// AND leaves ch open with buffer space so the device.wg-tracked transaction
// writer's late (blocking) send lands harmlessly instead of deadlocking
// device.Stop()'s wg.Wait(). Regression fence for the residual leak/deadlock
// from the #3095 review (was tracked in #3096).
func TestAwaitTransactionResponse_BailsOnStop(t *testing.T) {
	a := &UdpAgent{}
	a.signals.stop = make(chan struct{})
	close(a.signals.stop) // agent tearing down
	ch := make(chan *core.PacketParserData, 1)

	got, ok := a.awaitTransactionResponse(ch)
	if ok || got != nil {
		t.Fatalf("awaitTransactionResponse = (%v, %v), want (nil, false) on stop", got, ok)
	}
	// ch must remain OPEN and buffered so a late transaction write can't block
	// the (device.wg-tracked) writer or panic on a closed channel.
	select {
	case ch <- &core.PacketParserData{}:
	default:
		t.Fatal("ch must stay open with buffer space after a stop bail (else the transaction writer deadlocks device.Stop())")
	}
}

// TestAwaitTransactionResponse_PrefersBufferedResponseOverStop fences the
// non-blocking-receive-first behavior: an already-delivered response must be
// returned even when signals.stop is already closed, rather than dropped for the
// stop bail. Without the leading non-blocking receive, the single select would
// pick the stop branch pseudo-randomly (~50%) and discard a real response.
func TestAwaitTransactionResponse_PrefersBufferedResponseOverStop(t *testing.T) {
	a := &UdpAgent{}
	a.signals.stop = make(chan struct{})
	close(a.signals.stop) // agent stopping
	ch := make(chan *core.PacketParserData, 1)
	want := &core.PacketParserData{}
	ch <- want // response already delivered

	got, ok := a.awaitTransactionResponse(ch)
	if !ok || got != want {
		t.Fatalf("awaitTransactionResponse = (%v, %v), want (buffered response, true) despite closed signals.stop", got, ok)
	}
}

// TestAwaitOrStop_EncryptedPktChPath fences the generic awaitOrStop for its
// SECOND caller type — preAccessRequest's EncryptedPktCh (chan
// *core.MsgAssemblerData), a different element type than the ResponseMsgCh path
// above, so it also proves the helper is genuinely type-agnostic. preAccessRequest
// is reachable synchronously from the a.wg-tracked Knock, so before this guard a
// bare <-EncryptedPktCh deadlocked Stop()'s wg.Wait() when SendMsgToPacket
// discarded the message (it's non-blocking) or the device was mid-teardown —
// nothing then writes the channel. Regression fence for the #3095 19th-review
// finding.
func TestAwaitOrStop_EncryptedPktChPath(t *testing.T) {
	t.Run("prefers a delivered packet over the stop bail", func(t *testing.T) {
		stop := make(chan struct{})
		close(stop) // agent tearing down, yet a packet already arrived
		ch := make(chan *core.MsgAssemblerData, 1)
		want := &core.MsgAssemblerData{}
		ch <- want

		got, ok := awaitOrStop(ch, stop)
		if !ok || got != want {
			t.Fatalf("awaitOrStop = (%v, %v), want (packet, true) despite closed stop", got, ok)
		}
		if _, open := <-ch; open {
			t.Fatal("awaitOrStop must close ch on the receive path")
		}
	})

	t.Run("bails on stop and leaves ch open for a late device.wg write", func(t *testing.T) {
		stop := make(chan struct{})
		close(stop)
		ch := make(chan *core.MsgAssemblerData, 1) // empty — no packet delivered

		got, ok := awaitOrStop(ch, stop)
		if ok || got != nil {
			t.Fatalf("awaitOrStop = (%v, %v), want (nil, false) on stop", got, ok)
		}
		// The device.wg encrypt writer (device.go: mad.encryptedPktCh <- mad) is a
		// BLOCKING send, so ch must stay open+buffered — a late send has to land in
		// the buffer instead of blocking the writer and deadlocking device.Stop().
		select {
		case ch <- &core.MsgAssemblerData{}:
		default:
			t.Fatal("ch must stay open with buffer space after a stop bail (else the encrypt writer deadlocks device.Stop())")
		}
	})
}

// TestAwaitOrDeadline_TimesOut fences the #3112 fix: preAccessRequest's
// encrypt-await must give up on a deadline (not park until the next Stop()) when
// no packet arrives and the agent is NOT stopping — e.g. SendMsgToPacket
// discarded the message on a full msgToPacketQueue. The nil-deadline variant
// (awaitOrStop, used by the transaction ResponseMsgCh path) must never time out.
func TestAwaitOrDeadline_TimesOut(t *testing.T) {
	stop := make(chan struct{}) // open — agent is running, not stopping

	t.Run("deadline fires when neither a value nor stop arrives", func(t *testing.T) {
		ch := make(chan *core.MsgAssemblerData, 1) // empty — packet was discarded
		timer := time.NewTimer(20 * time.Millisecond)
		defer timer.Stop()

		got, ok := awaitOrDeadline(ch, stop, timer.C)
		if ok || got != nil {
			t.Fatalf("awaitOrDeadline = (%v, %v), want (nil, false) on deadline", got, ok)
		}
		// Bail path still leaves ch open+buffered, so a late device.wg write can't
		// deadlock device.Stop() — same contract as the stop bail.
		select {
		case ch <- &core.MsgAssemblerData{}:
		default:
			t.Fatal("ch must stay open with buffer space after a deadline bail")
		}
	})

	t.Run("a delivered value wins over a pending deadline", func(t *testing.T) {
		ch := make(chan *core.MsgAssemblerData, 1)
		want := &core.MsgAssemblerData{}
		ch <- want
		timer := time.NewTimer(10 * time.Second) // long — must not preempt the value
		defer timer.Stop()

		got, ok := awaitOrDeadline(ch, stop, timer.C)
		if !ok || got != want {
			t.Fatalf("awaitOrDeadline = (%v, %v), want (value, true) — the leading receive must beat the deadline", got, ok)
		}
	})
}

// TestSendOrStop_NeverStarted_ReturnsFalseNoHang fences the defensive nil-channel
// guard (24th-review obs 1). On a never-Start()ed agent both sendMsgCh and
// signals.stop are nil, so the bare select would block forever; the guard must
// return false instead so a caller that skips IsRunning() can't hang.
func TestSendOrStop_NeverStarted_ReturnsFalseNoHang(t *testing.T) {
	a := &UdpAgent{} // never Start()ed: sendMsgCh + signals.stop are nil
	done := make(chan bool, 1)
	go func() { done <- a.sendOrStop(&core.MsgData{}) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("sendOrStop on a never-Start()ed agent must return false, not enqueue")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sendOrStop hung on a never-Start()ed agent — the nil-sendMsgCh guard is missing")
	}
}

// TestAwaitOrDeadline_NilChannel_ReturnsFalse fences awaitOrDeadline's symmetric
// nil-channel guard: a nil ch never delivers, so without the guard the select
// (all-nil arms) would hang.
func TestAwaitOrDeadline_NilChannel_ReturnsFalse(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		_, ok := awaitOrDeadline[*core.MsgAssemblerData](nil, nil, nil)
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("awaitOrDeadline(nil, ...) must return (nil, false)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("awaitOrDeadline hung on a nil channel — the nil-ch guard is missing")
	}
}

// TestStop_WithActiveKnockTarget_ReturnsPromptly fences the interruptible Knock
// error backoff. With a live knock target, knockResourceRoutine spawns a
// sub-routine that sits in Knock; a racing Stop() bails its send/receive on
// signals.stop, but Knock then enters its ~errWaitTime (~4.9s) error backoff.
// Since Knock is a.wg-tracked and Stop() runs a.wg.Wait() before device.Stop(),
// an unconditional sleep would stall the whole teardown by that long — so the
// backoff must bail on signals.stop. Unlike the empty-map deadlock tests, this
// one actually spawns a knock sub-routine.
func TestStop_WithActiveKnockTarget_ReturnsPromptly(t *testing.T) {
	a, _ := newStartedTestAgent(t)
	a.AddServer(testServerPeer())
	if err := a.AddResource(&KnockResource{
		AuthServiceId: "asp", ResourceId: "res", ServerIp: "127.0.0.1", ServerPort: 62206,
	}); err != nil {
		t.Fatalf("AddResource: %v", err)
	}
	a.StartKnockLoop()

	// Wait until the knock's send has created a connection — i.e. the sub-routine
	// is past its send and blocked in awaitTransactionResponse — rather than
	// sleeping a fixed lower bound that a loaded CI runner could beat (which would
	// let this pass without exercising the backoff bail). Nothing answers
	// 127.0.0.1:62206, so the sub-routine then sits in the error path.
	waitFor(t, 3*time.Second, func() bool {
		a.remoteConnectionMutex.Lock()
		defer a.remoteConnectionMutex.Unlock()
		return len(a.remoteConnectionMap) > 0
	})

	start := time.Now()
	a.Stop()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Stop() took %s with an active knock target — Knock's error backoff must bail on signals.stop, not sleep out the full ~4.9s", elapsed)
	}
}

// waitFor polls cond until it is true or the timeout elapses, failing the test on
// timeout. Preferred over a fixed sleep for "wait until X happened" so a loaded
// runner can't race past the setup and leave a test exercising nothing.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s", timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestStop_ConcurrentAndDouble_NoDoubleClosePanic fences the running-CAS guard
// on Stop() itself. Stop() closes signals.stop (and stops the device) with no
// per-call idempotency, so a second or concurrent Stop() — reachable via two
// web-console RestartAgent requests or an SDK Close racing RestartAgent — would
// double-close and panic without the CompareAndSwap(true, false) gate.
func TestStop_ConcurrentAndDouble_NoDoubleClosePanic(t *testing.T) {
	a, _ := newStartedTestAgent(t)

	const callers = 8
	var wg sync.WaitGroup
	var panicked atomic.Value
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicked.Store(fmt.Sprint(r))
				}
			}()
			a.Stop() // only the CAS winner tears down; the rest return early
		}()
	}
	wg.Wait()
	if v := panicked.Load(); v != nil {
		t.Fatalf("concurrent Stop() panicked (double-close of signals.stop): %v", v)
	}
	// An explicit extra Stop() after teardown must also be a clean no-op.
	a.Stop()
}

// TestBeginTrackedOp_ConcurrentStop_NoWaitGroupReusePanic fences #3103's sharp
// edge: a direct SDK op registering via beginTrackedOp (a.wg.Add under
// lifecycleMu.RLock) must not race Stop()'s CAS+wg.Wait into a "WaitGroup is
// reused before previous Wait has returned" panic. Pre-fix, the raw a.wg.Add(1)
// that Knock / StartKnockLoop did could add while Stop()'s Wait sat at 0;
// beginTrackedOp either adds before Stop's CAS (so Wait counts it) or sees
// running=false under the RLock and bails. A panic crashes the goroutine and
// fails the test; run under -race.
func TestBeginTrackedOp_ConcurrentStop_NoWaitGroupReusePanic(t *testing.T) {
	a, _ := newStartedTestAgent(t)

	done := make(chan struct{})
	var hammers sync.WaitGroup
	for i := 0; i < 24; i++ {
		hammers.Add(1)
		go func() {
			defer hammers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if a.beginTrackedOp() {
					a.wg.Done() // simulate a quick tracked op releasing its token
				}
			}
		}()
	}

	time.Sleep(30 * time.Millisecond) // let the hammers spin up around the Add/Wait boundary
	a.Stop()                          // CAS + wg.Wait, racing the guarded Adds
	close(done)
	hammers.Wait()
}

// TestRestart_ConcurrentSendOrStop_NoFieldRace fences the other half of #3103: a
// Stop()->Start() reassignment of signals.stop / sendMsgCh must not data-race the
// lock-free-looking reads in sendOrStop. Both sides now take lifecycleMu (Start
// for writing, sendOrStop's snapshot for reading), so -race sees a happens-before
// edge instead of a torn field read. Fails under -race without the mutex.
func TestRestart_ConcurrentSendOrStop_NoFieldRace(t *testing.T) {
	a, dir := newStartedTestAgent(t)

	done := make(chan struct{})
	var hammers sync.WaitGroup
	for i := 0; i < 16; i++ {
		hammers.Add(1)
		go func() {
			defer hammers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				_ = a.sendOrStop(&core.MsgData{}) // snapshots signals.stop/sendMsgCh under RLock
			}
		}()
	}

	// Restart reassigns the channels under lifecycleMu.Lock while the hammers
	// snapshot them under RLock.
	a.Stop()
	if err := a.Start(dir, 1); err != nil {
		t.Fatalf("restart Start: %v", err)
	}
	close(done)
	hammers.Wait()
	a.Stop()
}

// TestRestart_ConcurrentMapDelete_NoMapRace fences finding #1 of the #3103 review:
// Start() re-inits knockTargetMap / serverPeerMap, and the map-only SDK removers
// RemoveServer (serverPeerMutex) / RemoveResource (knockTargetMapMutex) touch
// those maps under their mutexes. Start() must take the same mutexes around the
// reassignment, else a concurrent RemoveServer/RemoveResource races the
// map-header write. Fails under -race without the mutexes at Start().
//
// Uses the map-only removers deliberately: AddServer/AddResource additionally
// touch a.device (AddPeer / NextCounterIndex), a broader pre-existing
// a.device-lifecycle race beyond #3103's field-reassignment scope (tracked
// separately) that would otherwise mask this map-specific fence.
func TestRestart_ConcurrentMapDelete_NoMapRace(t *testing.T) {
	a, dir := newStartedTestAgent(t)

	done := make(chan struct{})
	var hammers sync.WaitGroup
	for i := 0; i < 12; i++ {
		hammers.Add(1)
		go func() {
			defer hammers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				a.RemoveServer("no-such-key")  // serverPeerMutex, map-only
				a.RemoveResource("asp", "res") // knockTargetMapMutex, map-only (no match -> no signal)
			}
		}()
	}

	// Restart re-inits both maps; the hammers delete from them under their mutexes.
	a.Stop()
	if err := a.Start(dir, 1); err != nil {
		t.Fatalf("restart Start: %v", err)
	}
	close(done)
	hammers.Wait()
	a.Stop()
}

// TestRestart_ConcurrentMapUpdatedSignal_NoFieldRace fences the #3095 post-merge
// finding: knockTargetMapUpdated is reassigned in Start() under lifecycleMu.Lock,
// but its senders (AddResource / RemoveResource / the debounced updateResources
// callback) read the field to send on it. It hammers the exact send pattern those
// three sites use — mapUpdatedSignal() snapshot + non-blocking send — against a
// concurrent restart. With the snapshot under RLock there's a happens-before with
// Start()'s Lock-write; without it the field read/write is a DATA RACE.
// (TestRestart_ConcurrentMapDelete uses no-match removers that never reach the
// send, so it does not cover this.)
func TestRestart_ConcurrentMapUpdatedSignal_NoFieldRace(t *testing.T) {
	a, dir := newStartedTestAgent(t)

	done := make(chan struct{})
	var hammers sync.WaitGroup
	for i := 0; i < 12; i++ {
		hammers.Add(1)
		go func() {
			defer hammers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				// exactly what AddResource/RemoveResource/updateResources do
				mapUpdated := a.mapUpdatedSignal()
				select {
				case mapUpdated <- struct{}{}:
				default:
				}
			}
		}()
	}

	a.Stop()
	if err := a.Start(dir, 1); err != nil {
		t.Fatalf("restart Start: %v", err)
	}
	close(done)
	hammers.Wait()
	a.Stop()
}

// TestStop_ConcurrentResponseAwaitingCalls_NoHang hammers the three response-
// awaiting SDK methods against a concurrent Stop() and asserts every call
// returns. Without the receive-side guard, a send stranded in sendMsgCh's buffer
// by the raced Stop() produces no response and strands the caller on
// <-ResponseMsgCh forever. Complements the deterministic helper unit tests with
// -race coverage of the real methods.
func TestStop_ConcurrentResponseAwaitingCalls_NoHang(t *testing.T) {
	a, _ := newStartedTestAgent(t)
	peer := testServerPeer()
	a.AddServer(peer)
	target := &KnockTarget{
		KnockResource: KnockResource{
			AuthServiceId: "asp",
			ResourceId:    "res",
			ServerIp:      "127.0.0.1",
			ServerPort:    62206,
		},
		ServerPeer: peer,
	}

	const workers = 18
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// No server answers 127.0.0.1:62206, so each of these sends then
			// awaits a response that only Stop()'s teardown will resolve.
			switch i % 3 {
			case 0:
				_, _ = a.ListResource(target)
			case 1:
				_, _ = a.RegisterPublicKey("otp", target)
			case 2:
				_, _ = a.ExitKnockRequest(target)
			}
		}(i)
	}
	a.Stop() // race teardown against the in-flight response-awaiting calls

	doneAll := make(chan struct{})
	go func() { wg.Wait(); close(doneAll) }()
	select {
	case <-doneAll:
	case <-time.After(8 * time.Second):
		t.Fatal("a response-awaiting call did not return after Stop() — receive not guarded (leaked goroutine)")
	}
}

// TestKnock_NilKnockRequestResult_NoPanic fences the SDK-crash slice of c6f9c769.
// knockRequest returns (nil, err) when resolveServerAddr fails (here: a
// KnockTarget with no ServerPeer). Without the nil-guard, Knock dereferences the
// nil ackMsg at the ErrCode read and crashes the live knock loop and SDK Knock;
// with it, Knock synthesizes an ackMsg from err.
func TestKnock_NilKnockRequestResult_NoPanic(t *testing.T) {
	// A near-bare agent is enough: Knock returns before touching the device or the
	// send/receive channels because resolveServerAddr fails first. knockUser must
	// be non-nil (knockRequest reads UserId for logging). running=true satisfies
	// Knock's beginTrackedOp gate (#3103) so it reaches the nil-guard rather than
	// bailing early; closing signals.stop makes Knock's post-error backoff bail
	// immediately (its select on signals.stop) instead of sleeping out the full
	// ~errWaitTime (~4.9s) — the nil-guard runs BEFORE the backoff, so it's still
	// exercised.
	a := &UdpAgent{knockUser: &KnockUser{UserId: "tester"}}
	a.signals.stop = make(chan struct{})
	close(a.signals.stop)
	a.running.Store(true)
	res := &KnockTarget{} // ServerPeer nil -> knockRequest returns (nil, ErrKnockServerNotFound)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Knock panicked on nil knockRequest result (c6f9c769 regression): %v", r)
		}
	}()
	ack, _ := a.Knock(res) // must not nil-deref reading the synthesized ackMsg.ErrCode
	if ack == nil {
		t.Fatal("Knock returned a nil ackMsg; the nil-guard must synthesize one from err")
	}
	if ack.ErrCode != common.ErrKnockServerNotFound.ErrorCode() {
		t.Fatalf("synthesized ackMsg.ErrCode = %q, want %q", ack.ErrCode, common.ErrKnockServerNotFound.ErrorCode())
	}
}
