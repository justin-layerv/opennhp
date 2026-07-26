package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
)

type recordingUDPWriteSocket struct {
	mu             sync.Mutex
	deadlines      []time.Time
	writes         int
	writeN         int
	writeErr       error
	setDeadlineErr map[int]error
	blockSetCall   int
	setStarted     chan struct{}
	setRelease     chan struct{}
	writeStarted   chan struct{}
	writeRelease   chan struct{}
}

// delayedCancelContext models the observable gap after a parent context's Done
// channel closes but before its registered child-cancellation callback runs.
// Standard contexts can expose that gap because Done closes before cancellation
// propagation has visited every derived context.
type delayedCancelContext struct {
	context.Context
	mu         sync.Mutex
	done       chan struct{}
	err        error
	registered bool
}

func newDelayedCancelContext() *delayedCancelContext {
	return &delayedCancelContext{
		Context: context.Background(),
		done:    make(chan struct{}),
	}
}

func (c *delayedCancelContext) Done() <-chan struct{} {
	return c.done
}

func (c *delayedCancelContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// AfterFunc records that context.WithDeadline registered its propagation
// callback, then deliberately drops that callback: cancelWithoutPropagation
// closes Done without ever invoking it, reproducing the propagation-lag window.
// The returned stop closure mirrors context.AfterFunc's fire-once contract so
// the derived context's cancel() unregisters cleanly.
func (c *delayedCancelContext) AfterFunc(_ func()) func() bool {
	c.mu.Lock()
	c.registered = true
	c.mu.Unlock()
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.registered {
			return false
		}
		c.registered = false
		return true
	}
}

func (c *delayedCancelContext) propagationRegistered() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registered
}

func (c *delayedCancelContext) cancelWithoutPropagation() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = context.Canceled
	close(c.done)
}

func (f *recordingUDPWriteSocket) SetWriteDeadline(deadline time.Time) error {
	f.mu.Lock()
	f.deadlines = append(f.deadlines, deadline)
	call := len(f.deadlines)
	err := f.setDeadlineErr[call]
	block := call == f.blockSetCall
	started := f.setStarted
	release := f.setRelease
	f.mu.Unlock()
	if block {
		if started != nil {
			started <- struct{}{}
		}
		if release != nil {
			<-release
		}
	}
	return err
}

func (f *recordingUDPWriteSocket) WriteToUDP(payload []byte, _ *net.UDPAddr) (int, error) {
	f.mu.Lock()
	f.writes++
	n := f.writeN
	err := f.writeErr
	started := f.writeStarted
	release := f.writeRelease
	f.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if n < 0 {
		n = len(payload)
	}
	return n, err
}

func (f *recordingUDPWriteSocket) snapshot() ([]time.Time, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.deadlines...), f.writes
}

func TestWriteUDPDatagramOrdinaryWriteAvoidsDeadlineSyscalls(t *testing.T) {
	socket := &recordingUDPWriteSocket{writeN: -1}
	s := &UdpServer{udpWriteSocket: socket}
	payload := []byte("ordinary")

	n, err := s.writeUDPDatagram(context.Background(), payload, &net.UDPAddr{}, time.Time{})
	if err != nil || n != len(payload) {
		t.Fatalf("write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	deadlines, writes := socket.snapshot()
	if len(deadlines) != 0 || writes != 1 {
		t.Fatalf("deadline calls=%d writes=%d, want 0 and 1", len(deadlines), writes)
	}
}

func TestWriteUDPDatagramOrdinaryWritesRemainConcurrent(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	socket := &recordingUDPWriteSocket{writeN: -1, writeStarted: started, writeRelease: release}
	s := &UdpServer{udpWriteSocket: socket}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := s.writeUDPDatagram(context.Background(), []byte("ordinary"), &net.UDPAddr{}, time.Time{})
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("ordinary writes did not enter the physical socket concurrently")
		}
	}
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("ordinary write: %v", err)
		}
	}
	deadlines, writes := socket.snapshot()
	if len(deadlines) != 0 || writes != 2 {
		t.Fatalf("deadline calls=%d writes=%d, want 0 and 2", len(deadlines), writes)
	}
}

func TestWriteUDPDatagramUsesEarlierDeadlineAndResets(t *testing.T) {
	for _, tc := range []struct {
		name           string
		contextOffset  time.Duration
		explicitOffset time.Duration
		wantOffset     time.Duration
	}{
		{name: "context earlier", contextOffset: 2 * time.Second, explicitOffset: 3 * time.Second, wantOffset: 2 * time.Second},
		{name: "explicit earlier", contextOffset: 3 * time.Second, explicitOffset: 2 * time.Second, wantOffset: 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := &recordingUDPWriteSocket{writeN: -1}
			s := &UdpServer{udpWriteSocket: socket}
			start := time.Now()
			contextDeadline := start.Add(tc.contextOffset)
			explicitDeadline := start.Add(tc.explicitOffset)
			wantDeadline := start.Add(tc.wantOffset)
			ctx, cancel := context.WithDeadline(context.Background(), contextDeadline)
			defer cancel()

			if _, err := s.writeUDPDatagram(ctx, []byte("bounded"), &net.UDPAddr{}, explicitDeadline); err != nil {
				t.Fatalf("writeUDPDatagram: %v", err)
			}
			deadlines, _ := socket.snapshot()
			if len(deadlines) != 2 {
				t.Fatalf("deadline calls = %d, want arm and reset", len(deadlines))
			}
			if !deadlines[0].Equal(wantDeadline) {
				t.Fatalf("armed deadline = %v, want earlier deadline %v", deadlines[0], wantDeadline)
			}
			if !deadlines[1].IsZero() || s.udpWriteDeadlineDirty.Load() {
				t.Fatalf("reset deadline = %v dirty=%v, want zero and clean", deadlines[1], s.udpWriteDeadlineDirty.Load())
			}
		})
	}
}

func TestWriteUDPDatagramResetFailurePreservesWriteAndForcesNextClear(t *testing.T) {
	resetFailure := errors.New("reset failed")
	socket := &recordingUDPWriteSocket{
		writeN:         -1,
		setDeadlineErr: map[int]error{2: resetFailure},
	}
	s := &UdpServer{udpWriteSocket: socket}
	payload := []byte("sent")

	n, err := s.writeUDPDatagram(context.Background(), payload, &net.UDPAddr{}, time.Now().Add(time.Second))
	if n != len(payload) || !errors.Is(err, resetFailure) {
		t.Fatalf("write with reset failure = (%d, %v), want (%d, reset failure)", n, err, len(payload))
	}
	if !s.udpWriteDeadlineDirty.Load() {
		t.Fatal("failed reset did not leave socket deadline state dirty")
	}

	n, err = s.writeUDPDatagram(context.Background(), payload, &net.UDPAddr{}, time.Time{})
	if err != nil || n != len(payload) {
		t.Fatalf("ordinary write after dirty reset = (%d, %v), want success", n, err)
	}
	deadlines, writes := socket.snapshot()
	if len(deadlines) != 3 || !deadlines[2].IsZero() || writes != 2 || s.udpWriteDeadlineDirty.Load() {
		t.Fatalf("deadlines=%v writes=%d dirty=%v, want mandatory clear then second write", deadlines, writes, s.udpWriteDeadlineDirty.Load())
	}
}

func TestWriteUDPDatagramDirtyClearFailurePreventsWrite(t *testing.T) {
	resetFailure := errors.New("reset failed")
	clearFailure := errors.New("clear failed")
	socket := &recordingUDPWriteSocket{
		writeN:         -1,
		setDeadlineErr: map[int]error{2: resetFailure, 3: clearFailure},
	}
	s := &UdpServer{udpWriteSocket: socket}
	payload := []byte("sent")

	if _, err := s.writeUDPDatagram(context.Background(), payload, &net.UDPAddr{}, time.Now().Add(time.Second)); !errors.Is(err, resetFailure) {
		t.Fatalf("first write error = %v, want reset failure", err)
	}
	if n, err := s.writeUDPDatagram(context.Background(), payload, &net.UDPAddr{}, time.Time{}); n != 0 || !errors.Is(err, clearFailure) {
		t.Fatalf("dirty clear = (%d, %v), want (0, clear failure)", n, err)
	}
	_, writes := socket.snapshot()
	if writes != 1 || !s.udpWriteDeadlineDirty.Load() {
		t.Fatalf("writes=%d dirty=%v, want no second write and dirty state retained", writes, s.udpWriteDeadlineDirty.Load())
	}
}

func TestWriteUDPDatagramSetFailureMarksSocketDirty(t *testing.T) {
	setFailure := errors.New("set failed")
	socket := &recordingUDPWriteSocket{
		writeN:         -1,
		setDeadlineErr: map[int]error{1: setFailure},
	}
	s := &UdpServer{udpWriteSocket: socket}

	if n, err := s.writeUDPDatagram(context.Background(), []byte("not sent"), &net.UDPAddr{}, time.Now().Add(time.Second)); n != 0 || !errors.Is(err, setFailure) {
		t.Fatalf("deadline set failure = (%d, %v), want (0, set failure)", n, err)
	}
	_, writes := socket.snapshot()
	if writes != 0 || !s.udpWriteDeadlineDirty.Load() {
		t.Fatalf("writes=%d dirty=%v, want no write and mandatory future clear", writes, s.udpWriteDeadlineDirty.Load())
	}
}

func TestWriteUDPDatagramReportsShortWrite(t *testing.T) {
	socket := &recordingUDPWriteSocket{writeN: 2}
	s := &UdpServer{udpWriteSocket: socket}

	n, err := s.writeUDPDatagram(context.Background(), []byte("short"), &net.UDPAddr{}, time.Now().Add(time.Second))
	if n != 2 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write = (%d, %v), want (2, io.ErrShortWrite)", n, err)
	}
}

func TestWriteUDPDatagramJoinsWriteAndResetFailures(t *testing.T) {
	writeFailure := errors.New("write failed")
	resetFailure := errors.New("reset failed")
	socket := &recordingUDPWriteSocket{
		writeN:         2,
		writeErr:       writeFailure,
		setDeadlineErr: map[int]error{2: resetFailure},
	}
	s := &UdpServer{udpWriteSocket: socket}

	n, err := s.writeUDPDatagram(context.Background(), []byte("partial"), &net.UDPAddr{}, time.Now().Add(time.Second))
	if n != 2 || !errors.Is(err, writeFailure) || !errors.Is(err, resetFailure) {
		t.Fatalf("combined failure = (%d, %v), want byte count and both causes", n, err)
	}
	if !s.udpWriteDeadlineDirty.Load() {
		t.Fatal("reset failure did not retain dirty deadline state")
	}
}

func TestWriteUDPDatagramDeadlineExpiresWhileWaitingForGate(t *testing.T) {
	s := &UdpServer{udpWriteSocket: &recordingUDPWriteSocket{writeN: -1}}
	s.initUDPWriteGate()
	if err := s.udpWriteGate.Acquire(context.Background(), udpWriteGateWeight); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.udpWriteGate.Release(udpWriteGateWeight) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if n, err := s.writeUDPDatagram(ctx, []byte("blocked"), &net.UDPAddr{}, time.Time{}); n != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("gate wait = (%d, %v), want deadline exceeded", n, err)
	}
}

func TestWriteUDPDatagramDirtyClearCannotOverlapRunningOrdinaryWrite(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	socket := &recordingUDPWriteSocket{writeN: -1, writeStarted: started, writeRelease: release}
	s := &UdpServer{udpWriteSocket: socket}
	firstResult := make(chan error, 1)
	go func() {
		_, err := s.writeUDPDatagram(context.Background(), []byte("ordinary"), &net.UDPAddr{}, time.Time{})
		firstResult <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("ordinary physical write did not start")
	}

	// Simulate a failed deadline reset becoming visible while an ordinary
	// writer owns shared access. Recovery must acquire the exclusive weight
	// before clearing socket-global deadline state.
	s.udpWriteDeadlineDirty.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if n, err := s.writeUDPDatagram(ctx, []byte("recovery"), &net.UDPAddr{}, time.Time{}); n != 0 || !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatalf("dirty recovery while ordinary write runs = (%d, %v), want deadline exceeded", n, err)
	}
	deadlines, writes := socket.snapshot()
	if len(deadlines) != 0 || writes != 1 {
		close(release)
		t.Fatalf("deadline calls=%d writes=%d, want no dirty clear overlapping the running write", len(deadlines), writes)
	}

	close(release)
	if err := <-firstResult; err != nil {
		t.Fatalf("ordinary write: %v", err)
	}
}

func TestWriteUDPDatagramCancellationDuringDeadlineArmResetsWithoutWriting(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	socket := &recordingUDPWriteSocket{
		writeN:       -1,
		blockSetCall: 1,
		setStarted:   started,
		setRelease:   release,
	}
	s := &UdpServer{udpWriteSocket: socket}
	ctx := newDelayedCancelContext()
	result := make(chan error, 1)
	go func() {
		_, err := s.writeUDPDatagram(ctx, []byte("must-not-send"), &net.UDPAddr{}, time.Now().Add(time.Second))
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("deadline arm did not start")
	}
	// Pin the Go toolchain behavior that makes this propagation-lag simulation
	// deterministic instead of silently falling back to a watcher goroutine.
	if !ctx.propagationRegistered() {
		t.Fatal("context.WithDeadline did not register parent AfterFunc propagation")
	}
	ctx.cancelWithoutPropagation()
	close(release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("write error = %v, want canceled", err)
	}
	deadlines, writes := socket.snapshot()
	if len(deadlines) != 2 || !deadlines[1].IsZero() || writes != 0 || s.udpWriteDeadlineDirty.Load() {
		t.Fatalf("deadlines=%v writes=%d dirty=%v, want arm/reset, no write, clean state", deadlines, writes, s.udpWriteDeadlineDirty.Load())
	}
}

func TestWriteUDPDatagramSerializesPhysicalWrites(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWrites := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseWrites()
	socket := &recordingUDPWriteSocket{writeN: -1, writeStarted: started, writeRelease: release}
	s := &UdpServer{udpWriteSocket: socket}
	firstResult := make(chan error, 1)
	go func() {
		_, err := s.writeUDPDatagram(context.Background(), []byte("one"), &net.UDPAddr{}, time.Now().Add(time.Second))
		firstResult <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first physical write did not start")
	}
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelSecond()
	secondResult := make(chan error, 1)
	go func() {
		_, err := s.writeUDPDatagram(secondCtx, []byte("two"), &net.UDPAddr{}, time.Time{})
		secondResult <- err
	}()
	select {
	case <-started:
		t.Fatal("second physical write started before first released the shared gate")
	case err := <-secondResult:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued second write error = %v, want deadline exceeded", err)
		}
	}
	releaseWrites()
	if err := <-firstResult; err != nil {
		t.Fatalf("first serialized write: %v", err)
	}
	_, writes := socket.snapshot()
	if writes != 1 {
		t.Fatalf("physical writes = %d, want only the gate holder", writes)
	}
}

func TestWriteUDPDatagramRealSocketPayload(t *testing.T) {
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	payload := []byte("shared-writer-proof")
	s := &UdpServer{listenConn: sender}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n, err := s.writeUDPDatagram(ctx, payload, receiver.LocalAddr().(*net.UDPAddr), time.Time{})
	if err != nil || n != len(payload) {
		t.Fatalf("real write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _, err = receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload = %q, want %q", buf[:n], payload)
	}
}

func TestSendPacketObservesCanceledServerLifecycle(t *testing.T) {
	s := newSendMessageTestServer(t, make(chan *core.MsgData, 1))
	s.lifecycleCtx, s.lifecycleCancel = context.WithCancel(context.Background())
	s.lifecycleCancel()
	pkt := s.device.AllocatePoolPacket()
	pkt.Content = append(pkt.Content[:0], "shutdown"...)
	conn := &UdpConn{ConnData: &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}}}

	if n, err := s.SendPacket(pkt, conn); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("send during server shutdown = (%d, %v), want context canceled", n, err)
	}
}

func TestWriteUDPDatagramNilListenerFailsClearly(t *testing.T) {
	s := &UdpServer{}
	if _, err := s.writeUDPDatagram(context.Background(), []byte("x"), &net.UDPAddr{}, time.Time{}); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("nil-listener error = %v, want initialized diagnostic", err)
	}
}

func TestWriteUDPDatagramNilContextFailsClosed(t *testing.T) {
	s := &UdpServer{udpWriteSocket: &recordingUDPWriteSocket{writeN: -1}}
	if n, err := s.writeUDPDatagram(nil, []byte("x"), &net.UDPAddr{}, time.Time{}); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("nil-context result = (%d, %v), want context cancellation", n, err)
	}
}
