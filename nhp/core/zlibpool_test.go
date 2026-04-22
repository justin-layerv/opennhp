package core

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	log "github.com/OpenNHP/opennhp/nhp/log"
)

// BenchmarkZlibCompressPooled measures the encrypt-path compression cost
// when the zlib.Writer and bytes.Buffer come from the pools added in this
// change. Pairs with BenchmarkZlibCompressUnpooled for a like-for-like
// allocation comparison.
func BenchmarkZlibCompressPooled(b *testing.B) {
	data := bytes.Repeat([]byte("ABCDEFGHIJ"), 100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := getBytesBuffer()
		w := getZlibWriter(buf)
		if _, err := w.Write(data); err != nil {
			b.Fatalf("write: %v", err)
		}
		if err := w.Close(); err != nil {
			b.Fatalf("close: %v", err)
		}
		_ = buf.Bytes()
		putZlibWriter(w)
		putBytesBuffer(buf)
	}
}

// BenchmarkZlibCompressUnpooled is the pre-pool equivalent: a fresh
// zlib.Writer and bytes.Buffer per iteration, mirroring the code shape
// that existed before this PR.
func BenchmarkZlibCompressUnpooled(b *testing.B) {
	data := bytes.Repeat([]byte("ABCDEFGHIJ"), 100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		if _, err := w.Write(data); err != nil {
			b.Fatalf("write: %v", err)
		}
		if err := w.Close(); err != nil {
			b.Fatalf("close: %v", err)
		}
		_ = buf.Bytes()
	}
}

// BenchmarkZlibDecompressPooled measures the decrypt-path decompression
// cost when the zlib.Reader and bytes.Buffer come from the pools.
func BenchmarkZlibDecompressPooled(b *testing.B) {
	data := bytes.Repeat([]byte("ABCDEFGHIJ"), 100)
	compressed := createZlibCompressed(b, data)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := getBytesBuffer()
		r, err := getZlibReader(bytes.NewReader(compressed))
		if err != nil {
			b.Fatalf("reader: %v", err)
		}
		if _, err := io.Copy(buf, r); err != nil {
			b.Fatalf("copy: %v", err)
		}
		_ = r.Close()
		putZlibReader(r)
		putBytesBuffer(buf)
	}
}

// BenchmarkZlibDecompressUnpooled is the pre-pool equivalent for the
// decrypt path.
func BenchmarkZlibDecompressUnpooled(b *testing.B) {
	data := bytes.Repeat([]byte("ABCDEFGHIJ"), 100)
	compressed := createZlibCompressed(b, data)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		r, err := zlib.NewReader(bytes.NewReader(compressed))
		if err != nil {
			b.Fatalf("reader: %v", err)
		}
		if _, err := io.Copy(&buf, r); err != nil {
			b.Fatalf("copy: %v", err)
		}
		_ = r.Close()
	}
}

// BenchmarkEncryptBodyCompressed is the end-to-end counterpart of
// BenchmarkDecryptBodyCompressed. It exercises encryptBody via
// Device.MsgToPacket — including AEAD Seal and header packing — so
// the pool's win on the send hot path is measured in a shape that
// matches real traffic, not only as an isolated micro-bench.
func BenchmarkEncryptBodyCompressed(b *testing.B) {
	// Silence the per-call log.Info in createMsgAssemblerData so the
	// benchmark output isn't interleaved with log lines. The log
	// package doesn't expose a getter for the current global logger,
	// so Cleanup resets to the package default (level Info, no file)
	// rather than snapshotting the prior instance. If a previous test
	// customized the logger, that customization is not restored —
	// acceptable here because no other bench in this file depends on
	// logger state.
	log.SetGlobalLogger(log.NewLogger("", log.LogLevelSilent, "", ""))
	b.Cleanup(func() {
		log.SetGlobalLogger(log.NewLogger("", log.LogLevelInfo, "", ""))
	})

	agentPrivKey := make([]byte, 32)
	for i := range agentPrivKey {
		agentPrivKey[i] = byte(i + 1)
	}
	serverPrivKey := make([]byte, 32)
	for i := range serverPrivKey {
		serverPrivKey[i] = byte(i + 33)
	}

	agentDevice := NewDevice(NHP_AGENT, agentPrivKey, nil)
	if agentDevice == nil {
		b.Fatal("failed to create agent device")
	}
	serverDevice := NewDevice(NHP_SERVER, serverPrivKey, nil)
	if serverDevice == nil {
		b.Fatal("failed to create server device")
	}

	serverPeer := &UdpPeer{
		PubKeyBase64: serverDevice.PublicKeyBase64(),
		Ip:           "127.0.0.1",
		Port:         12346,
		Type:         NHP_SERVER,
	}
	agentDevice.AddPeer(serverPeer)

	connData := &ConnectionData{
		Device:           agentDevice,
		LocalAddr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		RemoteAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346},
		InitTime:         time.Now().UnixNano(),
		CookieStore:      &CookieStore{},
		SendQueue:        make(chan *Packet, 16),
		RecvQueue:        make(chan *Packet, 16),
		BlockSignal:      make(chan struct{}, 1),
		SetTimeoutSignal: make(chan struct{}, 1),
		StopSignal:       make(chan struct{}),
	}

	message := bytes.Repeat([]byte("ABCDEFGHIJ"), 100)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		md := &MsgData{
			ConnData:      connData,
			PeerPk:        serverPeer.PublicKey(),
			HeaderType:    NHP_KNK,
			TransactionId: uint64(i + 1),
			Compress:      true,
			Message:       message,
		}
		mad, err := agentDevice.MsgToPacket(md)
		if err != nil {
			b.Fatalf("MsgToPacket failed: %v", err)
		}
		mad.Destroy()
	}
}

// TestGetZlibReaderResetRecovery fences the round-3 fix: after
// getZlibReader encounters either a malformed zlib header (Reset fails)
// or a valid header followed by a corrupt deflate stream (io.Copy fails
// mid-stream), the reader must still end up back in the pool so the
// next well-formed packet decompresses via the pooled instance rather
// than allocating a fresh one. Without this, an adversarial peer
// spraying malformed frames could defeat the pool on the decrypt hot
// path.
func TestGetZlibReaderResetRecovery(t *testing.T) {
	payload := bytes.Repeat([]byte("the quick brown fox "), 8)
	validCompressed := createZlibCompressed(t, payload)

	t.Run("malformed header", func(t *testing.T) {
		// Prime the pool with a usable reader.
		r, err := getZlibReader(bytes.NewReader(validCompressed))
		if err != nil {
			t.Fatalf("prime get: %v", err)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			t.Fatalf("prime copy: %v", err)
		}
		_ = r.Close()
		putZlibReader(r)

		// Reset must fail on malformed input; the reader should still
		// come back to the pool.
		badSrc := bytes.NewReader([]byte{0x00, 0x01, 0x02, 0x03})
		if _, err := getZlibReader(badSrc); err == nil {
			t.Fatal("expected error on malformed header, got nil")
		}

		// Next well-formed packet must decompress via the pool.
		r2, err := getZlibReader(bytes.NewReader(validCompressed))
		if err != nil {
			t.Fatalf("recovery get: %v", err)
		}
		var out bytes.Buffer
		if _, err := io.Copy(&out, r2); err != nil {
			t.Fatalf("recovery copy: %v", err)
		}
		_ = r2.Close()
		putZlibReader(r2)
		if !bytes.Equal(out.Bytes(), payload) {
			t.Fatalf("payload mismatch after recovery")
		}
	})

	t.Run("mid-stream corruption", func(t *testing.T) {
		// Valid zlib header (0x78 0x9c = default compression) followed
		// by garbage: Reset succeeds, io.Copy errors inside the body.
		corrupt := append([]byte{0x78, 0x9c}, bytes.Repeat([]byte{0xff}, 16)...)
		r, err := getZlibReader(bytes.NewReader(corrupt))
		if err != nil {
			t.Fatalf("expected Reset to succeed on valid header, got %v", err)
		}
		if _, err := io.Copy(io.Discard, r); err == nil {
			t.Fatal("expected io.Copy to error on corrupt deflate body")
		}
		_ = r.Close()
		putZlibReader(r)

		// Next well-formed packet must still decompress via the pool.
		r2, err := getZlibReader(bytes.NewReader(validCompressed))
		if err != nil {
			t.Fatalf("recovery get: %v", err)
		}
		var out bytes.Buffer
		if _, err := io.Copy(&out, r2); err != nil {
			t.Fatalf("recovery copy: %v", err)
		}
		_ = r2.Close()
		putZlibReader(r2)
		if !bytes.Equal(out.Bytes(), payload) {
			t.Fatalf("payload mismatch after recovery")
		}
	})
}

// TestGetZlibReaderDetachesSrcOnResetFailure fences the round-7 fix.
// On malformed input, getZlibReader returns the reader to the pool
// via putZlibReader, which Reset()s to an empty source. Without that
// detach, the pooled instance would retain a pointer to the caller's
// src (aliasing the packet buffer) across pool lifetime, keeping the
// buffer alive longer than needed.
func TestGetZlibReaderDetachesSrcOnResetFailure(t *testing.T) {
	// Prime the pool with a real reader so the target call below
	// actually exercises the Reset path. A cold pool would fall
	// through to zlib.NewReader and never touch the retention
	// invariant this test is fencing. sync.Pool makes no retention
	// promise across GC, so priming in-test is the only reliable way.
	priming := createZlibCompressed(t, []byte("prime"))
	primed, err := getZlibReader(bytes.NewReader(priming))
	if err != nil {
		t.Fatalf("prime get: %v", err)
	}
	if _, err := io.Copy(io.Discard, primed); err != nil {
		t.Fatalf("prime copy: %v", err)
	}
	_ = primed.Close()
	putZlibReader(primed)

	finalized := make(chan struct{}, 1)

	// Confine the src to an inner scope so no locals retain it after
	// this function returns. Only the pool could keep it alive.
	func() {
		src := bytes.NewReader([]byte{0x00, 0x01, 0x02, 0x03})
		runtime.SetFinalizer(src, func(_ *bytes.Reader) {
			select {
			case finalized <- struct{}{}:
			default:
			}
		})
		if _, err := getZlibReader(src); err == nil {
			t.Fatal("expected error on malformed header")
		}
	}()

	// GC+finalizer is inherently slow on loaded CI runners; 5s is a
	// conservative ceiling. Finalizers run on a separate goroutine
	// and are queued after GC, so alternate runtime.GC with a short
	// wait until the finalizer fires (or we time out).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		select {
		case <-finalized:
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("malformed src was not GC'd — pool retained a reference after Reset failure")
}

// TestPutBytesBufferScrubsBackingArray fences the security invariant
// that putBytesBuffer zeroes the full backing slice before pool-return.
// Rather than rely on sync.Pool round-tripping a specific buffer (which
// is subject to GC eviction and goroutine-to-P preemption), this test
// calls putBytesBuffer directly on a buffer we hold a reference to and
// inspects the backing array post-call. That isolates the scrub logic
// from pool-scheduling nondeterminism while still covering the exact
// code path that compressed plaintext would flow through.
func TestPutBytesBufferScrubsBackingArray(t *testing.T) {
	buf := &bytes.Buffer{}
	buf.Grow(4096)
	buf.Write(bytes.Repeat([]byte("SECRET-PAYLOAD-"), 32))
	if !bytes.Contains(buf.Bytes(), []byte("SECRET-PAYLOAD-")) {
		t.Fatal("setup: marker not present in buffer pre-return")
	}

	// Snapshot the backing array via a slice that stays alive across
	// the Reset that putBytesBuffer performs. buf.Bytes() after Reset
	// would return an empty view; snapshotting beforehand lets us
	// observe the same storage post-scrub.
	pre := buf.Bytes()
	backing := pre[:cap(pre)]

	putBytesBuffer(buf)

	if bytes.Contains(backing, []byte("SECRET")) {
		t.Fatalf("backing array contains residue of prior payload after putBytesBuffer: %q", backing)
	}
	for _, b := range backing {
		if b != 0 {
			t.Fatalf("backing array not fully zeroed; byte=%d", b)
		}
	}
}

// TestPutBytesBufferDropsOversize fences the 64 KiB pool cap. Buffers
// that grew past maxPooledBufferSize (e.g. while absorbing a
// decompression bomb) must not be returned to the pool, otherwise
// long-running processes would retain the swollen backing array.
func TestPutBytesBufferDropsOversize(t *testing.T) {
	big := &bytes.Buffer{}
	big.Grow(maxPooledBufferSize + 1)
	if big.Cap() <= maxPooledBufferSize {
		t.Fatalf("setup: want cap > %d, got %d", maxPooledBufferSize, big.Cap())
	}
	putBytesBuffer(big)

	// Every buffer that does come back from the pool must respect the
	// cap. sync.Pool gives no ordering guarantee, so we can't prove
	// "never" for the specific oversize instance — but we can prove
	// the invariant holds for whichever buffers Get returns. 32
	// iterations is enough to cycle through sync.Pool's per-P slots
	// on any reasonable GOMAXPROCS, so a pooled oversize buffer would
	// have been sampled at least once.
	for i := 0; i < 32; i++ {
		got := getBytesBuffer()
		if got.Cap() > maxPooledBufferSize {
			t.Fatalf("Get returned buffer with cap %d > %d", got.Cap(), maxPooledBufferSize)
		}
		putBytesBuffer(got)
	}
}

// TestZlibPoolReaderConcurrent exercises zlib.Reader reuse under
// concurrent load to verify the sync.Pool + zlib.Resetter pattern is
// free of shared-state hazards.
func TestZlibPoolReaderConcurrent(t *testing.T) {
	const workers = 16
	const iters = 64
	payload := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog "), 32)
	compressed := createZlibCompressed(t, payload)

	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < iters; i++ {
				buf := getBytesBuffer()
				r, err := getZlibReader(bytes.NewReader(compressed))
				if err != nil {
					errCh <- err
					return
				}
				if _, err := io.Copy(buf, r); err != nil {
					errCh <- err
					return
				}
				_ = r.Close()
				if !bytes.Equal(buf.Bytes(), payload) {
					errCh <- errors.New("decompressed payload does not match input")
					return
				}
				putZlibReader(r)
				putBytesBuffer(buf)
			}
			errCh <- nil
		}()
	}

	for w := 0; w < workers; w++ {
		if err := <-errCh; err != nil {
			t.Fatalf("worker: %v", err)
		}
	}
}
