package core

import (
	"bytes"
	"compress/zlib"
	"io"
	"runtime"
	"sync"
)

// maxPooledBufferSize caps the size of buffers we return to the pool.
// Well-formed NHP packets fit within PacketBufferSize (4 KiB); the 16×
// multiplier leaves headroom for compressible payloads that expand
// temporarily during decompression while still capping retention well
// below the MaxDecompressedBodySize decompression ceiling.
// Legitimate payloads that decompress to >64 KiB are uncommon in NHP
// (the on-wire packet is itself capped at PacketBufferSize) but not
// illegal; such buffers are scrubbed and dropped rather than retained.
// The cap is about bounding steady-state pool memory, not rejecting
// traffic.
const maxPooledBufferSize = 16 * PacketBufferSize

// zlibWriterPool reuses zlib.Writer instances across encryptBody() calls.
// A fresh *zlib.Writer carries ~4KB of internal state (sliding window,
// deflate tables, bit buffer), so pooling eliminates that allocation on
// the hot packet-send path.
var zlibWriterPool = sync.Pool{
	New: func() any {
		// zlib.NewWriterLevel only returns an error on an invalid
		// compression level; DefaultCompression is always valid. Panic
		// if that invariant ever breaks so the pool never hands out
		// a nil writer that would crash on first use.
		w, err := zlib.NewWriterLevel(io.Discard, zlib.DefaultCompression)
		if err != nil {
			panic("zlib.NewWriterLevel with DefaultCompression failed: " + err.Error())
		}
		return w
	},
}

// zlibReaderPool reuses zlib.Reader instances across decryptBody() calls.
// zlib.NewReader reads the 2-byte header and allocates a ~32KB inflate
// window on every call; reusing via zlib.Resetter amortizes both costs.
// The pool stores io.ReadCloser because the stdlib constructor returns
// that interface; each stored value also satisfies zlib.Resetter.
// No New func is set — unlike the writer, the reader's constructor needs
// a real source to parse the header, so a cold Get() returns nil and
// getZlibReader handles first-use construction inline.
var zlibReaderPool sync.Pool

// nopReader is a stateless reader that always returns EOF. Handed to
// zlib.Resetter.Reset when pool-returning a reader so the pooled
// instance does not retain a pointer to the caller's src. Stateless
// (zero fields) so concurrent calls from multiple putZlibReader
// invocations are race-free by construction. Implements both Read and
// ReadByte so zlib's Reset satisfies its flate.Reader type assertion
// directly, avoiding the ~4 KiB bufio.NewReader wrap that would
// otherwise happen on every pool-return.
type nopReader struct{}

func (nopReader) Read([]byte) (int, error) { return 0, io.EOF }
func (nopReader) ReadByte() (byte, error)  { return 0, io.EOF }

var emptyReader io.Reader = nopReader{}

// bytesBufferPool reuses *bytes.Buffer for both compress and decompress
// paths. Reset() zeroes length but keeps capacity, so reuse avoids
// re-growing the backing array on subsequent packets.
var bytesBufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func getZlibWriter(w io.Writer) *zlib.Writer {
	zw := zlibWriterPool.Get().(*zlib.Writer)
	zw.Reset(w)
	return zw
}

// putZlibWriter returns a writer to the pool. Reset(io.Discard) clears
// any pending internal state, detaches the writer from the caller's
// buffer, and discards any buffered-but-unflushed compressed data.
// Both are safe here: on the success path Close has already been
// called so no data is pending, and on the error path we are
// abandoning the write by design. Calling this after a Write/Close
// error is fine: Reset unconditionally restores the writer to an
// initial usable state.
func putZlibWriter(zw *zlib.Writer) {
	zw.Reset(io.Discard)
	zlibWriterPool.Put(zw)
}

// getZlibReader returns a reader wrapping src. On first use for a given
// pool slot the constructor runs (which reads the zlib header); on reuse
// Reset() is used, which is a fixed-size operation. A Reset failure
// (e.g. malformed zlib header) is returned directly — we do not retry
// via zlib.NewReader because src has already been advanced past the
// bad header and a second attempt would surface the same error. The
// reader itself is returned to the pool even on Reset failure: a failed
// Reset does not corrupt internal state, so the reader is still usable
// for the next well-formed packet. This matters under adversarial input
// where malformed frames would otherwise defeat the pool.
func getZlibReader(src io.Reader) (io.ReadCloser, error) {
	v := zlibReaderPool.Get()
	if v == nil {
		return zlib.NewReader(src)
	}
	rc := v.(io.ReadCloser)
	if err := rc.(zlib.Resetter).Reset(src, nil); err != nil {
		// Route through putZlibReader so the pooled instance doesn't
		// retain a reference to the caller's src (which aliases the
		// packet buffer) across pool lifetime. zlib.Resetter.Reset
		// has no precondition on prior state, so the second Reset
		// inside putZlibReader is safe after this failed one.
		putZlibReader(rc)
		return nil, err
	}
	return rc, nil
}

// putZlibReader returns a reader to the pool. Caller must have drained
// or intentionally abandoned the stream; zlib.Resetter.Reset on next
// Get() will re-point it at a new source. Reset to the package-level
// emptyReader here so the pooled reader does not retain a reference to
// the caller's src (which aliases the packet buffer) across pool
// lifetime, mirroring putZlibWriter's Reset(io.Discard).
//
// The Reset call intentionally fails at the header-read step (EOF
// source has no bytes to parse), but the detach happens first:
// zlib.Reset reassigns z.r to the new source before attempting the
// header read, so the caller's src is released regardless. The next
// getZlibReader will Reset against a real source and restore the
// reader to usable state. The error is ignored for that reason.
//
// The type assertion is load-bearing on the stdlib contract: every
// value the pool holds came from zlib.NewReader or getZlibReader,
// both of which return a *zlib.Reader that implements zlib.Resetter.
func putZlibReader(rc io.ReadCloser) {
	_ = rc.(zlib.Resetter).Reset(emptyReader, nil)
	zlibReaderPool.Put(rc)
}

func getBytesBuffer() *bytes.Buffer {
	buf := bytesBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func putBytesBuffer(buf *bytes.Buffer) {
	// Scrub the full backing array on every call — including the
	// bomb path below where we drop the buffer from the pool. NHP is
	// security-critical; plaintext (including decompression-bomb
	// output up to MaxDecompressedBodySize) is cleared before the
	// buffer becomes GC-eligible. Reset first to realign the read
	// offset so the returned view spans the entire backing slice.
	buf.Reset()
	b := buf.Bytes()
	SetZero(b[:cap(b)])

	if buf.Cap() > maxPooledBufferSize {
		// Oversize buffer: dropped from the pool to bound retention
		// well below the MaxDecompressedBodySize ceiling. Already
		// scrubbed above, so it can become GC-eligible safely. Keep
		// buf alive across the SetZero call so a sufficiently clever
		// compiler cannot elide the zeroing as dead stores to
		// unreachable memory.
		runtime.KeepAlive(buf)
		return
	}
	bytesBufferPool.Put(buf)
}
