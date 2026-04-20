package verifier

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"runtime"
	"testing"
)

func TestFallbackVerifier_Fields(t *testing.T) {
	v := &FallbackVerifier{
		Measure:      "test-measure",
		SerialNumber: "test-sn",
	}
	if got := v.GetMeasure(); got != "test-measure" {
		t.Errorf("GetMeasure() = %q, want %q", got, "test-measure")
	}
	if got := v.GetSerialNumber(); got != "test-sn" {
		t.Errorf("GetSerialNumber() = %q, want %q", got, "test-sn")
	}
}

// Happy-path fence — round-trips a real attestation JSON so a future
// rename or accessor bug fails loudly. The bomb/boundary tests only
// exercise error paths; without this the good path could silently break.
func TestNewVerifier_ValidPayload(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(zlibCompress(t, []byte(`{"measure":"m-42","serial_number":"sn-42"}`)))
	v, err := NewVerifier(b64)
	if err != nil {
		t.Fatalf("NewVerifier on valid payload: %v", err)
	}
	if err := v.Verify(); err != nil {
		t.Errorf("Verify() = %v, want nil", err)
	}
	if got := v.GetMeasure(); got != "m-42" {
		t.Errorf("GetMeasure() = %q, want %q", got, "m-42")
	}
	if got := v.GetSerialNumber(); got != "sn-42" {
		t.Errorf("GetSerialNumber() = %q, want %q", got, "sn-42")
	}
}

// Uses TotalAlloc (not HeapAlloc) so GC timing doesn't influence the delta.
// Don't t.Parallel() — TotalAlloc is process-wide. If any test in this
// package ever adds t.Parallel(), this bomb test will start to flake
// because a sibling's allocations will land inside the baseline window.
// In that case: extract this test to a separate file with a build
// constraint (`//go:build !parallel`), or move it behind the shared
// decompression helper tracked in #1196.
func TestNewVerifier_DecompressionBombRejected(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	zeros := make([]byte, 1024*1024)
	for i := 0; i < 64; i++ {
		if _, err := zw.Write(zeros); err != nil {
			t.Fatalf("zlib Write on iteration %d: %v", i, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib Close: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(zbuf.Bytes())

	// Clear carryover from prior tests in the binary so the TotalAlloc
	// baseline reflects only what NewVerifier allocates below.
	runtime.GC()

	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	_, err := NewVerifier(b64)
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	if !errors.Is(err, ErrVerifierPayloadTooLarge) {
		t.Fatalf("NewVerifier on a 64 MB decompressed payload returned %v, want ErrVerifierPayloadTooLarge", err)
	}
	// Pre-fix shape crossed 60 MB on the same input; 8 MiB catches regressions.
	const ceiling = 8 * 1024 * 1024
	if delta := int64(m1.TotalAlloc - m0.TotalAlloc); delta > ceiling {
		t.Errorf("NewVerifier allocated %d bytes; ceiling %d — cap may have regressed", delta, ceiling)
	}
}

// Pins the cap at exactly maxVerifierPayload: a regression lowering it would
// fail the at-cap subtest, a regression raising it would fail the over-cap.
func TestNewVerifier_CapBoundary(t *testing.T) {
	t.Run("at cap does not trigger size error", func(t *testing.T) {
		payload := bytes.Repeat([]byte{' '}, maxVerifierPayload)
		_, err := NewVerifier(base64.StdEncoding.EncodeToString(zlibCompress(t, payload)))
		if errors.Is(err, ErrVerifierPayloadTooLarge) {
			t.Errorf("payload at cap rejected with size error; cap may be off-by-one: %v", err)
		}
		// Payload is space-padded garbage, so the JSON stage must reject
		// it — if NewVerifier ever returned nil on this shape, the cap
		// test would pass for the wrong reason.
		if err == nil {
			t.Error("expected a JSON-stage error for space-padded payload; got nil")
		}
	})

	t.Run("one byte over cap rejected with sentinel", func(t *testing.T) {
		payload := bytes.Repeat([]byte{' '}, maxVerifierPayload+1)
		_, err := NewVerifier(base64.StdEncoding.EncodeToString(zlibCompress(t, payload)))
		if !errors.Is(err, ErrVerifierPayloadTooLarge) {
			t.Errorf("payload one byte past cap not rejected with sentinel; got %v", err)
		}
	})
}
