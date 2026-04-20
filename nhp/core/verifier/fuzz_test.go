package verifier

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"testing"
)

// FuzzNewVerifier exercises base64 -> zlib -> JSON decode in NewVerifier.
// Evidence is attacker-influenced in the DHP_KNK flow (post-auth,
// pre-policy), so panics here become a remote DoS. Seed corpus covers
// each decode-stage boundary. The decompression-cap is fenced separately
// by TestNewVerifier_DecompressionBombRejected.
func FuzzNewVerifier(f *testing.F) {
	// Seed boundary cases: all-good, garbage JSON, truncated zlib body,
	// empty-valid-JSON, empty string, bad base64, bare zlib header.
	good := zlibCompress(f, []byte(`{"measure":"m","serial_number":"s"}`))
	f.Add(base64.StdEncoding.EncodeToString(good))
	f.Add(base64.StdEncoding.EncodeToString(zlibCompress(f, []byte(`{"measure":}`))))
	f.Add(base64.StdEncoding.EncodeToString(good[:5])) // truncated mid-zlib
	f.Add(base64.StdEncoding.EncodeToString(zlibCompress(f, []byte(`{}`))))
	f.Add("")
	f.Add("!!!not_base64!!!")
	f.Add(base64.StdEncoding.EncodeToString([]byte{0x78, 0x9c})) // bare zlib header

	f.Fuzz(func(t *testing.T, b64 string) {
		// 8 KB keeps per-execution cost low; the real bomb defense lives
		// in NewVerifier's maxVerifierPayload cap.
		if len(b64) > 8192 {
			return
		}
		v, err := NewVerifier(b64)
		if err != nil || v == nil {
			return
		}
		// Exercise every interface method so a future Verifier
		// implementation's panic also gets caught here.
		_ = v.Verify()
		_ = v.GetMeasure()
		_ = v.GetSerialNumber()
	})
}

// zlibCompress seed-corpus helper — explicit BestSpeed so seed bytes stay
// stable across Go versions if zlib.DefaultCompression's underlying default
// ever changes.
func zlibCompress(t testing.TB, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
	if err != nil {
		t.Fatalf("zlib.NewWriterLevel: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}
