package utils

import (
	"encoding/base64"
	"testing"
)

// Tests ported verbatim from OpenNHP upstream (#2208). PubKeyFingerprint is the
// stable routing id a relay uses to address an upstream nhp-server cluster
// (POST /relay/{serverId}); the Go relay and the TypeScript js-agent must
// compute identical fingerprints.

func TestPubKeyFingerprintDeterministic(t *testing.T) {
	// Distinct from the golden-vector inputs (fill-0x42 and 1..32) so this test
	// exercises an independent input rather than silently re-running a vector.
	key := []byte("deterministic-input-not-a-golden-vector")
	got1 := PubKeyFingerprint(key)
	got2 := PubKeyFingerprint(key)
	if got1 != got2 {
		t.Fatalf("fingerprint not deterministic: %s vs %s", got1, got2)
	}
	if len(got1) != PubKeyFingerprintLen {
		t.Fatalf("fingerprint length = %d, want %d", len(got1), PubKeyFingerprintLen)
	}
}

func TestPubKeyFingerprintDistinct(t *testing.T) {
	a := []byte("key-a-key-a-key-a-key-a-key-a-32")
	b := []byte("key-b-key-b-key-b-key-b-key-b-32")
	fa := PubKeyFingerprint(a)
	fb := PubKeyFingerprint(b)
	if fa == fb {
		t.Fatalf("distinct keys produced same fingerprint: %s", fa)
	}
}

// TestPubKeyFingerprintCrossLanguageVectors locks in the exact strings the
// TypeScript js-agent also asserts (endpoints/js-agent/test/fingerprint.test.ts,
// landed in #2208 P6). Each suite pins its own implementation to the same two
// constants, in its own toolchain -- the Go test never runs the TS code and the
// js-agent CI job never runs Go. The two copies no longer drift silently:
// scripts/check-golden-vectors.sh (wired into CI) extracts the marked
// consts below and the js-agent test's, and fails if they disagree -- so a
// one-sided algorithm change (hash, prefix length, or base64 variant) is caught
// at PR time. Keep each nhp-golden-vector label matched with the TS test.
func TestPubKeyFingerprintCrossLanguageVectors(t *testing.T) {
	const wantFill0x42 = "Ql7U5KNrMOo" // nhp-golden-vector: fill-0x42
	const wantSeq1To32 = "riFsLvUkejc" // nhp-golden-vector: seq-1to32

	filled := make([]byte, 32)
	for i := range filled {
		filled[i] = 0x42
	}
	if got := PubKeyFingerprint(filled); got != wantFill0x42 {
		t.Fatalf("fill(0x42) fingerprint = %q, want %q", got, wantFill0x42)
	}

	seq := make([]byte, 32)
	for i := range seq {
		seq[i] = byte(i + 1)
	}
	if got := PubKeyFingerprint(seq); got != wantSeq1To32 {
		t.Fatalf("[1..32] fingerprint = %q, want %q", got, wantSeq1To32)
	}
}

func TestPubKeyFingerprintFromBase64(t *testing.T) {
	raw := []byte("the-quick-brown-fox-jumps-over-32")
	want := PubKeyFingerprint(raw)
	got, err := PubKeyFingerprintFromBase64(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("FromBase64 mismatch: got %s want %s", got, want)
	}

	if _, err := PubKeyFingerprintFromBase64("!!!not-base64!!!"); err == nil {
		t.Fatalf("expected error for invalid base64 input")
	}
}
