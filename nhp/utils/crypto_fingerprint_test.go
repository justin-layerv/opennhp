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
// TypeScript js-agent must assert (its own fingerprint test, ported in a later
// #2208 phase -- the js-agent does not exist in this repo yet, so for now these
// vectors stand on their own). Once both sides exist they assert the same
// constants; if either changes algorithm -- hash, prefix length, or base64
// variant -- they break before a divergent build can ship.
func TestPubKeyFingerprintCrossLanguageVectors(t *testing.T) {
	// TODO(#2208): once the js-agent lands (P6), assert these same vectors in
	// its fingerprint test so the cross-language contract is enforced on both
	// sides, not just Go.
	filled := make([]byte, 32)
	for i := range filled {
		filled[i] = 0x42
	}
	if got := PubKeyFingerprint(filled); got != "Ql7U5KNrMOo" {
		t.Fatalf("fill(0x42) fingerprint = %q, want %q", got, "Ql7U5KNrMOo")
	}

	seq := make([]byte, 32)
	for i := range seq {
		seq[i] = byte(i + 1)
	}
	if got := PubKeyFingerprint(seq); got != "riFsLvUkejc" {
		t.Fatalf("[1..32] fingerprint = %q, want %q", got, "riFsLvUkejc")
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
