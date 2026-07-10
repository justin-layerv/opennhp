package internalauth

import (
	"encoding/base64"
	"testing"
)

// TestPubKeyFingerprintVectors pins the exact output of this module's copy of
// the fingerprint against the same two repo-defined vectors the nhp/utils and
// js-agent suites assert (nhp/utils/crypto_fingerprint_test.go and
// endpoints/js-agent/test/fingerprint.test.ts carry them with
// `nhp-golden-vector` labels; scripts/check-golden-vectors.sh cross-checks
// THAT Go↔TS pair textually). This module's copy is deliberately NOT wired
// into that script: its drift fence is the compile-and-run lockstep test in
// endpoints/relay/pubkey_fingerprint_lockstep_test.go, which asserts equality
// with utils.PubKeyFingerprint over random inputs — stronger than a text
// extraction. The hand-copied constants below exist so this stdlib-only module
// still fails its OWN test suite (which external consumers like qurl-service
// run via `go test` of their pinned module version) if the construction here
// changes, without needing the nhp repo checked out.
func TestPubKeyFingerprintVectors(t *testing.T) {
	const wantFill0x42 = "Ql7U5KNrMOo" // fill-0x42, copied from the labeled vector
	const wantSeq1To32 = "riFsLvUkejc" // seq-1to32, copied from the labeled vector

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

func TestPubKeyFingerprintLength(t *testing.T) {
	got := PubKeyFingerprint([]byte("length-check-input-not-a-real-key"))
	if len(got) != PubKeyFingerprintLen {
		t.Fatalf("fingerprint length = %d, want %d", len(got), PubKeyFingerprintLen)
	}
}

func TestPubKeyFingerprintFromBase64(t *testing.T) {
	raw := []byte("internalauth-fromb64-roundtrip-32")
	want := PubKeyFingerprint(raw)
	got, err := PubKeyFingerprintFromBase64(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("FromBase64 mismatch: got %s want %s", got, want)
	}

	if _, err := PubKeyFingerprintFromBase64("!!!not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64 input")
	}
}
