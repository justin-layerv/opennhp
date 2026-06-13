package utils

import "testing"

func TestSHA256(t *testing.T) {
	// Known NIST vector for "abc".
	const wantABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := SHA256("abc"); got != wantABC {
		t.Fatalf("SHA256(\"abc\") = %q, want %q", got, wantABC)
	}

	got := SHA256("some-secret-value")
	if len(got) != 64 {
		t.Fatalf("SHA256 length = %d, want 64 lowercase hex chars", len(got))
	}
	if got == "some-secret-value" {
		t.Fatal("SHA256 returned the input verbatim")
	}
	if got != SHA256("some-secret-value") {
		t.Fatal("SHA256 is not deterministic")
	}
}
