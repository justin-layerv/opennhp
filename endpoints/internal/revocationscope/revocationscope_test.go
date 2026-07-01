package revocationscope

import (
	"slices"
	"testing"
)

// TestAckable pins the canonical AC-ackable wire scope set to exactly
// {qurl, resource, session} and fences the structural #2793 guards: "cell" (a
// server-side fanout selector the AC drops without acking) and "admission" (an
// AC-internal index dimension) are NOT ackable. This is the single source both
// the AC apply/ack gate (wireRevocationScope) and the server proof-tracking gate
// (trackFanout) derive from, so a drift here is a drift everywhere — which is the
// point of sharing it.
func TestAckable(t *testing.T) {
	want := []string{"qurl", "resource", "session"}
	if got := All(); !slices.Equal(got, want) {
		t.Fatalf("All() = %v, want %v (canonical ackable set)", got, want)
	}
	for _, s := range want {
		if !Contains(s) {
			t.Errorf("Contains(%q) = false, want true", s)
		}
	}
	// The dangerous near-misses must be excluded — "cell" especially (the #2793
	// false-age-out scope) and "admission" (the reserved AC-internal dimension).
	for _, s := range []string{"cell", "admission", "", "Qurl", " qurl", "qurl ", "unknown"} {
		if Contains(s) {
			t.Errorf("Contains(%q) = true, want false (must not be ackable)", s)
		}
	}
	// All() must return a fresh copy: mutating the result cannot affect the source.
	cp := All()
	cp[0] = "mutated"
	if Contains("mutated") || !Contains("qurl") {
		t.Fatal("All() must return a fresh copy; the canonical source was mutated through it")
	}
}
