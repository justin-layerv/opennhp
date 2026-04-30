package server

import (
	"strings"
	"testing"
)

// FuzzVerifyACPubkeyRevoked throws random presented strings at random
// list shapes and asserts the kernel never panics and never returns an
// unknown verdict. The kernel's whitespace-trim + linear scan are
// straightforward today, but #1507 cr round 15 flagged that fuzzing
// is cheap and would catch any future panic-prone refactor of the
// trim path (e.g., switching to a normalization library that mishandles
// invalid UTF-8 / over-long strings / null bytes).
//
// Seeds cover the boundary cases the kernel doc claims: empty
// presented, empty-list-entry, whitespace, URL-safe-vs-std base64,
// long inputs, and multi-element lists. The fuzzer should explore
// from there.
func FuzzVerifyACPubkeyRevoked(f *testing.F) {
	f.Add("", "")
	f.Add("AAAA", "")
	f.Add("", "AAAA")
	f.Add("AAAA", "AAAA")
	f.Add(" AAAA ", "AAAA")
	f.Add("AAAA\n", "AAAA")
	f.Add("AAAA", "AAAA\nBBBB\n")
	f.Add("AB-_", "AB+/") // url-safe vs std — must not normalize
	f.Add(strings.Repeat("A", 4096), "AAAA")
	f.Add("\x00", "\x00")
	f.Add("\xff\xfe", "AAAA")
	f.Add("AAAA", "\nAAAA\t")

	f.Fuzz(func(t *testing.T, presented, listJoined string) {
		// 128KB cap on the joined list keeps the fuzzer focused on
		// kernel logic rather than memory pressure.
		if len(listJoined) > 128*1024 || len(presented) > 4096 {
			return
		}
		// Newline-split the joined string into a list. Mirrors how an
		// operator might paste a multi-line set of revoked pubkeys.
		var revoked []string
		if listJoined != "" {
			revoked = strings.Split(listJoined, "\n")
		}
		got := verifyACPubkeyRevoked(presented, revoked)
		switch got {
		case verdictACPubkeyRevokeOK, verdictACPubkeyRevokeRevoked:
			// expected
		default:
			t.Fatalf("verifyACPubkeyRevoked(%q, %v) returned unknown verdict %v",
				presented, revoked, got)
		}
	})
}
