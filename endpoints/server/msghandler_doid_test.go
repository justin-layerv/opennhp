// These tests mutate the package-level ExeDirPath via t.Cleanup and
// therefore cannot run with t.Parallel(). Other parallel tests in this
// package (udpserver_test.go, httpserver_test.go, etc.) are safe only
// because they don't touch ExeDirPath — the real invariant is "any
// test that mutates ExeDirPath must not be parallel". If a future
// test under this constraint needs t.Parallel(), ExeDirPath needs to
// become an injectable parameter first; the current global mutation
// would race with any concurrent reader.
package server

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestValidateDoID(t *testing.T) {
	cases := []struct {
		name  string
		doId  string
		valid bool
	}{
		{"simple alphanumeric", "object123", true},
		{"with hyphen", "object-123", true},
		{"with underscore", "object_123", true},
		{"mixed case", "ObjectABC_123", true},
		{"max length 64 chars", strings.Repeat("a", 64), true},
		// UUIDs are the production DoId shape (google/uuid .String() is 36
		// chars of [a-f0-9-]). Positive-pinning the RFC-4122 shape means a
		// future regex tightening — e.g., dropping the hyphen class to
		// lock out `foo-bar` — would break a real production payload and
		// fail this test instead of silently breaking prod.
		{"RFC-4122 UUID shape", "550e8400-e29b-41d4-a716-446655440000", true},
		{"empty is rejected", "", false},
		{"65 chars is too long", strings.Repeat("a", 65), false},
		// Traversal shapes — all hit the same "char not in [a-zA-Z0-9_-]" branch,
		// but each is a named threat that deserves an explicit fence.
		{"parent traversal", "../etc/evil", false},
		{"absolute path", "/etc/evil", false},
		{"double dot", "..", false},
		// Bare path separator without `..` — pins the intent that any
		// separator is rejected, not just traversal sequences.
		{"bare forward slash", "foo/bar", false},
		// Shapes that bypass filepath.Base-only defenses — regex catches them.
		{"null byte", "evil\x00json", false},
		{"backslash", "path\\to\\file", false},
		{"unicode directory separator U+2044", "a\u2044b", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := common.ValidateDoID(tc.doId)
			if tc.valid && err != nil {
				t.Errorf("ValidateDoID(%q) returned error %v, want nil", tc.doId, err)
			}
			if !tc.valid {
				if err == nil {
					t.Errorf("ValidateDoID(%q) returned nil, want error", tc.doId)
				} else if !errors.Is(err, common.ErrInvalidDoID) {
					// Every downstream caller (db/utils.go,
					// msghandler.go) uses errors.Is against the sentinel
					// to classify the failure. A future refactor that
					// wrapped or replaced the sentinel would pass the
					// "err != nil" check but silently break the contract.
					t.Errorf("ValidateDoID(%q) = %v, want sentinel ErrInvalidDoID (errors.Is must succeed)", tc.doId, err)
				}
			}
		})
	}
}

func TestSaveZdtoConfig_RejectsPathTraversal(t *testing.T) {
	origExeDir := ExeDirPath
	t.Cleanup(func() { ExeDirPath = origExeDir })
	ExeDirPath = t.TempDir()

	err := SaveZdtoConfig(&common.DRGMsg{DoId: "foo/../../../bar"})
	if err == nil {
		t.Fatal("SaveZdtoConfig accepted a traversal DoId")
	}
	// Use errors.Is so callers can programmatically distinguish this
	// class of failure — and so this test pins that the sentinel is
	// stable. No attacker-supplied bytes are echoed in the wire error.
	if !errors.Is(err, common.ErrInvalidDoID) {
		t.Errorf("error %v is not common.ErrInvalidDoID — wire error must be the fixed sentinel", err)
	}
	// Exact-match against the sentinel string fences the "someone
	// widened the error by formatting the rejected DoId back in"
	// regression class in one shot. A substring check for ".." only
	// catches traversal-shaped inputs; this pins the full wire text.
	if err.Error() != common.ErrInvalidDoID.Error() {
		t.Errorf("wire error %q != sentinel %q — attacker DoId bytes may be leaking", err.Error(), common.ErrInvalidDoID.Error())
	}

	// Broken validator that errored after writing would slip past a
	// string-only assertion; fence the filesystem too.
	etcDir := filepath.Join(ExeDirPath, "etc", "ztdo")
	if _, err := os.Stat(etcDir); err == nil {
		entries, _ := os.ReadDir(etcDir)
		if len(entries) > 0 {
			t.Errorf("etcDir %q was populated despite rejection: %v", etcDir, entries)
		}
	}
}

func TestSaveZdtoConfig_AcceptsValidDoId(t *testing.T) {
	origExeDir := ExeDirPath
	t.Cleanup(func() { ExeDirPath = origExeDir })
	ExeDirPath = t.TempDir()

	if err := SaveZdtoConfig(&common.DRGMsg{DoId: "legit-object-123"}); err != nil {
		t.Fatalf("SaveZdtoConfig rejected a valid DoId: %v", err)
	}
	expected := filepath.Join(ExeDirPath, "etc", "ztdo", "data-legit-object-123.json")
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("expected config file at %q, got: %v", expected, err)
	}
}

func TestReadZdtoConfig_RejectsPathTraversal(t *testing.T) {
	origExeDir := ExeDirPath
	t.Cleanup(func() { ExeDirPath = origExeDir })
	ExeDirPath = t.TempDir()

	_, err := ReadZdtoConfig("foo/../../../bar")
	if err == nil {
		t.Fatal("ReadZdtoConfig accepted a traversal DoId")
	}
	if !errors.Is(err, common.ErrInvalidDoID) {
		t.Errorf("error %v is not common.ErrInvalidDoID — wire error must be the fixed sentinel", err)
	}
}

// Fences the path-leak fix: a validated-but-unknown DoId causes
// os.Open to fail with a *PathError that wraps the full filesystem
// path. ReadZdtoConfig now scrubs that inside the function — the raw
// error goes to the server log, but the error returned to callers is
// the fixed errReadConfigFailed sentinel with no filesystem bytes.
// This test pins that contract so a future refactor that re-exposes
// the raw PathError fails fast.
func TestReadZdtoConfig_MissingFileScrubsPath(t *testing.T) {
	origExeDir := ExeDirPath
	t.Cleanup(func() { ExeDirPath = origExeDir })
	ExeDirPath = t.TempDir()

	_, err := ReadZdtoConfig("validbutunknown")
	if err == nil {
		t.Fatal("ReadZdtoConfig accepted a missing DoId")
	}
	if !errors.Is(err, errReadConfigFailed) {
		t.Errorf("error %v is not errReadConfigFailed — scrub regressed", err)
	}
	// Fail if the error text still contains filesystem-layout bytes.
	// Anchor on substrings that would only appear if the raw PathError
	// leaked through: the filename, the tempdir prefix, the "etc/ztdo"
	// segment, or the common "no such file" phrase.
	for _, leak := range []string{"data-validbutunknown.json", "etc/ztdo", ExeDirPath, "no such file"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q — scrub regressed", err.Error(), leak)
		}
	}
}
