package ac

import (
	"log"
	"os"
	"testing"
)

// TestMain seeds AWS_REGION because NewACRegistration requires it (#1659).
// Also unsets AWS_DEFAULT_REGION so a developer shell with that var set
// can't leak into tests that exercise resolver precedence.
//
// Both env mutations are intentionally process-wide for the entire test
// binary — tests in this package should assume AWS_DEFAULT_REGION is
// unset at startup. Tests that exercise the unset path use t.Setenv to
// clear AWS_REGION locally; cleanup restores the seeded value.
func TestMain(m *testing.M) {
	if err := os.Setenv("AWS_REGION", "us-east-2"); err != nil {
		log.Fatalf("TestMain: failed to seed AWS_REGION: %v", err)
	}
	if err := os.Unsetenv("AWS_DEFAULT_REGION"); err != nil {
		log.Fatalf("TestMain: failed to unset AWS_DEFAULT_REGION: %v", err)
	}
	os.Exit(m.Run())
}
