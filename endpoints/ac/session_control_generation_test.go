package ac

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSessionControlGenerationPersistsAcrossBootsAndGapRetry(t *testing.T) {
	dir := t.TempDir()
	first, err := reserveBootSessionControlGeneration(dir)
	if err != nil || first != 1 {
		t.Fatalf("first boot generation = %d, %v", first, err)
	}
	second, err := reserveBootSessionControlGeneration(dir)
	if err != nil || second != 2 {
		t.Fatalf("second boot generation = %d, %v", second, err)
	}
	gap, err := reserveGapSessionControlGeneration(dir, second)
	if err != nil || gap != 3 {
		t.Fatalf("gap generation = %d, %v", gap, err)
	}
	// A retry after persistence is idempotent for the same in-memory current.
	retry, err := reserveGapSessionControlGeneration(dir, second)
	if err != nil || retry != gap {
		t.Fatalf("gap retry generation = %d, %v, want %d", retry, err, gap)
	}
	mode, err := os.Stat(filepath.Join(dir, sessionControlGenerationRelativePath))
	if err != nil {
		t.Fatal(err)
	}
	if got := mode.Mode().Perm(); got != 0o600 {
		t.Fatalf("state mode = %o, want 600", got)
	}
}

func TestGapSessionControlGenerationAmbiguousRetryRequiresDirectorySync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, sessionControlGenerationRelativePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// Model rename success followed by a parent-directory fsync failure: the
	// incremented value is visible, but durability has not been established.
	if err := os.WriteFile(path, []byte("8"), 0o600); err != nil {
		t.Fatal(err)
	}
	syncErr := errors.New("injected directory sync failure")
	if _, err := reserveGapSessionControlGenerationWithSync(dir, 7, func(string) error {
		return syncErr
	}); !errors.Is(err, syncErr) {
		t.Fatalf("ambiguous retry error = %v, want %v", err, syncErr)
	}

	var syncedDir string
	got, err := reserveGapSessionControlGenerationWithSync(dir, 7, func(dir string) error {
		syncedDir = dir
		return nil
	})
	if err != nil || got != 8 {
		t.Fatalf("durable retry = %d, %v, want 8", got, err)
	}
	if syncedDir != filepath.Dir(path) {
		t.Fatalf("synced directory = %q, want %q", syncedDir, filepath.Dir(path))
	}
}

func TestSessionControlGenerationCorruptionAndPersistenceFailureFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, sessionControlGenerationRelativePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("01"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reserveBootSessionControlGeneration(dir); err == nil {
		t.Fatal("noncanonical generation state was accepted")
	}

	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reserveBootSessionControlGeneration(blocked); err == nil {
		t.Fatal("state-directory creation failure was accepted")
	}
}
