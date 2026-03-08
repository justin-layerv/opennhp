package server

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/utils"
)

// setupTestMetadataDir creates a temporary directory tree that mimics the
// layout expected by loadMetadata / saveMetadata (ExeDirPath + metadataDir).
// It returns the temp root (set as ExeDirPath) and a cleanup function.
func setupTestMetadataDir(t *testing.T) (string, func()) {
	t.Helper()
	tmpDir := t.TempDir()

	// Save and restore package-level state.
	origExeDir := ExeDirPath
	origIndex := md5Index
	origCachedDir := cachedMetadataDirAbs
	ExeDirPath = tmpDir
	md5Index = make(map[string]string)
	cachedMetadataDirAbs = ""

	metaDir := filepath.Join(tmpDir, metadataDir)
	if err := os.MkdirAll(metaDir, os.ModePerm); err != nil {
		t.Fatalf("failed to create metadata dir: %v", err)
	}

	return tmpDir, func() {
		ExeDirPath = origExeDir
		md5Index = origIndex
		cachedMetadataDirAbs = origCachedDir
	}
}

// writeMetadataFile writes a FileMetadata JSON file directly to disk,
// bypassing saveMetadata (useful for testing initMD5Index independently).
func writeMetadataFile(t *testing.T, meta FileMetadata) {
	t.Helper()
	metaPath := filepath.Join(ExeDirPath, metadataDir, meta.UUID+".json")
	if err := utils.SaveStructAsJsonFile(metaPath, meta); err != nil {
		t.Fatalf("failed to write metadata file: %v", err)
	}
}

// --- initMD5Index tests ---

func TestInitMD5Index_PopulatesFromDisk(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	files := []FileMetadata{
		{UUID: "uuid-1", MD5: "aaa111", Original: "a.txt", Path: "uuid-1/a.txt", Size: 10},
		{UUID: "uuid-2", MD5: "bbb222", Original: "b.txt", Path: "uuid-2/b.txt", Size: 20},
		{UUID: "uuid-3", MD5: "ccc333", Original: "c.txt", Path: "uuid-3/c.txt", Size: 30},
	}
	for _, m := range files {
		writeMetadataFile(t, m)
	}

	initMD5Index()

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 3 {
		t.Fatalf("expected 3 index entries, got %d", len(md5Index))
	}
	for _, m := range files {
		got, ok := md5Index[m.MD5]
		if !ok {
			t.Errorf("md5 %q missing from index", m.MD5)
		}
		if got != m.UUID {
			t.Errorf("md5 %q: expected uuid %q, got %q", m.MD5, m.UUID, got)
		}
	}
}

func TestInitMD5Index_EmptyDir(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	initMD5Index()

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 0 {
		t.Fatalf("expected 0 index entries for empty dir, got %d", len(md5Index))
	}
}

func TestInitMD5Index_SkipsNonJSON(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	// Write a valid metadata file.
	writeMetadataFile(t, FileMetadata{UUID: "uuid-1", MD5: "aaa111"})

	// Write a non-JSON file that should be ignored.
	nonJSON := filepath.Join(ExeDirPath, metadataDir, "README.txt")
	if err := os.WriteFile(nonJSON, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	initMD5Index()

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 1 {
		t.Fatalf("expected 1 index entry, got %d", len(md5Index))
	}
}

func TestInitMD5Index_SkipsCorruptJSON(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	// Write a corrupt JSON file.
	corruptPath := filepath.Join(ExeDirPath, metadataDir, "corrupt-uuid.json")
	if err := os.WriteFile(corruptPath, []byte("{invalid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a valid file.
	writeMetadataFile(t, FileMetadata{UUID: "uuid-1", MD5: "aaa111"})

	initMD5Index()

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 1 {
		t.Fatalf("expected 1 index entry (skipping corrupt), got %d", len(md5Index))
	}
}

// --- checkFileExists tests ---

func TestCheckFileExists_Found(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	meta := FileMetadata{UUID: "uuid-1", MD5: "abc123", Original: "file.txt", Path: "uuid-1/file.txt", Size: 100}
	writeMetadataFile(t, meta)
	initMD5Index()

	got, found := checkFileExists("abc123")
	if !found {
		t.Fatal("expected file to be found")
	}
	if got.UUID != meta.UUID {
		t.Errorf("expected UUID %q, got %q", meta.UUID, got.UUID)
	}
	if got.MD5 != meta.MD5 {
		t.Errorf("expected MD5 %q, got %q", meta.MD5, got.MD5)
	}
}

func TestCheckFileExists_NotFound(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	initMD5Index()

	_, found := checkFileExists("nonexistent-hash")
	if found {
		t.Fatal("expected file not to be found")
	}
}

func TestCheckFileExists_StaleEntry(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	// Populate index with an entry whose metadata file does not exist on disk.
	md5IndexMu.Lock()
	md5Index["stale-hash"] = "missing-uuid"
	md5IndexMu.Unlock()

	_, found := checkFileExists("stale-hash")
	if found {
		t.Fatal("expected stale entry to return not found")
	}

	// Verify the stale entry was cleaned up.
	md5IndexMu.RLock()
	_, stillThere := md5Index["stale-hash"]
	md5IndexMu.RUnlock()

	if stillThere {
		t.Error("stale index entry should have been removed")
	}
}

// --- saveMetadata index update tests ---

func TestSaveMetadata_UpdatesIndex(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	meta := FileMetadata{
		UUID:      "uuid-save-1",
		MD5:       "save-hash-1",
		Original:  "saved.txt",
		Path:      "uuid-save-1/saved.txt",
		Size:      42,
		UploadURI: "storage/download/uuid-save-1/saved.txt",
	}
	if err := saveMetadata(meta); err != nil {
		t.Fatalf("saveMetadata failed: %v", err)
	}

	md5IndexMu.RLock()
	uuid, exists := md5Index[meta.MD5]
	md5IndexMu.RUnlock()

	if !exists {
		t.Fatal("expected MD5 to be in index after saveMetadata")
	}
	if uuid != meta.UUID {
		t.Errorf("expected UUID %q, got %q", meta.UUID, uuid)
	}

	// Verify the saved file can be loaded back correctly.
	got, found := checkFileExists(meta.MD5)
	if !found {
		t.Fatal("checkFileExists should find newly saved metadata")
	}
	if got.Original != meta.Original {
		t.Errorf("expected Original %q, got %q", meta.Original, got.Original)
	}
}

func TestSaveMetadata_EmptyMD5NotIndexed(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	meta := FileMetadata{UUID: "uuid-nohash", MD5: ""}
	if err := saveMetadata(meta); err != nil {
		t.Fatalf("saveMetadata failed: %v", err)
	}

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 0 {
		t.Error("empty MD5 should not be added to index")
	}
}

func TestSaveMetadata_DuplicateMD5OverwritesIndex(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	// Save first file with a given MD5.
	meta1 := FileMetadata{
		UUID:      "uuid-first",
		MD5:       "duplicate-hash",
		Original:  "first.txt",
		Path:      "uuid-first/first.txt",
		Size:      100,
		UploadURI: "storage/download/uuid-first/first.txt",
	}
	if err := saveMetadata(meta1); err != nil {
		t.Fatalf("saveMetadata(meta1) failed: %v", err)
	}

	// Save second file with the same MD5 but different UUID.
	meta2 := FileMetadata{
		UUID:      "uuid-second",
		MD5:       "duplicate-hash",
		Original:  "second.txt",
		Path:      "uuid-second/second.txt",
		Size:      200,
		UploadURI: "storage/download/uuid-second/second.txt",
	}
	if err := saveMetadata(meta2); err != nil {
		t.Fatalf("saveMetadata(meta2) failed: %v", err)
	}

	// Index should point to the second UUID (last-write-wins).
	md5IndexMu.RLock()
	indexedUUID := md5Index["duplicate-hash"]
	md5IndexMu.RUnlock()

	if indexedUUID != "uuid-second" {
		t.Errorf("expected index to point to uuid-second, got %q", indexedUUID)
	}

	// checkFileExists should return the second file's metadata.
	got, found := checkFileExists("duplicate-hash")
	if !found {
		t.Fatal("expected duplicate-hash to be found")
	}
	if got.UUID != "uuid-second" {
		t.Errorf("expected UUID uuid-second, got %q", got.UUID)
	}
}

// --- concurrency test ---

func TestCheckFileExists_ConcurrentSafe(t *testing.T) {
	_, cleanup := setupTestMetadataDir(t)
	defer cleanup()

	// Pre-populate several metadata files.
	const n = 50
	metas := make([]FileMetadata, n)
	for i := 0; i < n; i++ {
		m := FileMetadata{
			UUID:     fmt.Sprintf("uuid-%04d", i),
			MD5:      fmt.Sprintf("md5-%04d", i),
			Original: "file.txt",
			Path:     fmt.Sprintf("uuid-%04d/file.txt", i),
			Size:     int64(i),
		}
		writeMetadataFile(t, m)
		metas[i] = m
	}
	initMD5Index()

	var wg sync.WaitGroup
	// Concurrent readers.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			got, found := checkFileExists(metas[idx].MD5)
			if !found {
				t.Errorf("concurrent read: md5 %q not found", metas[idx].MD5)
				return
			}
			if got.UUID != metas[idx].UUID {
				t.Errorf("concurrent read: expected UUID %q, got %q", metas[idx].UUID, got.UUID)
			}
		}(i)
	}

	// Concurrent writers (saving new metadata).
	for i := n; i < n+20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			m := FileMetadata{
				UUID:      fmt.Sprintf("uuid-%04d", idx),
				MD5:       fmt.Sprintf("md5-%04d", idx),
				Original:  "new.txt",
				Path:      fmt.Sprintf("uuid-%04d/new.txt", idx),
				Size:      int64(idx),
				UploadURI: fmt.Sprintf("storage/download/uuid-%04d/new.txt", idx),
			}
			if err := saveMetadata(m); err != nil {
				t.Errorf("concurrent saveMetadata failed: %v", err)
			}
		}(i)
	}

	wg.Wait()
}
