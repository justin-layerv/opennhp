package ac

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const sessionControlGenerationRelativePath = "state/session-control-generation"

func readSessionControlGeneration(path string) (uint64, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	text := string(raw)
	if strings.TrimSpace(text) != text || text == "" || (len(text) > 1 && text[0] == '0') {
		return 0, errors.New("session-control generation state is not canonical")
	}
	for _, ch := range text {
		if ch < '0' || ch > '9' {
			return 0, errors.New("session-control generation state is not canonical")
		}
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("session-control generation state is not a positive uint64")
	}
	return value, nil
}

func persistSessionControlGeneration(path string, generation uint64) error {
	if generation == 0 {
		return errors.New("cannot persist zero session-control generation")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create session-control state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".session-control-generation-*")
	if err != nil {
		return fmt.Errorf("create session-control state temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod session-control state temp file: %w", err)
	}
	if _, err := tmp.WriteString(strconv.FormatUint(generation, 10)); err != nil {
		return fmt.Errorf("write session-control generation: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync session-control generation: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close session-control generation: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace session-control generation: %w", err)
	}
	cleanup = false
	return syncSessionControlGenerationDirectory(dir)
}

func syncSessionControlGenerationDirectory(dir string) error {
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open session-control state directory: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync session-control state directory: %w", err)
	}
	return nil
}

// reserveBootSessionControlGeneration durably advances the process incarnation
// before boot teardown. A crash after persistence but before readiness merely
// burns a generation; the next boot advances again and remains monotonic.
func reserveBootSessionControlGeneration(dir string) (uint64, error) {
	path := filepath.Join(dir, sessionControlGenerationRelativePath)
	current, err := readSessionControlGeneration(path)
	if err != nil {
		return 0, err
	}
	if current == math.MaxUint64 {
		return 0, errors.New("session-control generation exhausted")
	}
	next := current + 1
	if err := persistSessionControlGeneration(path, next); err != nil {
		return 0, err
	}
	return next, nil
}

// reserveGapSessionControlGeneration advances one already-running AC. A retry
// after an ambiguous post-rename error accepts an on-disk current+1 value; any
// other drift is corrupt/foreign state and fails closed.
func reserveGapSessionControlGeneration(dir string, current uint64) (uint64, error) {
	return reserveGapSessionControlGenerationWithSync(dir, current, syncSessionControlGenerationDirectory)
}

func reserveGapSessionControlGenerationWithSync(dir string, current uint64, syncDir func(string) error) (uint64, error) {
	if current == 0 || current == math.MaxUint64 {
		return 0, errors.New("invalid current session-control generation")
	}
	if syncDir == nil {
		return 0, errors.New("nil session-control directory sync function")
	}
	path := filepath.Join(dir, sessionControlGenerationRelativePath)
	persisted, err := readSessionControlGeneration(path)
	if err != nil {
		return 0, err
	}
	if persisted == current+1 {
		// This is the ambiguous retry branch: the preceding attempt may have
		// renamed the new value into place but failed its parent-directory fsync.
		// Do not advertise the new authority generation until that directory
		// entry has been made durable by a successful retry.
		if err := syncDir(filepath.Dir(path)); err != nil {
			return 0, fmt.Errorf("resync session-control state directory: %w", err)
		}
		return persisted, nil
	}
	if persisted != current {
		return 0, fmt.Errorf("session-control generation state mismatch: persisted=%d current=%d", persisted, current)
	}
	next := current + 1
	if err := persistSessionControlGeneration(path, next); err != nil {
		return 0, err
	}
	return next, nil
}
