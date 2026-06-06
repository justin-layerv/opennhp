package utils

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// GetRandomUint32 returns a uniformly random non-zero uint32 drawn from
// the system CSPRNG (crypto/rand). Zero is excluded so the result is
// safe to use directly as an XOR mask / header preamble without a
// degenerate all-zero value.
//
// It uses crypto/rand rather than math/rand because nhp/utils is an
// exported package: today's only caller (curve header obfuscation in
// SetTypeAndPayloadSize) does not depend on unpredictability, but a
// future caller reaching for this helper as a nonce/identifier source
// gets a CSPRNG by default rather than a footgun. See issue #1133.
//
// crypto/rand.Read does not fail on supported platforms (Go 1.24+); a
// read error indicates a catastrophically broken CSPRNG, so we panic
// rather than return a predictable value from a function whose contract
// is unpredictability.
func GetRandomUint32() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(fmt.Sprintf("utils.GetRandomUint32: crypto/rand failed: %v", err))
		}
		if r := binary.BigEndian.Uint32(b[:]); r != 0 {
			return r
		}
	}
}

func CatchPanic() {
	if x := recover(); x != nil {
		for _, line := range append([]string{fmt.Sprint(x)}, strings.Split(string(debug.Stack()), "\n")...) {
			if len(strings.TrimSpace(line)) > 0 {
				log.Error("%s", line)
			}
		}
	}
}

func CatchPanicThenRun(catchFun func()) {
	if x := recover(); x != nil {
		for _, line := range append([]string{fmt.Sprint(x)}, strings.Split(string(debug.Stack()), "\n")...) {
			if len(strings.TrimSpace(line)) > 0 {
				log.Error("%s", line)
			}
		}
		if catchFun != nil {
			catchFun()
		}
	}
}

func DownloadFileToTemp(fileUrl string, pattern string) (string, error) {
	tempDir, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", err
	}

	fileName := filepath.Base(fileUrl)
	tempFilePath := filepath.Join(tempDir, fileName)

	outFile, err := os.Create(tempFilePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = outFile.Close() }()

	resp, err := http.Get(fileUrl)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download file (%s): status code %s", fileUrl, resp.Status)
	}

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return "", err
	}

	return tempFilePath, nil
}

func GenerateTempFilePath(pattern string) (string, error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}

	tempPath := file.Name()

	if err := file.Close(); err != nil {
		return "", err
	}

	return tempPath, nil
}

// IsValidPathComponent checks that a sanitized path component (from filepath.Base)
// is not empty or a special directory entry. Use after filepath.Base to validate
// user-supplied filenames and path segments.
func IsValidPathComponent(s string) bool {
	return s != "" && s != "." && s != ".."
}

// IsPathWithinDir checks that absPath is a child of dirAbs (both must be absolute).
// Use to prevent path traversal attacks after resolving paths with filepath.Abs.
func IsPathWithinDir(absPath, dirAbs string) bool {
	return strings.HasPrefix(absPath, dirAbs+string(os.PathSeparator))
}

func SaveStructAsJsonFile(filePath string, data any) error {
	if data == nil {
		return errors.New("data cannot be nil")
	}
	if filePath == "" {
		return errors.New("file path cannot be empty")
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data to JSON: %w", err)
	}

	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JSON to file: %w", err)
	}

	return nil
}

func LoadJsonFileAsStruct(filePath string) (any, error) {
	if filePath == "" {
		return nil, errors.New("file path cannot be empty")
	}

	jsonData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var data map[string]any

	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON %s to struct: %w", string(jsonData), err)
	}

	return data, nil
}

// ErrInvalidConfigPath is returned by UpdateTomlConfig when filePath
// fails the absolute/traversal gate. Exposed as a sentinel so callers
// can distinguish gate rejections from downstream I/O failures via
// errors.Is without coupling to the error message wording.
var ErrInvalidConfigPath = errors.New("UpdateTomlConfig: invalid filePath")

// UpdateTomlConfig rewrites a scalar TOML key in the file at filePath.
// Intended for service-owned config files (etc/config.toml, etc/dhp.toml)
// not user-influenced input — the defense-in-depth reject on relative-
// or traversal-bearing paths enforces that contract at runtime in
// addition to the gosec suppression below.
//
// Gate scope: the check catches lexical-path attacks (relative paths,
// component-wise "..") but does NOT resolve symlinks. A filePath that
// passes the gate but traverses a symlink pointing outside the service-
// owned directory will still be written to the symlink target. This is
// defensible under the "service-owned config path only" contract — the
// parent directory is not attacker-writable on deployed hosts — but a
// future caller that takes paths from a less-trusted source should
// additionally filepath.EvalSymlinks and recheck.
//
// Ownership semantics: the atomic write-to-temp + rename pattern
// replaces the target file rather than writing through to the
// existing inode, so the post-rename file inherits the calling
// process's uid/gid (not the original file's). No-op in production —
// the agent is the only caller and rotates its own etc/ files — but
// a future caller that rotates a file owned by a different uid must
// chown after UpdateTomlConfig or call via the owning process.
//
// Concurrency: two concurrent UpdateTomlConfig calls on the same
// filePath race at the rename boundary. Readers always see one
// consistent version (atomic rename guarantees either pre-write or
// one of the two writes), but the losing write is silently
// overwritten. In production the only caller is the agent's secret-
// rotation path, which serializes its own rotations, so this is not
// a practical hazard. A future caller that invokes UpdateTomlConfig
// from multiple goroutines against the same file must serialize
// those callers externally.
func UpdateTomlConfig(filePath string, key string, value any) error {
	if !filepath.IsAbs(filePath) {
		return fmt.Errorf("%w: must be absolute, got %q", ErrInvalidConfigPath, filePath)
	}
	// Component-wise ".." reject — a literal-substring check would
	// over-broadly reject legitimate filenames like "/etc/foo..bar.toml".
	// filepath.ToSlash normalizes Windows "\" separators to "/" so
	// the split catches mixed-separator shapes like "/etc/nhp/.." on
	// Windows too (nhp deploys to Linux-only today, but the util is
	// exported and tested on darwin/win dev boxes).
	for _, seg := range strings.Split(filepath.ToSlash(filePath), "/") {
		if seg == ".." {
			return fmt.Errorf("%w: must be free of .. segments, got %q", ErrInvalidConfigPath, filePath)
		}
	}
	content, err := os.ReadFile(filePath) //nolint:gosec // G304: filePath validated above; service-owned config paths only.
	if err != nil {
		return fmt.Errorf("UpdateTomlConfig: read: %w", err)
	}

	var newContent string

	switch value := value.(type) {
	case string:
		// QuoteMeta(key) so a future caller passing a key containing
		// regex metacharacters (`.`, `*`, `+`, `(`, `[` ...) can't
		// alter the replacement semantics. Current callers all pass
		// string literals (PrivateKeyBase64, TEEPrivateKeyBase64), so
		// this is defense-in-depth, not a present hazard.
		//
		// ReplaceAllLiteralString (not ReplaceAllString) because the
		// latter expands $1, ${name}, $$, etc. in the replacement —
		// today's values are all base64 ECDH keys with no `$`, but
		// belt-and-suspenders: a future caller passing a value with
		// `$` would otherwise get surprising expansion.
		re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*".+"\s*$`)
		newContent = re.ReplaceAllLiteralString(string(content), fmt.Sprintf("%s = \"%s\"", key, value))
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}

	// Atomic write-to-temp + rename. Rotation is writing a fresh
	// private key — a crash between "truncate-then-write" and
	// "chmod" would leave the new key on disk with the old 0644
	// mode (the exact failure mode the permission-tightening is
	// preventing). os.CreateTemp generates a unique name
	// (avoiding PID-reuse or same-process concurrent collisions),
	// creates with mode 0600, and hands back an already-open file.
	// os.Rename on the same filesystem is atomic, so either the
	// old file or the fully-written new file is visible to readers
	// at any instant.
	//
	// We sync the temp file before rename to durably capture the
	// new bytes. We deliberately DO NOT fsync the parent directory
	// — that would close the "power-loss window where the rename
	// is in page cache but not on disk" gap, but this service
	// neither runs on ephemeral storage nor tolerates the extra
	// latency; agent key-rotation on a clean shutdown is the only
	// path exercised in practice.
	//
	// Crash residue: if the process is SIGKILLed (or panics
	// non-recoverably) between tmp.Close() and os.Rename, the
	// temp file remains in `dir` at 0600 carrying the freshly
	// rotated key bytes. The file is same-owner, same-perm as
	// the target — blast radius is bounded — and a clean
	// restart either (a) re-rotates, leaving the orphan as an
	// acceptable residue, or (b) ops tooling cleans `*.tmp.*`
	// under etc/ at startup. No eager sweep on Open; filing a
	// startup-sweep enhancement would belong in agent init, not
	// this helper.
	dir := filepath.Dir(filePath)
	// os.CreateTemp creates the file with mode 0600 on Unix by
	// design (see Go stdlib docs); no explicit Chmod needed to
	// land the post-rename file at 0600.
	//
	// G304 (taint analysis on the path argument): `dir` comes from
	// the same filePath that passed the absolute+no-.. gate at the
	// top of this function; the pattern is a fixed literal suffix.
	// Neither input is attacker-controlled here.
	tmp, err := os.CreateTemp(dir, filepath.Base(filePath)+".tmp.*") //nolint:gosec // G304
	if err != nil {
		return fmt.Errorf("UpdateTomlConfig: open temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write([]byte(newContent)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("UpdateTomlConfig: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("UpdateTomlConfig: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("UpdateTomlConfig: close temp: %w", err)
	}
	// G703: filePath is the same value that passed the absolute+
	// no-.. gate at the top of this function; tmpPath is produced
	// by os.CreateTemp inside the same directory. Neither is
	// attacker-controlled here.
	if err := os.Rename(tmpPath, filePath); err != nil { //nolint:gosec // G703
		return fmt.Errorf("UpdateTomlConfig: rename into place: %w", err)
	}
	cleanupTmp = false
	return nil
}
