package ebpf

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// committedXDPObjectRel deliberately reaches outside the nhp Go module: the
// native AC path loads this tracked object from endpoints/ac/main/etc, so the
// contract test needs the same full-repo checkout CI uses.
const committedXDPObjectRel = "endpoints/ac/main/etc/nhp_ebpf_xdp.o"

// Match the C identifier token __packed only; longer identifiers like
// foo__packed are intentionally outside the #2818 failure mode.
var barePackedRE = regexp.MustCompile(`\b__packed\b`)

type ebpfTestPaths struct {
	repoRoot     string
	xdpSourceDir string
}

func resolveEbpfTestPaths(t *testing.T) ebpfTestPaths {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get test working directory: %v", err)
	}

	searchRoots := []string{cwd}
	if _, thisFile, _, ok := runtime.Caller(0); ok && filepath.IsAbs(thisFile) {
		searchRoots = append(searchRoots, filepath.Dir(thisFile))
	}
	for _, root := range searchRoots {
		if paths, ok := findEbpfTestPaths(root); ok {
			return paths
		}
	}
	t.Fatalf("cannot locate nhp_ebpf_xdp.c from test working directory %s", cwd)
	return ebpfTestPaths{}
}

func findEbpfTestPaths(root string) (ebpfTestPaths, bool) {
	var moduleLayout *ebpfTestPaths
	for dir := filepath.Clean(root); ; dir = filepath.Dir(dir) {
		monorepoXDPDir := filepath.Join(dir, "nhp", "ebpf", "xdp")
		// endpoints marks the full monorepo; an isolated nhp checkout can also
		// make a parent directory look like <dir>/nhp/ebpf/xdp.
		if fileExists(filepath.Join(dir, "endpoints")) && fileExists(filepath.Join(monorepoXDPDir, "nhp_ebpf_xdp.c")) {
			return ebpfTestPaths{repoRoot: dir, xdpSourceDir: monorepoXDPDir}, true
		}

		moduleXDPDir := filepath.Join(dir, "ebpf", "xdp")
		if moduleLayout == nil && fileExists(filepath.Join(moduleXDPDir, "nhp_ebpf_xdp.c")) {
			moduleLayout = &ebpfTestPaths{repoRoot: dir, xdpSourceDir: moduleXDPDir}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	if moduleLayout != nil {
		return *moduleLayout, true
	}
	return ebpfTestPaths{}, false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestXDPSources_DoNotUseBarePacked audits the XDP C translation units for the
// exact #2818 failure mode: a bare `__packed` token that is undefined in this
// include graph and therefore parses as a declarator instead of a packing
// attribute. Macro aliases like `#define __packed __attribute__((packed))` are
// rejected too; use `__attribute__((packed))` for packed structs, or leave the
// struct naturally aligned and pin the ABI with `_Static_assert`.
func TestXDPSources_DoNotUseBarePacked(t *testing.T) {
	testPaths := resolveEbpfTestPaths(t)
	var paths []string
	for _, pattern := range []string{"*.c", "*.h"} {
		matches, err := filepath.Glob(filepath.Join(testPaths.xdpSourceDir, pattern))
		if err != nil {
			t.Fatalf("glob XDP sources: %v", err)
		}
		paths = append(paths, matches...)
	}
	if len(paths) == 0 {
		t.Fatal("no XDP C/header sources found under nhp/ebpf/xdp")
	}

	for _, path := range paths {
		if filepath.Base(path) == "vmlinux.h" {
			continue
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			code := stripCCommentsAndLiterals(string(b))
			if loc := barePackedRE.FindStringIndex(code); loc != nil {
				t.Fatalf("%s contains bare __packed token near %q; use __attribute__((packed)) or an explicit natural-alignment _Static_assert",
					relPath(testPaths.repoRoot, path), snippet(code, loc[0], loc[1]))
			}
		})
	}
}

// TestCommittedXDPObject_ConnTrackABI asserts the native AC object committed in
// the repo matches the conn_track ABI Go serializes against. make test-ebpf
// recompiles release/nhp-ac/etc/nhp_ebpf_xdp.o from source; this test closes the
// adjacent gap where the source/release object is correct but the tracked native
// object still carries a stale 14/16-byte layout or the historical `__packed`
// ELF symbol.
func TestCommittedXDPObject_ConnTrackABI(t *testing.T) {
	objPath := filepath.Join(resolveEbpfTestPaths(t).repoRoot, committedXDPObjectRel)
	if _, err := os.Stat(objPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("%s is not present; committed-object ABI check requires the full monorepo checkout used by CI and the native AC runtime", committedXDPObjectRel)
		}
		t.Fatalf("stat %s: %v", committedXDPObjectRel, err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		t.Fatalf("LoadCollectionSpec(%s): %v", committedXDPObjectRel, err)
	}
	assertCommittedXDPObjectStrippedBTF(t, objPath)
	ctMap := spec.Maps["conn_track"]
	if ctMap == nil {
		t.Fatalf("%s has no conn_track map", committedXDPObjectRel)
	}
	if got, want := ctMap.KeySize, uint32(connTrackKeySize); got != want {
		t.Fatalf("committed conn_track KeySize = %d, want %d (ipv4_ct_tuple ABI: %d field bytes + %d trailing pad)",
			got, want, connTrackKeyDataLen, connTrackKeySize-connTrackKeyDataLen)
	}

	if hasELFSymbol(t, objPath, "__packed") {
		t.Fatalf("%s still contains an ELF symbol named __packed; regenerate it after removing the no-op C token", committedXDPObjectRel)
	}
}

func assertCommittedXDPObjectStrippedBTF(t *testing.T, path string) {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("open ELF %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	hasBTF := false
	hasBTFExt := false
	for _, section := range f.Sections {
		switch section.Name {
		case ".BTF":
			hasBTF = true
		case ".BTF.ext":
			hasBTFExt = true
		}
		if strings.HasPrefix(section.Name, ".debug_") {
			t.Fatalf("%s contains %s; regenerate it with scripts/check-ebpf-committed-object-drift.sh --update so the committed object is DWARF-stripped while retaining BTF", committedXDPObjectRel, section.Name)
		}
	}
	if !hasBTF || !hasBTFExt {
		t.Fatalf("%s must retain .BTF and .BTF.ext sections after DWARF stripping (has .BTF=%t, has .BTF.ext=%t)", committedXDPObjectRel, hasBTF, hasBTFExt)
	}
}

// stripCCommentsAndLiterals is a narrow scanner for the ASCII C used here, not a
// full C preprocessor lexer. It preserves code bytes while skipping ordinary
// comments, backslash-continued line comments, and string/char literals so prose
// mentions of __packed do not trip the bare-token audit. It assumes well-formed,
// compilable input; the compiler catches unterminated literals before this
// guard matters.
func stripCCommentsAndLiterals(src string) string {
	var out strings.Builder
	out.Grow(len(src))

	for i := 0; i < len(src); i++ {
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '/' {
			i += 2
			for i < len(src) {
				if src[i] == '\n' {
					out.WriteByte('\n')
					if i > 0 && src[i-1] == '\\' {
						i++
						continue
					}
					break
				}
				i++
			}
			continue
		}
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '*' {
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				if src[i] == '\n' {
					out.WriteByte('\n')
				}
				i++
			}
			if i+1 < len(src) {
				i++
			}
			continue
		}
		if src[i] == '"' || src[i] == '\'' {
			quote := src[i]
			out.WriteByte(' ')
			for i++; i < len(src); i++ {
				if src[i] == '\n' {
					out.WriteByte('\n')
				}
				if src[i] == '\\' {
					i++
					continue
				}
				if src[i] == quote {
					break
				}
			}
			continue
		}
		out.WriteByte(src[i])
	}
	return out.String()
}

func hasELFSymbol(t *testing.T, path, name string) bool {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("open ELF %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	syms, err := f.Symbols()
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			return false
		}
		t.Fatalf("read ELF symbols from %s: %v", path, err)
	}
	for _, sym := range syms {
		if sym.Name == name {
			return true
		}
	}
	return false
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

func snippet(s string, start, end int) string {
	const context = 24
	lo := start - context
	if lo < 0 {
		lo = 0
	}
	hi := end + context
	if hi > len(s) {
		hi = len(s)
	}
	return s[lo:hi]
}
