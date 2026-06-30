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
			code, loc := findBarePackedToken(string(b))
			if loc != nil {
				t.Fatalf("%s contains bare __packed token near %q; use __attribute__((packed)) or an explicit natural-alignment _Static_assert",
					relPath(testPaths.repoRoot, path), snippet(code, loc[0], loc[1]))
			}
		})
	}
}

const (
	scannerContinuedStringLiteralSrc     = "const char *msg = \"split \\\n__packed prose\";\nstruct key { int x; } __packed;"
	scannerCRLFContinuedStringLiteralSrc = "const char *msg = \"split \\\r\n__packed prose\";\r\nstruct key { int x; } __packed;"
	scannerMultilineBlockCommentSrc      = "/* historical\n__packed\nfootgun */\nstruct key { int x; };"
	scannerContinuedLineCommentSrc       = "// historical __packed footgun \\\n__packed is still part of the comment\nstruct key { int x; } __packed;"
)

func TestBarePackedAuditScanner(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "bare token in code",
			src:  "struct key { int x; } __packed;",
			want: true,
		},
		{
			name: "bare token at beginning of input",
			src:  "__packed struct key { int x; };",
			want: true,
		},
		{
			name: "macro alias definition is rejected by policy",
			src:  "#define __packed __attribute__((packed))\nstruct key { int x; };",
			want: true,
		},
		{
			name: "fully spelled packed attribute",
			src:  "struct key { int x; } __attribute__((packed));",
			want: false,
		},
		{
			name: "line comment",
			src:  "// historical __packed footgun\nstruct key { int x; };",
			want: false,
		},
		{
			name: "backslash continued line comment",
			src:  "// historical __packed footgun \\\n__packed is still part of the comment\nstruct key { int x; };",
			want: false,
		},
		{
			name: "crlf backslash continued line comment",
			src:  "// historical __packed footgun \\\r\n__packed is still part of the comment\r\nstruct key { int x; };",
			want: false,
		},
		{
			name: "block comment",
			src:  "/* historical __packed footgun */\nstruct key { int x; };",
			want: false,
		},
		{
			name: "multiline block comment",
			src:  scannerMultilineBlockCommentSrc,
			want: false,
		},
		{
			name: "bare token after block comment is not swallowed",
			src:  "/* historical __packed footgun */\nstruct key { int x; } __packed;",
			want: true,
		},
		{
			name: "block comment preserves boundary before bare token",
			src:  "foo/* gap */__packed;",
			want: true,
		},
		{
			name: "block comment preserves boundary inside non-token",
			src:  "__pa/* gap */cked;",
			want: false,
		},
		{
			name: "string literal",
			src:  "const char *msg = \"do not write __packed\";\nstruct key { int x; };",
			want: false,
		},
		{
			name: "bare token after string literal is not swallowed",
			src:  "const char *msg = \"do not write __packed\";\nstruct key { int x; } __packed;",
			want: true,
		},
		{
			name: "bare token after escaped quote in string literal is not swallowed",
			src: `const char *msg = "quote: \" and __packed prose";
struct key { int x; } __packed;`,
			want: true,
		},
		{
			name: "bare token after continued string literal is not swallowed",
			src:  scannerContinuedStringLiteralSrc,
			want: true,
		},
		{
			name: "bare token after crlf continued string literal is not swallowed",
			src:  scannerCRLFContinuedStringLiteralSrc,
			want: true,
		},
		{
			name: "ordinary code line splice creates bare token",
			src:  "__pa\\\ncked struct key { int x; };",
			want: true,
		},
		{
			name: "ordinary code crlf line splice creates bare token",
			src:  "__pa\\\r\ncked struct key { int x; };",
			want: true,
		},
		{
			name: "char literal",
			src:  "const char marker = '_'; /* __packed */\nstruct key { int x; };",
			want: false,
		},
		{
			name: "bare token after escaped quote in char literal is not swallowed",
			src: `const char quote = '\'';
struct key { int x; } __packed;`,
			want: true,
		},
		{
			name: "longer identifier",
			src:  "int foo__packed = 1;\nstruct key { int x; };",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, loc := findBarePackedToken(tt.src)
			got := loc != nil
			if got != tt.want {
				t.Errorf("bare __packed detection = %t, want %t; stripped source:\n%s", got, tt.want, code)
			}
		})
	}
}

// This overlaps a few detection fixtures so newline preservation is asserted
// separately from whether a stripped source still contains a bare token. Ordinary
// code splices are excluded because C removes those newlines before tokenizing.
func TestBarePackedAuditScanner_PreservesSkippedNewlines(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantToken bool
	}{
		{
			name:      "continued string literal",
			src:       scannerContinuedStringLiteralSrc,
			wantToken: true,
		},
		{
			name:      "crlf continued string literal",
			src:       scannerCRLFContinuedStringLiteralSrc,
			wantToken: true,
		},
		{
			name:      "multiline block comment",
			src:       scannerMultilineBlockCommentSrc,
			wantToken: false,
		},
		{
			name:      "backslash continued line comment",
			src:       scannerContinuedLineCommentSrc,
			wantToken: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, loc := findBarePackedToken(tt.src)
			if strings.Count(code, "\n") != strings.Count(tt.src, "\n") {
				t.Fatalf("stripped source preserved %d newlines, want %d; stripped source:\n%s",
					strings.Count(code, "\n"), strings.Count(tt.src, "\n"), code)
			}
			if got := loc != nil; got != tt.wantToken {
				t.Fatalf("bare __packed detection = %t, want %t; stripped source:\n%s", got, tt.wantToken, code)
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
// mentions of __packed do not trip the bare-token audit. Block comments and
// literals are replaced with a leading space while preserving embedded newlines,
// matching C's token-boundary behavior closely enough for this guard.
// Backslash-newline splices in ordinary code are collapsed before token
// matching; delimiters formed by such splices are not re-lexed as comments or
// literals. It assumes well-formed, compilable input; the compiler catches
// unterminated literals before this guard matters.
func stripCCommentsAndLiterals(src string) string {
	var out strings.Builder
	out.Grow(len(src))

	for i := 0; i < len(src); i++ {
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '/' {
			i += 2
			for i < len(src) {
				if src[i] == '\n' {
					out.WriteByte('\n')
					if hasLineContinuationBeforeNewline(src, i) {
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
			out.WriteByte(' ')
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
					if end, ok := escapedNewlineEnd(src, i); ok {
						out.WriteByte('\n')
						i = end
					} else {
						i++
					}
					continue
				}
				if src[i] == quote {
					break
				}
			}
			continue
		}
		if end, ok := escapedNewlineEnd(src, i); ok {
			i = end
			continue
		}
		out.WriteByte(src[i])
	}
	return out.String()
}

func escapedNewlineEnd(src string, slash int) (int, bool) {
	if slash+1 >= len(src) || src[slash] != '\\' {
		return 0, false
	}
	if src[slash+1] == '\n' {
		return slash + 1, true
	}
	if slash+2 < len(src) && src[slash+1] == '\r' && src[slash+2] == '\n' {
		return slash + 2, true
	}
	return 0, false
}

func hasLineContinuationBeforeNewline(src string, newline int) bool {
	i := newline - 1
	if i >= 0 && src[i] == '\r' {
		i--
	}
	return i >= 0 && src[i] == '\\'
}

// findBarePackedToken returns loc indexes into the stripped code, not the
// original source. Callers use loc only to print a nearby diagnostic snippet.
func findBarePackedToken(src string) (string, []int) {
	code := stripCCommentsAndLiterals(src)
	return code, barePackedRE.FindStringIndex(code)
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
