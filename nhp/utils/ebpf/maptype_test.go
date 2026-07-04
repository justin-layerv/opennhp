package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

// IsMapFull detector proof (#2163). Runs on every platform (no kernel needed):
// it asserts the errno-based detection that the AC fail-closed path relies on.
// The behavioral proof that a full HASH map actually produces this error (and
// that LRU_HASH would silently evict instead) is in
// maptype_eviction_linux_test.go.

func TestIsMapFull(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"bare E2BIG", syscall.E2BIG, true},
		// Exactly how cilium/ebpf surfaces a full-map insert: wrapMapError turns
		// unix.E2BIG into `fmt.Errorf("key too big for map: %w", err)`, then
		// Map.update wraps that as `fmt.Errorf("update: %w", ...)`.
		{"cilium-wrapped E2BIG", fmt.Errorf("update: %w", fmt.Errorf("key too big for map: %w", syscall.E2BIG)), true},
		{"key-not-exist is not full", cebpf.ErrKeyNotExist, false},
		{"ENOENT is not full", syscall.ENOENT, false},
		{"EPERM is not full", syscall.EPERM, false},
		{"unrelated error is not full", errors.New("boom"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMapFull(tc.err); got != tc.want {
				t.Fatalf("IsMapFull(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestMapTypeName proves MapTypeName (used in the fail-closed log so operators
// see the full map by name, #2163) maps each MapType* constant to its name and
// renders unknown ordinals safely. The names MUST be real map declarations in
// the .c, so it cross-checks each against the XDP source — if a future rename
// drifts the mapping from the actual declaration, this fails even off-kernel.
func TestMapTypeName(t *testing.T) {
	cases := map[int]string{
		MapTypeWhitelist:     "spp",
		MapTypeSdWhitelist:   "sdwhitelist",
		MapTypeIcmpWhitelist: "icmpwhitelist",
		MapTypeSrcAndPort:    "src_port",
		MapTypeSrcPortList:   "port_list",
		MapTypeProtocolPort:  "protocol_port",
	}
	src := readXdpSource(t)
	for mt, want := range cases {
		if got := MapTypeName(mt); got != want {
			t.Errorf("MapTypeName(%d) = %q, want %q", mt, got, want)
		}
		// The name must correspond to an actual map declaration in the source
		// (mapTypeForName t.Fatals if the terminator isn't found).
		if typ := mapTypeForName(t, src, want); typ == "" {
			t.Errorf("MapTypeName(%d)=%q has no `} %s SEC(\".maps\");` declaration in the XDP source", mt, want, want)
		}
	}
	// Unknown ordinals render without panicking.
	if got := MapTypeName(0); got != "unknown(0)" {
		t.Errorf("MapTypeName(0) = %q, want %q", got, "unknown(0)")
	}
	if got := MapTypeName(99); got != "unknown(99)" {
		t.Errorf("MapTypeName(99) = %q, want %q", got, "unknown(99)")
	}
}

// TestXdpSource_AdmissionMapsAndConnTrackAreHash is the declaration-level
// regression guard for the #2163/#2814 map-type decisions. It parses the XDP C
// source and asserts the BPF_MAP_TYPE of each named map. This is complementary
// to the kernel behavioral tests: those prove HASH rejects on full and the full
// conn_track cache still degrades correctly; this test proves the declarations
// in source haven't regressed (someone flipping spp or conn_track back to
// LRU_HASH fails CI even on a machine that can't run BPF).
//
// NOTE: this intentionally checks the .c SOURCE, not the committed native AC
// object, because this is a declaration-policy test: it should fail on a source
// edit that flips an allow-rule or conntrack map back to LRU before any object
// regeneration happens. The committed object's conn_track ABI is guarded
// separately in xdp_object_contract_test.go; broader source/object byte
// freshness is now gated in CI by scripts/check-ebpf-committed-object-drift.sh,
// which recompiles the object and diffs load-relevant bytes against the
// committed native AC object; wiring this gate was tracked by #2823.
func TestXdpSource_AdmissionMapsAndConnTrackAreHash(t *testing.T) {
	src := readXdpSource(t)

	want := map[string]string{
		// authoritative allow-rule maps — MUST be plain HASH (fail-closed on full)
		"spp":            "BPF_MAP_TYPE_HASH",
		"src_port":       "BPF_MAP_TYPE_HASH",
		"sdwhitelist":    "BPF_MAP_TYPE_HASH",
		"port_list":      "BPF_MAP_TYPE_HASH",
		"protocol_port":  "BPF_MAP_TYPE_HASH",
		"icmpwhitelist":  "BPF_MAP_TYPE_HASH",
		"spp_v6":         "BPF_MAP_TYPE_HASH",
		"src_port_v6":    "BPF_MAP_TYPE_HASH",
		"icmp_wl_v6":     "BPF_MAP_TYPE_HASH",
		"sdwhitelist_v6": "BPF_MAP_TYPE_HASH",
		"port_list_v6":   "BPF_MAP_TYPE_HASH",
		"conn_track":     "BPF_MAP_TYPE_HASH",
		"conn_track_v6":  "BPF_MAP_TYPE_HASH",
		"frag_state_v6":  "BPF_MAP_TYPE_HASH",
	}

	for name, wantType := range want {
		got := mapTypeForName(t, src, name)
		if got != wantType {
			t.Errorf("map %q declared as %s, want %s (#2163/#2814: admission maps and established-flow caches must be HASH so full maps fail new inserts without silently evicting existing sessions)", name, got, wantType)
		}
	}
}

// readEbpfSource loads an eBPF .c source by base name from the eBPF source dir
// (resolves either the full monorepo layout or an isolated nhp module checkout).
func readEbpfSource(t *testing.T, name string) string {
	t.Helper()
	srcPath := filepath.Join(resolveEbpfTestPaths(t).xdpSourceDir, name)
	b, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("reading eBPF source %s: %v", srcPath, err)
	}
	return string(b)
}

// readXdpSource loads the XDP source (both .c files live in nhp/ebpf/xdp/).
func readXdpSource(t *testing.T) string { return readEbpfSource(t, "nhp_ebpf_xdp.c") }

// mapTypeDeclRe matches a `__uint(type, BPF_MAP_TYPE_*)` declaration. It is
// invariant across maps (the per-map part is the terminator regex built in
// mapTypeForName), so compile it once at package scope rather than per call.
var mapTypeDeclRe = regexp.MustCompile(`__uint\(\s*type\s*,\s*(BPF_MAP_TYPE_[A-Z_]+)\s*\)`)

// mapTypeForName extracts the BPF_MAP_TYPE_* of the map definition whose
// closing `} <name> SEC(".maps");` matches name. The .c declares each map as an
// anonymous struct literal terminated by `} <name> SEC(".maps");`, so we find
// that terminator, then search backwards for the nearest `__uint(type, ...)`.
func mapTypeForName(t *testing.T, src, name string) string {
	t.Helper()
	// Locate `} <name> SEC(".maps");`
	term := regexp.MustCompile(`\}\s*` + regexp.QuoteMeta(name) + `\s+SEC\("\.maps"\)\s*;`)
	loc := term.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("map %q: no `} %s SEC(\".maps\");` terminator found in source", name, name)
		return ""
	}
	// Search the text BEFORE the terminator for the last type declaration.
	matches := mapTypeDeclRe.FindAllStringSubmatch(src[:loc[0]], -1)
	if len(matches) == 0 {
		t.Fatalf("map %q: no __uint(type, BPF_MAP_TYPE_*) found before its terminator", name)
		return ""
	}
	return matches[len(matches)-1][1]
}

// readTcEgressSource loads the tc egress source (same dir as the XDP source).
func readTcEgressSource(t *testing.T) string { return readEbpfSource(t, "tc_egress.c") }

// TestTcEgressSource_SppIsHash extends the #2163 map-type guard to the tc_egress
// source. The original guard (TestXdpSource_AdmissionMapsAndConnTrackAreHash)
// only checked the XDP source — the exact gap that let tc_egress's duplicate
// `spp` stay LRU_HASH after #2163 flipped the XDP `spp` to HASH, which crash-
// looped every AC once #2961 enabled FilterMode=EBPFXDP in sandbox.
func TestTcEgressSource_SppIsHash(t *testing.T) {
	src := readTcEgressSource(t)
	if got := mapTypeForName(t, src, "spp"); got != "BPF_MAP_TYPE_HASH" {
		t.Errorf("tc_egress `spp` declared as %s, want BPF_MAP_TYPE_HASH — it is the SAME pinned map as nhp_ebpf_xdp.c's `spp`; LRU_HASH silently evicts admitted sessions (#2163) and mismatches the XDP HASH, boot-failing the AC under FilterMode=EBPFXDP", got)
	}
}

// TestTcEgressSource_WrittenExpiryMapsHaveReapers is the #3022 guard for the
// "missed the duplicate map" class that caused the spp crash loop and follow-up
// reaper. Any tc-egress-written, expiry-bearing pinned map is a datapath-fill
// vector with no scheduler-owned expiry path, so it must be listed in
// whitelistReapTargets. Conversely, a target that tc_egress does not write is
// premature sweep work; this intentionally keeps spp_v6 out until the IPv6
// tc-egress datapath actually writes return-path pinholes there.
func TestTcEgressSource_WrittenExpiryMapsHaveReapers(t *testing.T) {
	tcSrc := readTcEgressSource(t)
	pinned := parsePinnedMaps(t, tcSrc)
	updateTargetNames, updateCallCount := tcEgressMapUpdateTargetNamesAndCallCount(tcSrc)
	if len(updateTargetNames) != updateCallCount {
		t.Fatalf("tc_egress has %d bpf_map_update_elem calls, but the #3022 guard parser only recognizes %d direct `&map` targets; extend tcEgressMapUpdateTargets with the new writer form in the same PR", updateCallCount, len(updateTargetNames))
	}
	updated := map[string]struct{}{}
	for _, name := range updateTargetNames {
		updated[name] = struct{}{}
	}

	// Expiry-bearing map values use the shared `expire_time` field name. This is
	// load-bearing for the guard: a new tc-egress fill vector must keep that
	// convention, or extend this detector in the same PR.
	const expiryFieldName = "expire_time"

	writtenExpiryMaps := map[string]struct{}{}
	for name := range updated {
		decl, ok := pinned[name]
		if !ok {
			continue
		}
		if !strings.Contains(structBody(t, tcSrc, decl.value), expiryFieldName) {
			continue
		}
		writtenExpiryMaps[name] = struct{}{}
	}
	if len(writtenExpiryMaps) == 0 {
		t.Fatal("tc_egress has no expiry-bearing pinned map writes; expected at least `spp`, so the #3022 reaper-coverage guard is vacuous")
	}
	if len(whitelistReapTargets) != 1 {
		t.Fatalf("whitelistReapTargets has %d targets; handle multi-target occupancy/error semantics from #3043 in the same PR that adds target #2", len(whitelistReapTargets))
	}

	reapedMaps := map[string]struct{}{}
	for _, target := range whitelistReapTargets {
		reapedMaps[target.mapName] = struct{}{}
		if _, ok := writtenExpiryMaps[target.mapName]; !ok {
			t.Errorf("whitelistReapTargets registers %q, but tc_egress does not write that expiry-bearing pinned map; do not add sweep work before the datapath-fill vector exists (#3022)", target.mapName)
		}
	}
	for name := range writtenExpiryMaps {
		if _, ok := reapedMaps[name]; !ok {
			t.Errorf("tc_egress writes expiry-bearing pinned map %q via bpf_map_update_elem, but whitelistReapTargets has no matching reaper target; add the target before landing this datapath-fill vector (#3022)", name)
		}
	}
}

func TestTcEgressMapUpdateTargets_IgnoresComments(t *testing.T) {
	src := `
// bpf_map_update_elem(&spp_v6, &key, &value, BPF_ANY);
/*
 * bpf_map_update_elem(&sdwhitelist, &key, &value, BPF_ANY);
 */
const char *example = "bpf_map_update_elem(&sdwhitelist, &key, &value, BPF_ANY);";
// A /* inside a line comment must not start a block comment that hides code.
bpf_map_update_elem(&spp, &key, &value, BPF_ANY);
// */ bpf_map_update_elem(&sdwhitelist, &key, &value, BPF_ANY);
`
	got := tcEgressMapUpdateTargets(src)
	if _, ok := got["spp"]; !ok {
		t.Fatal("tcEgressMapUpdateTargets missed real spp update")
	}
	for _, name := range []string{"spp_v6", "sdwhitelist"} {
		if _, ok := got[name]; ok {
			t.Fatalf("tcEgressMapUpdateTargets reported commented update for %q", name)
		}
	}
}

// pinnedMapDecl is a LIBBPF_PIN_BY_NAME map declaration parsed from an eBPF .c
// source. Two objects that both declare a map with the same SEC(".maps") name
// and LIBBPF_PIN_BY_NAME resolve to ONE kernel map at /sys/fs/bpf/<name>, so
// every field here must be identical across objects or the second object's
// LoadAndAssign fails with an incompatible-pinned-map error.
type pinnedMapDecl struct {
	typ        string // BPF_MAP_TYPE_*
	key        string // __type(key, …), whitespace-normalized
	value      string // __type(value, …), whitespace-normalized
	maxEntries string // __uint(max_entries, …), macro-resolved to its numeric value
}

var (
	// One map declaration: `struct { … } <name> SEC(".maps");`. The map bodies
	// contain no nested braces, so [^}]* safely spans the (multi-line) body up to
	// the closing brace. Anonymous `struct {` only matches map literals, never a
	// named `struct foo {` type.
	ebpfMapDeclRe     = regexp.MustCompile(`struct\s*\{([^}]*)\}\s*(\w+)\s+SEC\("\.maps"\)\s*;`)
	mapKeyRe          = regexp.MustCompile(`__type\(\s*key\s*,\s*(.+?)\s*\)`)
	mapValueRe        = regexp.MustCompile(`__type\(\s*value\s*,\s*(.+?)\s*\)`)
	mapMaxEntriesRe   = regexp.MustCompile(`__uint\(\s*max_entries\s*,\s*(\w+)\s*\)`)
	mapPinByNameRe    = regexp.MustCompile(`__uint\(\s*pinning\s*,\s*LIBBPF_PIN_BY_NAME\s*\)`)
	tcMapUpdateRe     = regexp.MustCompile(`\bbpf_map_update_elem\s*\(\s*&([A-Za-z_][A-Za-z0-9_]*)\s*,`)
	tcMapUpdateCallRe = regexp.MustCompile(`\bbpf_map_update_elem\s*\(`)
	ebpfWSRe          = regexp.MustCompile(`\s+`)
	macroNumericRe    = regexp.MustCompile(`^\d+$`)
)

// resolveMacro resolves a `max_entries` token to its numeric value using the
// file's own `#define`s, so the parity check compares VALUES not tokens: two
// files both writing `MAX_ENTRIES` but with different `#define MAX_ENTRIES N`
// would still mismatch the kernel's pinned-map size check, so they must diff
// here too. A bare numeric literal is returned as-is; an unresolved token falls
// back to itself (still catches a token rename).
func resolveMacro(src, token string) string {
	if token == "" || macroNumericRe.MatchString(token) {
		return token
	}
	re := regexp.MustCompile(`(?m)^\s*#define\s+` + regexp.QuoteMeta(token) + `\s+(\S+)`)
	if m := re.FindStringSubmatch(src); m != nil {
		return m[1]
	}
	return token
}

// parsePinnedMaps returns every LIBBPF_PIN_BY_NAME map in src, keyed by its
// SEC(".maps") symbol name. Non-pinned maps are skipped: they get an unpinned
// per-object instance, so they cannot collide at a shared /sys/fs/bpf/<name>.
func parsePinnedMaps(t *testing.T, src string) map[string]pinnedMapDecl {
	t.Helper()
	out := map[string]pinnedMapDecl{}
	norm := func(re *regexp.Regexp, body string) string {
		if m := re.FindStringSubmatch(body); m != nil {
			return ebpfWSRe.ReplaceAllString(strings.TrimSpace(m[1]), " ")
		}
		return ""
	}
	for _, m := range ebpfMapDeclRe.FindAllStringSubmatch(src, -1) {
		body, name := m[1], m[2]
		if !mapPinByNameRe.MatchString(body) {
			continue
		}
		d := pinnedMapDecl{
			typ:        norm(mapTypeDeclRe, body),
			key:        norm(mapKeyRe, body),
			value:      norm(mapValueRe, body),
			maxEntries: resolveMacro(src, norm(mapMaxEntriesRe, body)),
		}
		out[name] = d
	}
	return out
}

func tcEgressMapUpdateTargets(src string) map[string]struct{} {
	names, _ := tcEgressMapUpdateTargetNamesAndCallCount(src)
	out := map[string]struct{}{}
	for _, name := range names {
		out[name] = struct{}{}
	}
	return out
}

func tcEgressMapUpdateTargetNamesAndCallCount(src string) ([]string, int) {
	// Model the direct libbpf helper idiom used by tc_egress.c:
	// `bpf_map_update_elem(&map, ...)`. If a future datapath writes through a map
	// pointer or wrapper helper, extend this parser with that form in the same PR.
	src = stripCCommentsAndLiterals(src)
	names := []string{}
	for _, m := range tcMapUpdateRe.FindAllStringSubmatch(src, -1) {
		names = append(names, m[1])
	}
	return names, len(tcMapUpdateCallRe.FindAllStringIndex(src, -1))
}

// structBody returns the whitespace-normalized field list of the `struct <name>`
// definition referenced by a map's __type(key|value, …). typeToken looks like
// "struct whitelist_key"; a non-"struct X" token (a scalar) is returned verbatim
// (the token equality check already covers it). The map bodies have no nested
// braces and neither do these small POD structs, so [^}]* captures the body.
func structBody(t *testing.T, src, typeToken string) string {
	t.Helper()
	name := strings.TrimSpace(strings.TrimPrefix(typeToken, "struct"))
	if name == "" || name == typeToken {
		return typeToken // not a "struct X" reference — nothing to expand
	}
	// Capture the field body AND the post-brace attributes (e.g.
	// `__attribute__((packed))`), since packed-ness changes the on-wire size just
	// like a field edit does.
	re := regexp.MustCompile(`struct\s+` + regexp.QuoteMeta(name) + `\s*\{([^}]*)\}([^;]*);`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("struct %q (referenced by a pinned map) not found in source", name)
		return ""
	}
	// Strip comments so field-size annotations present in one file's copy (the XDP
	// source annotates `// 4`, `// 2`, …; tc_egress.c does not) don't read as a
	// divergence — only the actual fields + packed-ness matter.
	body := stripCCommentsAndLiterals(m[1] + " " + m[2])
	return ebpfWSRe.ReplaceAllString(strings.TrimSpace(body), " ")
}

// TestSharedPinnedMaps_XdpTcParity is the "never again" guard for the sandbox
// crash: every LIBBPF_PIN_BY_NAME map declared in BOTH the XDP and TC objects is
// one shared kernel map at /sys/fs/bpf/<name>, so their declarations must match
// exactly (type + key + value + max_entries) or the second LoadAndAssign fails
// and the AC boot-fails under FilterMode=EBPFXDP. Parses the .c sources so it
// fails at PR time on any machine — no kernel, no compiled object needed. This
// is the check that #2163 (XDP-only) lacked when it flipped `spp` to HASH.
func TestSharedPinnedMaps_XdpTcParity(t *testing.T) {
	xdpSrc := readXdpSource(t)
	tcSrc := readTcEgressSource(t)
	xdp := parsePinnedMaps(t, xdpSrc)
	tc := parsePinnedMaps(t, tcSrc)

	shared := 0
	for name, x := range xdp {
		c, ok := tc[name]
		if !ok {
			continue
		}
		shared++
		// Report the specific diverging field (type/key/value/max_entries) rather
		// than a struct dump — any one mismatch fails the second LoadAndAssign and
		// boot-fails the AC under FilterMode=EBPFXDP (the #2163/#2961 crash-loop).
		diff := func(field, xv, cv string) {
			if xv != cv {
				t.Errorf("pinned map %q: %s differs — nhp_ebpf_xdp.c=%q vs tc_egress.c=%q. Both pin /sys/fs/bpf/%s, so the declarations MUST be identical.", name, field, xv, cv, name)
			}
		}
		diff("type", x.typ, c.typ)
		diff("key", x.key, c.key)
		diff("value", x.value, c.value)
		diff("max_entries", x.maxEntries, c.maxEntries)
		// Compare the referenced key/value STRUCT BODIES, not just the type token.
		// The structs are defined inline in each .c (not a shared header), so a
		// field edit to one file's copy would keep the token equal while diverging
		// the kernel's pinned-map key/value SIZE — the exact incompatible-pinned-map
		// failure this guard exists to catch. (Done here rather than a compile-time
		// _Static_assert in nhp_ebpf_xdp.c: that object is committed and
		// freshness-gated, so an added assert churns its bytes.)
		diff("key struct body", structBody(t, xdpSrc, x.key), structBody(t, tcSrc, c.key))
		diff("value struct body", structBody(t, xdpSrc, x.value), structBody(t, tcSrc, c.value))
	}
	// Non-vacuous: today `spp` is the shared pinned map. If a refactor removes all
	// overlap this guard becomes a no-op silently, so fail loudly instead.
	if shared == 0 {
		t.Fatal("no LIBBPF_PIN_BY_NAME map is shared between nhp_ebpf_xdp.c and tc_egress.c (expected at least `spp`); the parser or the sources changed — re-verify this parity guard is still exercised")
	}
}
