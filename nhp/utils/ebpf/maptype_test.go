package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

// readXdpSource loads the XDP source from either the full monorepo layout or an
// isolated nhp module checkout.
func readXdpSource(t *testing.T) string {
	t.Helper()
	srcPath := filepath.Join(resolveEbpfTestPaths(t).xdpSourceDir, "nhp_ebpf_xdp.c")
	b, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("reading XDP source %s: %v", srcPath, err)
	}
	return string(b)
}

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
