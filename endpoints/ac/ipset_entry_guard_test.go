package ac

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// replacedEntryFormats maps each fmt.Sprintf format string that once built an
// ipset entry to the builder that replaced it. Keeping the mapping explicit (as
// opposed to a loose "looks comma-shaped" heuristic) is what keeps this fence
// free of false positives on unrelated formatting.
//
// Every format here carries a distinctive marker — a proto prefix, a port verb,
// or the all-ports range — so it cannot plausibly be anything but an ipset
// entry. The two ICMP grammars are NOT here; see icmpEntryFormats.
var replacedEntryFormats = map[string]string{
	"%s,%d,%s":          "ipsetHashTCP",
	"%s,1-65535,%s":     "ipsetHashTCPAllPorts",
	"%s,udp:%d,%s":      "ipsetHashUDP",
	"%s,udp:1-65535,%s": "ipsetHashUDPAllPorts",
	"%s,%d":             "ipsetHashNetPort",
	"%s,1-65535":        "ipsetHashNetAllPorts",
	"%s,udp:%d":         "ipsetHashNetUDPPort",
	"%s,udp:1-65535":    "ipsetHashNetUDPAllPorts",
}

// icmpEntryFormats are the two remaining grammars, held separately because
// "%s,%s" and "%s,%s,%s" are generic comma joins — a future unrelated
// fmt.Sprintf("%s,%s", ...) anywhere in the package would otherwise trip this
// fence with a misleading "rebuilds an ipset entry grammar" error.
//
// Matching them requires corroboration: an ICMP entry gets its type field from
// utils.ICMPEchoType, so a call is only reported when that appears among its
// arguments. That keeps full coverage of the grammars without the false-positive
// surface the bare format strings would carry.
var icmpEntryFormats = map[string]string{
	"%s,%s,%s": "ipsetHashICMP",
	"%s,%s":    "ipsetHashNetICMP",
}

// icmpEchoTypeFunc is the corroborating call that distinguishes an ICMP ipset
// entry from an arbitrary comma join.
const icmpEchoTypeFunc = "ICMPEchoType"

// callsICMPEchoType reports whether any argument invokes utils.ICMPEchoType.
func callsICMPEchoType(args []ast.Expr) bool {
	found := false
	for _, arg := range args {
		ast.Inspect(arg, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == icmpEchoTypeFunc {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// TestIpsetEntryFormats_OnlyBuiltByHelpers enforces the "single source of truth"
// property the ipsetHash* doc comment claims. The format fences in
// msghandler_test.go pin what each builder returns, but nothing stops a new
// admission path from side-stepping the builders and re-inlining a raw
// fmt.Sprintf — at which point the grammar has two sources that can drift
// independently, and the fences would still be green.
//
// This walks every non-test file in the package and fails on any fmt.Sprintf
// whose format string is one of the entry grammars the builders own. Test files
// are exempt so msghandler_bench_test.go can keep the fmt.Sprintf baselines it
// benchmarks the builders against.
//
// Two deliberate boundaries, both sized to the threat model — accidental
// re-inlining by a future admission path, not adversarial evasion. Treat the
// list below as the fence's actual reach, not as a summary of a wider net:
//
//   - Only a literal format string passed to fmt.Sprintf is matched. Every other
//     route to the same bytes slips past — a format held in a named constant or
//     variable, fmt.Fprintf/Appendf, strings.Join, or plain "+" concatenation.
//     Closing those needs type-checked analysis of what reaches ipset.Add, which
//     is a different tool than this fence.
//   - The two generic ICMP joins additionally require a utils.ICMPEchoType
//     argument (see icmpEntryFormats), so an unrelated fmt.Sprintf("%s,%s", ...)
//     elsewhere in the package does not trip this fence.
//
// If you are here because this went red: call the named builder instead. If you
// genuinely need one of these format strings for something that is not an ipset
// entry, narrow the map rather than deleting the fence.
func TestIpsetEntryFormats_OnlyBuiltByHelpers(t *testing.T) {
	// Go runs a package's tests with that package's directory as the working
	// directory, so the package sources are the current directory.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no package sources found — this fence would silently pass on an empty scan")
	}

	fset := token.NewFileSet()
	scanned := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		scanned++

		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "fmt" || sel.Sel.Name != "Sprintf" {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			format, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			helper, owned := replacedEntryFormats[format]
			if !owned {
				// The generic ICMP joins only count with corroboration.
				if h, ambiguous := icmpEntryFormats[format]; ambiguous && callsICMPEchoType(call.Args[1:]) {
					helper, owned = h, true
				}
			}
			if owned {
				t.Errorf("%s: fmt.Sprintf(%q, ...) rebuilds an ipset entry grammar owned by %s — call %s instead, so the format the kernel datapath depends on keeps a single definition",
					fset.Position(call.Pos()), format, helper, helper)
			}
			return true
		})
	}

	if scanned == 0 {
		t.Fatal("scanned no non-test sources — the fence must not pass vacuously")
	}
}
