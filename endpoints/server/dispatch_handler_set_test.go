package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// dispatchedHandlers is the pinned set of handlers that run under
// dispatchHandler's recover(). It is a REVIEW GATE, not documentation.
//
// PR #3643 wrapped these goroutines in a recover(), which changed their failure
// semantics: a panic no longer crashes the process, so a handler that unlocks a
// mutex only on its happy path now leaks that lock instead — a silent deadlock
// where there used to be a loud, ASG-self-healing crash. That PR audited the
// bare-unlock sections reachable from this set (see the lock-order section of
// endpoints/server/CLAUDE.md), but an audit is true only for the set it was run
// against.
//
// A handler joining this list inherits the changed semantics and brings its own
// lock discipline with it, so the audit has to be re-run. Pinning the set makes
// that a deliberate step instead of something a reviewer has to notice.
//
// This is cache-correct as a Go test, unlike the repo-walking
// ErrorCodeToError fence (see scripts/check-errorcode-to-error-callers.sh):
// udpserver.go is a source file of THIS package, so editing it invalidates the
// package's cached test result.
//
// Removing an entry means a handler left the recovered set — fine, drop it.
// Adding one means a handler joined it: re-run the audit first.
var dispatchedHandlers = []string{
	"s.HandleDHPDARMessage",
	"s.HandleDHPDAVMessage",
	"s.HandleDHPDRGMessage",
	"s.HandleKnockRequest",
	"s.HandleListRequest",
	"s.HandleOTPRequest",
	"s.HandleRegisterRequest",
	// NHP_RLY is wrapped in a closure because HandleRelayForward returns no
	// error; the closure is folded to the handler it actually calls, so an
	// anonymous signature cannot match any future closure.
	//
	// Note this folds EVERY `recv.Method()` call in the closure body, so adding
	// a log line or metric increment inside it also moves this string even
	// though the dispatched set is unchanged. That is a deliberate second-order
	// gate — a new call inside a recovered closure is worth a look — and the
	// failure message distinguishes the two causes.
	"func{s.HandleRelayForward}",
}

// TestDispatchedHandlerSetIsPinned fails when a handler is added to or removed
// from the recovered dispatch path without updating the pinned set above.
//
// Extraction is AST-based rather than regex over source lines: an earlier
// version scraped `s.dispatchHandler(ppd, ...` textually and folded the inline
// closure by scanning for `})`, which made a gofmt reflow of the dispatch block
// trip the test with a formatting-only failure. Parsing removes that class
// entirely — the pin now moves only when the dispatched set actually changes.
func TestDispatchedHandlerSetIsPinned(t *testing.T) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "udpserver.go", nil, 0)
	if err != nil {
		t.Fatalf("parse udpserver.go: %v", err)
	}

	var found []string
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "dispatchHandler" || len(call.Args) < 2 {
			return true
		}
		found = append(found, describeHandlerArg(call.Args[1]))
		return true
	})

	if len(found) == 0 {
		t.Fatal("no s.dispatchHandler(..., handler) call sites found — the dispatch site moved or was renamed")
	}

	sort.Strings(found)
	want := append([]string(nil), dispatchedHandlers...)
	sort.Strings(want)

	if strings.Join(found, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the handler identities running under dispatchHandler's recover() changed.\n\n"+
			"got:\n  %s\n\nwant:\n  %s\n\n"+
			"TWO DIFFERENT CAUSES — check which one you have:\n\n"+
			"(a) A handler joined or left the dispatched set. This is the one that matters.\n"+
			"    A handler here no longer crashes the process on panic — it is recovered, so\n"+
			"    a bare happy-path mutex unlock leaks the lock and deadlocks later requests\n"+
			"    instead, and any other happy-path-only cleanup leaks too. Before updating\n"+
			"    this list, re-run the non-defer-unlock audit over the new handler's call\n"+
			"    graph (endpoints/server/CLAUDE.md, Lock Order) and confirm it releases every\n"+
			"    lock via defer. connDataForOutboundAddr is the named hazard — it holds\n"+
			"    remoteConnectionMapMutex across three helpers with bare unlocks.\n\n"+
			"(b) Only a `func{...}` entry changed. A dispatched closure gained or lost a\n"+
			"    `recv.Method()` call — a log line, a metric increment, a second helper —\n"+
			"    so its folded identity moved while the dispatched set did NOT. Confirm the\n"+
			"    new call is safe to run under the recover, then update the pinned string.",
			strings.Join(found, "\n  "), strings.Join(want, "\n  "))
	}
}

// describeHandlerArg renders the handler argument as a stable identity string.
// A method value becomes "recv.Method"; an inline closure is folded to the
// methods it calls, so the pin names the handler that actually runs rather than
// an anonymous signature that would match any future closure.
func describeHandlerArg(arg ast.Expr) string {
	switch a := arg.(type) {
	case *ast.SelectorExpr:
		if ident, ok := a.X.(*ast.Ident); ok {
			return ident.Name + "." + a.Sel.Name
		}
		return a.Sel.Name
	case *ast.FuncLit:
		var calls []string
		ast.Inspect(a.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok {
					calls = append(calls, ident.Name+"."+sel.Sel.Name)
				}
			}
			return true
		})
		sort.Strings(calls)
		return "func{" + strings.Join(calls, ";") + "}"
	case *ast.Ident:
		return a.Name
	}
	return "<unrecognized handler expression>"
}
