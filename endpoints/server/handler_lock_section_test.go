package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// auditedBareUnlockFuncs is the set of functions that hold a mutex across a
// NON-defer unlock on a path reachable from dispatchHandler's recover().
//
// The safety property recorded in endpoints/server/CLAUDE.md is NOT "no bare
// unlock is reachable" — these are. It is that each such critical section
// cannot panic, so recover() can never leave one of these locks held. That
// makes the regression subtle: it is not adding a bare unlock, it is adding a
// panic-capable CALL inside a critical section that already exists here.
//
// dispatch_handler_set_test.go fences the other direction (a new handler
// joining the recovered set). This one fences the inside of the sections that
// set already reaches — the risk that has no other guard.
//
// Removing an entry is fine (the section stopped existing). Adding one means a
// new bare-unlock section appeared on the handler path: audit it first, and
// only then pin it here.
var auditedBareUnlockFuncs = map[string]string{
	"resolveAgentPeerForKnock": "nhpauth.go",
	"applyAspMapDelta":         "udpserver.go",
	"loadPluginOnce":           "udpserver.go",
	"LoadPlugin":               "udpserver.go",
	"snapshotLiveACConns":      "httpserver.go",
	"handleNhpOpenResource":    "udpserver.go",
}

// builtinsSafeInsideCriticalSection are unqualified builtins permitted between
// a Lock and a non-defer Unlock in the audited functions. Each operates on an
// already-initialized value or is a pure allocation: none can fault on
// attacker-controlled input, which is the property the audit rests on.
var builtinsSafeInsideCriticalSection = map[string]bool{
	"len": true, "cap": true, "make": true, "append": true,
	"delete": true, "copy": true,
}

// qualifiedCallsSafeInsideCriticalSection are permitted package-qualified
// calls, matched on the FULL "pkg.Func" identity rather than the method name.
//
// The qualification matters. An earlier version whitelisted the bare selector
// name "Clone", which is receiver-agnostic: any future `x.Clone()` on some
// unrelated type — a custom, potentially panic-capable method that merely
// shares the name — would have been read as panic-free and slipped past this
// fence. Matching "slices.Clone" cannot be satisfied by a method on a value.
//
// Do NOT extend either map casually. An entry here is a claim that the call
// cannot panic while a lock is held on a remote-reachable path.
var qualifiedCallsSafeInsideCriticalSection = map[string]bool{
	"slices.Clone": true,
}

// TestAuditedCriticalSectionsStayPanicFree walks each audited function and
// fails if a call appears between a Lock and its non-defer Unlock.
func TestAuditedCriticalSectionsStayPanicFree(t *testing.T) {
	byFile := map[string][]string{}
	for fn, file := range auditedBareUnlockFuncs {
		byFile[file] = append(byFile[file], fn)
	}

	fset := token.NewFileSet()
	checked := map[string]bool{}

	for file, wantFuncs := range byFile {
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		want := map[string]bool{}
		for _, fn := range wantFuncs {
			want[fn] = true
		}

		for _, decl := range parsed.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil || !want[fd.Name.Name] {
				continue
			}
			checked[fd.Name.Name] = true
			for _, offense := range scanCriticalSections(fset, fd) {
				t.Errorf("%s: %s", fd.Name.Name, offense)
			}
		}
	}

	var missing []string
	for fn := range auditedBareUnlockFuncs {
		if !checked[fn] {
			missing = append(missing, fn)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("audited function(s) not found — renamed or removed without updating the pin: %s\n"+
			"If the function is gone its critical section is too; drop the entry. If it moved, update the file.",
			strings.Join(missing, ", "))
	}
}

// scanCriticalSections reports calls that appear while a lock is held and will
// be released by a NON-defer Unlock.
//
// It tracks `held` in source order and descends into nested blocks carrying the
// current state, because the real code releases inside a nested block and then
// calls out — `applyAspMapDelta`'s "unlock, ensurePluginLoaded, return" arm is
// the shape, and it is correct (CLAUDE.md: authServiceMap is leaf-most and
// sequenced with, never nested inside, pluginHandlerMap).
//
// A block that ends in return/continue/break does not propagate its final state
// back out: an early-return arm that unlocks says nothing about whether the
// fallthrough path still holds the lock. Without that rule this would go
// false-NEGATIVE on everything after such an arm.
func scanCriticalSections(fset *token.FileSet, fd *ast.FuncDecl) []string {
	var offenses []string

	report := func(call *ast.CallExpr, name string) {
		pos := fset.Position(call.Pos())
		offenses = append(offenses, fmt.Sprintf(
			"%s:%d calls %s() while holding a lock released without defer.\n"+
				"    The audit in endpoints/server/CLAUDE.md rests on these sections being\n"+
				"    panic-free: dispatchHandler recovers handler panics, so a panic here\n"+
				"    would leave this lock held forever and deadlock later requests — a\n"+
				"    silent hang where there used to be a loud, ASG-self-healing crash.\n"+
				"    Either move the call out of the critical section, or switch that\n"+
				"    unlock to defer so unwinding releases it.",
			pos.Filename, pos.Line, name))
	}

	// inspectHeld flags disallowed calls in a statement evaluated under a lock.
	inspectHeld := func(stmt ast.Stmt) {
		ast.Inspect(stmt, func(n ast.Node) bool {
			// Deferred calls run at function exit, not inside the section.
			if _, isDefer := n.(*ast.DeferStmt); isDefer {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := lockName(call)
			if name == "" ||
				name == "Lock" || name == "RLock" || name == "Unlock" || name == "RUnlock" {
				return true
			}
			// Builtins are unqualified idents; everything else must match on
			// its full pkg.Func identity, so a same-named method on some other
			// type cannot inherit a whitelist entry.
			if _, isIdent := call.Fun.(*ast.Ident); isIdent {
				if builtinsSafeInsideCriticalSection[name] {
					return true
				}
			} else if qualifiedCallsSafeInsideCriticalSection[calleeIdentity(call)] {
				return true
			}
			report(call, calleeIdentity(call))
			return true
		})
	}

	terminates := func(stmts []ast.Stmt) bool {
		if len(stmts) == 0 {
			return false
		}
		switch stmts[len(stmts)-1].(type) {
		case *ast.ReturnStmt, *ast.BranchStmt:
			return true
		}
		return false
	}

	// walkList threads `held` through a statement list and returns its state.
	var walkList func(stmts []ast.Stmt, held bool) bool
	walkList = func(stmts []ast.Stmt, held bool) bool {
		for _, stmt := range stmts {
			if exprStmt, ok := stmt.(*ast.ExprStmt); ok {
				if call, ok := exprStmt.X.(*ast.CallExpr); ok {
					switch lockName(call) {
					case "Lock", "RLock":
						held = true
						continue
					case "Unlock", "RUnlock":
						held = false
						continue
					}
				}
			}

			switch s := stmt.(type) {
			case *ast.BlockStmt:
				held = walkList(s.List, held)
				continue
			case *ast.IfStmt:
				// The condition itself is evaluated under the lock.
				if held && s.Cond != nil {
					inspectHeld(&ast.ExprStmt{X: s.Cond})
				}
				if s.Init != nil && held {
					inspectHeld(s.Init)
				}
				if s.Body != nil {
					inner := walkList(s.Body.List, held)
					if !terminates(s.Body.List) {
						held = inner
					}
				}
				if s.Else != nil {
					switch e := s.Else.(type) {
					case *ast.BlockStmt:
						inner := walkList(e.List, held)
						if !terminates(e.List) {
							held = inner
						}
					case *ast.IfStmt:
						held = walkList([]ast.Stmt{e}, held)
					}
				}
				continue
			case *ast.ForStmt:
				if s.Body != nil {
					held = walkList(s.Body.List, held)
				}
				continue
			case *ast.RangeStmt:
				if held {
					// The ranged expression is evaluated under the lock.
					inspectHeld(&ast.ExprStmt{X: s.X})
				}
				if s.Body != nil {
					held = walkList(s.Body.List, held)
				}
				continue
			}

			if held {
				inspectHeld(stmt)
			}
		}
		return held
	}

	walkList(fd.Body.List, false)
	return offenses
}

// lockName returns the bare callee name. Used for lock-op detection, where the
// receiver is irrelevant: mu.Lock(), s.someMapMutex.Lock(), and g.lastNanos
// .CompareAndSwap() all matter by their method name alone.
func lockName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// calleeIdentity renders a call as "pkg.Func" when the receiver is a plain
// ident, and falls back to the bare method name otherwise. Whitelist lookups
// use this rather than lockName so an entry cannot be inherited by a same-named
// method on an unrelated type; the fallback deliberately cannot match any
// qualified whitelist entry.
func calleeIdentity(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if recv, ok := f.X.(*ast.Ident); ok {
			return recv.Name + "." + f.Sel.Name
		}
		return f.Sel.Name
	}
	return ""
}
