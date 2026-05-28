//go:build !nhp_debug

package common

// assertUniquePointerLocked is a no-op in non-debug builds. The
// production build pays zero cost: no scan, no branch beyond the
// inlinable method call, no observability surface. The debug-build
// counterpart (tokenstore_debug_on.go, gated `//go:build nhp_debug`)
// implements the actual scan + panic for #2214's CI fence.
//
// Both variants run with ts.mu already held by Store, so neither
// takes any locks of its own.
func (ts *TokenStore[E]) assertUniquePointerLocked(_ string, _ E) {}
