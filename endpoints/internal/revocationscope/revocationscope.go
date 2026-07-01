// Package revocationscope is the single source of truth for the qURL v2
// revocation wire scopes an Access Controller applies AND acknowledges
// (NHP_RVA). It lives in endpoints/internal/ — the repo's home for AC↔server
// wire-contract code both daemons must agree on (alongside acktoken) — so the
// AC's apply/ack gate (endpoints/ac wireRevocationScope) and the NHP server's
// proof-of-delivery tracking gate (endpoints/server trackFanout) derive from ONE
// declaration and cannot drift.
//
// Drift here would re-introduce the #2793 false-age-out: the server tracking a
// scope the AC never acks (a never-arriving NHP_RVA → a false RevocationAgedOut
// on every targeted AC), or skipping a scope the AC does ack (a real un-proven
// revoke). Sharing the set makes that drift impossible by construction rather
// than caught after the fact by a mirror test.
package revocationscope

import "slices"

// ackable is the canonical set of wire scopes the AC applies and acks:
// qurl/resource/session. It is unexported and reached only via Contains/All so no
// consumer can mutate the shared source.
//
//   - "cell" is a server-side fanout selector with no AC-local index: the server
//     fans a cell-scoped revoke out, but the AC drops it WITHOUT acking, so it is
//     deliberately EXCLUDED here (the server must not proof-track it).
//   - "admission" is an AC-internal index dimension that is never a wire scope.
//
// The string values mirror qurl-service's revocation-event scopes byte-for-byte
// (the cross-repo wire contract); keep them stable.
var ackable = []string{"qurl", "resource", "session"}

// Contains reports whether scope is a wire scope the AC applies and acks. Both
// the AC apply/ack gate and the server proof-tracking gate call this, so the two
// cannot disagree about which scopes are ackable.
func Contains(scope string) bool {
	return slices.Contains(ackable, scope)
}

// All returns the ackable wire scopes as a fresh slice, in canonical declaration
// order — for tests and any consumer that needs to enumerate the set. Callers
// must not mutate the canonical source, hence the copy.
func All() []string {
	return slices.Clone(ackable)
}
