package ac

// Pubkey allowlist for NHP_ARD ("redispatch") targets (#1156).
//
// The AC accepts a list of new server peers every time it receives an
// NHP_ARD message. Pre-#1156, any pubkey inside an ARD target was
// trusted verbatim — a single compromised server in the AC's peer
// set could inject attacker-controlled pubkeys and then extract the
// AC's license key over NHP_AOL against those pubkeys. See the issue
// for the full attack walkthrough.
//
// The allowlist is the set of server pubkeys this AC will accept from
// ARD. Sources (union; the trust check is a single map lookup — the
// numbering is for documentation, not precedence):
//
//   - Config.ServerPubKeyBase64 — the shared registration pubkey,
//     always trusted. Immutable after first load (updateBaseConfig
//     does not include it in the reload-patched field set) — the
//     snapshot relies on this invariant.
//
//   - server.toml peer pubkeys (UdpAC.serverPeerMap) — operator-
//     managed list that already exists for AOL-path peer setup.
//
//   - Config.ServerPubKeyAllowlist — operator-managed extras,
//     intended as the forward-compat slot for per-region /
//     per-tenant pubkeys rotated in out-of-band.
//
// All three sources plus the strict-mode flag are grouped under a
// single lock (UdpAC.serverPeerMutex) so readers never observe a
// partial reload. Writers (updateBaseConfig) acquire the same lock
// for all ARD-trust fields so a concurrent reload during an ARD
// flood is race-clean without an atomic.Pointer swap.

import (
	"encoding/base64"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// maxPubkeyLogSamples caps how many pubkey prefixes we include in
// a batched Warning summary (for both the filter-reject summary in
// filterRedispatchTargets and the load-drop summary in
// normalizeAllowlistWithDrops). Three is enough for forensics
// without bloating the log line, and both call sites use the same
// value so the ops-side eyeball contract is uniform.
const maxPubkeyLogSamples = 3

// ardTrust is the consistent view of everything
// filterRedispatchTargets needs: the trusted pubkey set (union of
// the three sources) plus the strict-mode flag. Built once per
// ARD receive under a single read lock.
//
// The map is a fresh copy so the caller can iterate without holding
// the lock — in practice an ARD has a handful of targets and
// allocating a short-lived snapshot map is cheaper than threading
// the lock through the whole filter loop.
type ardTrust struct {
	trusted map[string]struct{}
	strict  bool
}

// contains reports whether pubKey is in the trusted set. Empty
// pubkey is always rejected — RedirectTarget.Validate() enforces
// non-empty upstream, but the snapshot is the defense-in-depth
// layer that catches a refactor which skips the outer check.
func (t ardTrust) contains(pubKey string) bool {
	if pubKey == "" {
		return false
	}
	_, ok := t.trusted[pubKey]
	return ok
}

// ardTrustSnapshotConfigReads enumerates the Config fields that
// ardTrustSnapshot reads. Maintained as a compile-time fence: if a
// future field is added to ardTrustSnapshot's read set, it must
// also be referenced here AND patched in reloadARDTrust's
// `updateBaseConfig` block (see config.go line ~334 for the
// reload contract). A field rename in Config breaks the compile
// here; a new field added to the snapshot read set but forgotten
// here is caught by the test
// `TestARDTrustSnapshotConfigReads_FenceIsExhaustive`
//
// This is a static reference, not a function call — the compiler
// keeps it alive but the runtime never executes the assignment.
type ardTrustSnapshotConfigReads struct {
	RequireServerPubKeyAllowlist bool
	ServerPubKeyBase64           string
}

var _ardTrustSnapshotConfigReadsFence = func(c Config) ardTrustSnapshotConfigReads {
	return ardTrustSnapshotConfigReads{
		RequireServerPubKeyAllowlist: c.RequireServerPubKeyAllowlist,
		ServerPubKeyBase64:           c.ServerPubKeyBase64,
	}
}

// ardTrustSnapshot builds a consistent view of the allowlist + the
// strict-mode flag. Holds serverPeerMutex for the copy so readers
// never observe a partial reload; releases before returning so the
// filter loop doesn't block a concurrent reload.
//
// Pre-condition: a.config is non-nil. Guaranteed once loadBaseConfig
// has succeeded (Start returns its error and aborts otherwise).
//
// Config fields read: see `ardTrustSnapshotConfigReads` above — if
// adding a field, update that fence type AND reloadARDTrust.
func (a *UdpAC) ardTrustSnapshot() ardTrust {
	a.serverPeerMutex.RLock()
	defer a.serverPeerMutex.RUnlock()

	snap := ardTrust{
		trusted: make(map[string]struct{}, len(a.serverPeerMap)+len(a.serverPubKeyAllowlist)+1),
		strict:  a.config.RequireServerPubKeyAllowlist,
	}
	if a.config.ServerPubKeyBase64 != "" {
		snap.trusted[a.config.ServerPubKeyBase64] = struct{}{}
	}
	for k := range a.serverPeerMap {
		snap.trusted[k] = struct{}{}
	}
	for k := range a.serverPubKeyAllowlist {
		snap.trusted[k] = struct{}{}
	}
	return snap
}

// normalizeAllowlist sanitizes an operator-supplied pubkey list:
// whitespace trimmed, empties dropped, duplicates collapsed, and
// malformed base64 entries dropped with a warning. Pure — no lock,
// no UdpAC reference — so the caller can build the set before
// acquiring the mutex and holding it only for the swap.
//
// Base64 validation is defense-in-depth: a malformed entry could
// never match a real pubkey (so it's harmless), but catching it at
// load time tells an operator "you pasted this wrong" immediately,
// faster than waiting for MetricARDPubkeyPermitUnknown to flag it
// when an ARD fires in prod.
func normalizeAllowlist(raw []string) map[string]struct{} {
	set, _ := normalizeAllowlistWithDrops(raw)
	return set
}

// normalizeAllowlistWithDrops is the workhorse behind
// normalizeAllowlist — it additionally reports how many entries were
// rejected, so the first-load path in updateBaseConfig can fail Start
// (not just log) when strict mode is ON and the operator's
// allowlist contains typos. Pure; safe to call without the mutex.
//
// Per-entry drops log at Debug, with a single Warning summary at
// the end when any were dropped. An operator who accidentally pastes
// a large malformed blob (e.g. a CSV) gets one loud line plus the
// drop count rather than N Warning lines per entry. See #1239.
func normalizeAllowlistWithDrops(raw []string) (map[string]struct{}, int) {
	set := make(map[string]struct{}, len(raw))
	var (
		dropped        int
		droppedSamples []string
	)
	for _, k := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(k); err != nil {
			log.Debug("ARD allowlist: dropping malformed base64 entry %s: %v",
				pubKeyPrefix(k), err)
			if len(droppedSamples) < maxPubkeyLogSamples {
				droppedSamples = append(droppedSamples, pubKeyPrefix(k))
			}
			dropped++
			continue
		}
		set[k] = struct{}{}
	}
	if dropped > 0 {
		log.Warning("ARD allowlist: dropped %d malformed base64 entries; sample prefixes=%v",
			dropped, droppedSamples)
	}
	return set, dropped
}

// allowlistPubkeySources returns the deduplicated, sorted union of
// all currently-trusted server pubkeys. Used by updateBaseConfig to
// emit a one-line "what's actually trusted right now" log on every
// allowlist change, so an operator can verify the TOML edit took
// effect without grepping multiple log lines.
func (a *UdpAC) allowlistPubkeySources() []string {
	snap := a.ardTrustSnapshot()
	out := make([]string, 0, len(snap.trusted))
	for k := range snap.trusted {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pubKeyPrefix trims a base64 pubkey to a short logging prefix. Full
// pubkeys aren't secret (they're distributed with every AC config)
// but the prefix keeps log lines grep-friendly. Twelve ASCII chars +
// ellipsis rune disambiguates Curve25519 pubkeys in a fleet of a
// few hundred.
//
// Caller contract: pubKey is base64-encoded (ASCII-only). All
// current callers (Config fields validated as base64, NHP_ARD
// target.PubKeyBase64) preserve this. The utf8.RuneStart walk
// below is belt-and-braces against a future caller that violates
// the contract — it ensures we never slice mid-rune and emit
// invalid UTF-8 into CloudWatch log lines.
func pubKeyPrefix(pubKey string) string {
	if len(pubKey) <= 12 {
		return pubKey
	}
	// For ASCII inputs byte 12 is always a rune start; the loop
	// exits on the first iteration. For non-ASCII inputs we walk
	// back to the preceding rune boundary so the emitted prefix
	// stays valid UTF-8.
	cutoff := 12
	for cutoff > 0 && !utf8.RuneStart(pubKey[cutoff]) {
		cutoff--
	}
	return pubKey[:cutoff] + "…"
}
