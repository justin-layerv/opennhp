package server

// replaceOrAppendACConn admits an incoming ACConn into an existing
// slice for one acId, using PubKeyBase64 as the AC's stable identity.
//
// Identity: pubkey is stable across AC socket recreation (port change,
// NAT rebind, EIP swap, AC daemon restart, server-driven peer
// redispatch). IP/port are NOT stable. Matching by IP — the pre-#1157-
// F3-reliability behavior — let a same-pubkey reconnect from a NEW
// (IP, port) append instead of replace, filling the slice past
// MaxACConnsPerID and tripping the FIFO branch on a DIFFERENT
// pubkey's only slot.
//
// Returns: the resulting slice; replaced=true iff a same-pubkey slot
// was overwritten; stale = the displaced ACConn (or nil) for
// connection teardown outside the connection-map lock. stale is
// non-nil in two distinct cases the caller must distinguish via
// replaced: same-pubkey-different-addr (replaced=true) is benign —
// caller logs informationally but does NOT emit
// MetricACConnEviction; FIFO eviction (replaced=false) is a cap
// event and the caller MUST emit MetricACConnEviction.
//
// Slice header contract: the caller MUST store the returned slice
// back into the map. The replace branch mutates the input in place
// (same ptr+len), but the FIFO branch rebinds the header via a
// `slices.Delete`-shaped shift (`append(existing[:evictAt],
// existing[evictAt+1:]...)`) followed by `append(..., incoming)` —
// that combined operation may return a new backing array, and the
// intermediate sub-slice headers have different len/cap from the
// caller's pre-call header. A caller that drops the return value
// and re-uses the pre-call header would silently regress on the
// FIFO path.
//
// Caller MUST hold acConnectionMapMutex across the call — the input
// slice is the map's stored slice and is mutated in place.
//
// Precondition: incoming.ACPeer, incoming.ConnData, and
// incoming.ConnData.RemoteAddr are all non-nil, and
// incoming.ACPeer.PubKeyBase64 is non-empty (AAK signature
// verification upstream rejects empty pubkeys; an empty value here
// would match a partial-state existing entry whose pubkey is also
// empty and silently replace it). Partial entries in `existing`
// (any of those three fields nil) are skipped on BOTH the match
// loop and the FIFO-victim walk — guards the .String() deref on
// the matched branch AND the caller's log-line deref of
// `staleConn.ACPeer.PubKeyBase64` /
// `staleConn.ConnData.RemoteAddr.String()` (which would panic
// inside the connection-map lock — a server-wide DoS). Mirrors the
// defensive shape of extractPubkeysFromConns in
// ac_pubkey_cap_gate.go on the same slice.
//
// Empty-pubkey design decision (#1968 cr rounds 19-28): NO in-
// helper guard against an empty incoming pubkey. Production never
// reaches this branch (AAK signature verification upstream rejects
// empty pubkeys, and HandleACOnline at msghandler.go derives the
// pubkey from `base64.StdEncoding.EncodeToString(ppd.RemotePubKey)`
// AFTER signature verification has populated RemotePubKey). The
// two defensive options were both rejected:
//   - Silent return (`return existing, false, nil`): walks the
//     wrapper into logging "New AC instance registered" + building
//     an AAK with Registered=true on an entry the slice doesn't
//     contain — the same observable failure shape this PR fixes.
//   - Panic: adds a new panic to a production hot path for a case
//     upstream already rejects.
//
// The godoc precondition is the documented contract; test-only
// callers violating it are pinned by
// TestReplaceOrAppendACConn_EmptyPubkeyIncoming_AppendsAsNormalSlot
// which fences the current observable behavior so a future
// "loosening" change has to update the test.
func replaceOrAppendACConn(existing []*ACConn, incoming *ACConn) (out []*ACConn, replaced bool, stale *ACConn) {
	pubkey := incoming.ACPeer.PubKeyBase64 // precondition: see godoc
	for i, e := range existing {
		if e == nil || e.ACPeer == nil || e.ConnData == nil || e.ConnData.RemoteAddr == nil {
			continue
		}
		if e.ACPeer.PubKeyBase64 == pubkey {
			// `.String()` is normalization-aware by happy accident of
			// Go's net package: net.IP.String() prints IPv4-mapped
			// IPv6 (e.g., ::ffff:10.0.0.1) as the IPv4 form, so two
			// connections at the "same" address through different
			// stacks compare equal. Pre-fix code used IP.Equal()
			// which is normalization-aware by design; this is the
			// equivalent property via stringification. If a future
			// Go release ever changes the IPv4-mapped print shape,
			// the stale != nil decision would flip silently — pin
			// the assumption here.
			//
			// Same-pubkey same-addr (stale == nil) is the keepalive-
			// race case: production reuses the existing ConnData
			// pointer on this path (remoteConnectionMap is keyed by
			// the address, so a re-registration at the same address
			// finds the existing UdpConn and threads its ConnData
			// through). The full-struct overwrite at existing[i] is
			// safe because the ConnData pointer is identical; if a
			// future flow ever introduces a new ConnData at the same
			// (IP, port), the live socket reference would swap
			// silently and the wrapper wouldn't tear down the old
			// one. Fenced by
			// TestReplaceOrAppendACConn_SamePubkeySameAddr_NoStale
			// (full-struct overwrite pin) — if the assumption ever
			// breaks, that test's pointer-identity assertion is the
			// shape to look at first.
			if e.ConnData.RemoteAddr.String() != incoming.ConnData.RemoteAddr.String() {
				stale = e
			}
			existing[i] = incoming
			return existing, true, stale
		}
	}

	if len(existing) >= MaxACConnsPerID {
		// FIFO-evict the oldest non-partial entry. With same-pubkey
		// replacement above this fires only on distinct-pubkey
		// overflow — F3 permit mode admitted N+1 distinct pubkeys.
		// In permit mode the evictee can still be a live AC's only
		// slot; strict mode (NHP_AC_PUBKEY_CAP_VERIFY=true) closes
		// that residual case at the F3 gate.
		//
		// Walk past partial entries to find the oldest real victim.
		// Production never inserts partials, but a partial slot 0
		// would crash the caller's log-line deref of stale.ACPeer.
		// PubKeyBase64 / stale.ConnData.RemoteAddr.String() inside
		// the connection-map lock — server-wide DoS. The walk is
		// bounded by MaxACConnsPerID and only fires on the cap
		// branch.
		evictAt := -1
		for i, e := range existing {
			if e != nil && e.ACPeer != nil && e.ConnData != nil && e.ConnData.RemoteAddr != nil {
				evictAt = i
				break
			}
		}
		if evictAt >= 0 {
			stale = existing[evictAt]
			// Defensive only: the subsequent append-of-incoming
			// overwrites this slot in every branch (either via
			// the shift's destination or via append after the
			// shift). Kept because the cost is one mov on a
			// non-hot branch and the intent (don't leave the
			// evicted pointer reachable through the backing array)
			// is structurally clear.
			existing[evictAt] = nil
			existing = append(existing[:evictAt], existing[evictAt+1:]...)
		}
		// If evictAt < 0 (all entries partial — only reachable on a
		// future invariant break), fall through to the append below.
		// The slice grows past MaxACConnsPerID temporarily; the next
		// legitimate registration's match loop will skip the partials
		// and re-trip this branch when the cap is breached by real
		// entries.
	}
	return append(existing, incoming), false, stale
}
