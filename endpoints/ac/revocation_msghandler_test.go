package ac

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/internal/revocationscope"
	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// P4e Slice 1: tests for the AC NHP_REV revocation message handler.
//
// These exercise HandleUdpACRevocation end-to-end against the real P4b apply
// primitive (ApplyRevocation) — not a mock — so "ApplyRevocation was invoked"
// is proven by its observable effect: the matching live AccessEntry's flow key
// is flushed immediately (via the recording flusher) and the entry is removed
// from tokenStore. The validation gates (scope allowlist, negative epoch) are
// proven NON-vacuously: a rejected event must leave live state untouched AND
// must not poison the epoch watermark, so a subsequent legitimate revoke still
// applies.
//
// Helpers (newTestACWithScheduler, qurlV2Entry, recordingFlusher.waitFor/
// snapshotKeys/count, mustKey) are shared with revocation_index_test.go — not
// duplicated here.

// withACId attaches a config so the handler's a.config.ACId log fields don't
// nil-deref; newTestACWithScheduler leaves config nil (the P4b apply tests don't
// touch it, but the handler does).
func withACId(a *UdpAC) *UdpAC {
	a.config = &Config{ACId: "test-ac"}
	return a
}

// revPPD builds a *core.PacketParserData whose BodyMessage is the JSON encoding
// of msg — the exact shape the server send side (Slice 2) will put on the wire.
func revPPD(t *testing.T, msg common.ACRevocationMsg) *core.PacketParserData {
	t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal ACRevocationMsg: %v", err)
	}
	return &core.PacketParserData{
		HeaderType:  core.NHP_REV,
		BodyMessage: body,
	}
}

// admitWithScheduledFlow stores a qURL v2 entry and schedules a far-future flow
// key for it (mirroring scheduleFlushIfEnabled on the admission path), returning
// the token and the flow key so a test can assert the flush hit exactly that
// key. The 10s deadline is far enough out that any observed flush within the
// short test window proves the revoke pulled it earlier rather than a natural
// expiry firing.
func admitWithScheduledFlow(t *testing.T, a *UdpAC, entry *AccessEntry, dstIP string) (string, FlowKey) {
	t.Helper()
	token := a.GenerateAccessToken(entry) // stores + indexes
	key := mustKey(t, "203.0.113.5", dstIP, 443, FlowProtoTCP)
	entry.recordScheduledKey(key)
	a.expirySched.Schedule(key, time.Now().Add(10*time.Second))
	return token, key
}

// TestHandleUdpACRevocation_AppliesMatchingEvent is the headline case: an
// NHP_REV with a matching scope/key and a fresh epoch must invoke
// ApplyRevocation, which flushes the matching entry's live flow immediately and
// removes it from tokenStore.
func TestHandleUdpACRevocation_AppliesMatchingEvent(t *testing.T) {
	a, flusher := newTestACWithScheduler(t)
	withACId(a)

	entry := qurlV2Entry("qhashX", "rhashX", "", "admX")
	token, key := admitWithScheduledFlow(t, a, entry, "198.51.100.9")

	// Precondition: indexed under qurl scope, present in tokenStore.
	if toks := a.revIndex.tokensFor(scopeQurl, "qhashX"); len(toks) != 1 {
		t.Fatalf("precondition: entry not indexed under qurl scope: %v", toks)
	}

	// scope_key is the PREFIXED wire form qurl-service emits; the handler strips
	// "qurl:" to the bare "qhashX" the index is keyed on.
	err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope:           "qurl",
		ScopeKey:        "qurl:qhashX",
		RevocationEpoch: 1,
		EventId:         "evt-1",
	}))
	if err != nil {
		t.Fatalf("HandleUdpACRevocation returned err=%v, want nil", err)
	}

	// ApplyRevocation was invoked: the flow was flushed immediately (not at the
	// 10s natural deadline) for exactly the revoked key.
	if !flusher.waitFor(1, 2*time.Second) {
		t.Fatalf("expected immediate flush of the revoked flow, flusher saw %d", flusher.count())
	}
	if got := flusher.snapshotKeys(); len(got) != 1 || got[0] != key {
		t.Fatalf("flushed wrong key: got %v, want [%v]", got, key)
	}

	// And the entry was removed from tokenStore (a re-knock cannot re-extend it).
	if _, found := a.tokenStore.Load(token); found {
		t.Fatalf("revoked entry still in tokenStore; ApplyRevocation did not delete it")
	}
	if toks := a.revIndex.tokensFor(scopeQurl, "qhashX"); len(toks) != 0 {
		t.Fatalf("revoked entry still indexed: %v", toks)
	}
}

// TestHandleUdpACRevocation_EachWireScopeApplies fences that every scope the
// wire contract allows (qurl/resource/session) is accepted and routed to the
// matching index dimension. SessionId is populated here explicitly so the
// session seam (empty until qurl-service #1010 in prod) is exercised.
func TestHandleUdpACRevocation_EachWireScopeApplies(t *testing.T) {
	// wireKey is the PREFIXED scope_key qurl-service emits; bareKey is what the
	// entry is indexed under (the handler strips wireKey down to bareKey).
	for _, tc := range []struct {
		name    string
		scope   string
		wireKey string
		entry   *AccessEntry
	}{
		{"qurl", "qurl", "qurl:qh", qurlV2Entry("qh", "rh", "sid", "ad")},
		{"resource", "resource", "resource:rh", qurlV2Entry("qh", "rh", "sid", "ad")},
		{"session", "session", "session:sid", qurlV2Entry("qh", "rh", "sid", "ad")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newTestACWithScheduler(t)
			withACId(a)
			token := a.GenerateAccessToken(tc.entry)

			err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
				Scope:           tc.scope,
				ScopeKey:        tc.wireKey,
				RevocationEpoch: 1,
			}))
			if err != nil {
				t.Fatalf("scope %s: HandleUdpACRevocation err=%v, want nil", tc.scope, err)
			}
			if _, found := a.tokenStore.Load(token); found {
				t.Fatalf("scope %s: entry not torn down — event was not applied", tc.scope)
			}
		})
	}
}

// TestHandleUdpACRevocation_StaleEpochDropped pins the epoch-gate path through
// the handler: after epoch 5 applies, a redelivered/older epoch for the same
// (scope, key) must be dropped — the re-admitted entry survives. (ApplyRevocation
// owns the watermark; this proves the handler does not bypass it.)
func TestHandleUdpACRevocation_StaleEpochDropped(t *testing.T) {
	a, _ := newTestACWithScheduler(t)
	withACId(a)

	// First revoke at epoch 5 applies and removes the entry.
	a.GenerateAccessToken(qurlV2Entry("qS", "rS", "", "aS"))
	if err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qS", RevocationEpoch: 5,
	})); err != nil {
		t.Fatalf("epoch 5 handler err=%v", err)
	}

	// Re-admit the same qURL hash (fresh session), then replay an OLDER epoch (4)
	// and the DUPLICATE epoch (5): both must be dropped as stale, leaving the
	// re-admitted entry alive.
	token := a.GenerateAccessToken(qurlV2Entry("qS", "rS", "", "aS2"))
	for _, stale := range []int64{4, 5} {
		if err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
			Scope: "qurl", ScopeKey: "qurl:qS", RevocationEpoch: stale,
		})); err != nil {
			t.Fatalf("stale epoch %d handler err=%v, want nil (drop is not an error)", stale, err)
		}
		if _, found := a.tokenStore.Load(token); !found {
			t.Fatalf("re-admitted entry wrongly removed by stale/duplicate epoch %d", stale)
		}
	}

	// A strictly-newer epoch (6) applies and removes it — proving the watermark
	// is at 5, not poisoned, and the handler reaches the apply path again.
	if err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qS", RevocationEpoch: 6,
	})); err != nil {
		t.Fatalf("epoch 6 handler err=%v", err)
	}
	if _, found := a.tokenStore.Load(token); found {
		t.Fatalf("entry should be gone after newer epoch 6")
	}
}

// TestHandleUdpACRevocation_NoLiveMatchIsNoOp: an NHP_REV for a scope/key with
// no live entry must be a clean no-op (no error, nothing flushed) — the common
// cell-wide-fanout case where this AC never admitted the revoked key.
func TestHandleUdpACRevocation_NoLiveMatchIsNoOp(t *testing.T) {
	a, flusher := newTestACWithScheduler(t)
	withACId(a)

	// A live entry under a DIFFERENT key, to prove the no-match revoke leaves it
	// untouched.
	survivor := a.GenerateAccessToken(qurlV2Entry("qLive", "rLive", "", "aLive"))

	err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qNeverAdmitted", RevocationEpoch: 1,
	}))
	if err != nil {
		t.Fatalf("no-match handler err=%v, want nil", err)
	}

	// Nothing flushed, and the unrelated live entry survives.
	if c := flusher.count(); c != 0 {
		t.Fatalf("no-match revoke flushed %d flows, want 0", c)
	}
	if _, found := a.tokenStore.Load(survivor); !found {
		t.Fatalf("unrelated live entry wrongly removed by a no-match revoke")
	}
}

// TestHandleUdpACRevocation_UnsupportedScopeRejected: a scope outside the wire
// allowlist must be rejected with ErrRevocationUnsupportedScope WITHOUT applying.
// "admission" is the sharp case — it IS a populated index dimension, so a raw
// revocationScope cast would actually flush by admission-id; the allowlist must
// stop it.
func TestHandleUdpACRevocation_UnsupportedScopeRejected(t *testing.T) {
	for _, scope := range []string{"admission", "cell", "", "QURL", "qurl "} {
		t.Run("scope="+scope, func(t *testing.T) {
			a, flusher := newTestACWithScheduler(t)
			withACId(a)

			// A live entry stamped with an AdmissionId, so a mistakenly-accepted
			// scope=="admission" event WOULD find and flush it — making the
			// rejection non-vacuous.
			entry := qurlV2Entry("qA", "rA", "", "the-admission-id")
			token := a.GenerateAccessToken(entry)

			err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
				Scope:           scope,
				ScopeKey:        "the-admission-id",
				RevocationEpoch: 1,
			}))
			if err == nil {
				t.Fatalf("scope=%q: expected rejection, got nil err", scope)
			}
			if !errors.Is(err, ErrRevocationUnsupportedScope) {
				t.Fatalf("scope=%q: err=%v, want ErrRevocationUnsupportedScope", scope, err)
			}

			// Nothing applied: the entry survives and nothing was flushed.
			if _, found := a.tokenStore.Load(token); !found {
				t.Fatalf("scope=%q: entry was torn down — an unsupported scope reached ApplyRevocation", scope)
			}
			if c := flusher.count(); c != 0 {
				t.Fatalf("scope=%q: %d flows flushed by a rejected event, want 0", scope, c)
			}
		})
	}
}

// TestHandleUdpACRevocation_NegativeEpochRejected: a negative wire epoch must be
// rejected with ErrRevocationNegativeEpoch BEFORE the uint64 conversion. Proven
// non-vacuously two ways: (1) the matching live entry is NOT torn down by the
// rejected event, and (2) the rejection does not poison the watermark — a
// subsequent legitimate epoch-1 revoke still applies.
func TestHandleUdpACRevocation_NegativeEpochRejected(t *testing.T) {
	a, flusher := newTestACWithScheduler(t)
	withACId(a)

	entry := qurlV2Entry("qNeg", "rNeg", "", "aNeg")
	token := a.GenerateAccessToken(entry)

	// Negative epoch → rejected, entry untouched.
	err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qNeg", RevocationEpoch: -1,
	}))
	if err == nil {
		t.Fatal("negative epoch: expected rejection, got nil err")
	}
	if !errors.Is(err, ErrRevocationNegativeEpoch) {
		t.Fatalf("negative epoch: err=%v, want ErrRevocationNegativeEpoch", err)
	}
	if _, found := a.tokenStore.Load(token); !found {
		t.Fatal("negative-epoch event reached ApplyRevocation and tore the entry down")
	}
	if c := flusher.count(); c != 0 {
		t.Fatalf("negative-epoch event flushed %d flows, want 0", c)
	}

	// Watermark not poisoned: a legitimate epoch-1 revoke now applies. (Had the
	// -1 converted to ~max-uint64 and been applied, epoch 1 would be dropped as
	// stale and the entry would survive — a fail-open.)
	if err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qNeg", RevocationEpoch: 1,
	})); err != nil {
		t.Fatalf("epoch 1 after rejected negative epoch: err=%v", err)
	}
	if _, found := a.tokenStore.Load(token); found {
		t.Fatal("entry survived a legitimate epoch-1 revoke — negative epoch poisoned the watermark")
	}
}

// TestHandleUdpACRevocation_MalformedBodyReturnsError: a body that is not valid
// ACRevocationMsg JSON must surface the unmarshal error (and apply nothing).
func TestHandleUdpACRevocation_MalformedBodyReturnsError(t *testing.T) {
	a, flusher := newTestACWithScheduler(t)
	withACId(a)
	a.GenerateAccessToken(qurlV2Entry("qM", "rM", "", "aM"))

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_REV,
		BodyMessage: []byte("{not valid json"),
	}
	if err := a.HandleUdpACRevocation(ppd); err == nil {
		t.Fatal("malformed body: expected a JSON parse error, got nil")
	}
	if c := flusher.count(); c != 0 {
		t.Fatalf("malformed body flushed %d flows, want 0", c)
	}
}

// TestHandleUdpACRevocation_EmptyScopeKeyRejected: a well-formed scope with an
// empty scope_key is rejected with ErrRevocationEmptyScopeKey (rather than
// silently no-opping inside ApplyRevocation), and applies nothing.
func TestHandleUdpACRevocation_EmptyScopeKeyRejected(t *testing.T) {
	a, flusher := newTestACWithScheduler(t)
	withACId(a)
	// A live entry that a (mistaken) empty-key apply could not target anyway, but
	// present to confirm nothing is flushed.
	survivor := a.GenerateAccessToken(qurlV2Entry("qEK", "rEK", "", "aEK"))

	err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "", RevocationEpoch: 1,
	}))
	if !errors.Is(err, ErrRevocationEmptyScopeKey) {
		t.Fatalf("empty scope_key: err=%v, want ErrRevocationEmptyScopeKey", err)
	}
	if c := flusher.count(); c != 0 {
		t.Fatalf("empty scope_key flushed %d flows, want 0", c)
	}
	if _, found := a.tokenStore.Load(survivor); !found {
		t.Fatal("empty scope_key event tore down a live entry")
	}
}

// TestHandleUdpACRevocation_StripsScopePrefixToBareKey is the load-bearing
// cross-slice test: qurl-service emits a PREFIXED scope_key ("<scope>:<hash>"),
// but the P4b index is keyed on the BARE hash. The handler must strip the prefix
// before ApplyRevocation, or revocation silently fails open (the prefixed key
// never matches the index). Proven non-vacuously: the entry is indexed under the
// bare hash, the wire event carries the prefixed form, and the entry is torn down
// — which can only happen if the strip occurred.
func TestHandleUdpACRevocation_StripsScopePrefixToBareKey(t *testing.T) {
	a, _ := newTestACWithScheduler(t)
	withACId(a)
	// Bare hash carried onto the entry (this is what scopeKeysForEntry indexes).
	entry := qurlV2Entry("barehashY", "rY", "", "aY")
	token := a.GenerateAccessToken(entry)
	if toks := a.revIndex.tokensFor(scopeQurl, "barehashY"); len(toks) != 1 {
		t.Fatalf("precondition: entry indexed under bare hash, got %v", toks)
	}

	// Wire event carries the PREFIXED key. If the handler forwarded it verbatim,
	// ApplyRevocation would look up "qurl:barehashY" — not in the index — and the
	// entry would survive (the silent fail-open this test guards against).
	if err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:barehashY", RevocationEpoch: 1,
	})); err != nil {
		t.Fatalf("prefixed-key apply err=%v", err)
	}
	if _, found := a.tokenStore.Load(token); found {
		t.Fatal("entry survived: handler did not strip the '<scope>:' prefix, so the index never matched (fail-open)")
	}
}

// TestHandleUdpACRevocation_PrefixMismatchRejected: a scope_key whose prefix
// disagrees with the scope (qurl-service always builds them consistently, so this
// is a malformed/forged event) is rejected without applying.
func TestHandleUdpACRevocation_PrefixMismatchRejected(t *testing.T) {
	a, flusher := newTestACWithScheduler(t)
	withACId(a)
	survivor := a.GenerateAccessToken(qurlV2Entry("qMM", "rMM", "", "aMM"))

	err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "resource:qMM", RevocationEpoch: 1,
	}))
	if !errors.Is(err, ErrRevocationScopeKeyPrefixMismatch) {
		t.Fatalf("prefix mismatch: err=%v, want ErrRevocationScopeKeyPrefixMismatch", err)
	}
	if c := flusher.count(); c != 0 {
		t.Fatalf("prefix-mismatch event flushed %d flows, want 0", c)
	}
	if _, found := a.tokenStore.Load(survivor); !found {
		t.Fatal("prefix-mismatch event tore down a live entry")
	}
}

// TestHandleUdpACRevocation_PrefixOnlyKeyRejected: a key that is only the prefix
// ("qurl:") with no identity is rejected as empty.
func TestHandleUdpACRevocation_PrefixOnlyKeyRejected(t *testing.T) {
	a, _ := newTestACWithScheduler(t)
	withACId(a)
	err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:", RevocationEpoch: 1,
	}))
	if !errors.Is(err, ErrRevocationEmptyScopeKey) {
		t.Fatalf("prefix-only key: err=%v, want ErrRevocationEmptyScopeKey", err)
	}
}

// TestBareScopeKey is the unit-level guard on the prefix-strip helper (the single
// source of truth for the malformed-key classification): a matching prefix yields
// the bare identity with nil error; empty/prefix-only yields
// ErrRevocationEmptyScopeKey; a mismatched/no prefix yields
// ErrRevocationScopeKeyPrefixMismatch. The identity may itself contain ':' (a
// session id is opaque), so only the single leading "<scope>:" is removed.
func TestBareScopeKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scope   revocationScope
		in      string
		want    string
		wantErr error // nil means ok
	}{
		{"qurl", scopeQurl, "qurl:abc", "abc", nil},
		{"resource", scopeResource, "resource:def", "def", nil},
		{"session_with_colon_in_id", scopeSession, "session:sess:123", "sess:123", nil},
		{"empty", scopeQurl, "", "", ErrRevocationEmptyScopeKey},
		{"prefix_only", scopeQurl, "qurl:", "", ErrRevocationEmptyScopeKey},
		{"mismatch", scopeQurl, "resource:abc", "", ErrRevocationScopeKeyPrefixMismatch},
		{"no_prefix", scopeQurl, "abc", "", ErrRevocationScopeKeyPrefixMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bareScopeKey(tc.scope, tc.in)
			if got != tc.want || !errors.Is(err, tc.wantErr) {
				t.Fatalf("bareScopeKey(%q,%q) = (%q,%v), want (%q,%v)", tc.scope, tc.in, got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// TestHandleUdpACRevocation_RejectsIncrementMetric proves the fail-closed reject
// paths increment MetricRevocationRejected. It uses a real metrics publisher
// per reject case so counts don't accumulate across cases. No scheduler is
// needed: every reject returns before the flush.
func TestHandleUdpACRevocation_RejectsIncrementMetric(t *testing.T) {
	for _, tc := range []struct {
		name string
		ppd  *core.PacketParserData
	}{
		{
			name: "malformed_body",
			ppd:  &core.PacketParserData{HeaderType: core.NHP_REV, BodyMessage: []byte("{bad")},
		},
		{
			name: "unsupported_scope",
			ppd:  revPPD(t, common.ACRevocationMsg{Scope: "admission", ScopeKey: "k", RevocationEpoch: 1}),
		},
		{
			name: "empty_scope_key",
			ppd:  revPPD(t, common.ACRevocationMsg{Scope: "qurl", ScopeKey: "", RevocationEpoch: 1}),
		},
		{
			// Properly-prefixed key so it passes the strip and reaches the epoch
			// gate (a bare "k" would be rejected earlier as a prefix mismatch).
			name: "negative_epoch",
			ppd:  revPPD(t, common.ACRevocationMsg{Scope: "qurl", ScopeKey: "qurl:k", RevocationEpoch: -1}),
		},
		{
			name: "prefix_mismatch",
			ppd:  revPPD(t, common.ACRevocationMsg{Scope: "qurl", ScopeKey: "resource:k", RevocationEpoch: 1}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &UdpAC{
				config:       &Config{ACId: "test-ac"},
				revIndex:     newRevocationIndex(),
				registration: &ACRegistration{metrics: metrics.NewPublisherForTest(t)},
			}
			if err := a.HandleUdpACRevocation(tc.ppd); err == nil {
				t.Fatalf("%s: expected a reject error, got nil", tc.name)
			}
			counters, _ := a.registration.metrics.CountersForTest(t)
			if got := counters[MetricRevocationRejected]; got != 1 {
				t.Fatalf("%s: %s = %v, want 1", tc.name, MetricRevocationRejected, got)
			}
		})
	}
}

// TestHandleUdpACRevocation_AppliedEventDoesNotIncrementRejectMetric is the
// negative control for the metric: a valid, applied event must NOT tick
// MetricRevocationRejected (otherwise the alarm would fire on normal traffic).
func TestHandleUdpACRevocation_AppliedEventDoesNotIncrementRejectMetric(t *testing.T) {
	f := newRecordingFlusher()
	sched := NewScheduler(f, WithTickInterval(2*time.Millisecond), WithWheelSize(256))
	sched.Start()
	t.Cleanup(func() { shutdownOrFail(t, sched) })
	a := &UdpAC{
		config:       &Config{ACId: "test-ac"},
		tokenStore:   common.NewTokenStore[*AccessEntry](),
		revIndex:     newRevocationIndex(),
		nhpSessions:  newNHPSessionIndex(),
		expirySched:  sched,
		registration: &ACRegistration{metrics: metrics.NewPublisherForTest(t)},
	}
	a.installExpiryHook()
	a.GenerateAccessToken(qurlV2Entry("qOK", "rOK", "", "aOK"))

	if err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qOK", RevocationEpoch: 1,
	})); err != nil {
		t.Fatalf("valid event err=%v", err)
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricRevocationRejected]; got != 0 {
		t.Fatalf("%s = %v after a valid applied event, want 0", MetricRevocationRejected, got)
	}
}

// ============================================================================
// P4e Slice 3 (#2793): AC → server proof-of-delivery ack (NHP_RVA).
// ============================================================================

// serverPubKey32 is a fixed 32-byte non-zero pubkey standing in for the server's
// authenticated pubkey on an inbound NHP_REV (ppd.RemotePubKey). The ack send
// addresses this verbatim; the bytes only need to be the right length.
func serverPubKey32() []byte {
	pk := make([]byte, core.PublicKeySize)
	for i := range pk {
		pk[i] = byte(i + 1)
	}
	return pk
}

// revPPDWithConn builds an inbound-NHP_REV PacketParserData that the ack path can
// reply on: a non-nil ConnData and an authenticated server pubkey. The ConnData
// fields are otherwise empty — sendRevocationAck only enqueues onto a.sendMsgCh
// (it does not drive the send machinery), so a zero-value ConnData suffices to
// carry the reply envelope through the channel in a unit test.
func revPPDWithConn(t *testing.T, msg common.ACRevocationMsg) *core.PacketParserData {
	t.Helper()
	ppd := revPPD(t, msg)
	ppd.ConnData = &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 46201}}
	ppd.RemotePubKey = serverPubKey32()
	return ppd
}

// acWithSendCapture builds a UdpAC wired to actually send a revocation ack: a
// real core.Device (for NextCounterIndex), a buffered sendMsgCh the test drains,
// a metrics publisher, the revocation index, a scheduler, and running=true. It
// returns the AC and the send channel.
func acWithSendCapture(t *testing.T) (*UdpAC, chan *core.MsgData) {
	t.Helper()
	f := newRecordingFlusher()
	sched := NewScheduler(f, WithTickInterval(2*time.Millisecond), WithWheelSize(256))
	sched.Start()
	t.Cleanup(func() { shutdownOrFail(t, sched) })

	sendCh := make(chan *core.MsgData, 8)
	a := &UdpAC{
		config:       &Config{ACId: "test-ac", DefaultCipherScheme: 0},
		device:       core.NewDevice(core.NHP_AC, testPrivateKey(), nil),
		tokenStore:   common.NewTokenStore[*AccessEntry](),
		revIndex:     newRevocationIndex(),
		nhpSessions:  newNHPSessionIndex(),
		expirySched:  sched,
		registration: &ACRegistration{metrics: metrics.NewPublisherForTest(t)},
		sendMsgCh:    sendCh,
	}
	a.installExpiryHook()
	a.bootID = "00112233445566778899aabbccddeeff"
	a.sessionFlushGeneration.Store(1)
	a.sessionFlushComplete.Store(true)
	a.sessionControlLeaseHeld.Store(true)
	a.running.Store(true)
	return a, sendCh
}

func sessionClosePPD(t *testing.T, msg common.ACSessionCloseMsg) *core.PacketParserData {
	t.Helper()
	body, err := json.Marshal(&msg)
	if err != nil {
		t.Fatalf("marshal session close: %v", err)
	}
	return &core.PacketParserData{
		BodyMessage:  body,
		ConnData:     &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 46202}},
		RemotePubKey: serverPubKey32(),
	}
}

func testRVAThroughACSendLoop(t *testing.T, enqueue func(*UdpAC, *core.PacketParserData) error) {
	t.Helper()
	serverKey := make([]byte, core.PrivateKeySize)
	for i := range serverKey {
		serverKey[i] = byte(255 - i)
	}
	serverDevice := core.NewDevice(core.NHP_SERVER, serverKey, nil)
	if serverDevice == nil {
		t.Fatal("NewDevice(server) returned nil")
	}
	acDevice := core.NewDevice(core.NHP_AC, testPrivateKey(), nil)
	if acDevice == nil {
		t.Fatal("NewDevice(AC) returned nil")
	}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 46321}
	serverPeer := &core.UdpPeer{
		Ip: remoteAddr.IP.String(), Port: remoteAddr.Port,
		PubKeyBase64: serverDevice.PublicKeyBase64(), Type: core.NHP_SERVER,
	}
	acDevice.AddPeer(serverPeer)
	acDevice.Start()
	t.Cleanup(acDevice.Stop)

	connData := &core.ConnectionData{
		Device: acDevice, RemoteAddr: remoteAddr,
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		SendQueue:            make(chan *core.Packet, 1), RecvQueue: make(chan *core.Packet, 1),
		BlockSignal: make(chan struct{}), SetTimeoutSignal: make(chan struct{}, 1), StopSignal: make(chan struct{}),
	}
	a := &UdpAC{
		config: &Config{ACId: "test-ac"}, device: acDevice,
		sendMsgCh: make(chan *core.MsgData, 1), remoteConnectionMap: map[string]*UdpConn{
			remoteAddr.String(): {ConnData: connData},
		},
	}
	a.signals.stop = make(chan struct{})
	a.bootID = "00112233445566778899aabbccddeeff"
	a.sessionFlushGeneration.Store(7)
	a.sessionFlushComplete.Store(true)
	a.running.Store(true)
	a.wg.Add(1)
	go a.sendMessageRoutine()
	t.Cleanup(func() {
		close(a.signals.stop)
		a.wg.Wait()
	})
	ppd := &core.PacketParserData{
		ConnData: connData, RemotePubKey: serverPeer.PublicKey(), CipherScheme: common.CIPHER_SCHEME_CURVE,
	}
	if err := enqueue(a, ppd); err != nil {
		t.Fatalf("enqueue RVA: %v", err)
	}
	select {
	case pkt := <-connData.SendQueue:
		if pkt == nil || pkt.HeaderType != core.NHP_RVA {
			t.Fatalf("send-loop packet = %#v, want NHP_RVA", pkt)
		}
		acDevice.ReleasePoolPacket(pkt)
	case <-time.After(2 * time.Second):
		t.Fatal("RVA did not reach the authenticated inbound connection send queue")
	}
}

func TestACAcknowledgementsTraverseRealSendLoopOnAuthenticatedInboundRoute(t *testing.T) {
	t.Run("session control RVA", func(t *testing.T) {
		testRVAThroughACSendLoop(t, func(a *UdpAC, ppd *core.PacketParserData) error {
			return a.sendSessionControlAck(ppd, &common.ACSessionCloseMsg{
				Kind: common.ACSessionCloseKind, Scope: common.ACSessionCloseScopeExact,
				EventID:        "ffeeddccbbaa99887766554433221100",
				AgentPublicKey: testNHPAgentKey('A'), SessionID: 1, SessionIssuedAtMillis: 2,
			}, 0)
		})
	})
	t.Run("generic revocation RVA", func(t *testing.T) {
		testRVAThroughACSendLoop(t, func(a *UdpAC, ppd *core.PacketParserData) error {
			a.registration = &ACRegistration{metrics: metrics.NewPublisherForTest(t)}
			a.sendRevocationAck(ppd, &common.ACRevocationMsg{
				Scope: "qurl", ScopeKey: "qurl:q1", RevocationEpoch: 1,
				EventId: "ffeeddccbbaa99887766554433221100",
			})
			return nil
		})
	})
}

func TestACSessionControlAckUsesObservedServerSourceOnOriginalNLBSocket(t *testing.T) {
	serverKey := make([]byte, core.PrivateKeySize)
	for index := range serverKey {
		serverKey[index] = byte(240 - index)
	}
	serverDevice := core.NewDevice(core.NHP_SERVER, serverKey, nil)
	acDevice := core.NewDevice(core.NHP_AC, testPrivateKey(), nil)
	if serverDevice == nil || acDevice == nil {
		t.Fatal("failed to construct wire devices")
	}
	actualServer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 46331}
	nlbAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 46332}
	serverPeer := &core.UdpPeer{Ip: nlbAddr.IP.String(), Port: nlbAddr.Port,
		PubKeyBase64: serverDevice.PublicKeyBase64(), Type: core.NHP_SERVER}
	acDevice.AddPeer(serverPeer)
	acDevice.Start()
	t.Cleanup(acDevice.Stop)

	nlbConn := &core.ConnectionData{Device: acDevice, RemoteAddr: nlbAddr,
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		SendQueue:            make(chan *core.Packet, 1), RecvQueue: make(chan *core.Packet, 1),
		BlockSignal: make(chan struct{}), SetTimeoutSignal: make(chan struct{}, 1), StopSignal: make(chan struct{})}
	a := &UdpAC{config: &Config{ACId: "test-ac"}, device: acDevice, sendMsgCh: make(chan *core.MsgData, 1),
		remoteConnectionMap: map[string]*UdpConn{nlbAddr.String(): {ConnData: nlbConn}}}
	a.signals.stop = make(chan struct{})
	a.bootID = "00112233445566778899aabbccddeeff"
	a.sessionFlushGeneration.Store(7)
	a.sessionFlushComplete.Store(true)
	a.running.Store(true)
	a.wg.Add(1)
	go a.sendMessageRoutine()
	t.Cleanup(func() { close(a.signals.stop); a.wg.Wait() })

	ppd := &core.PacketParserData{ConnData: nlbConn, ReceivedFrom: actualServer.AddrPort(),
		RemotePubKey: serverPeer.PublicKey(), CipherScheme: common.CIPHER_SCHEME_CURVE}
	if err := a.sendSessionControlAck(ppd, &common.ACSessionCloseMsg{
		Kind: common.ACSessionCloseKind, Scope: common.ACSessionCloseScopeExact,
		EventID: "ffeeddccbbaa99887766554433221100", AgentPublicKey: testNHPAgentKey('A'),
		SessionID: 1, SessionIssuedAtMillis: 2,
	}, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-nlbConn.SendQueue:
		if pkt == nil {
			t.Fatal("RVA packet is nil")
		}
		if pkt.HeaderType != core.NHP_RVA || pkt.SendTo != actualServer.AddrPort() {
			t.Fatalf("RVA packet route = %#v/%v, want original queue -> %s", pkt, pkt.SendTo, actualServer)
		}
		acDevice.ReleasePoolPacket(pkt)
	case <-time.After(2 * time.Second):
		t.Fatal("RVA did not use original NLB connection queue")
	}
	a.remoteConnectionMutex.Lock()
	defer a.remoteConnectionMutex.Unlock()
	if len(a.remoteConnectionMap) != 1 || a.remoteConnectionMap[nlbAddr.String()] == nil ||
		a.remoteConnectionMap[actualServer.String()] != nil {
		t.Fatalf("ack route created a second socket: %#v", a.remoteConnectionMap)
	}
}

func TestACSessionControlNLBIngressReturnsAuthenticatedRVAOnOriginalSocket(t *testing.T) {
	a, _ := acWithSendCapture(t)
	serverKey := make([]byte, core.PrivateKeySize)
	for index := range serverKey {
		serverKey[index] = byte(220 - index)
	}
	serverDevice := core.NewDevice(core.NHP_SERVER, serverKey, nil)
	if serverDevice == nil || a.device == nil {
		t.Fatal("failed to construct wire devices")
	}
	actualServer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 46341}
	nlbAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 46342}
	acAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 46343}
	a.device.AddPeer(&core.UdpPeer{Ip: nlbAddr.IP.String(), Port: nlbAddr.Port,
		PubKeyBase64: serverDevice.PublicKeyBase64(), Type: core.NHP_SERVER})
	serverDevice.AddPeer(&core.UdpPeer{Ip: acAddr.IP.String(), Port: acAddr.Port,
		PubKeyBase64: a.device.PublicKeyBase64(), Type: core.NHP_AC})
	a.device.Start()
	serverDevice.Start()
	t.Cleanup(a.device.Stop)
	t.Cleanup(serverDevice.Stop)

	nlbConn := &core.ConnectionData{Device: a.device, RemoteAddr: nlbAddr,
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		SendQueue:            make(chan *core.Packet, 1), RecvQueue: make(chan *core.Packet, 1),
		BlockSignal: make(chan struct{}), SetTimeoutSignal: make(chan struct{}, 1), StopSignal: make(chan struct{})}
	serverConn := &core.ConnectionData{Device: serverDevice, RemoteAddr: acAddr,
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		SendQueue:            make(chan *core.Packet, 1), RecvQueue: make(chan *core.Packet, 1),
		BlockSignal: make(chan struct{}), SetTimeoutSignal: make(chan struct{}, 1), StopSignal: make(chan struct{})}
	a.sendMsgCh = make(chan *core.MsgData, 1)
	a.remoteConnectionMap = map[string]*UdpConn{nlbAddr.String(): {ConnData: nlbConn}}
	a.signals.stop = make(chan struct{})
	a.wg.Add(1)
	go a.sendMessageRoutine()
	t.Cleanup(func() { close(a.signals.stop); a.wg.Wait() })

	closeMsg := common.ACSessionCloseMsg{
		Kind: common.ACSessionCloseKind, Scope: common.ACSessionCloseScopeExact,
		EventID: "1234567890abcdef1234567890abcdef", AgentPublicKey: testNHPAgentKey('N'),
		SessionID: 41, SessionIssuedAtMillis: 42,
	}
	closeBody, err := json.Marshal(closeMsg)
	if err != nil {
		t.Fatal(err)
	}
	acPublicKey, err := base64.StdEncoding.DecodeString(a.device.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	serverDevice.SendMsgToPacket(&core.MsgData{
		ConnData: serverConn, HeaderType: core.NHP_REV, CipherScheme: common.CIPHER_SCHEME_CURVE,
		TransactionId: serverDevice.NextCounterIndex(), Compress: true,
		PeerPk: acPublicKey, Message: closeBody,
	})
	var revPacket *core.Packet
	select {
	case revPacket = <-serverConn.SendQueue:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not encrypt NHP_REV")
	}
	revWire := append([]byte(nil), revPacket.Content...)
	serverDevice.ReleasePoolPacket(revPacket)
	revPPD, err := a.device.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: revWire, ReceivedFrom: actualServer.AddrPort()},
		ConnData:   nlbConn, InitTime: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("AC decrypt NHP_REV: %v", err)
	}
	if revPPD.ConnData != nlbConn || revPPD.ReceivedFrom != actualServer.AddrPort() {
		t.Fatalf("authenticated REV route = %p/%v, want NLB conn %p and source %v",
			revPPD.ConnData, revPPD.ReceivedFrom, nlbConn, actualServer.AddrPort())
	}
	if err := a.HandleUdpACRevocation(revPPD); err != nil {
		t.Fatalf("handle encrypted NHP_REV: %v", err)
	}
	var rvaPacket *core.Packet
	select {
	case rvaPacket = <-nlbConn.SendQueue:
	case <-time.After(2 * time.Second):
		t.Fatal("AC did not encrypt NHP_RVA on original connection")
	}
	if rvaPacket.SendTo != actualServer.AddrPort() {
		t.Fatalf("encrypted RVA destination = %v, want actual server %v", rvaPacket.SendTo, actualServer.AddrPort())
	}
	rvaWire := append([]byte(nil), rvaPacket.Content...)
	a.device.ReleasePoolPacket(rvaPacket)
	rvaPPD, err := serverDevice.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: rvaWire}, ConnData: serverConn, InitTime: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("server decrypt NHP_RVA: %v", err)
	}
	var ack common.ACSessionCloseAckMsg
	if err := common.DecodeACSessionCloseAckMsg(rvaPPD.BodyMessage, &ack); err != nil {
		t.Fatalf("strict RVA decode: %v", err)
	}
	if ack.EventID != closeMsg.EventID || ack.AgentPublicKey != closeMsg.AgentPublicKey ||
		ack.SessionID != closeMsg.SessionID || ack.SessionIssuedAtMillis != closeMsg.SessionIssuedAtMillis ||
		ack.BootID != a.bootID || ack.FlushGeneration != a.sessionFlushGeneration.Load() || ack.Closed != 0 {
		t.Fatalf("RVA authority = %#v, want exact zero-close acknowledgement", ack)
	}
	if nlbConn.RemoteAddr.String() != nlbAddr.String() || len(a.remoteConnectionMap) != 1 {
		t.Fatalf("NLB connection was mutated or duplicated: remote=%v map=%#v", nlbConn.RemoteAddr, a.remoteConnectionMap)
	}
}

func TestHandleUdpACRevocationSessionControlScopesAndAck(t *testing.T) {
	const (
		agentKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		runID    = "0123456789abcdef"
	)
	t.Run("exact session", func(t *testing.T) {
		a, sendCh := acWithSendCapture(t)
		a.storeToken("target", &AccessEntry{NHPSessionId: 77, NHPServerPublicKey: "server", NHPSessionOwnerId: "00112233445566778899aabbccddeeff", NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: 100})
		a.storeToken("same-id-new-issuance", &AccessEntry{NHPSessionId: 77, NHPServerPublicKey: "server", NHPSessionOwnerId: "ffeeddccbbaa99887766554433221100", NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: 101})
		a.storeToken("different-session", &AccessEntry{NHPSessionId: 78, NHPServerPublicKey: "server", NHPSessionOwnerId: "00112233445566778899aabbccddeeff", NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: 100})
		a.storeToken("different-agent", &AccessEntry{NHPSessionId: 77, NHPServerPublicKey: "server", NHPSessionOwnerId: "00112233445566778899aabbccddeeff", NHPAgentPublicKey: testNHPAgentKey('B'), NHPSessionIssuedAtMillis: 100})
		msg := common.ACSessionCloseMsg{
			Kind:                  common.ACSessionCloseKind,
			Scope:                 common.ACSessionCloseScopeExact,
			EventID:               "ffeeddccbbaa99887766554433221100",
			AgentPublicKey:        agentKey,
			SessionID:             77,
			SessionIssuedAtMillis: 100,
		}
		if err := a.HandleUdpACRevocation(sessionClosePPD(t, msg)); err != nil {
			t.Fatalf("HandleUdpACRevocation() error = %v", err)
		}
		if _, ok := a.tokenStore.Load("target"); ok {
			t.Fatal("exact target survived close")
		}
		for _, token := range []string{"same-id-new-issuance", "different-session", "different-agent"} {
			if _, ok := a.tokenStore.Load(token); !ok {
				t.Fatalf("exact close removed sibling %q", token)
			}
		}
		var ack common.ACSessionCloseAckMsg
		if err := common.DecodeACSessionCloseAckMsg(drainOneAck(t, sendCh).Message, &ack); err != nil {
			t.Fatalf("decode strict exact ack: %v", err)
		}
		if ack.Scope != msg.Scope || ack.EventID != msg.EventID || ack.AgentPublicKey != agentKey ||
			ack.SessionID != 77 || ack.SessionIssuedAtMillis != 100 || ack.Closed != 1 ||
			ack.BootID != a.bootID || ack.FlushGeneration != 1 {
			t.Fatalf("exact ack = %#v", ack)
		}
	})

	t.Run("agent cutoff", func(t *testing.T) {
		a, sendCh := acWithSendCapture(t)
		a.storeToken("old", &AccessEntry{NHPSessionId: 1, NHPServerPublicKey: "server", NHPSessionOwnerId: "00112233445566778899aabbccddeeff", NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: 100})
		a.storeToken("new", &AccessEntry{NHPSessionId: 2, NHPServerPublicKey: "server", NHPSessionOwnerId: "00112233445566778899aabbccddeeff", NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: 300})
		if got := len(a.nhpSessions.agentTokens(agentKey)); got != 2 {
			t.Fatalf("agent index tokens = %d, want 2", got)
		}
		msg := common.ACSessionCloseMsg{
			Kind:                common.ACSessionCloseKind,
			Scope:               common.ACSessionCloseScopeAgent,
			EventID:             "ffeeddccbbaa99887766554433221100",
			AgentPublicKey:      agentKey,
			IssuedThroughMillis: 200,
		}
		if err := a.HandleUdpACRevocation(sessionClosePPD(t, msg)); err != nil {
			t.Fatalf("HandleUdpACRevocation() error = %v", err)
		}
		if _, ok := a.tokenStore.Load("old"); ok {
			t.Fatal("old agent session survived cutoff")
		}
		if _, ok := a.tokenStore.Load("new"); !ok {
			t.Fatal("post-cutoff agent session was closed")
		}
		var ack common.ACSessionCloseAckMsg
		if err := json.Unmarshal(drainOneAck(t, sendCh).Message, &ack); err != nil {
			t.Fatalf("decode ack: %v", err)
		}
		if ack.Scope != msg.Scope || ack.EventID != msg.EventID || ack.Closed != 1 ||
			ack.BootID != a.bootID || ack.FlushGeneration != 1 {
			t.Fatalf("ack = %#v", ack)
		}
	})

	t.Run("run barrier", func(t *testing.T) {
		a, sendCh := acWithSendCapture(t)
		a.storeToken("attempt-1", &AccessEntry{NHPSessionId: 1, NHPServerPublicKey: "server", NHPSessionOwnerId: "00112233445566778899aabbccddeeff", NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: 100, NHPRunID: runID, NHPRunAttempt: 1})
		a.storeToken("attempt-2", &AccessEntry{NHPSessionId: 2, NHPServerPublicKey: "server", NHPSessionOwnerId: "00112233445566778899aabbccddeeff", NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: 200, NHPRunID: runID, NHPRunAttempt: 2})
		a.storeToken("sibling", &AccessEntry{NHPSessionId: 3, NHPServerPublicKey: "server", NHPSessionOwnerId: "00112233445566778899aabbccddeeff", NHPAgentPublicKey: agentKey, NHPSessionIssuedAtMillis: 100, NHPRunID: "fedcba9876543210", NHPRunAttempt: 1})
		if got := len(a.nhpSessions.runTokens(agentKey, runID)); got != 2 {
			t.Fatalf("run index tokens = %d, want 2", got)
		}
		msg := common.ACSessionCloseMsg{
			Kind:           common.ACSessionCloseKind,
			Scope:          common.ACSessionCloseScopeRun,
			EventID:        "ffeeddccbbaa99887766554433221100",
			AgentPublicKey: agentKey,
			RunID:          runID,
			RunAttempt:     2,
		}
		if err := a.HandleUdpACRevocation(sessionClosePPD(t, msg)); err != nil {
			t.Fatalf("HandleUdpACRevocation() error = %v", err)
		}
		if _, ok := a.tokenStore.Load("attempt-1"); ok {
			t.Fatal("older run attempt survived barrier")
		}
		if _, ok := a.tokenStore.Load("attempt-2"); !ok {
			t.Fatal("current run attempt was closed")
		}
		if _, ok := a.tokenStore.Load("sibling"); !ok {
			t.Fatal("fresh sibling RunID was closed")
		}
		var ack common.ACSessionCloseAckMsg
		if err := json.Unmarshal(drainOneAck(t, sendCh).Message, &ack); err != nil {
			t.Fatalf("decode ack: %v", err)
		}
		if ack.Scope != msg.Scope || ack.RunID != runID || ack.RunAttempt != 2 || ack.Closed != 1 {
			t.Fatalf("ack = %#v", ack)
		}
	})
}

func TestExactSessionCloseRetriesActualRuleAfterTransientFlushFailure(t *testing.T) {
	const agentKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	flusher := &failFirstSessionControlFlusher{}
	scheduler := NewScheduler(flusher, WithTickInterval(time.Hour))
	scheduler.Start()
	t.Cleanup(func() { shutdownOrFail(t, scheduler) })
	sendCh := make(chan *core.MsgData, 2)
	a := &UdpAC{
		config:       &Config{ACId: "test-ac", FilterMode: FilterMode_IPTABLES},
		device:       core.NewDevice(core.NHP_AC, testPrivateKey(), nil),
		tokenStore:   common.NewTokenStore[*AccessEntry](),
		revIndex:     newRevocationIndex(),
		nhpSessions:  newNHPSessionIndex(),
		expirySched:  scheduler,
		registration: &ACRegistration{metrics: metrics.NewPublisherForTest(t)},
		sendMsgCh:    sendCh,
	}
	a.bootID = "00112233445566778899aabbccddeeff"
	a.sessionFlushGeneration.Store(1)
	a.sessionFlushComplete.Store(true)
	a.sessionControlLeaseHeld.Store(true)
	a.running.Store(true)

	key, err := MakeFlowKey("192.0.2.50", "192.0.2.60", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	target := &AccessEntry{
		OpenTime:                 60,
		NHPSessionId:             77,
		NHPServerPublicKey:       "server",
		NHPSessionOwnerId:        "00112233445566778899aabbccddeeff",
		NHPAgentPublicKey:        agentKey,
		NHPSessionIssuedAtMillis: 100,
	}
	target.recordScheduledKey(key)
	targetToken := a.GenerateAccessToken(target)
	sibling := &AccessEntry{
		OpenTime:                 60,
		NHPSessionId:             77,
		NHPServerPublicKey:       "server",
		NHPSessionOwnerId:        "ffeeddccbbaa99887766554433221100",
		NHPAgentPublicKey:        agentKey,
		NHPSessionIssuedAtMillis: 101,
	}
	siblingToken := a.GenerateAccessToken(sibling)
	scheduler.Schedule(key, time.Now().Add(time.Hour))
	msg := common.ACSessionCloseMsg{
		Kind:                  common.ACSessionCloseKind,
		Scope:                 common.ACSessionCloseScopeExact,
		EventID:               "0123456789abcdeffedcba9876543210",
		AgentPublicKey:        agentKey,
		SessionID:             77,
		SessionIssuedAtMillis: 100,
	}

	if err := a.HandleUdpACRevocation(sessionClosePPD(t, msg)); err == nil {
		t.Fatal("first exact close unexpectedly converged")
	}
	if len(sendCh) != 0 {
		t.Fatal("failed exact close emitted an RVA")
	}
	if _, ok := a.tokenStore.Load(targetToken); !ok {
		t.Fatal("failed exact close destructively removed retry state")
	}
	if got := a.VerifyAccessToken(targetToken); got != nil {
		t.Fatal("pending exact-close token remained usable")
	}
	if a.nhpSessions.admitsSession(sessionFenceEntry(agentKey, 77, 100)) {
		t.Fatal("failed exact cleanup admitted the target tuple")
	}
	if !a.nhpSessions.admitsSession(sessionFenceEntry(agentKey, 77, 101)) {
		t.Fatal("pending exact cleanup rejected a sibling issuance")
	}

	if err := a.HandleUdpACRevocation(sessionClosePPD(t, msg)); err != nil {
		t.Fatalf("retry exact close error = %v", err)
	}
	if got := flusher.count(); got != 2 {
		t.Fatalf("flush calls = %d, want actual key retried once", got)
	}
	if _, ok := a.tokenStore.Load(targetToken); ok {
		t.Fatal("converged exact close retained target token")
	}
	if _, ok := a.tokenStore.Load(siblingToken); !ok {
		t.Fatal("converged exact close removed sibling token")
	}
	var ack common.ACSessionCloseAckMsg
	if err := common.DecodeACSessionCloseAckMsg(drainOneAck(t, sendCh).Message, &ack); err != nil {
		t.Fatalf("decode retry ack: %v", err)
	}
	if ack.Scope != common.ACSessionCloseScopeExact || ack.SessionID != 77 ||
		ack.SessionIssuedAtMillis != 100 || ack.Closed != 1 || ack.BootID != a.bootID || ack.FlushGeneration != 1 {
		t.Fatalf("retry exact ack = %#v", ack)
	}
}

type failFirstSessionControlFlusher struct {
	mu    sync.Mutex
	calls int
}

func (f *failFirstSessionControlFlusher) Flush(context.Context, FlowKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls == 1 {
		return errors.New("injected transient flush failure")
	}
	return nil
}

func (f *failFirstSessionControlFlusher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestSessionControlCloseRetriesActualRuleAfterTransientFlushFailure(t *testing.T) {
	const agentKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	flusher := &failFirstSessionControlFlusher{}
	scheduler := NewScheduler(flusher, WithTickInterval(time.Hour))
	scheduler.Start()
	t.Cleanup(func() { shutdownOrFail(t, scheduler) })
	sendCh := make(chan *core.MsgData, 2)
	a := &UdpAC{
		config:       &Config{ACId: "test-ac", FilterMode: FilterMode_IPTABLES},
		device:       core.NewDevice(core.NHP_AC, testPrivateKey(), nil),
		tokenStore:   common.NewTokenStore[*AccessEntry](),
		revIndex:     newRevocationIndex(),
		nhpSessions:  newNHPSessionIndex(),
		expirySched:  scheduler,
		registration: &ACRegistration{metrics: metrics.NewPublisherForTest(t)},
		sendMsgCh:    sendCh,
	}
	a.bootID = "00112233445566778899aabbccddeeff"
	a.sessionFlushGeneration.Store(1)
	a.sessionFlushComplete.Store(true)
	a.sessionControlLeaseHeld.Store(true)
	a.running.Store(true)

	key, err := MakeFlowKey("192.0.2.10", "192.0.2.20", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	entry := &AccessEntry{
		OpenTime:                 60,
		NHPSessionId:             1,
		NHPServerPublicKey:       "server",
		NHPSessionOwnerId:        "00112233445566778899aabbccddeeff",
		NHPAgentPublicKey:        agentKey,
		NHPSessionIssuedAtMillis: 100,
	}
	entry.recordScheduledKey(key)
	token := a.GenerateAccessToken(entry)
	scheduler.Schedule(key, time.Now().Add(time.Hour))
	msg := common.ACSessionCloseMsg{
		Kind:                common.ACSessionCloseKind,
		Scope:               common.ACSessionCloseScopeAgent,
		EventID:             "ffeeddccbbaa99887766554433221100",
		AgentPublicKey:      agentKey,
		IssuedThroughMillis: 200,
	}

	if err := a.HandleUdpACRevocation(sessionClosePPD(t, msg)); err == nil {
		t.Fatal("first close unexpectedly converged")
	}
	if len(sendCh) != 0 {
		t.Fatal("failed close emitted an RVA")
	}
	if _, ok := a.tokenStore.Load(token); !ok {
		t.Fatal("failed close destructively removed retry state")
	}
	if got := len(entry.snapshotScheduledKeys()); got != 1 {
		t.Fatalf("failed close retained %d keys, want 1", got)
	}
	if got := a.VerifyAccessToken(token); got != nil {
		t.Fatal("closing token remained usable after teardown began")
	}
	if scheduler.IsBreakerOpen() {
		t.Fatal("single direct flush failure should not be inferred through the scheduler breaker")
	}
	newer := sessionFenceEntry(agentKey, 2, 201)
	if a.nhpSessions.admitsSession(newer) {
		t.Fatal("failed agent cleanup admitted a newer same-agent session while cutoff was pending")
	}

	if err := a.HandleUdpACRevocation(sessionClosePPD(t, msg)); err != nil {
		t.Fatalf("retry close error = %v", err)
	}
	if flusher.count() != 2 {
		t.Fatalf("flush calls = %d, want actual key retried once", flusher.count())
	}
	if _, ok := a.tokenStore.Load(token); ok {
		t.Fatal("converged close retained token")
	}
	if !a.nhpSessions.admitsSession(newer) {
		t.Fatal("successful agent cleanup retry did not admit a post-cutoff session")
	}
	drainOneAck(t, sendCh)
}

func TestRunSessionCloseDoesNotAdmitRequestedAttemptUntilRetryConverges(t *testing.T) {
	const (
		agentKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		runID    = "0123456789abcdef"
	)
	flusher := &failFirstSessionControlFlusher{}
	scheduler := NewScheduler(flusher, WithTickInterval(time.Hour))
	scheduler.Start()
	t.Cleanup(func() { shutdownOrFail(t, scheduler) })
	sendCh := make(chan *core.MsgData, 2)
	a := &UdpAC{
		config:       &Config{ACId: "test-ac", FilterMode: FilterMode_IPTABLES},
		device:       core.NewDevice(core.NHP_AC, testPrivateKey(), nil),
		tokenStore:   common.NewTokenStore[*AccessEntry](),
		revIndex:     newRevocationIndex(),
		nhpSessions:  newNHPSessionIndex(),
		expirySched:  scheduler,
		registration: &ACRegistration{metrics: metrics.NewPublisherForTest(t)},
		sendMsgCh:    sendCh,
	}
	a.bootID = "00112233445566778899aabbccddeeff"
	a.sessionFlushGeneration.Store(1)
	a.sessionFlushComplete.Store(true)
	a.sessionControlLeaseHeld.Store(true)
	a.running.Store(true)

	key, err := MakeFlowKey("192.0.2.30", "192.0.2.40", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	entry := &AccessEntry{
		OpenTime:                 60,
		NHPSessionId:             1,
		NHPServerPublicKey:       "server",
		NHPSessionOwnerId:        "00112233445566778899aabbccddeeff",
		NHPAgentPublicKey:        agentKey,
		NHPSessionIssuedAtMillis: 100,
		NHPRunID:                 runID,
		NHPRunAttempt:            1,
	}
	entry.recordScheduledKey(key)
	token := a.GenerateAccessToken(entry)
	scheduler.Schedule(key, time.Now().Add(time.Hour))
	msg := common.ACSessionCloseMsg{
		Kind:           common.ACSessionCloseKind,
		Scope:          common.ACSessionCloseScopeRun,
		EventID:        "0123456789abcdeffedcba9876543210",
		AgentPublicKey: agentKey,
		RunID:          runID,
		RunAttempt:     2,
	}

	if err := a.HandleUdpACRevocation(sessionClosePPD(t, msg)); err == nil {
		t.Fatal("first run close unexpectedly converged")
	}
	if len(sendCh) != 0 {
		t.Fatal("failed run close emitted an RVA")
	}
	if _, ok := a.tokenStore.Load(token); !ok {
		t.Fatal("failed run close removed retry state")
	}
	if err := a.runAttemptBarriers().requireExact(agentKey, runID, 2, 1); !errors.Is(err, errNHPRunAttemptBarrierPending) {
		t.Fatalf("requested attempt after failed cleanup = %v, want pending", err)
	}

	if err := a.HandleUdpACRevocation(sessionClosePPD(t, msg)); err != nil {
		t.Fatalf("retry run close error = %v", err)
	}
	if got := flusher.count(); got != 2 {
		t.Fatalf("flush calls = %d, want actual key retried once", got)
	}
	if _, ok := a.tokenStore.Load(token); ok {
		t.Fatal("converged run close retained older attempt")
	}
	if err := a.runAttemptBarriers().requireExact(agentKey, runID, 2, 1); err != nil {
		t.Fatalf("requested attempt after retry convergence = %v", err)
	}
	drainOneAck(t, sendCh)
}

// drainOneAck returns the single MsgData enqueued on sendCh, or fails if none /
// more than one is present. Used to assert exactly one NHP_RVA was sent.
func drainOneAck(t *testing.T, sendCh chan *core.MsgData) *core.MsgData {
	t.Helper()
	select {
	case md := <-sendCh:
		select {
		case extra := <-sendCh:
			t.Fatalf("expected exactly one enqueued message, got a second: type=%d", extra.HeaderType)
		default:
		}
		return md
	default:
		t.Fatal("expected one enqueued NHP_RVA, got none")
		return nil
	}
}

// TestHandleUdpACRevocation_SendsAckOnAppliedEvent: a validated event that
// flushes a live entry must enqueue exactly one NHP_RVA addressed to the
// server's authenticated pubkey, echoing scope + scope_key VERBATIM (still
// prefixed) + epoch + event_id, and tick MetricRevocationAckSent. This is the
// headline proof-of-delivery property (#2793).
func TestHandleUdpACRevocation_SendsAckOnAppliedEvent(t *testing.T) {
	a, sendCh := acWithSendCapture(t)
	a.GenerateAccessToken(qurlV2Entry("qAck", "rAck", "", "aAck"))

	if err := a.HandleUdpACRevocation(revPPDWithConn(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qAck", RevocationEpoch: 7, EventId: "evt-ack-1",
	})); err != nil {
		t.Fatalf("applied event err=%v", err)
	}

	md := drainOneAck(t, sendCh)
	if md.HeaderType != core.NHP_RVA {
		t.Fatalf("enqueued header type=%d, want NHP_RVA(%d)", md.HeaderType, core.NHP_RVA)
	}
	// Addressed to the server's authenticated pubkey from the inbound REV.
	if string(md.PeerPk) != string(serverPubKey32()) {
		t.Fatalf("ack PeerPk does not match the inbound server pubkey")
	}
	var got common.ACRevocationAckMsg
	if err := json.Unmarshal(md.Message, &got); err != nil {
		t.Fatalf("ack body not ACRevocationAckMsg JSON: %v", err)
	}
	// scope_key echoed VERBATIM (still prefixed) — NOT the bare "qAck".
	want := common.ACRevocationAckMsg{Scope: "qurl", ScopeKey: "qurl:qAck", RevocationEpoch: 7, EventId: "evt-ack-1"}
	if got != want {
		t.Fatalf("ack body = %+v, want %+v", got, want)
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if c := counters[MetricRevocationAckSent]; c != 1 {
		t.Fatalf("%s = %v, want 1", MetricRevocationAckSent, c)
	}
	if c := counters[MetricRevocationAckSendFailed]; c != 0 {
		t.Fatalf("%s = %v, want 0", MetricRevocationAckSendFailed, c)
	}
}

// TestHandleUdpACRevocation_SendsAckEvenWhenNothingFlushed is the CONVERGENCE
// property (the load-bearing correctness point of #2793): an NHP_REV that flushes
// nothing — the common cell-wide-fanout case where this AC never admitted the key
// — must STILL ack. Without this, the server would retry to age-out and falsely
// mark the revoke degraded. Proven non-vacuously: no live entry matches, nothing
// is flushed, yet exactly one NHP_RVA is enqueued.
func TestHandleUdpACRevocation_SendsAckEvenWhenNothingFlushed(t *testing.T) {
	a, sendCh := acWithSendCapture(t)
	// A live entry under a DIFFERENT key, so the revoke matches nothing.
	a.GenerateAccessToken(qurlV2Entry("qOther", "rOther", "", "aOther"))

	if err := a.HandleUdpACRevocation(revPPDWithConn(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qNeverAdmitted", RevocationEpoch: 1, EventId: "evt-noflush",
	})); err != nil {
		t.Fatalf("no-match event err=%v", err)
	}

	md := drainOneAck(t, sendCh)
	if md.HeaderType != core.NHP_RVA {
		t.Fatalf("enqueued header type=%d, want NHP_RVA", md.HeaderType)
	}
	var got common.ACRevocationAckMsg
	if err := json.Unmarshal(md.Message, &got); err != nil {
		t.Fatalf("ack body not ACRevocationAckMsg JSON: %v", err)
	}
	if got.ScopeKey != "qurl:qNeverAdmitted" || got.RevocationEpoch != 1 {
		t.Fatalf("ack body = %+v, want scope_key=qurl:qNeverAdmitted epoch=1", got)
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if c := counters[MetricRevocationAckSent]; c != 1 {
		t.Fatalf("%s = %v, want 1 (convergence ack on a no-flush event)", MetricRevocationAckSent, c)
	}
}

// TestHandleUdpACRevocation_NoAckOnRejectPath: a rejected event (here an
// unsupported scope) must NOT enqueue an NHP_RVA — reject paths age out to the
// server's degraded metric by design, surfacing server↔AC validation drift rather
// than masking it. Proven non-vacuously: the send channel stays empty and
// MetricRevocationAckSent is 0 while MetricRevocationRejected ticks.
func TestHandleUdpACRevocation_NoAckOnRejectPath(t *testing.T) {
	a, sendCh := acWithSendCapture(t)

	if err := a.HandleUdpACRevocation(revPPDWithConn(t, common.ACRevocationMsg{
		Scope: "admission", ScopeKey: "admission:x", RevocationEpoch: 1, EventId: "evt-reject",
	})); err == nil {
		t.Fatal("expected a reject error for scope=admission, got nil")
	}

	select {
	case md := <-sendCh:
		t.Fatalf("a rejected event enqueued an ack (type=%d) — reject paths must not ack", md.HeaderType)
	default:
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if c := counters[MetricRevocationAckSent]; c != 0 {
		t.Fatalf("%s = %v after a rejected event, want 0", MetricRevocationAckSent, c)
	}
	if c := counters[MetricRevocationRejected]; c != 1 {
		t.Fatalf("%s = %v, want 1", MetricRevocationRejected, c)
	}
}

// TestSendRevocationAck_NoConnIsCountedFailure: an applied event whose inbound
// ppd has no usable connection/pubkey (a malformed-but-validated edge) must not
// panic and must tick MetricRevocationAckSendFailed rather than silently
// swallowing the missed ack. This is the branch the existing no-ConnData handler
// tests exercise implicitly; here it is asserted directly.
func TestSendRevocationAck_NoConnIsCountedFailure(t *testing.T) {
	a, sendCh := acWithSendCapture(t)
	a.GenerateAccessToken(qurlV2Entry("qNC", "rNC", "", "aNC"))

	// revPPD (no ConnData / no RemotePubKey) — the apply still succeeds, but the
	// ack cannot be sent.
	if err := a.HandleUdpACRevocation(revPPD(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qNC", RevocationEpoch: 1, EventId: "evt-nc",
	})); err != nil {
		t.Fatalf("applied event err=%v", err)
	}
	select {
	case md := <-sendCh:
		t.Fatalf("expected no enqueued ack without a connection, got type=%d", md.HeaderType)
	default:
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if c := counters[MetricRevocationAckSendFailed]; c != 1 {
		t.Fatalf("%s = %v, want 1", MetricRevocationAckSendFailed, c)
	}
	if c := counters[MetricRevocationAckSent]; c != 0 {
		t.Fatalf("%s = %v, want 0", MetricRevocationAckSent, c)
	}
}

// TestSendRevocationAck_QueueFullIsCountedFailure: when the AC's sendMsgCh is
// full, the non-blocking ack enqueue must DROP the NHP_RVA with
// MetricRevocationAckSendFailed (the server retries the NHP_REV) rather than block
// the revoke receive path — and it must NOT tick MetricRevocationAckSent. This is
// the backpressure branch (msghandler.go select default), the one most likely to
// fire under real load, and previously the only ack-send failure branch with no
// direct test.
func TestSendRevocationAck_QueueFullIsCountedFailure(t *testing.T) {
	a, _ := acWithSendCapture(t)
	// Replace the buffered capture channel with an unbuffered one that has no
	// reader, so the non-blocking ack enqueue hits the select's default arm.
	a.sendMsgCh = make(chan *core.MsgData)

	// A valid event (no live match → convergence ack attempted). The apply path
	// validates and converges, then tries to ack; the full queue drops it.
	if err := a.HandleUdpACRevocation(revPPDWithConn(t, common.ACRevocationMsg{
		Scope: "qurl", ScopeKey: "qurl:qFull", RevocationEpoch: 1, EventId: "evt-full",
	})); err != nil {
		t.Fatalf("validated event err=%v", err)
	}

	counters, _ := a.registration.metrics.CountersForTest(t)
	if c := counters[MetricRevocationAckSendFailed]; c != 1 {
		t.Fatalf("%s = %v, want 1 (a full sendMsgCh must drop the ack as a counted failure)", MetricRevocationAckSendFailed, c)
	}
	if c := counters[MetricRevocationAckSent]; c != 0 {
		t.Fatalf("%s = %v, want 0 (the ack was dropped, not sent)", MetricRevocationAckSent, c)
	}
}

// TestWireRevocationScope_AllowlistGate is the unit-level guard on the scope
// gate itself: exactly the three wire scopes are accepted (and round-trip to the
// matching typed constant), everything else — crucially "admission" and "cell" —
// is rejected.
//
// The accepted set is sourced from the shared endpoints/internal/revocationscope
// package, which the server's proof-tracking gate (trackFanout) also calls — so
// the AC apply/ack allowlist and the server's "which scopes do I expect an
// NHP_RVA for" set are the SAME set by construction and cannot drift (#2793).
// This test pins the AC-visible behavior of that shared gate; the canonical set
// itself is pinned in revocationscope's own TestAckable.
func TestWireRevocationScope_AllowlistGate(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want revocationScope
	}{
		{"qurl", scopeQurl},
		{"resource", scopeResource},
		{"session", scopeSession},
	} {
		got, ok := wireRevocationScope(tc.in)
		if !ok || got != tc.want {
			t.Fatalf("wireRevocationScope(%q) = (%q,%v), want (%q,true)", tc.in, got, ok, tc.want)
		}
	}
	// Reject the AC-meaningful near-misses: "admission" (the reserved AC-internal
	// dimension a raw cast would wrongly accept) and "cell" (server-only). The
	// exhaustive near-miss coverage (case, whitespace, unknown) lives in
	// revocationscope's TestAckable — wireRevocationScope is now just a typed
	// wrapper over revocationscope.Contains, so re-listing them here is redundant.
	for _, bad := range []string{"admission", "cell"} {
		if got, ok := wireRevocationScope(bad); ok {
			t.Fatalf("wireRevocationScope(%q) = (%q,true), want rejected", bad, got)
		}
	}
}

// TestACScopeConstants_MatchSharedAckable closes the last drift seam: wireRevocationScope
// now ACCEPTS scopes via the shared revocationscope.Contains, but ApplyRevocation /
// scopeKeysForEntry INDEX live entries using the AC's own typed constants
// (scopeQurl/scopeResource/scopeSession, revocation_index.go). If a scope string were
// renamed in the shared package but not in these constants (or vice-versa),
// wireRevocationScope would accept a scope the AC index can never match — a silent
// no-match that still converges and acks. Pin the two so that drift fails loudly here.
func TestACScopeConstants_MatchSharedAckable(t *testing.T) {
	got := []string{string(scopeQurl), string(scopeResource), string(scopeSession)}
	want := revocationscope.All()
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("AC index scope constants %v != shared revocationscope.All() %v — wireRevocationScope would accept a scope the AC index cannot match", got, want)
	}
}
