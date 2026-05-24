package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// fakeAgentKeysQuerier mocks the DDB Query path for AgentPeerLookup.
// Tests that need to assert call count / inject errors operate on
// this struct directly.
type fakeAgentKeysQuerier struct {
	mu    sync.Mutex
	calls int
	rows  map[string]map[string]types.AttributeValue // keyed by pubkey b64
	err   error                                      // returned for every Query call
}

func newFakeAgentKeysQuerier() *fakeAgentKeysQuerier {
	return &fakeAgentKeysQuerier{
		rows: map[string]map[string]types.AttributeValue{},
	}
}

func (f *fakeAgentKeysQuerier) put(pubKeyB64, ownerID, agentID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[pubKeyB64] = map[string]types.AttributeValue{
		"public_key": &types.AttributeValueMemberS{Value: pubKeyB64},
		"owner_id":   &types.AttributeValueMemberS{Value: ownerID},
		"agent_id":   &types.AttributeValueMemberS{Value: agentID},
	}
}

func (f *fakeAgentKeysQuerier) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	if f.err != nil {
		return nil, f.err
	}

	// Mirror the real DDB shape: KeyConditionExpression "public_key = :pk"
	// is the only branch we exercise. Attribute value lookup is best-effort —
	// the real client validates this; for tests we just look at :pk.
	pk := ""
	if v, ok := in.ExpressionAttributeValues[":pk"]; ok {
		if s, ok := v.(*types.AttributeValueMemberS); ok {
			pk = s.Value
		}
	}
	if pk == "" {
		return &dynamodb.QueryOutput{Items: nil}, nil
	}
	row, ok := f.rows[pk]
	if !ok {
		return &dynamodb.QueryOutput{Items: nil}, nil
	}
	return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{row}}, nil
}

func (f *fakeAgentKeysQuerier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// pubkeyB64 returns a deterministic 32-byte b64-encoded pubkey for
// tests. Each (filler) byte differs so tests can keep many distinct
// pubkeys without collision.
func pubkeyB64(filler byte) string {
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = filler
	}
	return base64.StdEncoding.EncodeToString(pk)
}

// newTestLookup constructs an AgentPeerLookup wired to a fake querier
// with an injectable clock for TTL tests.
func newTestLookup(t *testing.T, q AgentKeysQuerier) *AgentPeerLookup {
	t.Helper()
	l, err := NewAgentPeerLookup(q, "qurl-agent-keys-test")
	if err != nil {
		t.Fatalf("NewAgentPeerLookup: %v", err)
	}
	return l
}

// TestAgentPeerLookup_CacheMissThenHit asserts the standard flow:
// first lookup queries DDB; second lookup is a cache hit.
func TestAgentPeerLookup_CacheMissThenHit(t *testing.T) {
	q := newFakeAgentKeysQuerier()
	pk := pubkeyB64(0x01)
	q.put(pk, "owner-1", "agent-1")

	l := newTestLookup(t, q)

	peer, err := l.LookupAgentByPubKey(context.Background(), pk)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if peer == nil || peer.PublicKeyBase64() != pk {
		t.Fatalf("first lookup: peer=%v want pubkey=%q", peer, pk)
	}
	if peer.DeviceType() != core.NHP_AGENT {
		t.Errorf("peer DeviceType=%d want NHP_AGENT(%d)", peer.DeviceType(), core.NHP_AGENT)
	}
	if got := q.callCount(); got != 1 {
		t.Errorf("DDB calls after first lookup=%d want 1", got)
	}

	peer2, err := l.LookupAgentByPubKey(context.Background(), pk)
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if peer2 == nil {
		t.Fatal("second lookup returned nil peer")
	}
	if got := q.callCount(); got != 1 {
		t.Errorf("DDB calls after cache hit=%d want 1 (cache miss)", got)
	}
}

// TestAgentPeerLookup_CacheExpiry asserts that an entry past TTL
// gets re-fetched from DDB on the next lookup.
func TestAgentPeerLookup_CacheExpiry(t *testing.T) {
	q := newFakeAgentKeysQuerier()
	pk := pubkeyB64(0x02)
	q.put(pk, "owner-2", "agent-2")

	l := newTestLookup(t, q)

	// Inject a clock so we can expire deterministically.
	now := time.Now()
	l.now = func() time.Time { return now }

	if _, err := l.LookupAgentByPubKey(context.Background(), pk); err != nil {
		t.Fatalf("warm lookup: %v", err)
	}
	if q.callCount() != 1 {
		t.Fatalf("DDB calls=%d want 1", q.callCount())
	}

	// Advance clock to mid-TTL: still cached.
	now = now.Add(30 * time.Second)
	if _, err := l.LookupAgentByPubKey(context.Background(), pk); err != nil {
		t.Fatalf("mid-ttl lookup: %v", err)
	}
	if q.callCount() != 1 {
		t.Errorf("DDB calls at mid-ttl=%d want 1 (still cached)", q.callCount())
	}

	// Advance past TTL: re-query.
	now = now.Add(31 * time.Second)
	if _, err := l.LookupAgentByPubKey(context.Background(), pk); err != nil {
		t.Fatalf("post-ttl lookup: %v", err)
	}
	if q.callCount() != 2 {
		t.Errorf("DDB calls after ttl expiry=%d want 2", q.callCount())
	}
}

// TestAgentPeerLookup_UnknownPubkey asserts unknown pubkeys return
// ErrAgentUnknownPubkey and are NOT cached (so a future bootstrap
// resolves immediately, not after TTL).
func TestAgentPeerLookup_UnknownPubkey(t *testing.T) {
	q := newFakeAgentKeysQuerier()
	pk := pubkeyB64(0x03)

	l := newTestLookup(t, q)

	_, err := l.LookupAgentByPubKey(context.Background(), pk)
	if !errors.Is(err, ErrAgentUnknownPubkey) {
		t.Fatalf("err=%v want ErrAgentUnknownPubkey", err)
	}

	// Now register the pubkey and re-lookup — should hit DDB again
	// (unknown wasn't cached) and succeed.
	q.put(pk, "owner-3", "agent-3")
	peer, err := l.LookupAgentByPubKey(context.Background(), pk)
	if err != nil {
		t.Fatalf("post-bootstrap lookup: %v", err)
	}
	if peer == nil {
		t.Fatal("post-bootstrap peer=nil")
	}
	if q.callCount() != 2 {
		t.Errorf("DDB calls=%d want 2 (unknown not cached)", q.callCount())
	}
}

// TestAgentPeerLookup_DDBErrorRetryAfter asserts a transient DDB
// error returns ErrAgentLookupRetryAfter (wrapped) and does NOT
// cache anything — so a retry can recover.
func TestAgentPeerLookup_DDBErrorRetryAfter(t *testing.T) {
	q := newFakeAgentKeysQuerier()
	q.err = &types.ProvisionedThroughputExceededException{Message: aws.String("throttled")}

	l := newTestLookup(t, q)
	pk := pubkeyB64(0x04)

	_, err := l.LookupAgentByPubKey(context.Background(), pk)
	if !errors.Is(err, ErrAgentLookupRetryAfter) {
		t.Fatalf("err=%v want ErrAgentLookupRetryAfter", err)
	}

	// Clear the error and put the row — second call should succeed.
	q.err = nil
	q.put(pk, "owner-4", "agent-4")
	peer, err := l.LookupAgentByPubKey(context.Background(), pk)
	if err != nil {
		t.Fatalf("recovered lookup: %v", err)
	}
	if peer == nil {
		t.Fatal("recovered peer=nil")
	}
	if q.callCount() != 2 {
		t.Errorf("DDB calls=%d want 2 (error not cached)", q.callCount())
	}
}

// TestAgentPeerLookup_GenericDDBError asserts a non-throttle DDB
// failure also wraps as retry-after (we don't classify error
// subtypes — anything from the SDK is transient from our POV).
func TestAgentPeerLookup_GenericDDBError(t *testing.T) {
	q := newFakeAgentKeysQuerier()
	q.err = errors.New("internal server error")

	l := newTestLookup(t, q)
	pk := pubkeyB64(0x05)

	_, err := l.LookupAgentByPubKey(context.Background(), pk)
	if !errors.Is(err, ErrAgentLookupRetryAfter) {
		t.Fatalf("err=%v want ErrAgentLookupRetryAfter", err)
	}
}

// TestAgentPeerLookup_DDBErrorPreservesSDKType asserts the
// underlying typed SDK error stays reachable through errors.As
// across the ErrAgentLookupRetryAfter wrap. fmt.Errorf("%w: %w", ...)
// (Go 1.20+ multi-%w) is what makes this work — a regression to
// %v on the inner err would silently break log/metric triage that
// keys on *types.ProvisionedThroughputExceededException vs other
// SDK types.
func TestAgentPeerLookup_DDBErrorPreservesSDKType(t *testing.T) {
	q := newFakeAgentKeysQuerier()
	q.err = &types.ProvisionedThroughputExceededException{Message: aws.String("throttled")}

	l := newTestLookup(t, q)
	pk := pubkeyB64(0x06)

	_, err := l.LookupAgentByPubKey(context.Background(), pk)
	if !errors.Is(err, ErrAgentLookupRetryAfter) {
		t.Fatalf("err=%v want ErrAgentLookupRetryAfter", err)
	}

	var ptex *types.ProvisionedThroughputExceededException
	if !errors.As(err, &ptex) {
		t.Errorf("errors.As(*ProvisionedThroughputExceededException) failed; %%w chain broken: %v", err)
	}
}

// TestAgentPeerLookup_HappyPathQueryShape asserts the Query input
// targets the correct table + GSI + KeyConditionExpression. The
// pubkey-index GSI is the load-bearing piece — a regression that
// silently drops the IndexName would full-scan the base table.
func TestAgentPeerLookup_HappyPathQueryShape(t *testing.T) {
	var captured *dynamodb.QueryInput
	q := &captureAgentKeysQuerier{
		inner: newFakeAgentKeysQuerier(),
		captureFn: func(in *dynamodb.QueryInput) {
			captured = in
		},
	}
	pk := pubkeyB64(0x06)
	q.inner.put(pk, "owner-6", "agent-6")

	l := newTestLookup(t, q)
	if _, err := l.LookupAgentByPubKey(context.Background(), pk); err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if captured == nil {
		t.Fatal("Query was not called")
	}
	if got := aws.ToString(captured.TableName); got != "qurl-agent-keys-test" {
		t.Errorf("TableName=%q want %q", got, "qurl-agent-keys-test")
	}
	if got := aws.ToString(captured.IndexName); got != "pubkey-index" {
		t.Errorf("IndexName=%q want %q", got, "pubkey-index")
	}
	if got := aws.ToString(captured.KeyConditionExpression); got != "public_key = :pk" {
		t.Errorf("KeyConditionExpression=%q want %q", got, "public_key = :pk")
	}
	if v, ok := captured.ExpressionAttributeValues[":pk"]; !ok {
		t.Error(":pk attribute missing")
	} else if s, ok := v.(*types.AttributeValueMemberS); !ok || s.Value != pk {
		t.Errorf(":pk value=%v want %q", v, pk)
	}
	// Limit=2 (not 1) is load-bearing for the pubkey-collision
	// detection in queryAndCache — see the godoc there. The reader
	// still admits Items[0] when there's no collision; the extra
	// projected attribute set on the happy path is negligible.
	if captured.Limit == nil || *captured.Limit != 2 {
		t.Errorf("Limit=%v want 2 (Limit>=2 is required for collision detection)", captured.Limit)
	}
}

// TestAgentPeerLookup_EmptyPubkeyShortCircuits asserts an empty
// pubkey returns unknown without hitting DDB. This is the upstream-
// invariant fence for noise responder regressions that fail to
// populate ppd.RemotePubKey.
func TestAgentPeerLookup_EmptyPubkeyShortCircuits(t *testing.T) {
	q := newFakeAgentKeysQuerier()
	l := newTestLookup(t, q)

	_, err := l.LookupAgentByPubKey(context.Background(), "")
	if !errors.Is(err, ErrAgentUnknownPubkey) {
		t.Fatalf("err=%v want ErrAgentUnknownPubkey", err)
	}
	if q.callCount() != 0 {
		t.Errorf("DDB calls on empty pubkey=%d want 0", q.callCount())
	}
}

// TestAgentPeerLookup_NilLookup asserts a nil receiver returns
// unknown without panicking — the wire-up gate at the call site
// uses non-nil to mean "DDB path active", and a nil receiver is the
// disabled state. This is a defense-in-depth guard.
func TestAgentPeerLookup_NilLookup(t *testing.T) {
	var l *AgentPeerLookup
	_, err := l.LookupAgentByPubKey(context.Background(), pubkeyB64(0x07))
	if !errors.Is(err, ErrAgentUnknownPubkey) {
		t.Fatalf("err=%v want ErrAgentUnknownPubkey", err)
	}
}

// TestAgentPeerLookup_Invalidate asserts manual invalidation evicts
// a cached entry (used by an admin "force re-resolve" path).
func TestAgentPeerLookup_Invalidate(t *testing.T) {
	q := newFakeAgentKeysQuerier()
	pk := pubkeyB64(0x08)
	q.put(pk, "owner-8", "agent-8")

	l := newTestLookup(t, q)

	if _, err := l.LookupAgentByPubKey(context.Background(), pk); err != nil {
		t.Fatalf("warm: %v", err)
	}
	l.invalidate(pk)

	if _, err := l.LookupAgentByPubKey(context.Background(), pk); err != nil {
		t.Fatalf("post-invalidate: %v", err)
	}
	if q.callCount() != 2 {
		t.Errorf("DDB calls=%d want 2 (cache evicted)", q.callCount())
	}
}

// TestAgentPeerLookup_NilQuerier asserts a nil querier returns
// unknown without panicking (the disabled-but-non-nil state).
func TestAgentPeerLookup_NilQuerier(t *testing.T) {
	l, err := NewAgentPeerLookup(nil, "x")
	if err != nil {
		t.Fatalf("NewAgentPeerLookup: %v", err)
	}
	_, err = l.LookupAgentByPubKey(context.Background(), pubkeyB64(0x09))
	if !errors.Is(err, ErrAgentUnknownPubkey) {
		t.Fatalf("err=%v want ErrAgentUnknownPubkey", err)
	}
}

// TestAgentPeerLookup_Concurrent asserts concurrent cache hits/misses
// don't race on the cache or clock. The race detector catches
// memory-model regressions; the explicit assertions below catch a
// future change that silently makes lookups lose data under
// contention (e.g., a refactor that drops the singleflight or
// swaps the LRU for a non-thread-safe map).
func TestAgentPeerLookup_Concurrent(t *testing.T) {
	const numPubkeys = 10
	const goroutines = 8
	const itersPerGoroutine = 50

	q := newFakeAgentKeysQuerier()
	for i := 0; i < numPubkeys; i++ {
		q.put(pubkeyB64(byte(0x10+i)), "owner", "agent")
	}

	l := newTestLookup(t, q)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < itersPerGoroutine; i++ {
				pk := pubkeyB64(byte(0x10 + (i % numPubkeys)))
				peer, err := l.LookupAgentByPubKey(context.Background(), pk)
				if err != nil {
					t.Errorf("goroutine %d iter %d: unexpected error: %v", gid, i, err)
					return
				}
				if peer == nil {
					t.Errorf("goroutine %d iter %d: nil peer", gid, i)
					return
				}
				if peer.PubKeyBase64 != pk {
					t.Errorf("goroutine %d iter %d: peer.PubKeyBase64=%q want %q", gid, i, peer.PubKeyBase64, pk)
					return
				}
				if i%5 == 0 {
					l.invalidate(pk)
				}
			}
		}(g)
	}
	wg.Wait()

	// Sanity bounds:
	//   - Lower: at least one DDB query per distinct pubkey.
	//   - Upper: each goroutine invalidates every 5 iters
	//     (itersPerGoroutine/5 = 10 forced re-queries per goroutine
	//     in the absolute worst case where every invalidate
	//     produces a unique re-query and singleflight never piggybacks
	//     across goroutines). Add the initial-fill of numPubkeys to
	//     that and tolerate a small fudge factor for scheduling jitter.
	//
	// Tighter than goroutines*itersPerGoroutine — that bound (400)
	// is so loose a regression that drops the singleflight gate on
	// the invalidation path would still pass it. The tighter
	// ceiling here catches that.
	calls := q.callCount()
	maxExpected := numPubkeys + goroutines*(itersPerGoroutine/5) + numPubkeys // fudge
	if calls < numPubkeys {
		t.Errorf("DDB calls=%d want at least %d (one per distinct pubkey)", calls, numPubkeys)
	}
	if calls > maxExpected {
		t.Errorf("DDB calls=%d exceeds tight upper bound %d (singleflight likely regressed on the invalidation path)", calls, maxExpected)
	}
}

// blockingAgentKeysQuerier wraps a fake and gates Query on a release
// channel so the test can fan N goroutines into LookupAgentByPubKey
// before any of them complete the underlying DDB call. This is what
// makes the singleflight assertion below load-bearing — without the
// gate, the race detector might see one goroutine win, populate the
// cache, and the rest take the cache-hit path; we want all N to be
// in the LRU-miss → DDB-Query window simultaneously.
type blockingAgentKeysQuerier struct {
	inner   *fakeAgentKeysQuerier
	release chan struct{} // closed by the test to let queries proceed
	entered chan struct{} // signaled on each Query entry so the test can count concurrent waiters
}

func (b *blockingAgentKeysQuerier) Query(ctx context.Context, in *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	select {
	case b.entered <- struct{}{}:
	default:
		// Non-blocking send: the channel is sized to the test's
		// expected concurrency. Reaching the default arm means the
		// channel is full — either because singleflight deduplicated
		// (same-pubkey test: only the winner reaches Query, so the
		// channel never fills via the underlying-Query path) or
		// because more callers arrived than expected. Both cases must
		// not block the underlying Query, otherwise the test
		// deadlocks; the assertions in each caller test (callCount /
		// entered-channel reads) are what verify the dedupe / fan-out
		// invariant, not this send.
	}
	<-b.release
	return b.inner.Query(ctx, in, opts...)
}

// TestAgentPeerLookup_Singleflight_DedupsConcurrentMissOnSamePubkey
// fences the singleflight invariant: N concurrent first-knocks for
// the same fresh agent must produce exactly one DDB Query and every
// caller must observe the same *core.UdpPeer pointer.
//
// Without singleflight, all N goroutines miss the LRU, all N hit
// DDB, and each constructs a distinct *UdpPeer. Pointer identity
// matters because (a) it bounds the DDB cost amplifier under load
// (one Query per pubkey-window, not N) and (b) downstream callers
// hold the cached pointer; a future eviction/admin path reading
// back the pointer would otherwise observe a different identity
// than the concurrent caller held. The fix wraps the LRU-miss path
// in singleflight.Group keyed on pubKeyB64 so concurrent callers
// piggyback on a single resolve.
//
// Note: PeerGroup promotion in device.AddPeer is NOT one of the
// things singleflight prevents here — peers from queryAndCache have
// empty Ip/Port/Hostname, so udpPeersShareAddress returns true and
// AddPeer takes the overwrite branch even when distinct pointers
// are presented. See the godoc on AgentPeerLookup for why this
// matters if the peer-construction shape changes.
func TestAgentPeerLookup_Singleflight_DedupsConcurrentMissOnSamePubkey(t *testing.T) {
	const concurrency = 16

	inner := newFakeAgentKeysQuerier()
	pk := pubkeyB64(0x42)
	inner.put(pk, "owner-1", "agent-1")

	q := &blockingAgentKeysQuerier{
		inner:   inner,
		release: make(chan struct{}),
		entered: make(chan struct{}, concurrency),
	}
	l := newTestLookup(t, q)

	// Barrier: every caller signals once via the onSingleflightEnter
	// hook just BEFORE entering sfGroup.Do. The releaser waits for
	// all N signals before releasing the winner's blocked Query —
	// only then is the singleflight slot guaranteed to have all
	// piggybackers committed.
	//
	// Without this hook-driven barrier, a "launched-before-Lookup"
	// WaitGroup only proves goroutines have been SCHEDULED, not that
	// they've reached sfGroup.Do. A fast winner could complete Query
	// and populate the cache before stragglers entered sfGroup.Do,
	// degenerating the assertion below into a probabilistic cache-hit
	// test that proves nothing about singleflight.
	enterCh := make(chan struct{}, concurrency)
	l.onSingleflightEnter = func(string) {
		enterCh <- struct{}{}
	}

	type result struct {
		peer *core.UdpPeer
		err  error
	}
	results := make(chan result, concurrency)

	go func() {
		// Wait for all N callers to be at the entry of sfGroup.Do.
		for i := 0; i < concurrency; i++ {
			<-enterCh
		}
		// At this point the winner is already (or imminently) inside
		// the Query call; wait for it to actually arrive there before
		// releasing — guarantees the singleflight slot is closed.
		<-q.entered
		close(q.release)
	}()

	for i := 0; i < concurrency; i++ {
		go func() {
			peer, err := l.LookupAgentByPubKey(context.Background(), pk)
			results <- result{peer: peer, err: err}
		}()
	}

	// Collect outcomes.
	var firstPeer *core.UdpPeer
	for i := 0; i < concurrency; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, r.err)
		}
		if r.peer == nil {
			t.Fatalf("call %d: nil peer", i)
		}
		if firstPeer == nil {
			firstPeer = r.peer
			continue
		}
		// All callers must observe the SAME *core.UdpPeer pointer —
		// this is what makes the downstream AddAgentPeer →
		// device.AddPeer call idempotent (matching pointer ⇒
		// matching address ⇒ no PeerGroup promotion).
		if r.peer != firstPeer {
			t.Errorf("call %d: peer pointer %p differs from first %p (singleflight should return identical pointer)",
				i, r.peer, firstPeer)
		}
	}

	if got := inner.callCount(); got != 1 {
		t.Errorf("DDB calls=%d want 1 (singleflight should dedupe %d concurrent lookups)", got, concurrency)
	}
}

// TestAgentPeerLookup_Singleflight_DoesNotDedupeDifferentPubkeys
// fences the other half of the singleflight invariant: N concurrent
// first-knocks for N DIFFERENT pubkeys must each produce their own
// DDB Query — singleflight's grouping key must be the pubkey, not
// owner_id or any broader scope.
//
// A regression that widened the singleflight key (e.g. constant
// key, owner_id-only key) would silently collapse independent
// resolves and either (a) hand back a peer for the wrong pubkey
// to N-1 callers or (b) fail-fan-out a single unknown-pubkey error
// to N callers. Neither is caught by
// TestAgentPeerLookup_Concurrent (which exercises a mix of cache
// hits + invalidations) nor by the same-pubkey dedupe test (which
// only fences the N→1 direction). This test fences the inverse
// N→N direction: distinct keys must NOT share a singleflight slot.
func TestAgentPeerLookup_Singleflight_DoesNotDedupeDifferentPubkeys(t *testing.T) {
	const concurrency = 16

	inner := newFakeAgentKeysQuerier()
	pubkeys := make([]string, concurrency)
	for i := 0; i < concurrency; i++ {
		pk := pubkeyB64(byte(0x50 + i))
		pubkeys[i] = pk
		inner.put(pk, "owner-x", fmt.Sprintf("agent-%d", i))
	}

	// Use the blocking querier so all N goroutines are simultaneously
	// in the LRU-miss → singleflight.Do window before any underlying
	// Query completes. Without the gate a fast first responder could
	// populate the cache before the rest enter and the test would
	// degenerate to "cache hits, no dedupe to test".
	q := &blockingAgentKeysQuerier{
		inner:   inner,
		release: make(chan struct{}),
		entered: make(chan struct{}, concurrency),
	}
	l := newTestLookup(t, q)

	// Same barrier as the same-pubkey test (via the
	// onSingleflightEnter hook). Each caller registers ONCE on entry
	// into sfGroup.Do; the releaser waits for all N before closing
	// release. Since each caller has its own pubkey, there is no
	// piggybacking — we then also wait for all N inner Query entries
	// to confirm the winners reached Query simultaneously.
	enterCh := make(chan struct{}, concurrency)
	l.onSingleflightEnter = func(string) {
		enterCh <- struct{}{}
	}

	type result struct {
		pk   string
		peer *core.UdpPeer
		err  error
	}
	results := make(chan result, concurrency)

	go func() {
		// All N callers committed to sfGroup.Do.
		for i := 0; i < concurrency; i++ {
			<-enterCh
		}
		// All N winners arrived at the inner Query — distinct pubkeys,
		// so each is its own slot's winner. There's no piggybacking
		// here to wait for.
		for i := 0; i < concurrency; i++ {
			<-q.entered
		}
		close(q.release)
	}()

	for i := 0; i < concurrency; i++ {
		pk := pubkeys[i]
		go func() {
			peer, err := l.LookupAgentByPubKey(context.Background(), pk)
			results <- result{pk: pk, peer: peer, err: err}
		}()
	}

	for i := 0; i < concurrency; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("pk=%q: unexpected error: %v", r.pk, r.err)
		}
		if r.peer == nil {
			t.Fatalf("pk=%q: nil peer", r.pk)
		}
		// Each goroutine must see the peer for ITS pubkey, not
		// someone else's. A regression that broadened the singleflight
		// key would hand peer A back to caller B.
		if r.peer.PubKeyBase64 != r.pk {
			t.Errorf("pk=%q: got peer for %q (singleflight key over-broadened?)",
				r.pk, r.peer.PubKeyBase64)
		}
	}

	if got := inner.callCount(); got != concurrency {
		t.Errorf("DDB calls=%d want %d (one per distinct pubkey; singleflight key must NOT collapse distinct pubkeys)",
			got, concurrency)
	}
}

// TestAgentPeerLookup_PubkeyCollisionEmitsMetricAndWarn fences the
// defense-in-depth detection: when the qurl-service writer-side
// soft uniqueness check fails open and the pubkey-index GSI hosts
// >1 rows for the same pubkey, the reader still admits the agent
// (multi-tenant separation enforced at the auth layer) but emits
// MetricAgentLookupPubkeyCollision so operators see the invariant
// violation in real time.
//
// Regression fence for two things at once:
//   - Limit must stay >1 so the second row is even visible.
//   - The metric must fire when Items > 1.
func TestAgentPeerLookup_PubkeyCollisionEmitsMetricAndWarn(t *testing.T) {
	pk := pubkeyB64(0x77)
	q := &collidingAgentKeysQuerier{pk: pk}

	l := newTestLookup(t, q)
	m := &fakeCounterIncrementer{}
	l.SetMetrics(m)

	peer, err := l.LookupAgentByPubKey(context.Background(), pk)
	if err != nil {
		t.Fatalf("LookupAgentByPubKey: %v", err)
	}
	if peer == nil {
		t.Fatal("peer is nil (collision should still admit Items[0])")
	}
	if peer.PublicKeyBase64() != pk {
		t.Errorf("peer pubkey=%q want %q", peer.PublicKeyBase64(), pk)
	}

	got := m.count(MetricAgentLookupPubkeyCollision)
	if got != 1 {
		t.Errorf("%s counter=%d want 1 (collision detection should emit)",
			MetricAgentLookupPubkeyCollision, got)
	}

	// Sanity: Limit=2 must reach the querier so the second row is
	// actually visible. If the production code regresses Limit back
	// to 1, the collidingQuerier asserts and the test fails loudly.
	if got := q.lastLimit; got != 2 {
		t.Errorf("Query Limit=%d want 2 (Limit=1 would hide collisions; see queryAndCache comment)",
			got)
	}
}

// TestAgentPeerLookup_PubkeyCollisionAdmitsItemsZero fences the
// admit-Items[0] half of the collision contract that the existing
// metric+WARN test only covers indirectly. The package godoc
// documents "the resolver returns whichever row DDB hands back
// first" and the queryAndCache implementation reads `out.Items[0]`
// explicitly. A future regression to `out.Items[1]`,
// `out.Items[len-1]`, or any shuffle of the slice would slip past
// the existing collision test (which sets both rows to the same
// pubkey and so can't distinguish which row was admitted).
//
// This test stubs the GSI to return TWO rows with DISTINCT
// public_key strings — impossible against the real
// `KeyConditionExpression="public_key = :pk"` query but a valid
// adversarial fake — and asserts the returned peer's pubkey
// matches Items[0]. Round-16 review test-coverage gap.
func TestAgentPeerLookup_PubkeyCollisionAdmitsItemsZero(t *testing.T) {
	first := pubkeyB64(0x11)
	second := pubkeyB64(0x22)
	q := &distinctRowCollisionQuerier{first: first, second: second}

	l := newTestLookup(t, q)
	m := &fakeCounterIncrementer{}
	l.SetMetrics(m)

	peer, err := l.LookupAgentByPubKey(context.Background(), first)
	if err != nil {
		t.Fatalf("LookupAgentByPubKey: %v", err)
	}
	if peer == nil {
		t.Fatal("peer is nil (collision should still admit Items[0])")
	}
	if got := peer.PublicKeyBase64(); got != first {
		t.Errorf("admitted peer pubkey=%q want %q (Items[0]); regression "+
			"to Items[1] or non-first row would surface here as the second pubkey %q",
			got, first, second)
	}
	if got := m.count(MetricAgentLookupPubkeyCollision); got != 1 {
		t.Errorf("%s counter=%d want 1 (defense-in-depth fence still required)",
			MetricAgentLookupPubkeyCollision, got)
	}
}

// TestAgentPeerLookup_SetMetricsSetOnceContract fences the
// nil-after-non-nil guard on SetMetrics. The set-once contract is
// documented as load-bearing (a future partial-reset refactor that
// re-invokes SetMetrics(nil) would silently dark the pubkey-collision
// counter and the next squat event would lose its forensic signal);
// this test makes the contract a regression fence.
//
// Scenarios:
//   - First non-nil call wires the publisher (positive baseline).
//   - Subsequent SetMetrics(nil) is REJECTED — the original publisher
//     stays attached and IncrCounter still fires.
//   - nil-first-then-non-nil is allowed (construction order in
//     UdpServer.Start: lookup built before publisher).
func TestAgentPeerLookup_SetMetricsSetOnceContract(t *testing.T) {
	pk := pubkeyB64(0xAA)
	// Use the collision-emitting querier so the metric path fires
	// on every LookupAgentByPubKey call — that's how we observe
	// whether SetMetrics(nil) accepted or rejected the clear.
	collider := &collidingAgentKeysQuerier{pk: pk}
	l := newTestLookup(t, collider)

	// Phase 1: nil-first is allowed (mirrors Start order).
	l.SetMetrics(nil)
	if l.metrics != nil {
		t.Errorf("after SetMetrics(nil) with no prior set, l.metrics=%v want nil", l.metrics)
	}

	// Phase 2: wire a real counter.
	first := &fakeCounterIncrementer{}
	l.SetMetrics(first)
	if l.metrics != first {
		t.Errorf("after SetMetrics(first), l.metrics=%v want %v", l.metrics, first)
	}

	// Trigger one collision to baseline the counter.
	if _, err := l.LookupAgentByPubKey(context.Background(), pk); err != nil {
		t.Fatalf("LookupAgentByPubKey: %v", err)
	}
	if got := first.count(MetricAgentLookupPubkeyCollision); got != 1 {
		t.Fatalf("baseline collision counter=%d want 1", got)
	}

	// Phase 3: a follow-up SetMetrics(nil) MUST be rejected — first
	// stays wired.
	l.SetMetrics(nil)
	if l.metrics != first {
		t.Errorf("after SetMetrics(nil) post-wire, l.metrics=%v want %v (set-once contract broken — a partial-reset refactor would silently dark the counter)", l.metrics, first)
	}

	// Invalidate so the next lookup re-queries and re-emits the
	// counter. If the set-once contract regressed, the counter would
	// stay at 1.
	l.invalidate(pk)
	if _, err := l.LookupAgentByPubKey(context.Background(), pk); err != nil {
		t.Fatalf("post-clear-attempt LookupAgentByPubKey: %v", err)
	}
	if got := first.count(MetricAgentLookupPubkeyCollision); got != 2 {
		t.Errorf("post-clear-attempt collision counter=%d want 2 (set-once should have preserved the publisher wiring; a nil-clear-accepted regression would leave the counter at 1)", got)
	}

	// Phase 4: a replacement non-nil call IS allowed — set-once only
	// blocks nil-clear, not legitimate replacement. (Documented but
	// not required by current callers; fence so a future tightening
	// of the rule has to update this test.)
	second := &fakeCounterIncrementer{}
	l.SetMetrics(second)
	if l.metrics != second {
		t.Errorf("after SetMetrics(second), l.metrics=%v want %v (non-nil replacement should be allowed)", l.metrics, second)
	}
}

// TestAgentPeerLookup_CachedOwnerIDPopulated fences the KEYS_ONLY
// metadata plumbing: after a successful LookupAgentByPubKey, the
// resolver's CachedOwnerID returns the owner_id projected by the
// pubkey-index GSI. The resolveAgentPeerForKnock caller reads this
// to enrich the agent_resolved log with the tenant owner; a
// regression that drops owner_id from agentCacheEntry would surface
// here as an empty string.
//
// Empty-pubkey lookup, expired entry, and "lookup never called for
// this pubkey" all return "" — non-fatal cases the caller treats as
// "no owner_id field on the log line."
func TestAgentPeerLookup_CachedOwnerIDPopulated(t *testing.T) {
	inner := newFakeAgentKeysQuerier()
	pk := pubkeyB64(0x88)
	inner.put(pk, "owner-keysonly-1", "agent-keysonly-1")
	l := newTestLookup(t, inner)

	// Pre-resolve so the cache is populated.
	if _, err := l.LookupAgentByPubKey(context.Background(), pk); err != nil {
		t.Fatalf("LookupAgentByPubKey: %v", err)
	}

	if got := l.CachedOwnerID(pk); got != "owner-keysonly-1" {
		t.Errorf("CachedOwnerID(%q)=%q want %q (KEYS_ONLY projection plumbing broken)",
			pk, got, "owner-keysonly-1")
	}

	// Negative case: a pubkey the lookup never observed has no
	// cached metadata — caller-side log line will just print
	// owner_id="" without it being a failure.
	if got := l.CachedOwnerID(pubkeyB64(0x99)); got != "" {
		t.Errorf("CachedOwnerID for never-resolved pubkey returned %q want \"\"", got)
	}

	// nil receiver tolerated (mirrors the nil-safe pattern in
	// LookupAgentByPubKey / SetMetrics).
	var nilLookup *AgentPeerLookup
	if got := nilLookup.CachedOwnerID(pk); got != "" {
		t.Errorf("nil-receiver CachedOwnerID returned %q want \"\"", got)
	}
}

// TestUdpServer_ResolveOwnerIDByPubKey fences the ForwarderDeps
// surface used by the forward-receiver path to resolve owner_id
// locally. Without this method, the receiver would always pass "" to
// PublishACKTokens — and a downstream tunnel-auth consumer hitting
// /nhp/internal/token/validate on different NLB-hashed instances
// would see inconsistent OwnerId for the same logical agent.
//
// Six cases pinned:
//  1. Cold-cache success: lookup hits DDB (via the fake querier),
//     populates the LRU, then surfaces the owner_id from the
//     KEYS_ONLY projection.
//  2. Unknown-pubkey fail-safe: returns "" (never errors), so the
//     forward path stamps the historical empty-OwnerId on the ACK
//     entry rather than blocking the knock.
//  3. Non-cloud-mode fail-safe: agentPeerLookup is nil, returns ""
//     immediately. Same empty-OwnerId contract as the HTTP knock
//     path and as the legacy non-cloud UDP path.
//  4. Empty pubkey short-circuits without a DDB hit.
//  5. DDB outage (LookupAgentByPubKey returns ErrAgentLookupRetryAfter)
//     degrades to "" rather than bubbling the error — the forward
//     path stamps empty on the ACK entry as the documented fail-safe.
//  6. Input-format contract: ResolveOwnerIDByPubKey expects a
//     base64.StdEncoding-encoded pubkey (the shape produced at
//     nhpauth.go:160 and used by req.PublicKey at udpserver.go:3612).
//     A regression at the call site that wrapped the input in a
//     second base64 encode would silently degrade every UDP knock
//     to empty-OwnerId — the lookup would miss, the fail-safe would
//     kick in, no error logged. Pinning the format here catches
//     that without needing to mount the full handleNhpOpenResource
//     path.
func TestUdpServer_ResolveOwnerIDByPubKey(t *testing.T) {
	inner := newFakeAgentKeysQuerier()
	pk := pubkeyB64(0xA1)
	inner.put(pk, "owner-forward-receiver-1", "agent-forward-receiver-1")
	l := newTestLookup(t, inner)

	s := &UdpServer{agentPeerLookup: l}

	t.Run("cold-cache lookup populates owner_id", func(t *testing.T) {
		got := s.ResolveOwnerIDByPubKey(context.Background(), pk)
		if got != "owner-forward-receiver-1" {
			t.Errorf("ResolveOwnerIDByPubKey(%q) = %q, want %q (forward-receiver path must resolve owner_id locally so it stays consistent across NLB-hashed instances)",
				pk, got, "owner-forward-receiver-1")
		}
	})

	t.Run("unknown pubkey returns empty fail-safe", func(t *testing.T) {
		got := s.ResolveOwnerIDByPubKey(context.Background(), pubkeyB64(0xA2))
		if got != "" {
			t.Errorf("ResolveOwnerIDByPubKey(unknown) = %q, want \"\" (unknown pubkey must NOT block the forward knock — degrade to empty-OwnerId contract)", got)
		}
	})

	t.Run("nil agentPeerLookup (non-cloud-mode) returns empty", func(t *testing.T) {
		sNil := &UdpServer{agentPeerLookup: nil}
		got := sNil.ResolveOwnerIDByPubKey(context.Background(), pk)
		if got != "" {
			t.Errorf("ResolveOwnerIDByPubKey with nil agentPeerLookup = %q, want \"\" (non-cloud-mode must return empty without panic)", got)
		}
	})

	t.Run("empty pubkey returns empty", func(t *testing.T) {
		got := s.ResolveOwnerIDByPubKey(context.Background(), "")
		if got != "" {
			t.Errorf("ResolveOwnerIDByPubKey(\"\") = %q, want \"\" (empty input must short-circuit, not hit DDB)", got)
		}
	})

	t.Run("DDB outage returns empty fail-safe", func(t *testing.T) {
		// The fail-safe contract explicitly covers "DDB outage"; this
		// closes the test gap by injecting an error on the querier and
		// asserting the wrapped LookupAgentByPubKey failure propagates
		// as the empty-OwnerId degraded mode rather than blocking the
		// knock or panicking. Uses a cold pubkey so the LRU can't
		// short-circuit before the DDB call.
		failingInner := newFakeAgentKeysQuerier()
		failingInner.err = errors.New("ddb outage: provisioned throughput exceeded")
		failingLookup := newTestLookup(t, failingInner)
		failingServer := &UdpServer{agentPeerLookup: failingLookup}

		got := failingServer.ResolveOwnerIDByPubKey(context.Background(), pubkeyB64(0xA3))
		if got != "" {
			t.Errorf("ResolveOwnerIDByPubKey under DDB outage = %q, want \"\" (LookupAgentByPubKey failure must degrade to empty, NOT bubble the error or panic — the forward-receiver path stamps empty on the ACK entry as the documented fail-safe behavior)", got)
		}
	})

	t.Run("input format contract: expects already-base64 pubkey, double-encode returns empty", func(t *testing.T) {
		// Pin the input-format contract. ResolveOwnerIDByPubKey expects
		// the already-base64-encoded pubkey shape produced at
		// nhpauth.go:160 (and used by req.PublicKey at the local UDP
		// call site, udpserver.go:3612). A regression that wrapped
		// req.PublicKey in another base64.Encode at the call site would
		// silently degrade every knock to empty-OwnerId — the lookup
		// would miss because the cache key is the once-encoded form;
		// the fail-safe would kick in; no error would be logged.
		//
		// Pass `pk` (already base64) → hits cache, surfaces owner_id.
		// Pass base64(pk) (double-encoded) → cache miss, DDB miss, "".
		// Distinct from "unknown pubkey returns empty" — that asserts
		// fail-safe on an unmapped pubkey; this asserts that the EXACT
		// SAME logical pubkey, encoded one extra time, fails the
		// lookup. Catches a future double-encode regression without
		// needing to mount the full handleNhpOpenResource path.
		oncePK := pk
		twicePK := base64.StdEncoding.EncodeToString([]byte(oncePK))
		if twicePK == oncePK {
			t.Fatalf("test bug: double-encoded pubkey equals once-encoded pubkey, regression check is meaningless")
		}

		if got := s.ResolveOwnerIDByPubKey(context.Background(), oncePK); got != "owner-forward-receiver-1" {
			t.Errorf("once-encoded pubkey lookup = %q, want %q (regression baseline)", got, "owner-forward-receiver-1")
		}
		if got := s.ResolveOwnerIDByPubKey(context.Background(), twicePK); got != "" {
			t.Errorf("double-encoded pubkey lookup = %q, want \"\" (a call-site that wrapped req.PublicKey in another base64.Encode must NOT silently match the stored once-encoded form)", got)
		}
	})
}

// distinctRowCollisionQuerier returns TWO rows with DIFFERENT
// public_key strings on every Query. STRUCTURALLY IMPOSSIBLE in
// production: the qurl-agent-keys GSI partition key is public_key,
// so a real KeyConditionExpression="public_key = :pk" query cannot
// return rows with different public_key values. This fake is a
// hypothetical-regression fence — it exercises a code path that
// can only arise from a future bug (e.g., the resolver query stops
// keying on public_key, or the GSI is rebuilt with a different
// hash key) and asserts the admit-Items[0] invariant holds in that
// adversarial scenario. Distinct from collidingAgentKeysQuerier
// (same-pubkey-twice), which exercises the production-reachable
// writer-side soft-uniqueness-failed-open case.
type distinctRowCollisionQuerier struct {
	first  string
	second string
}

func (d *distinctRowCollisionQuerier) Query(_ context.Context, _ *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	row0 := map[string]types.AttributeValue{
		"public_key": &types.AttributeValueMemberS{Value: d.first},
	}
	row1 := map[string]types.AttributeValue{
		"public_key": &types.AttributeValueMemberS{Value: d.second},
	}
	return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{row0, row1}}, nil
}

// fakeCounterIncrementer captures IncrCounter calls so collision
// tests can assert MetricAgentLookupPubkeyCollision fired.
type fakeCounterIncrementer struct {
	mu     sync.Mutex
	counts map[string]int
}

func (f *fakeCounterIncrementer) IncrCounter(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counts == nil {
		f.counts = map[string]int{}
	}
	f.counts[name]++
}

func (f *fakeCounterIncrementer) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[name]
}

// collidingAgentKeysQuerier returns TWO rows for the configured
// pubkey on every Query — simulating the writer-side uniqueness
// invariant failing open (two owners' bootstrap registrations
// racing or a rotation-orphan row that hasn't TTL-expired).
type collidingAgentKeysQuerier struct {
	pk        string
	mu        sync.Mutex
	calls     int
	lastLimit int32
}

func (c *collidingAgentKeysQuerier) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	c.mu.Lock()
	c.calls++
	if in.Limit != nil {
		c.lastLimit = *in.Limit
	}
	c.mu.Unlock()
	row := map[string]types.AttributeValue{
		"public_key": &types.AttributeValueMemberS{Value: c.pk},
	}
	return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{row, row}}, nil
}

// TestUnwrapDynamoDBStorage_NilInputReturnsNilNoError asserts the
// unwrap helper handles a nil StorageBackend gracefully: returns
// (nil, nil) — NOT the cycle sentinel — so
// NewAgentPeerLookupFromStorage produces the disabled state without
// firing MetricAgentLookupInitFailure. Etcd-backed and pre-storage
// boot paths rely on this. Companion test
// TestUnwrapDynamoDBStorage_NonNilNonDDBReturnsNil covers the
// non-nil but non-DDB case the previous test-name implied.
func TestUnwrapDynamoDBStorage_NilInputReturnsNilNoError(t *testing.T) {
	got, err := unwrapDynamoDBStorage(nil)
	if err != nil {
		t.Errorf("unwrapDynamoDBStorage(nil) err=%v want nil (nil-input is not a cycle)", err)
	}
	if got != nil {
		t.Errorf("unwrapDynamoDBStorage(nil)=%v want nil", got)
	}
}

// nonDDBStorage is a minimal StorageBackend that is NOT a
// *DynamoDBStorage and does NOT implement Backend(). Mirrors the
// shape of any future top-level storage implementation a developer
// might add (e.g., in-memory, file-backed) without thinking about
// the unwrap chain — the resolver should treat it as "no DDB
// underneath" and return nil cleanly.
//
// Embedding the StorageBackend interface (without initializing it)
// satisfies the interface contract for type purposes — calls to
// nil-embedded methods would panic, but the unwrap helper only
// type-asserts (`*DynamoDBStorage`, `unwrapper`) and never invokes
// the embedded methods, so the type-assertion paths return false
// cleanly and the helper exits with (nil, nil). Pattern is
// idiomatic for "test fixture that satisfies the interface but
// isn't usable as a real backend."
type nonDDBStorage struct {
	StorageBackend
}

// TestUnwrapDynamoDBStorage_NonNilNonDDBReturnsNil asserts the
// helper returns nil (rather than panicking or looping) when given
// a non-nil StorageBackend that isn't a DynamoDBStorage and
// doesn't expose a Backend() unwrapper. This is the interesting
// "no DDB present" path — the nil-input case alone doesn't fence
// regressions where a new StorageBackend implementation lands
// without the unwrap contract.
func TestUnwrapDynamoDBStorage_NonNilNonDDBReturnsNil(t *testing.T) {
	got, err := unwrapDynamoDBStorage(&nonDDBStorage{})
	if err != nil {
		t.Errorf("unwrapDynamoDBStorage(nonDDB) err=%v want nil (no-unwrapper is not a cycle)", err)
	}
	if got != nil {
		t.Errorf("unwrapDynamoDBStorage(nonDDB)=%v want nil", got)
	}
}

// TestUnwrapDynamoDBStorage_WalksFullDecoratorChain asserts the
// helper finds the underlying *DynamoDBStorage through a multi-level
// Backend() chain. Order-independent by design: unwrapDynamoDBStorage
// walks Backend() until it finds *DynamoDBStorage; the wrap order in
// CreateStorageBackend does not affect correctness. The regression
// this fences is "a decorator was added without a Backend()
// unwrapper" — that decorator would terminate the walk early, and
// the agent peer lookup would silently disable. Both reachable
// terminal states are asserted (got != nil; got == ddb), so a future
// re-ordering of the wraps in dynamodb_storage.go does NOT need a
// paired test update — the chain just walks a different sequence
// and still hits the same DDB.
func TestUnwrapDynamoDBStorage_WalksFullDecoratorChain(t *testing.T) {
	ddb := &DynamoDBStorage{
		client: dynamodb.New(dynamodb.Options{}),
		config: DynamoDBConfig{AgentKeysTable: "qurl-agent-keys-test"},
	}
	// Build a chain that exercises all three production decorators.
	// The specific order here is illustrative of the current
	// CreateStorageBackend shape, but the test's assertions are
	// order-independent (see godoc above).
	metricsWrapped := NewMetricsStorage(ddb)
	logged := NewLoggingStorage(metricsWrapped)
	cached := NewCachedStorage(logged, CacheConfig{
		MaxEntries:         16,
		DefaultTTL:         60,
		ReassignmentTTL:    5,
		ReassignmentWindow: 300,
	})

	got, err := unwrapDynamoDBStorage(cached)
	if err != nil {
		t.Fatalf("unwrapDynamoDBStorage err=%v want nil (full chain has no cycle)", err)
	}
	if got == nil {
		t.Fatal("unwrapDynamoDBStorage walked through full chain returned nil")
	}
	if got != ddb {
		t.Errorf("unwrapDynamoDBStorage returned %p want %p (must be the original *DynamoDBStorage)", got, ddb)
	}
}

// TestUnwrapDynamoDBStorage_CurrentChainDepthFits asserts the
// production decorator chain stays well below unwrapMaxHops, so a
// future decorator addition that pushes the chain past the safe
// half-of-cap ratio forces a re-review of the cap (and a paired
// update here). The current production chain is 4 levels deep
// (CachedStorage → LoggingStorage → MetricsStorage → DynamoDBStorage)
// against unwrapMaxHops=16, so the ratio is well within the
// half-of-cap headroom this fence enforces.
func TestUnwrapDynamoDBStorage_CurrentChainDepthFits(t *testing.T) {
	const safeMax = unwrapMaxHops / 2
	ddb := &DynamoDBStorage{
		client: dynamodb.New(dynamodb.Options{}),
		config: DynamoDBConfig{AgentKeysTable: "qurl-agent-keys-test"},
	}
	metricsWrapped := NewMetricsStorage(ddb)
	logged := NewLoggingStorage(metricsWrapped)
	cached := NewCachedStorage(logged, CacheConfig{
		MaxEntries:         16,
		DefaultTTL:         60,
		ReassignmentTTL:    5,
		ReassignmentWindow: 300,
	})

	depth := countBackendDepth(cached)
	if depth > safeMax {
		t.Errorf("production decorator chain depth=%d exceeds safe half-of-cap %d (unwrapMaxHops=%d); "+
			"either re-review the cap before adding the decorator that pushed it past the ratio, "+
			"or update this test in the same PR with a documented reason",
			depth, safeMax, unwrapMaxHops)
	}
}

// countBackendDepth walks Backend() until the chain terminates or
// hits unwrapMaxHops, returning the number of hops. Used by the
// chain-depth fence above.
func countBackendDepth(s StorageBackend) int {
	type unwrapper interface{ Backend() StorageBackend }
	depth := 0
	for s != nil && depth < unwrapMaxHops {
		depth++
		if _, ok := s.(*DynamoDBStorage); ok {
			return depth
		}
		u, ok := s.(unwrapper)
		if !ok {
			return depth
		}
		s = u.Backend()
	}
	return depth
}

// TestNewAgentPeerLookupFromStorage_DisabledOnEmptyTable asserts
// that a DynamoDBStorage with an unset AgentKeysTable yields a
// nil lookup — i.e., the agent path is disabled when terraform
// hasn't plumbed the table name yet (greenfield envs / phased
// rollout).
func TestNewAgentPeerLookupFromStorage_DisabledOnEmptyTable(t *testing.T) {
	ddb := &DynamoDBStorage{
		client: dynamodb.New(dynamodb.Options{}),
		config: DynamoDBConfig{AgentKeysTable: ""},
	}
	got, err := NewAgentPeerLookupFromStorage(ddb)
	if err != nil {
		t.Fatalf("NewAgentPeerLookupFromStorage: %v", err)
	}
	if got != nil {
		t.Errorf("lookup=%v want nil (table unset)", got)
	}
}

// TestNewAgentPeerLookupFromStorage_HappyPath asserts the
// "DynamoDBStorage with AgentKeysTable set" path returns a usable
// (non-nil) lookup, paired with the disabled-state test above.
func TestNewAgentPeerLookupFromStorage_HappyPath(t *testing.T) {
	ddb := &DynamoDBStorage{
		client: dynamodb.New(dynamodb.Options{}),
		config: DynamoDBConfig{AgentKeysTable: "qurl-agent-keys-test"},
	}
	got, err := NewAgentPeerLookupFromStorage(ddb)
	if err != nil {
		t.Fatalf("NewAgentPeerLookupFromStorage: %v", err)
	}
	if got == nil {
		t.Fatal("lookup=nil want non-nil (table is set)")
	}
	if got.table != "qurl-agent-keys-test" {
		t.Errorf("lookup.table=%q want %q", got.table, "qurl-agent-keys-test")
	}
	if got.querier == nil {
		t.Error("lookup.querier=nil want non-nil agentLookupQuerier")
	}
}

// TestNewAgentPeerLookupFromStorage_WrapperCycleSurfacesError fences
// the wrapper-cycle path: a Backend() chain that loops back without
// reaching *DynamoDBStorage must return ErrAgentLookupStorageWrapperCycle
// (NOT silently `nil, nil` as in pre-#1833 builds). UdpServer.Start
// uses that error to set agentLookupInitFailed=true and emit
// MetricAgentLookupInitFailure — which is the only reason the metric
// is reachable today. A regression here turns the metric back into
// an unreachable fence and gives a wrapper-graph cycle no alarm
// signal beyond a single Warning log line at boot.
func TestNewAgentPeerLookupFromStorage_WrapperCycleSurfacesError(t *testing.T) {
	// cycleBackendShim returns a fresh shim on every Backend()
	// call. The unwrap walker therefore never sees the same `s`
	// twice (so the direct-self-loop guard `next == s` never
	// trips) and runs until unwrapMaxHops fires. This simulates a
	// future A→B→A wrapper cycle that the single-step guard would
	// miss.
	got, err := NewAgentPeerLookupFromStorage(&cycleBackendShim{})
	if !errors.Is(err, ErrAgentLookupStorageWrapperCycle) {
		t.Errorf("err=%v want ErrAgentLookupStorageWrapperCycle (UdpServer.Start gates MetricAgentLookupInitFailure on this)", err)
	}
	if got != nil {
		t.Errorf("lookup=%v want nil (cycle should disable the agent path)", got)
	}
}

// cycleBackendShim simulates a wrapper-graph cycle deeper than the
// single-step self-loop guard by handing back a fresh shim on every
// Backend() invocation — the unwrap walker can't recognize the loop
// via pointer identity and runs until unwrapMaxHops.
type cycleBackendShim struct {
	StorageBackend
}

func (c *cycleBackendShim) Backend() StorageBackend {
	return &cycleBackendShim{}
}

// TestNewAgentPeerLookupFromStorage_DirectSelfLoopSurfacesError
// fences the unification of the direct-self-loop and
// chain-too-deep paths: a wrapper whose Backend() returns the
// receiver itself (direct A→A self-loop) must produce the SAME
// ErrAgentLookupStorageWrapperCycle sentinel as the
// chain-too-deep / A→B→A path. Same operational consequence
// (agent path disabled in cloud mode → every agent knock fails
// at the responder layer); a split across silent-vs-alarmed
// reporting for two structurally identical misconfigs would
// leave the self-loop case without a metric to page on.
func TestNewAgentPeerLookupFromStorage_DirectSelfLoopSurfacesError(t *testing.T) {
	shim := &selfLoopBackendShim{}
	got, err := NewAgentPeerLookupFromStorage(shim)
	if !errors.Is(err, ErrAgentLookupStorageWrapperCycle) {
		t.Errorf("err=%v want ErrAgentLookupStorageWrapperCycle (direct self-loop must alarm-fail the same way the deeper cycle path does)", err)
	}
	if got != nil {
		t.Errorf("lookup=%v want nil (self-loop should disable the agent path)", got)
	}
}

// selfLoopBackendShim returns ITSELF from Backend(), tripping the
// `next == s` direct-self-loop guard in unwrapDynamoDBStorage.
type selfLoopBackendShim struct {
	StorageBackend
}

func (c *selfLoopBackendShim) Backend() StorageBackend {
	return c
}

// captureAgentKeysQuerier wraps a fake to expose the QueryInput for
// shape assertions. Forwards the actual response to the inner fake
// so assertion-only tests still get meaningful data back.
type captureAgentKeysQuerier struct {
	inner     *fakeAgentKeysQuerier
	captureFn func(in *dynamodb.QueryInput)
}

func (c *captureAgentKeysQuerier) Query(ctx context.Context, in *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if c.captureFn != nil {
		c.captureFn(in)
	}
	return c.inner.Query(ctx, in, opts...)
}
