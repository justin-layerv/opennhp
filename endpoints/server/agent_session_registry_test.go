package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestLiveNHPSessionRegistryRejectsInvalidAuthenticatedAgentKeys(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	now := time.Now()
	for _, key := range [][]byte{nil, {}, bytes.Repeat([]byte{0x01}, 31), bytes.Repeat([]byte{0x01}, 33)} {
		if _, err := registry.reserveNew(key, now); err == nil {
			t.Fatalf("reserveNew key length %d unexpectedly succeeded", len(key))
		}
		if err := registry.reserveExact(key, 77, now, now.Add(time.Minute)); err == nil {
			t.Fatalf("reserveExact key length %d unexpectedly succeeded", len(key))
		}
	}

	valid := bytes.Repeat([]byte{0x42}, 32)
	canonical := base64.StdEncoding.EncodeToString(valid)
	if got, err := decodeAgentPublicKey(canonical); err != nil || !bytes.Equal(got, valid) {
		t.Fatalf("decodeAgentPublicKey canonical = %x, %v", got, err)
	}
	for _, encoded := range []string{"", base64.StdEncoding.EncodeToString(valid[:31]), canonical[:len(canonical)-1]} {
		if _, err := decodeAgentPublicKey(encoded); err == nil {
			t.Fatalf("decodeAgentPublicKey(%q) unexpectedly succeeded", encoded)
		}
	}
}

func TestLiveNHPSessionRegistryRegeneratesAfterCollision(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	issued := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return issued }
	ids := []uint64{41, 41, 42}
	registry.newID = func() uint64 {
		id := ids[0]
		ids = ids[1:]
		return id
	}
	agent := bytes.Repeat([]byte{0x11}, 32)
	first, err := registry.reserveNew(agent, issued)
	if err != nil || first != 41 {
		t.Fatalf("first reservation = %d, %v; want 41, nil", first, err)
	}
	second, err := registry.reserveNew(agent, issued.Add(time.Nanosecond))
	if err != nil || second != 42 {
		t.Fatalf("collision regeneration = %d, %v; want 42, nil", second, err)
	}
}

func TestLiveNHPSessionRegistryConcurrentReservationsAreUnique(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	issued := time.Now()
	agent := bytes.Repeat([]byte{0x22}, 32)
	const count = 256
	ids := make(chan uint64, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			id, err := registry.reserveNew(agent, issued.Add(time.Duration(offset)*time.Nanosecond))
			ids <- id
			errs <- err
		}(i)
	}
	wg.Wait()
	close(ids)
	close(errs)
	seen := make(map[uint64]struct{}, count)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent reservation: %v", err)
		}
	}
	for id := range ids {
		if id == 0 {
			t.Fatal("concurrent reservation returned zero")
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("duplicate concurrent session ID %d", id)
		}
		seen[id] = struct{}{}
	}
}

func TestLiveNHPSessionRegistryForwardedCollisionFailsClosed(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	now := time.Now()
	agentA := bytes.Repeat([]byte{0x33}, 32)
	agentB := bytes.Repeat([]byte{0x44}, 32)
	if err := registry.reserveExact(agentA, 55, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("first forwarded reserve: %v", err)
	}
	if err := registry.reserveExact(agentA, 55, now, now.Add(30*time.Second)); err != nil {
		t.Fatalf("identical forwarded retry must be idempotent: %v", err)
	}
	if err := registry.reserveExact(agentB, 55, now, now.Add(time.Minute)); !errors.Is(err, errNHPSessionIDCollision) {
		t.Fatalf("different-agent collision = %v, want errNHPSessionIDCollision", err)
	}
	if err := registry.reserveExact(agentA, 55, now.Add(time.Nanosecond), now.Add(time.Minute)); !errors.Is(err, errNHPSessionIDCollision) {
		t.Fatalf("different-issuance collision = %v, want errNHPSessionIDCollision", err)
	}
}

func TestLiveNHPSessionRegistryFailedCloseRemainsRetryable(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	agent := bytes.Repeat([]byte{0x55}, 32)
	other := bytes.Repeat([]byte{0x66}, 32)
	if err := registry.reserveExact(agent, 61, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := registry.beginOpen(61, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.finishOpen(61, now, now.Add(time.Minute), now.Add(time.Minute+time.Duration(ACOpenCompensationTime)*time.Second), "ac-b", true); err != nil {
		t.Fatal(err)
	}
	if err := registry.beginOpen(61, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.finishOpen(61, now, now.Add(time.Minute), now.Add(time.Minute+time.Duration(ACOpenCompensationTime)*time.Second), "ac-a", true); err != nil {
		t.Fatal(err)
	}
	if err := registry.reserveExact(other, 62, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got := registry.snapshotAgentSessions(agent, now)
	if len(got) != 1 || got[0].SessionID != 61 || len(got[0].ACIDs) != 2 || got[0].ACIDs[0] != "ac-a" || got[0].ACIDs[1] != "ac-b" {
		t.Fatalf("close snapshots = %#v", got)
	}
	// A failed AC close does not call completeAgentSessionClose. The exact work
	// remains available for an idempotent retry.
	if retry := registry.snapshotAgentSessions(agent, now); len(retry) != 1 || retry[0].SessionID != got[0].SessionID || !retry[0].IssuedAt.Equal(got[0].IssuedAt) {
		t.Fatalf("failed close retry snapshots = %#v, want exact session %#v", retry, got[0])
	}
	if registry.completeAgentSessionClose(other, got[0]) {
		t.Fatal("different agent completed close")
	}
	stale := got[0]
	stale.IssuedAt = stale.IssuedAt.Add(time.Nanosecond)
	if registry.completeAgentSessionClose(agent, stale) {
		t.Fatal("different issuance completed close")
	}
	if !registry.completeAgentSessionClose(agent, got[0]) {
		t.Fatal("exact successful close was not completed")
	}
	if again := registry.snapshotAgentSessions(agent, now); len(again) != 0 {
		t.Fatalf("completed close snapshots = %#v, want empty", again)
	}
	otherClose := registry.snapshotAgentSessions(other, now)
	if len(otherClose) != 1 || otherClose[0].SessionID != 62 {
		t.Fatalf("other agent close = %#v", otherClose)
	}
	if !registry.completeAgentSessionClose(other, otherClose[0]) {
		t.Fatal("other agent exact close was not completed")
	}

	if snapshots := registry.snapshotAgentSessions(nil, now); snapshots != nil {
		t.Fatalf("empty authenticated key snapshots = %#v, want nil", snapshots)
	}
	if snapshots := registry.snapshotAgentSessions(bytes.Repeat([]byte{0x77}, 31), now); snapshots != nil {
		t.Fatalf("short authenticated key snapshots = %#v, want nil", snapshots)
	}

	// Replay admission is bounded independently from close completion.
	if got := registry.admitCloseEvent("event-1", now.Add(time.Minute)); got != closeEventNew {
		t.Fatalf("first close event admission = %v, want new", got)
	}
	if got := registry.admitCloseEvent("event-1", now.Add(time.Minute)); got != closeEventReplay {
		t.Fatalf("duplicate close event admission = %v, want replay", got)
	}
	now = now.Add(2 * time.Minute)
	if got := registry.admitCloseEvent("event-1", now.Add(time.Minute)); got != closeEventNew {
		t.Fatalf("expired replay entry admission = %v, want new", got)
	}
}

func TestLiveNHPSessionRegistryReleaseRetainsAdmittedSession(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	agent := bytes.Repeat([]byte{0x57}, 32)
	if err := registry.reserveExact(agent, 63, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := registry.beginOpen(63, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.finishOpen(63, now, now.Add(time.Minute), now.Add(time.Minute+time.Duration(ACOpenCompensationTime)*time.Second), "ac-admitted", true); err != nil {
		t.Fatal(err)
	}

	// A later token-publication or ACK failure may reject the overall knock
	// after the AC already opened its pinhole. Releasing the pending request must
	// retain that exact close work until EXT or natural expiry.
	registry.release(agent, 63, now)
	snapshots := registry.snapshotAgentSessions(agent, now)
	if len(snapshots) != 1 || snapshots[0].SessionID != 63 || len(snapshots[0].ACIDs) != 1 || snapshots[0].ACIDs[0] != "ac-admitted" {
		t.Fatalf("admitted session after release = %#v, want retained AC close work", snapshots)
	}
}

func TestLiveNHPSessionRegistryExitRacingOpenBlocksACKAndRetainsCloseWork(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	agent := bytes.Repeat([]byte{0x71}, 32)
	if err := registry.reserveExact(agent, 91, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := registry.beginOpen(91, now); err != nil {
		t.Fatal(err)
	}
	closing := registry.snapshotAgentSessions(agent, now)
	if len(closing) != 1 || closing[0].InFlight != 1 {
		t.Fatalf("closing snapshot = %#v, want one in-flight open", closing)
	}
	if err := registry.beginOpen(91, now); err == nil {
		t.Fatal("new AOP began after EXT marked the session closing")
	}
	if err := registry.finishOpen(91, now, now.Add(time.Minute), now.Add(time.Minute+time.Duration(ACOpenCompensationTime)*time.Second), "ac-raced", true); err == nil {
		t.Fatal("raced successful ART was accepted as an admission after EXT")
	}
	retry := registry.snapshotAgentSessions(agent, now)
	if len(retry) != 1 || retry[0].InFlight != 0 || len(retry[0].ACIDs) != 1 || retry[0].ACIDs[0] != "ac-raced" {
		t.Fatalf("post-race close snapshot = %#v", retry)
	}
	if !registry.completeAgentSessionClose(agent, retry[0]) {
		t.Fatal("raced session did not complete after exact AC close")
	}
}

func TestLiveNHPSessionRegistryCloseCutoffPreservesNewSession(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	agent := bytes.Repeat([]byte{0x72}, 32)
	if err := registry.reserveExact(agent, 92, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	closeIssuedThrough := now
	got := registry.snapshotAgentSessions(agent, closeIssuedThrough)
	if len(got) != 1 || got[0].SessionID != 92 {
		t.Fatalf("cutoff snapshots = %#v, want pre-EXT session", got)
	}
	if !registry.completeAgentSessionClose(agent, got[0]) {
		t.Fatal("pre-EXT session close did not complete")
	}

	// A post-EXT session retries after the bounded clock-skew window. Replaying
	// the older close cutoff must not select this genuinely newer issuance.
	now = closeIssuedThrough.Add(agentSessionCloseFutureSkew + time.Nanosecond)
	postCutoffIssuedAt := now
	if err := registry.reserveExact(agent, 93, postCutoffIssuedAt, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := registry.snapshotAgentSessions(agent, closeIssuedThrough); len(got) != 0 {
		t.Fatalf("older cutoff selected post-window session: %#v", got)
	}
	if err := registry.beginOpen(93, postCutoffIssuedAt); err != nil {
		t.Fatalf("post-EXT session was marked closing: %v", err)
	}
	if err := registry.finishOpen(93, postCutoffIssuedAt, now.Add(time.Minute), now.Add(time.Minute+time.Duration(ACOpenCompensationTime)*time.Second), "ac-new", true); err != nil {
		t.Fatalf("post-EXT session activation: %v", err)
	}
}

func TestLiveNHPSessionRegistrySeparatesAdmissionDeadlineFromACRetention(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	agent := bytes.Repeat([]byte{0x74}, 32)
	other := bytes.Repeat([]byte{0x75}, 32)
	sessionExpiresAt := now.Add(time.Second)
	retainUntil := sessionExpiresAt.Add(time.Duration(ACOpenCompensationTime) * time.Second)
	if err := registry.reserveExact(agent, 95, now, sessionExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := registry.beginOpen(95, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.finishOpen(95, now, sessionExpiresAt, retainUntil, "ac-retained", true); err != nil {
		t.Fatal(err)
	}

	now = sessionExpiresAt.Add(time.Nanosecond)
	if err := registry.beginOpen(95, time.Unix(1_800_000_000, 0)); !errors.Is(err, errNHPSessionNotReserved) {
		t.Fatalf("beginOpen after session deadline = %v, want not reserved", err)
	}
	snapshots := registry.snapshotAgentSessions(agent, now)
	if len(snapshots) != 1 || snapshots[0].SessionID != 95 || len(snapshots[0].ACIDs) != 1 {
		t.Fatalf("retained close work after session deadline = %#v", snapshots)
	}
	if err := registry.reserveExact(other, 95, now, now.Add(time.Minute)); !errors.Is(err, errNHPSessionIDCollision) {
		t.Fatalf("session id reuse during compensated AC lifetime = %v, want collision", err)
	}
}

func TestLiveNHPSessionRegistryRetainedIDCannotBeRegeneratedUntilACDeadline(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	issuedAt := time.Unix(1_800_000_000, 0)
	now := issuedAt
	registry.now = func() time.Time { return now }
	registry.newID = func() uint64 { return 96 }
	agent := bytes.Repeat([]byte{0x76}, 32)
	sessionExpiresAt := issuedAt.Add(time.Second)
	retainUntil := sessionExpiresAt.Add(time.Duration(ACOpenCompensationTime) * time.Second)
	if err := registry.reserveExact(agent, 96, issuedAt, sessionExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := registry.beginOpen(96, issuedAt); err != nil {
		t.Fatal(err)
	}
	if err := registry.finishOpen(96, issuedAt, sessionExpiresAt, retainUntil, "ac-retained", true); err != nil {
		t.Fatal(err)
	}
	now = sessionExpiresAt.Add(time.Nanosecond)
	if _, err := registry.reserveNew(agent, now); !errors.Is(err, errNHPSessionIDCollision) {
		t.Fatalf("regeneration during retention = %v, want collision", err)
	}
	now = retainUntil.Add(time.Nanosecond)
	if id, err := registry.reserveNew(agent, now); err != nil || id != 96 {
		t.Fatalf("regeneration after retention = %d, %v; want 96, nil", id, err)
	}
}

func TestLiveNHPSessionRegistryCloseCutoffRejectsReorderedOlderForward(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	agent := bytes.Repeat([]byte{0x77}, 32)

	// The fleet close arrives before this server sees the older forwarded
	// reservation. Recording the authenticated cutoff must be effective even
	// when there are no local sessions to snapshot yet.
	if got := registry.snapshotAgentSessions(agent, now); len(got) != 0 {
		t.Fatalf("empty close snapshot = %#v", got)
	}
	if err := registry.reserveExact(agent, 97, now.Add(-time.Second), now.Add(time.Minute)); !errors.Is(err, errNHPSessionNotReserved) {
		t.Fatalf("reordered pre-close forward = %v, want not reserved", err)
	}
	if _, err := registry.reserveNew(agent, now.Add(-time.Nanosecond)); !errors.Is(err, errNHPSessionNotReserved) {
		t.Fatalf("reordered local reservation = %v, want not reserved", err)
	}
	clockAheadPriorIssuedAt := now.Add(agentSessionCloseFutureSkew - time.Nanosecond)
	if err := registry.reserveExact(agent, 98, clockAheadPriorIssuedAt, now.Add(time.Minute)); !errors.Is(err, errNHPSessionNotReserved) {
		t.Fatalf("clock-ahead pre-close forward = %v, want not reserved", err)
	}

	now = now.Add(agentSessionCloseFutureSkew + time.Nanosecond)
	newerIssuedAt := now
	if err := registry.reserveExact(agent, 99, newerIssuedAt, now.Add(time.Minute)); err != nil {
		t.Fatalf("genuinely post-close forward rejected: %v", err)
	}
	if err := registry.beginOpen(99, newerIssuedAt); err != nil {
		t.Fatalf("post-close session could not begin AOP: %v", err)
	}
}

func TestLiveNHPSessionRegistryCloseCutoffCoversAOPReplayBoundary(t *testing.T) {
	if got, want := agentSessionCloseCutoffTTL, 125*time.Second; got != want {
		t.Fatalf("agent close-cutoff TTL = %s, want AOP replay floor + margin %s", got, want)
	}
	registry := newLiveNHPSessionRegistry()
	base := time.Unix(1_800_000_000, 0)
	now := base
	registry.now = func() time.Time { return now }
	agent := bytes.Repeat([]byte{0x78}, 32)
	if got := registry.snapshotAgentSessions(agent, base); len(got) != 0 {
		t.Fatalf("empty close snapshot = %#v", got)
	}

	now = base.Add(agentSessionCloseCutoffTTL - time.Nanosecond)
	if err := registry.reserveExact(agent, 102, base.Add(-time.Second), now.Add(time.Minute)); !errors.Is(err, errNHPSessionNotReserved) {
		t.Fatalf("reordered AOP one nanosecond before cutoff expiry = %v, want not reserved", err)
	}
	now = base.Add(agentSessionCloseCutoffTTL)
	if err := registry.reserveExact(agent, 102, base.Add(-time.Second), now.Add(time.Minute)); err != nil {
		t.Fatalf("reordered AOP at exact cutoff expiry = %v, want accepted after boundary", err)
	}
}

func TestLiveNHPSessionRegistryReserveExactBoundsFutureIssuance(t *testing.T) {
	registry := newLiveNHPSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	agent := bytes.Repeat([]byte{0x78}, 32)

	if err := registry.reserveExact(agent, 100, now.Add(agentSessionCloseFutureSkew), now.Add(time.Minute)); err != nil {
		t.Fatalf("issuance at future-skew boundary rejected: %v", err)
	}
	if err := registry.reserveExact(agent, 101, now.Add(agentSessionCloseFutureSkew+time.Nanosecond), now.Add(time.Minute)); !errors.Is(err, errNHPSessionNotReserved) {
		t.Fatalf("issuance beyond future-skew boundary = %v, want not reserved", err)
	}
}
