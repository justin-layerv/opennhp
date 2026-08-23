package ac

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestNHPRunAttemptBarriersFenceDelayedAOP(t *testing.T) {
	agent := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const runID = "0123456789abcdef"
	now := time.Unix(1_700_000_000, 0)
	b := newNHPRunAttemptBarriers()
	b.now = func() time.Time { return now }

	if err := b.requireExact(agent, runID, 1, 1); !errors.Is(err, errNHPRunAttemptBarrierMissing) {
		t.Fatalf("require before barrier = %v, want missing", err)
	}
	if err := b.record(agent, runID, 2, 1); err != nil {
		t.Fatalf("record attempt 2: %v", err)
	}
	if err := b.requireExact(agent, runID, 1, 1); !errors.Is(err, errNHPRunAttemptBarrierStale) {
		t.Fatalf("require attempt 1 = %v, want stale", err)
	}
	if err := b.requireExact(agent, runID, 2, 1); !errors.Is(err, errNHPRunAttemptBarrierPending) {
		t.Fatalf("require pending attempt 2 = %v, want pending", err)
	}
	if err := b.requireExact(agent, runID, 3, 1); !errors.Is(err, errNHPRunAttemptBarrierMissing) {
		t.Fatalf("require attempt 3 = %v, want missing", err)
	}
	if err := b.commit(agent, runID, 2, 1); err != nil {
		t.Fatalf("commit attempt 2: %v", err)
	}
	if err := b.requireExact(agent, runID, 2, 1); err != nil {
		t.Fatalf("require committed attempt 2: %v", err)
	}

	// A replayed lower barrier cannot roll the high watermark back, and an
	// exact retry cannot demote a converged attempt to pending.
	if err := b.record(agent, runID, 1, 1); err != nil {
		t.Fatalf("record lower replay: %v", err)
	}
	if err := b.record(agent, runID, 2, 1); err != nil {
		t.Fatalf("record exact retry: %v", err)
	}
	if err := b.requireExact(agent, runID, 1, 1); !errors.Is(err, errNHPRunAttemptBarrierStale) {
		t.Fatalf("require attempt 1 after replay = %v, want stale", err)
	}
	if err := b.requireExact(agent, runID, 2, 1); err != nil {
		t.Fatalf("exact retry demoted committed attempt: %v", err)
	}

	now = now.Add(nhpRunAttemptBarrierTTL)
	if err := b.requireExact(agent, runID, 2, 1); !errors.Is(err, errNHPRunAttemptBarrierMissing) {
		t.Fatalf("require expired attempt = %v, want missing", err)
	}
}

func TestNHPRunAttemptBarriersCapacityFailsClosed(t *testing.T) {
	b := newNHPRunAttemptBarriers()
	now := time.Unix(1_700_000_000, 0)
	b.now = func() time.Time { return now }
	for i := 0; i < maxNHPRunAttemptBarriers; i++ {
		key := nhpRunAttemptBarrierKey{agentPublicKey: "agent", runID: fmt.Sprintf("%016x", i)}
		b.entries[key] = nhpRunAttemptBarrier{attempt: 1, flushGeneration: 1, converged: true, expiresAt: now.Add(time.Minute)}
	}
	if err := b.record("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "0123456789abcdef", 1, 1); !errors.Is(err, errNHPRunAttemptBarrierCapacity) {
		t.Fatalf("record at capacity = %v, want capacity", err)
	}

	// Expiry cleanup frees capacity without weakening an existing watermark.
	now = now.Add(2 * time.Minute)
	if err := b.record("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "0123456789abcdef", 1, 1); err != nil {
		t.Fatalf("record after sweep: %v", err)
	}
}

func TestNHPRunAttemptBarrierPendingDoesNotExpireBeforeRetry(t *testing.T) {
	agent := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const runID = "0123456789abcdef"
	base := time.Unix(1_700_000_000, 0)
	now := base
	b := newNHPRunAttemptBarriers()
	b.now = func() time.Time { return now }
	if err := b.record(agent, runID, 2, 1); err != nil {
		t.Fatal(err)
	}
	now = base.Add(10 * nhpRunAttemptBarrierTTL)
	if err := b.requireExact(agent, runID, 2, 1); !errors.Is(err, errNHPRunAttemptBarrierPending) {
		t.Fatalf("pending barrier after retry delay = %v, want pending", err)
	}
	if err := b.commit(agent, runID, 2, 1); err != nil {
		t.Fatalf("commit delayed exact retry: %v", err)
	}
	if err := b.requireExact(agent, runID, 2, 1); err != nil {
		t.Fatalf("committed delayed retry: %v", err)
	}
}

func TestNHPRunAttemptBarriersAreFlushGenerationBound(t *testing.T) {
	agent := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const runID = "0123456789abcdef"
	b := newNHPRunAttemptBarriers()
	if err := b.record(agent, runID, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err := b.commit(agent, runID, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err := b.requireExact(agent, runID, 2, 2); !errors.Is(err, errNHPRunAttemptBarrierMissing) {
		t.Fatalf("generation 1 barrier authorized generation 2 AOP: %v", err)
	}
	if err := b.record(agent, runID, 2, 2); err != nil {
		t.Fatal(err)
	}
	if err := b.requireExact(agent, runID, 2, 2); !errors.Is(err, errNHPRunAttemptBarrierPending) {
		t.Fatalf("generation 2 pending barrier = %v, want pending", err)
	}
	if err := b.commit(agent, runID, 2, 2); err != nil {
		t.Fatal(err)
	}
	if err := b.requireExact(agent, runID, 2, 2); err != nil {
		t.Fatalf("generation 2 committed barrier did not authorize exact AOP: %v", err)
	}
	if err := b.record(agent, runID, 3, 1); !errors.Is(err, errNHPRunAttemptBarrierStale) {
		t.Fatalf("old generation advanced watermark: %v", err)
	}
}
