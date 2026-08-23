package ac

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

type siblingPreservationFlusher struct {
	calls atomic.Int32
}

func (f *siblingPreservationFlusher) Flush(context.Context, FlowKey) error {
	f.calls.Add(1)
	return nil
}

func TestSessionControlClosePreservesSharedFlowKeyAtSiblingDeadline(t *testing.T) {
	flusher := &siblingPreservationFlusher{}
	scheduler := NewScheduler(flusher, WithTickInterval(time.Hour))
	scheduler.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := scheduler.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	})

	a := &UdpAC{
		config:      &Config{FilterMode: FilterMode_IPTABLES},
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
		expirySched: scheduler,
	}
	const (
		agentKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		ownerID  = "00112233445566778899aabbccddeeff"
	)
	key := mustKey(t, "192.0.2.70", "192.0.2.80", 443, FlowProtoTCP)
	base := time.Now()
	closing := &AccessEntry{
		OpenTime:                 120,
		FirstKnockTime:           base,
		NHPSessionId:             11,
		NHPServerPublicKey:       "server",
		NHPSessionOwnerId:        ownerID,
		NHPAgentPublicKey:        agentKey,
		NHPSessionIssuedAtMillis: 1000,
	}
	sibling := &AccessEntry{
		OpenTime:                 60,
		FirstKnockTime:           base,
		NHPSessionId:             12,
		NHPServerPublicKey:       "server",
		NHPSessionOwnerId:        ownerID,
		NHPAgentPublicKey:        agentKey,
		NHPSessionIssuedAtMillis: 2000,
	}
	a.storeToken("closing", closing)
	a.storeToken("sibling", sibling)
	siblingEarlierDeadline := sibling.firewallDeadline().Add(flushSafetyMargin + 31*time.Millisecond)
	siblingDeadline := sibling.firewallDeadline().Add(flushSafetyMargin + 137*time.Millisecond)
	closingDeadline := closing.firewallDeadline().Add(flushSafetyMargin + 243*time.Millisecond)
	a.scheduleFlushIfEnabled(sibling, key.SrcIPString(), key.DstIPString(), int(key.DstPort), key.Protocol, siblingEarlierDeadline)
	a.scheduleFlushIfEnabled(sibling, key.SrcIPString(), key.DstIPString(), int(key.DstPort), key.Protocol, siblingDeadline)
	a.scheduleFlushIfEnabled(closing, key.SrcIPString(), key.DstIPString(), int(key.DstPort), key.Protocol, closingDeadline)

	closed, err := a.closeNHPExactSessionVerified(context.Background(), agentKey, closing.NHPSessionId, closing.NHPSessionIssuedAtMillis)
	if err != nil {
		t.Fatalf("closeNHPExactSessionVerified() error = %v", err)
	}
	if closed != 1 {
		t.Fatalf("closed entries = %d, want 1", closed)
	}
	if _, ok := a.tokenStore.Load("closing"); ok {
		t.Fatal("closed entry remains in tokenStore")
	}
	if _, ok := a.tokenStore.Load("sibling"); !ok {
		t.Fatal("live sibling was removed")
	}
	if got := flusher.calls.Load(); got != 0 {
		t.Fatalf("shared FlowKey flushes = %d, want 0", got)
	}
	if got := scheduler.EntryCount(); got != 1 {
		t.Fatalf("EntryCount after shared close = %d, want 1", got)
	}

	shard := scheduler.shards[key.shard()]
	shard.mu.Lock()
	entry := shard.entries[key]
	if entry == nil {
		shard.mu.Unlock()
		t.Fatal("shared FlowKey disappeared from scheduler")
	}
	gotDeadline := entry.deadlineNs
	shard.mu.Unlock()
	if want := monoNsAt(siblingDeadline); gotDeadline != want {
		t.Fatalf("shared FlowKey deadline = %d, want sibling deadline %d", gotDeadline, want)
	}
}
