package ac

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/utils"
)

type bootIPSet struct {
	mu    sync.Mutex
	calls [][]string
}

func (b *bootIPSet) Add(utils.IPTYPE, int, int, ...string) (string, error) {
	return "", nil
}

func (b *bootIPSet) Run(_ context.Context, args ...string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, append([]string(nil), args...))
	if len(args) == 2 && args[0] == "list" && args[1] == "-n" {
		return utils.DefaultSet + "\n" + utils.DefaultSetV6 + "\n" + utils.TempSet + "\n", nil
	}
	return "", nil
}

func (b *bootIPSet) called(want ...string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, call := range b.calls {
		if strings.Join(call, "\x00") == strings.Join(want, "\x00") {
			return true
		}
	}
	return false
}

func TestFlushInheritedNHPSessionsCompletesBeforeReadiness(t *testing.T) {
	key, err := MakeFlowKey("192.0.2.10", "192.0.2.20", 443, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey() error = %v", err)
	}
	flusher := newRecordingFlusher()
	scheduler := NewScheduler(flusher, WithTickInterval(time.Hour))
	scheduler.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = scheduler.Shutdown(ctx)
	})
	ipset := &bootIPSet{}
	ac := &UdpAC{
		config:      &Config{FilterMode: FilterMode_IPTABLES, EnableL3FlushOnExpiry: true},
		ipset:       ipset,
		expirySched: scheduler,
	}
	ac.enumerateFn = func() (int, error) {
		scheduler.Schedule(key, time.Now().Add(time.Hour))
		return 1, nil
	}

	if err := ac.flushInheritedNHPSessions(); err != nil {
		t.Fatalf("flushInheritedNHPSessions() error = %v", err)
	}
	if got := flusher.count(); got != 2 {
		t.Fatalf("conntrack flush calls = %d, want 2 (before and after ipset flush)", got)
	}
	if !ipset.called("flush", utils.DefaultSet) || !ipset.called("flush", utils.DefaultSetV6) {
		t.Fatalf("ipset calls = %#v", ipset.calls)
	}
	if got := scheduler.EntryCount(); got != 0 {
		t.Fatalf("scheduler entries after boot flush = %d", got)
	}
}

func TestFlushInheritedNHPSessionsRequiresRealTeardown(t *testing.T) {
	t.Run("missing scheduler", func(t *testing.T) {
		ac := &UdpAC{config: &Config{}, ipset: &bootIPSet{}}
		if err := ac.flushInheritedNHPSessions(); err == nil || !strings.Contains(err.Error(), "requires L3") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("dry run", func(t *testing.T) {
		scheduler := NewScheduler(&NoOpFlusher{}, WithDryRun(true))
		ac := &UdpAC{config: &Config{}, ipset: &bootIPSet{}, expirySched: scheduler}
		if err := ac.flushInheritedNHPSessions(); err == nil || !strings.Contains(err.Error(), "dry-run") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("injected failure", func(t *testing.T) {
		sentinel := errors.New("flush unavailable")
		ac := &UdpAC{bootSessionFlushFn: func(context.Context) error { return sentinel }}
		if err := ac.flushInheritedNHPSessions(); !errors.Is(err, sentinel) {
			t.Fatalf("error = %v", err)
		}
	})
}
