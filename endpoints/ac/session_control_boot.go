package ac

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/OpenNHP/opennhp/nhp/utils"
	utilebpf "github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

type ipsetRunner interface {
	Run(context.Context, ...string) (string, error)
}

// flushInheritedNHPSessions is the boot-ready boundary. It enumerates all
// session-tied allow rules, tears down established flow state, removes the
// allow rules, and verifies completion before NHP_AOL can advertise readiness.
// Tests may inject bootSessionFlushFn, but production never treats a missing
// scheduler or dry-run flusher as a successful flush.
func (a *UdpAC) flushInheritedNHPSessions() error {
	if a.bootSessionFlushFn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), bootEnumerationDeadline)
		defer cancel()
		return a.bootSessionFlushFn(ctx)
	}
	if a.expirySched == nil {
		return errors.New("session-control boot flush requires L3 flush-on-expiry")
	}
	if a.expirySched.dryRun.Load() {
		return errors.New("session-control boot flush cannot run with L3 flush dry-run enabled")
	}
	if err := a.enumerateAndScheduleFlushes(); err != nil {
		return err
	}
	keys := a.expirySched.SnapshotKeys()
	ctx, cancel := context.WithTimeout(context.Background(), bootEnumerationDeadline)
	defer cancel()

	// First remove established state for the inherited tuple while the
	// enumerated key is still available. eBPF/XDP needs its full conntrack
	// map cleanup before the coarse allow-rule delete; iptables gets a second
	// pass after ipset flush to close the narrow re-creation interval.
	for _, key := range keys {
		if err := a.flushInheritedConntrack(ctx, key); err != nil {
			return fmt.Errorf("flush inherited conntrack %s: %w", key, err)
		}
		if err := a.expirySched.flusher.Flush(ctx, key); err != nil {
			return fmt.Errorf("flush inherited allow/flow rule %s: %w", key, err)
		}
	}
	if err := a.flushInheritedIPSets(ctx); err != nil {
		return err
	}
	if a.config != nil && a.config.FilterMode == FilterMode_IPTABLES {
		for _, key := range keys {
			if err := a.expirySched.flusher.Flush(ctx, key); err != nil {
				return fmt.Errorf("verify inherited conntrack teardown %s: %w", key, err)
			}
		}
	}
	for _, key := range keys {
		a.expirySched.Cancel(key)
	}
	if remaining := a.expirySched.EntryCount(); remaining != 0 {
		return fmt.Errorf("session-control boot flush left %d scheduled entries", remaining)
	}
	return nil
}

func (a *UdpAC) flushInheritedIPSets(ctx context.Context) error {
	runner, ok := a.ipset.(ipsetRunner)
	if !ok || runner == nil {
		return errors.New("session-control boot flush requires an ipset runner")
	}
	names, err := runner.Run(ctx, "list", "-n")
	if err != nil {
		return fmt.Errorf("list ipsets before boot flush: %w", err)
	}
	present := make(map[string]bool)
	for _, name := range strings.Fields(names) {
		present[name] = true
	}
	for _, setName := range []string{utils.DefaultSet, utils.DefaultSetV6} {
		if !present[setName] {
			continue
		}
		if _, err := runner.Run(ctx, "flush", setName); err != nil {
			return fmt.Errorf("flush inherited ipset %s: %w", setName, err)
		}
	}
	return nil
}

func (a *UdpAC) flushInheritedConntrack(ctx context.Context, key FlowKey) error {
	if a.config != nil && a.config.FilterMode == FilterMode_IPTABLES {
		if !isFlowKeyIPv4(key) && !a.coarseConntrackHandlesV6.Load() {
			return errors.New("IPv6 inherited flow requires the netlink conntrack backend")
		}
		return nil
	}
	if a.surgicalConnFlush == nil {
		return nil
	}
	proto, ok := key.Protocol.ianaL4Proto()
	if !ok {
		return nil
	}
	if isFlowKeyIPv4(key) {
		if a.enumerateConnSrcPorts == nil {
			return errors.New("IPv4 conntrack enumerator is not wired")
		}
		ports, err := a.enumerateConnSrcPorts(key.SrcIPString(), key.DstIPString(), proto, key.DstPort)
		if errors.Is(err, utilebpf.ErrConnTrackMapNotPinned) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, port := range ports {
			if err := a.surgicalConnFlush(ctx, ConnFlowKey{Flow: key, SrcPort: port}); err != nil {
				return err
			}
		}
		return nil
	}
	if a.enumerateConnSrcPortsV6 == nil ||
		(a.surgicalConnFlushBatchV6 == nil && a.surgicalConnFlushV6 == nil) {
		return errors.New("IPv6 conntrack teardown is not wired")
	}
	ports, err := a.enumerateConnSrcPortsV6(key.SrcIPString(), key.DstIPString(), proto, key.DstPort)
	if errors.Is(err, utilebpf.ErrConnTrackMapNotPinned) {
		return nil
	}
	if err != nil {
		return err
	}
	if a.surgicalConnFlushBatchV6 != nil {
		results := a.surgicalConnFlushBatchV6(ctx, key, ports)
		if len(results) != len(ports) {
			return fmt.Errorf("IPv6 conntrack batch returned %d results for %d ports", len(results), len(ports))
		}
		for _, err := range results {
			if err != nil {
				return err
			}
		}
		return nil
	}
	for _, port := range ports {
		if err := a.surgicalConnFlushV6(ctx, ConnFlowKey{Flow: key, SrcPort: port}); err != nil {
			return err
		}
	}
	return nil
}
