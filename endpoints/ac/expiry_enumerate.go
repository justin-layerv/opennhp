package ac

import (
	"fmt"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// enumerateAndScheduleFlushes walks kernel allow-rule state at AC
// startup and Schedules a flush for each entry it finds. Called
// synchronously from UdpAC.Start() AFTER the scheduler is
// constructed but BEFORE the AC begins accepting NHP-AOPs.
//
// # Why synchronous + pre-traffic
//
// Under the L3-only enforcement contract, an AC restart that loses
// scheduler state but inherits kernel allow-rules from the
// previous process is a real correctness gap: those entries will
// expire naturally (kernel ipset / BPF map TTL) but no scheduler
// will fire to delete the conntrack / conn_track on existing
// flows. Existing TCP connections survive past their session end.
//
// To close the gap, the scheduler MUST learn every live kernel
// allow-rule at startup with its REMAINING TIMEOUT, so its later
// fire matches the kernel's natural expiry. We don't lose any
// entries; we don't double-flush; we don't admit traffic until
// the index is hot.
//
// # Failure mode
//
// If enumeration fails (ipset / BPF map read error), the AC
// startup returns the error. Better to fail closed at boot than
// admit traffic with a stale scheduler.
//
// # Top-level deadline
//
// bootEnumerationDeadline bounds the entire enumeration: a hung
// `ipset save` (rare but seen under runaway-tail conntrack flap) or
// a stalled cilium/ebpf iterator (no per-call timeout) would
// otherwise extend AC boot indefinitely. The mode-specific helpers
// observe this deadline
//
// Empirical anchoring: `ipset save`
// streams at ~50k-100k entries/sec on the AC's c5.large class;
// 1M entries → ~10-20s. 60s gives ~3-6× headroom for a paged-out
// kernel or contended I/O. An operator hitting this on a real
// million-session AC restart should re-check ipset kernel-table
// health (`nf_conntrack_count`, `ipset list defaultset | wc -l`)
// before raising the bound — the deadline is a "kernel state is
// pathological" signal, not a routine-tuning knob.
const bootEnumerationDeadline = 60 * time.Second

func (a *UdpAC) enumerateAndScheduleFlushes() error {
	if a.expirySched == nil {
		// Feature disabled — nothing to enumerate.
		return nil
	}
	start := time.Now()
	enumerate := a.enumerateFn
	if enumerate == nil {
		enumerate = a.enumerateKernelAllowRules
	}
	count, err := enumerate()
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("L3 flush boot enumeration failed after %s: %w", elapsed, err)
	}
	// Tightened to 0.8× deadline: both the iptables and BPF paths fail
	// hard on a deadline breach (exec.CommandContext + per-4096
	// iteration check). A successful return that nonetheless approaches
	// the bound is the actionable signal — investigate kernel-table
	// health before raising the constant. Post-deadline-on-success was
	// unreachable on the kernel-side budget anyway
	warnThreshold := bootEnumerationDeadline * 4 / 5
	if elapsed > warnThreshold {
		// Grep `[L3FlushSched] enumerate` for the per-map elapsed
		// breakdown emitted by enumerateBpfAllowRules (and the
		// per-set ipset_save elapsed in enumerateIpset*) — those
		// surface which subset of the shared aggregate deadline
		// burned through
		log.Warning("[L3FlushSched] boot enumeration completed near the deadline: %s > %s (%d entries; grep `[L3FlushSched] enumerate` for per-map breakdown and investigate kernel-table health if this trends up)", elapsed, warnThreshold, count)
	}
	log.Info("[L3FlushSched] boot enumeration: scheduled %d kernel allow-rules in %s",
		count, elapsed)
	return nil
}
