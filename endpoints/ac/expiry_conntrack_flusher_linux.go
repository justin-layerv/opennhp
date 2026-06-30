//go:build linux

package ac

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// ConntrackFlusher tears down kernel conntrack entries matching a
// FlowKey. Used in FilterMode_IPTABLES, where ESTABLISHED flows
// otherwise bypass the ipset deny on entry expiry.
//
// # v1 implementation
//
// Shells out to `conntrack -D` per Flush. Same fork/exec pattern as
// the existing IPSet.Add path in nhp/utils/iptables.go (which also
// shells out per call). This is intentionally simple, intentionally
// correct, and intentionally slow at scale: per-call cost ~5-10 ms
// limits steady-state throughput to ~100-200 flushes/sec/worker.
// At 64 workers that's ~6-12k flushes/sec total — fine for
// defense-in-depth, NOT enough for the L3-only million-session
// target's 100k flushes/sec headroom.
//
// # Backends (#2165)
//
// Flush dispatches on the configured ConntrackBackend:
//
//   - BackendExec (default): the v1 fork+exec `conntrack -D` path
//     documented below. IPv4-only.
//   - BackendNetlink: direct NFNL_SUBSYS_CTNETLINK via a pool of
//     pre-warmed netlink sockets (expiry_conntrack_flusher_netlink_linux.go).
//     No fork, no userspace-tool dependency, no locale-fragile stderr
//     scrape, and IPv4 + IPv6. This is the throughput path — each delete
//     is a netlink syscall (~100µs) rather than a ~5-10 ms fork+exec —
//     and the IPv6 capability closes the iptables-mode immediate-teardown
//     gap (#2794/#2797). Opt-in until soak-validated per the rollout plan.
//
// The backend is internal to the Linux build; FlowFlusher and every
// caller, scheduler, and test are unchanged across the toggle.
//
// Until netlink is the default, the bounded backpressure path in
// expiry_scheduler.go limits damage: if conntrack-delete sustained
// throughput is exceeded, the breaker opens and UdpAC fails closed at
// NHP-AOP admission. Better to fail loud than to silently late-flush.
//
// # Idempotency
//
// Exec: `conntrack -D` returns exit status 1 when no matching entries
// exist. The wrapper distinguishes ENOENT from real errors via
// stderr-text inspection — the kernel reports "0 flow entries have
// been deleted" on no-match, which we treat as success. Netlink: a
// delete of an already-gone entry surfaces ENOENT, mapped to success
// (see isConntrackENOENT). Both honor the FlowFlusher idempotency
// contract the scheduler's breaker relies on.
type ConntrackFlusher struct {
	// backend selects exec vs netlink; see ConntrackBackend.
	backend ConntrackBackend

	// pool is the pre-warmed netlink socket pool; non-nil iff
	// backend == BackendNetlink. Owned by this flusher — closed by Close.
	pool *ctNetlinkPool

	// ctOps owns raw netlink dump/delete calls. The real implementation wraps
	// ctConn; tests replace it so retry/deadline policy is covered in ordinary
	// CI without CAP_NET_ADMIN.
	ctOps ctNetlinkOps

	// netlinkDeleted counts conntrack entries the netlink backend has
	// actually deleted (cumulative, across all Flush calls). Published as
	// the L3FlushConntrackDeleted gauge so the soak can confirm the netlink
	// path is tearing flows down (vs no-op'ing) and read its rate against
	// the throughput target. Zero on the exec backend.
	netlinkDeleted atomic.Uint64

	// netlinkSlowDumps counts Flush calls whose successful conntrack dump
	// attempt exceeded netlinkSlowDumpThreshold (cumulative). Retry/reopen
	// overhead is excluded so the L3FlushConntrackSlowDumps gauge remains a
	// table-size latency signal for the soak: a rising rate is the O(table)
	// per-key dump hitting the table-size knee the throughput follow-up
	// tracks, exactly the large-table regime the single-threaded ≤200µs
	// benchmark can't surface. Zero on the exec backend.
	netlinkSlowDumps atomic.Uint64

	// Per-call timeout comes from the scheduler-supplied context
	// (defaultFlushCallTimeout in expiry_scheduler.go); we don't
	// add a second wrapper here. A previous `timeout uint8` field
	// claimed "caps fork+exec stalls" but was never wired into the
	// exec.CommandContext call. Removed as dead code.
	binary string // resolved path to the `conntrack` binary (exec backend)
	// metricSkipped counts keys no-op'd at Flush entry before backend work:
	// exec backend non-IPv4 expiry skips (`conntrack -D` is IPv4-only — see
	// Flush), and netlink backend mixed-family FlowKey regressions. Symmetric
	// with BpfFlusher.metricSkipped so the flushers stay operationally
	// observable.
	//
	// This is the EXPIRY-skip counter: a v6 key reaching this IPv4-only flusher is
	// a benign scheduled-expiry v6 leak (the original intent — iptables/ipset admit
	// v6 flows, so a v6 allow-rule's flush fires here at its firewall deadline and
	// the kernel TTL closes the established flow). It is NOT conflated with v6
	// immediate revokes: the revoke path's coarse reschedule is IPv4-only (#2778
	// part 2), so a v6 revoke is surfaced on MetricRevocationIPv6HardFail (#2794),
	// not here. The full expiry-vs-revoke split — incl. the deferred-tick residual
	// (#2901) — lives in the flushEntryNow godoc / the QURL_V2_KEYED_IDENTITY.md
	// Filter-mode/IPv6 caveat; kept local here to avoid re-deriving it.
	metricSkipped atomic.Uint64
}

// NewConntrackFlusher constructs a flusher. With no options (or
// WithBackend(BackendExec)) it backs onto the `conntrack` userspace
// tool — the v1 default. WithBackend(BackendNetlink) opens a pool of
// NFNL_SUBSYS_CTNETLINK sockets instead.
//
// Construction is fail-closed in both backends (the L3-only enforcement
// contract: an AC that enabled L3 flush but can't flush must NOT come
// up silently late-flushing):
//
//   - exec: errors if the `conntrack` binary is not installed (the AC's
//     user_data.sh.tpl installs conntrack-tools in the iptables-mode
//     setup; failure here means a malformed AMI). The resolved version
//     is logged so AC-log diffing across AMI rebuilds reveals an
//     unexpected version change before it bites the no-match stderr
//     classifier (see isConntrackNoEntries). Paired with the runbook
//     note in docs/runbooks/l3-flush-breaker-recovery.md and tracked as
//     a hard AMI-startup assertion in #2179.
//   - netlink: errors if any pooled socket fails to open (no CAP_NET_ADMIN,
//     a netns issue, an unsupported kernel). The caller (Start via
//     newFlusherForFilterMode) treats this as fatal.
func NewConntrackFlusher(opts ...ConntrackFlusherOption) (*ConntrackFlusher, error) {
	cfg := resolveConntrackFlusherConfig(opts...)
	f := &ConntrackFlusher{backend: cfg.backend, ctOps: realCtNetlinkOps{}}

	switch cfg.backend {
	case BackendNetlink:
		pool, err := newCtNetlinkPool(cfg.poolSize)
		if err != nil {
			return nil, fmt.Errorf("conntrack netlink backend init: %w", err)
		}
		f.pool = pool
		log.Info("[ConntrackFlusher] using direct netlink (NFNL_SUBSYS_CTNETLINK) backend — pool=%d, IPv4+IPv6", cfg.poolSize)
	default: // BackendExec
		bin, err := exec.LookPath("conntrack")
		if err != nil {
			return nil, fmt.Errorf("conntrack binary not found in PATH: %w", err)
		}
		if ver, vErr := readConntrackVersion(bin); vErr == nil {
			log.Info("[ConntrackFlusher] using conntrack at %s — %s (exec backend, IPv4-only)", bin, ver)
		} else {
			// Soft-fail: a `--version` flake shouldn't block AC start.
			// The flusher itself works regardless; this is observability.
			log.Warning("[ConntrackFlusher] conntrack at %s — version probe failed: %v", bin, vErr)
		}
		f.binary = bin
	}
	return f, nil
}

// IsNetlinkBackend reports whether this flusher uses the direct netlink
// backend. Used only for netlink-specific metric gating; capability decisions
// should use HandlesIPv6.
func (f *ConntrackFlusher) IsNetlinkBackend() bool { return f.backend == BackendNetlink }

// HandlesIPv6 reports whether this flusher's coarse Flush tears down
// IPv6 conntrack entries. True only for the netlink backend — exec's
// `conntrack -D` is invoked without `-f ipv6` and is IPv4-only. The AC
// reads this at Start to decide whether the iptables-mode immediate-
// revocation path still has to raise the IPv6 hard-fail (#2794): when
// the coarse path is v6-capable, a v6 revoke's RescheduleEarlier→Flush
// actually tears the flow down, so no hard-fail is warranted.
func (f *ConntrackFlusher) HandlesIPv6() bool { return f.IsNetlinkBackend() }

// Close releases backend resources. Exec backend: no-op. Netlink
// backend: closes every pooled socket. Safe to call once after the
// scheduler has drained (no Flush in flight); idempotent on a nil pool.
func (f *ConntrackFlusher) Close() error {
	if f.pool != nil {
		return f.pool.Close()
	}
	return nil
}

// NetlinkDeletedCount returns the cumulative number of conntrack entries
// the netlink backend has deleted. Always 0 on the exec backend (which
// has no per-entry visibility). Read by the L3FlushConntrackDeleted gauge.
func (f *ConntrackFlusher) NetlinkDeletedCount() uint64 {
	return f.netlinkDeleted.Load()
}

// NetlinkSlowDumpCount returns the cumulative number of Flush calls whose
// conntrack dump exceeded netlinkSlowDumpThreshold. Always 0 on the exec
// backend. Read by the L3FlushConntrackSlowDumps gauge.
func (f *ConntrackFlusher) NetlinkSlowDumpCount() uint64 {
	return f.netlinkSlowDumps.Load()
}

// SkippedCount returns the number of keys this flusher no-op'd before backend
// work — exec backend non-IPv4 expiry skips plus netlink backend mixed-family
// FlowKey regressions. The exec count is the benign scheduled-expiry v6-leak
// count described on the metricSkipped godoc (NOT a failed-revoke signal; that
// is MetricRevocationIPv6HardFail). Symmetric with BpfFlusher.SkippedCount for
// the metric publisher.
func (f *ConntrackFlusher) SkippedCount() uint64 {
	return f.metricSkipped.Load()
}

// readConntrackVersion runs `conntrack --version` with a short
// timeout and returns the trimmed first line of output. Used only
// for observability — see the NewConntrackFlusher godoc.
func readConntrackVersion(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if first == "" {
		return "", errors.New("empty --version output")
	}
	return first, nil
}

// Flush implements FlowFlusher, dispatching to the configured backend.
//
// CONTRACT (both backends): Returns nil on success OR on no-matching-flows
// (idempotent ENOENT no-op). msghandler.go's schedule-then-write reorder
// for #2168 relies on this — a scheduled flush against a never-written
// kernel entry (e.g., when the ipset.Add subsequently failed) MUST NOT
// bump FlushErr or trip the breaker. Returns a wrapped error on any
// other failure; the scheduler records this into the breaker.
func (f *ConntrackFlusher) Flush(ctx context.Context, key FlowKey) error {
	if f.backend == BackendNetlink {
		return f.flushNetlink(ctx, key)
	}
	return f.flushExec(ctx, key)
}

// flushExec is the v1 BackendExec path. Issues `conntrack -D -s SRC -d
// DST --dport PORT -p PROTO` to remove all kernel conntrack entries
// matching the FlowKey's (src_ip, dst_ip, dst_port, proto) tuple.
// Source port is intentionally unconstrained — the kernel deletes
// every flow matching the partial tuple.
//
// See Flush for the idempotency contract; here no-match is detected via
// isConntrackNoEntries ("0 flow entries have been deleted") and logged
// at Debug.
func (f *ConntrackFlusher) flushExec(ctx context.Context, key FlowKey) error {
	// IPv4-only. The conntrack invocation below doesn't pass
	// `-f ipv6`, so a non-IPv4-mapped key would produce a kernel-
	// call failure and trip the breaker on every fire. FlowKey
	// admits v6 by design (parseIPTo16 stores both families); the
	// constraint lives at the flusher boundary, matching the
	// BpfFlusher symmetric guard in expiry_bpf_flusher_linux.go.
	// This is the exec backend; the #2165 netlink backend handles v6 instead of
	// skipping. flushEntryNow does not reschedule v6 immediate revokes into the
	// exec backend, so a v6 key reaching here is a scheduled-expiry leak (or an
	// upstream scheduling regression), not the revoke-skip signal. Immediate
	// v6 revokes under iptables+exec are surfaced on MetricRevocationIPv6HardFail
	// at the revoke site.
	if !isIPv4Mapped(key.SrcIP) || !isIPv4Mapped(key.DstIP) {
		f.metricSkipped.Add(1)
		log.Warning("[ConntrackFlusher] non-IPv4 key %s reached the IPv4-only exec conntrack flusher — benign v6 scheduled-expiry leak or upstream scheduling regression. No-op'd; flow self-closes at kernel TTL; tracked in metricSkipped", key)
		return nil
	}
	srcIP := key.SrcIPString()
	dstIP := key.DstIPString()

	args := []string{
		"-D",
		"-s", srcIP,
		"-d", dstIP,
	}

	// Port + protocol filters. Skip when proto/port are unspecified
	// (the FlowKey may legitimately omit them for some allow-rule
	// shapes; partial-tuple delete still does the right thing).
	switch key.Protocol {
	case FlowProtoTCP:
		args = append(args, "-p", "tcp")
		if key.DstPort != 0 {
			args = append(args, "--dport", strconv.Itoa(int(key.DstPort)))
		}
	case FlowProtoUDP:
		args = append(args, "-p", "udp")
		if key.DstPort != 0 {
			args = append(args, "--dport", strconv.Itoa(int(key.DstPort)))
		}
	case FlowProtoICMP:
		args = append(args, "-p", "icmp")
	case FlowProtoAny:
		// No proto filter — conntrack -D will match any.
	}

	cmd := exec.CommandContext(ctx, f.binary, args...)
	// Pin LC_ALL=C so the "0 flow entries have been deleted" stderr
	// string the no-match-success detection greps for stays in the C
	// locale. Without this, an AMI build with a localized LC_ALL
	// would silently reclassify every no-match flush as a real error
	// and trip the L3 flush breaker. Moot on the netlink backend (#2165),
	// which has no stderr to scrape — set l3FlushConntrackBackend=netlink.
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	// `conntrack -D` exits non-zero on "0 flow entries have been
	// deleted" (no match). The kernel-side flow may have already
	// been GC'd by netfilter before we got here — treat as success.
	outStr := string(out)
	if isConntrackNoEntries(err, outStr) {
		log.Debug("[ConntrackFlusher] no matching entries for %s (idempotent)", key)
		return nil
	}

	return fmt.Errorf("conntrack -D %s: %w (output: %s)",
		strings.Join(args, " "), err, strings.TrimSpace(outStr))
}

// isConntrackNoEntries returns true when `conntrack -D` failed
// solely because no entries matched the tuple. The userspace
// tool's exit-status convention here is unfortunate (non-zero on
// no-match) so we have to inspect stderr text.
//
// The tool emits "0 flow entries have been deleted" on no-match;
// any other stderr indicates a real failure (permission denied,
// invalid arg, kernel-side ENETDOWN, etc.).
func isConntrackNoEntries(err error, output string) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	if exitErr.ExitCode() != 1 {
		return false
	}
	// Anchor on the start-of-line wording rather than a free
	// substring scan: a real failure whose stderr happens to
	// contain "0 flow entries have been deleted" inside a
	// diagnostic paragraph (e.g., a kernel-side error mentioning
	// the count) would otherwise misclassify as success. The
	// conntrack tool emits this exact text as the SUMMARY line —
	// either at the start of the line or after a newline.
	const marker = "0 flow entries have been deleted"
	if strings.HasPrefix(output, marker) {
		return true
	}
	// Match the line-start form `\n<marker>` for multi-line output
	// (the tool prepends a header line on some versions).
	return strings.Contains(output, "\n"+marker)
}
