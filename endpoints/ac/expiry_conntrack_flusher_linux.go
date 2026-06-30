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
// **Follow-up** (filed as #2165 — to be created): replace with
// direct netlink (CTA_FILTER-based partial-tuple delete) for the
// throughput target. The FlowFlusher interface boundary keeps the
// swap mechanical; no caller-visible change.
//
// Until then, the bounded backpressure path in expiry_scheduler.go
// limits damage: if conntrack-delete sustained throughput is
// exceeded, the breaker opens and UdpAC fails closed at NHP-AOP
// admission. Better to fail loud than to silently late-flush.
//
// # Idempotency
//
// `conntrack -D` returns exit status 1 when no matching entries
// exist. The wrapper distinguishes ENOENT from real errors via
// stderr-text inspection — the kernel reports "0 flow entries have
// been deleted" on no-match, which we treat as success.
type ConntrackFlusher struct {
	// Per-call timeout comes from the scheduler-supplied context
	// (defaultFlushCallTimeout in expiry_scheduler.go); we don't
	// add a second wrapper here. A previous `timeout uint8` field
	// claimed "caps fork+exec stalls" but was never wired into the
	// exec.CommandContext call. Removed as dead code.
	binary string // resolved path to the `conntrack` binary
	// metricSkipped counts non-IPv4 keys no-op'd at Flush entry
	// (conntrack -D is IPv4-only — see Flush). Symmetric with
	// BpfFlusher.metricSkipped so the two flushers stay operationally
	// observable. This counter is CONFLATED — it cannot tell apart:
	//   - a benign scheduled-expiry v6 leak (the original intent), and
	//   - a v6 IMMEDIATE revoke: flushEntryNow's coarse RescheduleEarlier
	//     reschedules a revoked v6 key into this flusher, where it lands
	//     here too (#2794). That case is a real (declared out-of-scope
	//     until #2165 netlink) immediate-revocation gap, NOT a benign skip.
	// Because of that conflation the revocation path does NOT rely on this
	// counter: flushEntryNow ticks the dedicated MetricRevocationIPv6HardFail
	// for v6 revokes directly. So a non-zero reading here means EITHER a v6
	// revoke (cross-check MetricRevocationIPv6HardFail) OR — if that revoke
	// metric is flat — an upstream regression scheduling a v6 expiry key.
	metricSkipped atomic.Uint64
}

// NewConntrackFlusher constructs a flusher backed by the
// `conntrack` userspace tool. Returns an error if the binary is
// not installed (the AC's user_data.sh.tpl installs conntrack-tools
// in the iptables-mode setup; failure here means a malformed AMI).
//
// Logs the resolved conntrack-tools version at construction so
// AC-log diffing across AMI rebuilds reveals an unexpected version
// change before it bites the no-match stderr-substring classifier
// (see isConntrackNoEntries). Operationally-paired with the runbook
// note in docs/runbooks/l3-flush-breaker-recovery.md and tracked
// as a hard AMI-startup assertion in #2179
func NewConntrackFlusher() (*ConntrackFlusher, error) {
	bin, err := exec.LookPath("conntrack")
	if err != nil {
		return nil, fmt.Errorf("conntrack binary not found in PATH: %w", err)
	}
	if ver, vErr := readConntrackVersion(bin); vErr == nil {
		log.Info("[ConntrackFlusher] using conntrack at %s — %s", bin, ver)
	} else {
		// Soft-fail: a `--version` flake shouldn't block AC start.
		// The flusher itself works regardless; this is observability.
		log.Warning("[ConntrackFlusher] conntrack at %s — version probe failed: %v", bin, vErr)
	}
	return &ConntrackFlusher{binary: bin}, nil
}

// SkippedCount returns the number of non-IPv4 keys this flusher
// has no-op'd (the conntrack invocation is IPv4-only by design).
// This is the CONFLATED counter described on metricSkipped: a
// non-zero reading is a v6 immediate revoke (cross-check
// MetricRevocationIPv6HardFail, #2794) OR — if that revoke metric is
// flat — an upstream regression scheduling a v6 expiry key. Symmetric
// with BpfFlusher.SkippedCount for the metric publisher.
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

// Flush implements FlowFlusher. Issues `conntrack -D -s SRC -d DST
// --dport PORT -p PROTO` to remove all kernel conntrack entries
// matching the FlowKey's (src_ip, dst_ip, dst_port, proto) tuple.
// Source port is intentionally unconstrained — the kernel deletes
// every flow matching the partial tuple.
//
// CONTRACT: Returns nil on success OR on no-matching-flows
// (idempotent ENOENT no-op). msghandler.go's schedule-then-write
// reorder for #2168 relies on this — a scheduled flush against a
// never-written kernel entry (e.g., when the ipset.Add subsequently
// failed) MUST NOT bump FlushErr or trip the breaker. Logged at
// Debug only; see isConntrackNoEntries for the "0 flow entries
// have been deleted" detection. Returns a wrapped error on any
// other failure; the scheduler records this into the breaker.
func (f *ConntrackFlusher) Flush(ctx context.Context, key FlowKey) error {
	// IPv4-only. The conntrack invocation below doesn't pass
	// `-f ipv6`, so a non-IPv4-mapped key would produce a kernel-
	// call failure and trip the breaker on every fire. FlowKey
	// admits v6 by design (parseIPTo16 stores both families); the
	// constraint lives at the flusher boundary, matching the
	// BpfFlusher symmetric guard in expiry_bpf_flusher_linux.go.
	// This branch IS reachable for a v6 IMMEDIATE revoke: flushEntryNow's
	// coarse RescheduleEarlier pulls a revoked v6 key here (#2794). That
	// is a declared out-of-scope gap (v6 teardown needs the #2165 netlink
	// flusher), already surfaced loudly via MetricRevocationIPv6HardFail at
	// the revoke site — so here we just no-op (Warning, no breaker trip).
	// A v6 *expiry* key reaching here with the revoke metric flat instead
	// signals an upstream regression scheduling v6 expiries. metricSkipped
	// conflates the two; see its godoc.
	if !isIPv4Mapped(key.SrcIP) || !isIPv4Mapped(key.DstIP) {
		f.metricSkipped.Add(1)
		log.Warning("[ConntrackFlusher] non-IPv4 key %s reached IPv4-only conntrack flusher — v6 immediate revoke (declared out of scope until #2165; see MetricRevocationIPv6HardFail) or an upstream v6-expiry schedule leak (no-op'd; tracked in metricSkipped)", key)
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
	// and trip the L3 flush breaker
	// Eliminated entirely once #2165 swaps to netlink.
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
