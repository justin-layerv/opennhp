//go:build linux

package ac

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

// enumerateKernelAllowRules dispatches to per-FilterMode
// implementations. iptables mode walks `ipset save defaultset`;
// eBPF mode walks the pinned BPF allow-rule maps via cilium/ebpf
// (see expiry_enumerate_ebpf_linux.go).
//
// Returns the number of entries scheduled and any error.
func (a *UdpAC) enumerateKernelAllowRules() (int, error) {
	switch a.config.FilterMode {
	case FilterMode_IPTABLES:
		// Walk both IPv4 and IPv6 session-tied sets. Tempset is
		// intentionally NOT enumerated — those entries are
		// auxiliary scan-tolerance rules (per
		// HandleAccessControl's PASS_KNOCKIP_WITH_RANGE branch)
		// and aren't session-tied; the scheduler's scope is
		// per-session tuples only.
		totalV4, err := a.enumerateIpsetSet(utils.DefaultSet)
		if err != nil {
			return totalV4, fmt.Errorf("ipset %s: %w", utils.DefaultSet, err)
		}
		totalV6, err := a.enumerateIpsetSet(utils.DefaultSetV6)
		if err != nil {
			// Only swallow the specific "set doesn't exist" case —
			// the V6 set is genuinely absent on IPv4-only
			// deployments. Real failures (permission denied,
			// ENETDOWN, ctx timeout) MUST fail loud so boot
			// doesn't silently proceed with a stale scheduler for
			// v6 flows
			if errors.Is(err, errIpsetSetNotFound) {
				log.Info("[L3FlushSched] %s does not exist (IPv4-only deployment); skipping v6 enumeration",
					utils.DefaultSetV6)
				return totalV4, nil
			}
			return totalV4, fmt.Errorf("ipset %s: %w", utils.DefaultSetV6, err)
		}
		return totalV4 + totalV6, nil
	case FilterMode_EBPFXDP:
		return a.enumerateBpfAllowRules()
	default:
		return 0, fmt.Errorf("unsupported FilterMode %d", a.config.FilterMode)
	}
}

// enumerateIpsetSet runs `ipset save <name>` and Schedules a
// flush for each parsed entry, using the entry's remaining
// timeout as the deadline.
//
// Streaming parse via stdout pipe so memory stays bounded at
// large set sizes (1M+ entries → multi-MB output).
// errIpsetSetNotFound is returned by enumerateIpsetSet when the
// requested set does not exist on this host (the most common case
// is the V6 set on an IPv4-only deployment). Callers can errors.Is
// for this to distinguish "set absent — expected" from real
// failures (permission denied, ENETDOWN, ctx timeout) which should
// fail loud
var errIpsetSetNotFound = errors.New("ipset set not found")

// maxCorruptIpsetLinesBeforeFail is the per-`ipset save` ceiling
// on undecodable lines (parseIpsetSaveLine !ok OR
// flowKeyFromIpsetEntry returning an error) before
// enumerateIpsetSet abandons the rest of the set and returns
// loud. Boundary semantics: this value is the TOLERATED count;
// the (N+1)th undecodable line trips the fail-loud branch
// (check is `parseErrors > maxCorruptIpsetLinesBeforeFail`). A boot enumerates BOTH defaultset and defaultsetv6, so
// the per-boot tolerance is 2× this value across the two calls
// (each set is independently corrupt-able). At the 1M-entry
// boot-enum target a one-off ipset format drift shouldn't
// fail-close the AC — but systemic corruption MUST trip the
// fail-loud contract before boot proceeds with a stale
// scheduler. 10 is comfortably above the empirical noise floor
// (kernel-emitted lines are deterministic; the only realistic
// source of single-line damage is racing `ipset save` against
// an in-flight `ipset add` that flushes mid-stream). Tracked
// via MetricL3FlushIpsetParseError dashboards.
const maxCorruptIpsetLinesBeforeFail = 10

// errIpsetCorruptLineFloodExceeded signals the per-call
// parse-error ceiling was exceeded. Distinct sentinel so callers
// (and tests) can errors.Is for the systemic-corruption case
// without locale-matching log strings.
var errIpsetCorruptLineFloodExceeded = errors.New("ipset save: parse-error ceiling exceeded")

func (a *UdpAC) enumerateIpsetSet(setName string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bootEnumerationDeadline)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ipset", "save", setName)
	// Pin LC_ALL=C so the stderr-text detection of "set not found"
	// stays in the C locale (same defense as ConntrackFlusher; cr
	// fence: round 3 finding 3 generalized).
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("ipset save stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("ipset save start: %w", err)
	}

	now := time.Now()
	count, err := scanIpsetSave(stdout, ipsetScanCallbacks{
		onSchedule: func(key FlowKey, remaining time.Duration) {
			a.expirySched.Schedule(key, now.Add(remaining))
		},
		onParseError: func() {
			a.incrMetric(MetricL3FlushIpsetParseError)
		},
	})
	if err != nil {
		// Fail-loud paths (parse-error flood + scanner error) all
		// abandon the rest of the child's output. SIGKILL the
		// child via ctx cancel BEFORE cmd.Wait() — without this,
		// the child keeps writing to a stdout pipe nobody reads;
		// once the pipe buffer (~64 KiB) fills, the child blocks
		// on write(2) and cmd.Wait() blocks with it until
		// bootEnumerationDeadline, turning fast-fail into
		// slow-fail. context.CancelFunc is idempotent so the
		// deferred cancel() above remains correct.
		cancel()
		_ = cmd.Wait()
		if errors.Is(err, errIpsetCorruptLineFloodExceeded) {
			// Inner err already carries the sentinel + "N
			// undecodable lines" detail; we only add the
			// valid-entries-scheduled-before-flood count for
			// triage. setName is added by the outer caller in
			// enumerateKernelAllowRules, so omitting it here
			// avoids the "ipset save defaultset: ipset save: ...
			// defaultset after N" double-wrap.
			return count, fmt.Errorf("%w (after %d valid entries scheduled)", err, count)
		}
		// Transport-error fall-through: scanner.Err returns plain
		// errors without setName context. The outer
		// enumerateKernelAllowRules wraps with "ipset %s: %w", so
		// no further setName context is needed here.
		return count, err
	}
	if err := cmd.Wait(); err != nil {
		// Distinguish "set doesn't exist" (expected on IPv4-only
		// deployments for the V6 set) from real failures (permission
		// denied, kernel ENETDOWN, ctx timeout). Only the former
		// should be silently swallowed by the caller; the rest must
		// fail loud or boot proceeds with a stale scheduler for those
		// flows
		stderrText := stderr.String()
		if isIpsetSetNotFoundStderr(stderrText, setName) {
			return count, fmt.Errorf("%w: %s", errIpsetSetNotFound, stderrText)
		}
		return count, fmt.Errorf("ipset save wait: %w (stderr: %s)", err, stderrText)
	}
	return count, nil
}

// isDecorativeIpsetSaveLine reports whether a line is one of the
// known non-add shapes `ipset save` emits — set header, comment,
// blank — that the scanner should skip silently. Anything outside
// this allowlist is treated as a potential add record and reaches
// parseIpsetSaveLine, where !ok bumps the corruption counter.
//
// Allowlist (NOT blacklist) is deliberate: truncated mid-emit
// output or format drift can produce a non-"add"-prefixed garbage
// line, and the corruption counter exists precisely to catch
// that. A blacklist that skipped everything except "add" would
// silently filter the case the metric is meant to surface.
//
// Verified against ipset 7.x as installed by user_data.sh.tpl on
// the AC AMI (the production target). Other producers — `flush`,
// `swap`, `destroy` etc. — are NOT in the allowlist by design;
// `ipset save` itself doesn't emit them, and treating them as
// corruption surfaces an ipset-tools upgrade that changes the
// dump format before the fleet absorbs the regression silently.
func isDecorativeIpsetSaveLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	if strings.HasPrefix(trimmed, "#") {
		return true
	}
	if strings.HasPrefix(trimmed, "create ") {
		return true
	}
	return false
}

// ipsetScanCallbacks bundles the side-effect callbacks
// scanIpsetSave invokes. Extracted so unit tests can pass fakes
// for the schedule and metric-bump paths and exercise the
// fail-loud contract against a strings.NewReader without
// privileged Linux+root infra.
//
// CONTRACT: both onSchedule and onParseError MUST be non-nil.
// scanIpsetSave fails fast with an error on a nil callback rather
// than dereferencing it mid-stream — see
// TestScanIpsetSave_RequiresBothCallbacks for the fence.
type ipsetScanCallbacks struct {
	onSchedule   func(key FlowKey, remaining time.Duration)
	onParseError func()
}

// scanIpsetSave streams ipset-save output, parses each line, and
// dispatches valid entries via cb.onSchedule. Returns the number
// of entries scheduled and one of:
//   - nil on clean EOF
//   - errIpsetCorruptLineFloodExceeded wrapped, when undecodable
//     lines exceed maxCorruptIpsetLinesBeforeFail (fail-loud)
//   - a wrapped scanner.Err() on transport-level failure
//
// Pure on rdr — no exec, no UdpAC dependency — so the
// fail-loud contract on systemic ipset-format drift is unit-testable
// without privileged Linux+root infra.
//
// CONTRACT for exec-based callers: a non-nil return abandons the
// rest of the child's output. The caller MUST cancel the child's
// ctx and call cmd.Wait() to avoid the pipe-buffer-fills →
// child-blocked-on-write → cmd.Wait()-blocked-on-deadline failure
// mode. enumerateIpsetSet does this via killChild() + _ = cmd.Wait();
// new callers must follow the same discipline.
func scanIpsetSave(rdr io.Reader, cb ipsetScanCallbacks) (int, error) {
	// Fail-fast at the top so a misconfigured caller gets a clear
	// error immediately rather than dereferencing a nil callback
	// on the first matching mid-stream event. Both callbacks are
	// required per the ipsetScanCallbacks CONTRACT godoc.
	if cb.onSchedule == nil || cb.onParseError == nil {
		return 0, errors.New("scanIpsetSave: both onSchedule and onParseError callbacks are required")
	}
	count := 0
	parseErrors := 0
	scanner := bufio.NewScanner(rdr)
	// `ipset save` lines are short (~80 chars) but defensively
	// size the buffer to 1 MiB to future-proof against a single
	// oversized entry. Without this, bufio.Scanner's default 64
	// KiB cap would cause scanner.Scan() to error and we'd lose
	// the rest of the stream.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// Skip KNOWN-decorative lines (create header, comments,
		// blanks) silently. An allowlist of known prefixes — NOT a
		// blacklist that filters anything except "add" — so a truly
		// corrupt line (truncated mid-emit, format drift) that
		// happens not to start with "add" still reaches
		// parseIpsetSaveLine and trips the corruption counter.
		// Without this gate, the always-present `create defaultset
		// ...` header would inflate the parse-error counter on
		// every healthy enumeration.
		if isDecorativeIpsetSaveLine(line) {
			continue
		}
		entry, ok := parseIpsetSaveLine(line)
		if !ok {
			parseErrors++
			cb.onParseError()
			// Symmetric Debug log with the flowKeyFromIpsetEntry
			// branch below — an alarm on
			// MetricL3FlushIpsetParseError needs a corresponding
			// log line to be actionable.
			log.Debug("[L3FlushSched] skipping unparseable ipset save line %q", line)
			if parseErrors > maxCorruptIpsetLinesBeforeFail {
				return count, fmt.Errorf("%w (%d undecodable lines; most recent: parser rejected %q)",
					errIpsetCorruptLineFloodExceeded, parseErrors, line)
			}
			continue
		}
		key, err := flowKeyFromIpsetEntry(entry)
		if err != nil {
			parseErrors++
			cb.onParseError()
			log.Debug("[L3FlushSched] skipping unparseable ipset entry %q: %v", line, err)
			if parseErrors > maxCorruptIpsetLinesBeforeFail {
				return count, fmt.Errorf("%w (%d undecodable lines; most recent: %w)",
					errIpsetCorruptLineFloodExceeded, parseErrors, err)
			}
			continue
		}
		// Past-timeout filter — symmetric with the BPF boot-enum
		// path. parseIpsetSaveLine accepts `timeout 0` and returns
		// remaining=0; this filter drops those silently. Reaches
		// nonzero traffic at the 1M-entry / 10-20s save-stream
		// scale because naturally-expiring entries hit timeout=0
		// mid-stream. The kernel-side ipset will GC the entry on
		// next match; scheduling a no-op flush against it just
		// spends ConntrackFlusher's ~10ms exec budget on a
		// known-zero-result call.
		if entry.remaining <= 0 {
			continue
		}
		cb.onSchedule(key, entry.remaining)
		count++
	}
	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("ipset save scan: %w", err)
	}
	return count, nil
}

// isIpsetSetNotFoundStderr matches the C-locale stderr text ipset
// produces when the requested set doesn't exist. Verified against
// ipset 7.x; the message has been stable since at least 6.x.
//
// The set-name parameter narrows the classifier: ipset can also
// emit "does not exist" for element-level errors during a save
// with a stale userspace cache (per ipset/lib/data.c) which we do
// NOT want to swallow as "set absent." Requiring the set name in
// the stderr text means an element-not-found never reclassifies
// to the whole-set-absent branch.
//
// The substring permits both observed wordings — "The set with
// the given name does not exist" (ipset 7.x) and "Set <name>
// does not exist" (6.x and some 7.x variants). The
// "set not in cache" branch keeps stale-cache misses classified
// here too (those ARE whole-set-absent from the perspective of
// the userspace tool's view).
func isIpsetSetNotFoundStderr(s, setName string) bool {
	hasSetName := setName != "" && strings.Contains(s, setName)
	switch {
	case strings.Contains(s, "set not in cache"):
		return true
	case strings.Contains(s, "set with the given name does not exist"):
		// The generic 7.x phrasing doesn't quote the set name; the
		// caller has the name in scope and we trust the call chain.
		return true
	case strings.Contains(s, "does not exist") && hasSetName:
		// Name-anchored "Set <name> does not exist" — safe.
		return true
	}
	return false
}

// ipsetEntry is a parsed `ipset save` line. Only `add` lines for
// our target set produce a non-zero result; `create` / `add` of
// other sets / comments are filtered.
type ipsetEntry struct {
	srcIP     string
	dstIP     string
	port      int
	proto     FlowProto // FlowProtoAny if line carries no proto prefix (defaultset legacy = TCP)
	remaining time.Duration
}

// parseIpsetSaveLine extracts the (src, port, dst, proto,
// remaining_timeout) from one `ipset save` output line. Returns
// (zero, false) on lines we don't care about (comments, create
// lines, port-range entries that are tempset shapes, etc.).
//
// Recognized add-line shapes (mirrors the formats written by
// HandleAccessControl):
//
//	add defaultset 192.0.2.1,443,192.0.2.2 timeout 285
//	add defaultset 192.0.2.1,tcp:443,192.0.2.2 timeout 285
//	add defaultset 192.0.2.1,udp:53,192.0.2.2 timeout 100
//	add defaultset 192.0.2.1,icmp:8/0,192.0.2.2 timeout 50
//
// Rejected (return false): port-range entries (1-65535), missing
// timeout (these are tempset/permanent which we don't schedule),
// negative timeout, non-add lines.
//
// Accepted but with remaining=0: `timeout 0` lines (naturally-
// expiring entries observed mid-`ipset save`). Callers MUST
// filter `entry.remaining <= 0` to drop these; scheduling a
// flush against an entry the kernel is about to GC would just
// burn the worker pool on ENOENT-noop calls. scanIpsetSave is
// the only caller and does this correctly.
func parseIpsetSaveLine(line string) (ipsetEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return ipsetEntry{}, false
	}
	if fields[0] != "add" {
		return ipsetEntry{}, false
	}
	// fields[1] = setName, fields[2] = "srcIP,port_or_proto:port,dstIP"
	// Today's set is `nocomment`, so timeout always lands at
	// fields[3]/fields[4]. Walking the trailing fields for the
	// "timeout" token (rather than indexing) keeps the parser
	// correct if ipset 7.x's `comment` flag is ever enabled on the
	// set — ipset would then emit `comment "..." timeout N` (or the
	// reverse), and a future config change to enable comment
	// shouldn't silently flip every line into the "no timeout =
	// skip" branch
	timeoutIdx := -1
	for i := 3; i < len(fields)-1; i++ {
		if fields[i] == "timeout" {
			timeoutIdx = i
			break
		}
	}
	if timeoutIdx < 0 {
		return ipsetEntry{}, false
	}
	timeoutSec, err := strconv.Atoi(fields[timeoutIdx+1])
	if err != nil {
		return ipsetEntry{}, false
	}
	// timeout 0 is accepted at the parser layer (returns ok with
	// remaining=0) so the downstream `entry.remaining <= 0` filter
	// in scanIpsetSave can drop it silently. Rejecting here would
	// route the line through the corruption-counter path —
	// problematic because at the 1M-entry / 10-20s save-stream
	// scale, naturally-expiring entries can hit timeout=0
	// mid-stream and would otherwise trip
	// errIpsetCorruptLineFloodExceeded on a healthy boot.
	if timeoutSec < 0 {
		return ipsetEntry{}, false
	}

	tuple := fields[2]
	parts := strings.Split(tuple, ",")
	if len(parts) != 3 {
		return ipsetEntry{}, false
	}
	srcIP, portTok, dstIP := parts[0], parts[1], parts[2]
	if strings.Contains(portTok, "-") {
		// Port range → tempset shape, not session-tied.
		return ipsetEntry{}, false
	}

	// Port-token shapes:
	//   "443"         → TCP (defaultset legacy, no prefix)
	//   "tcp:443"
	//   "udp:53"
	//   "icmp:8/0"
	var proto FlowProto
	var port int
	if colon := strings.Index(portTok, ":"); colon >= 0 {
		switch portTok[:colon] {
		case "tcp":
			proto = FlowProtoTCP
		case "udp":
			proto = FlowProtoUDP
		case "icmp":
			proto = FlowProtoICMP
			// icmp:8/0 has no port we care about
			return ipsetEntry{
				srcIP:     srcIP,
				dstIP:     dstIP,
				port:      0,
				proto:     proto,
				remaining: time.Duration(timeoutSec) * time.Second,
			}, true
		default:
			return ipsetEntry{}, false
		}
		port, err = strconv.Atoi(portTok[colon+1:])
		if err != nil {
			return ipsetEntry{}, false
		}
	} else {
		port, err = strconv.Atoi(portTok)
		if err != nil {
			return ipsetEntry{}, false
		}
		// Bare port (no `tcp:`/`udp:` prefix) is the defaultset
		// legacy write shape — classified as TCP. Debug-log so a
		// future write-path format drift (e.g., dropping the bare-
		// port form entirely) is observable in AC startup logs
		// without needing a parser change. Counter-side observability
		// is tracked in #2173 (item 11: bare-port write-site
		// assertion).
		log.Debug("[L3FlushSched] ipset bare-port entry %s,%d,%s classified as TCP (defaultset legacy shape)", srcIP, port, dstIP)
		proto = FlowProtoTCP
	}

	return ipsetEntry{
		srcIP:     srcIP,
		dstIP:     dstIP,
		port:      port,
		proto:     proto,
		remaining: time.Duration(timeoutSec) * time.Second,
	}, true
}

// flowKeyFromIpsetEntry constructs the scheduler's FlowKey from
// the parsed ipset entry. Validates IP shapes via MakeFlowKey.
func flowKeyFromIpsetEntry(e ipsetEntry) (FlowKey, error) {
	// Validate the IPs parse cleanly before MakeFlowKey rejects
	// them — gives a clearer error message at debug log time.
	if net.ParseIP(e.srcIP) == nil {
		return FlowKey{}, fmt.Errorf("invalid src IP %q", e.srcIP)
	}
	if net.ParseIP(e.dstIP) == nil {
		return FlowKey{}, fmt.Errorf("invalid dst IP %q", e.dstIP)
	}
	return MakeFlowKey(e.srcIP, e.dstIP, e.port, e.proto)
}
