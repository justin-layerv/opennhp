package server

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// UDP receive-buffer tuning for the NHP knock listen socket (#1159).
//
// The default kernel SO_RCVBUF on Linux is ~208 KB, which the kernel
// fills quickly under a sustained UDP flood. Once full, the kernel
// drops *incoming* packets uniformly — including legitimate knocks —
// which gives the attacker a free amplifier on collateral damage:
// every dropped legitimate knock means the operator's customers see
// auth timeouts before iptables, the rate limiter, or any cookie
// challenge runs.
//
// Raising SO_RCVBUF to 8 MiB gives the kernel a few hundred
// milliseconds of headroom to absorb spikes between scheduler ticks
// of the NHP receive goroutine. It does not stop the flood — that's
// the job of the iptables global cap (also #1159) and the per-IP
// limiter — but it raises the floor on legitimate-packet survival.
//
// Operator gotcha: SO_RCVBUF is silently clamped to
// net.core.rmem_max. setsockopt returns success and Go reports no
// error when the cap is hit — the only way to learn the actual size
// is getsockopt. user_data raises rmem_max via /etc/sysctl.d before
// the server starts; `verifyUDPRecvBuffer` below cross-checks the
// effective size after SetReadBuffer and logs a Warning if the
// kernel clamped it. Production stays serviceable either way (8 MiB
// vs 208 KiB still helps), but the warning is the actionable
// signal that the sysctl drop-in is missing or misordered.
const (
	// DefaultUDPRecvBufferBytes is the target SO_RCVBUF size for the
	// NHP knock listen socket. 8 MiB matches the sysctl drop-in
	// shipped in terraform/modules/compute/user_data.sh.tpl. Change
	// both together; the verify step below makes the asymmetry
	// loud at boot if they drift.
	DefaultUDPRecvBufferBytes = 8 * 1024 * 1024

	// UDPRecvBufferEnvVar overrides the target size at runtime
	// without a code change. Operators tuning a single instance
	// for a specific load test can bump this; the default covers
	// the common case.
	UDPRecvBufferEnvVar = "NHP_UDP_RECV_BUFFER_BYTES"
)

// parseUDPRecvBufferSize decodes the override env var. An empty or
// unset value yields DefaultUDPRecvBufferBytes; any non-positive or
// non-numeric value is an error so an operator typo cannot silently
// leave the socket at the kernel default. Extracted for unit tests.
//
// Surrounding whitespace is trimmed so a stray newline from a heredoc
// or a copy-pasted env file doesn't flip a valid number into a parse
// error and fail-close the boot path.
func parseUDPRecvBufferSize(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultUDPRecvBufferBytes, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q: %w", UDPRecvBufferEnvVar, raw, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s: must be positive, got %d", UDPRecvBufferEnvVar, n)
	}
	return n, nil
}

// errUDPRecvBufferClamped is returned by verifyUDPRecvBuffer when
// the kernel silently capped SO_RCVBUF below the requested target.
// Callers log + continue; the socket is still functional, just at
// a smaller buffer than intended.
var errUDPRecvBufferClamped = errors.New("kernel clamped SO_RCVBUF below target")

// tuneUDPRecvBuffer sets SO_RCVBUF to target on conn, then verifies
// the effective size and emits the boot-log line that operators rely
// on. Non-fatal across the board: every failure path logs and
// returns so the server stays in rotation. Caller passes the parsed
// target (parseUDPRecvBufferSize handles env-var validation).
func tuneUDPRecvBuffer(conn *net.UDPConn, target int) {
	if err := conn.SetReadBuffer(target); err != nil {
		log.Warning("[Server] SetReadBuffer(%d) failed: %v (continuing with kernel default)", target, err)
		return
	}
	effective, err := verifyUDPRecvBuffer(conn, target)
	if err == nil {
		// On linux the kernel doubles SO_RCVBUF internally, so effective
		// is 2× target on success. Other unices return target as-is —
		// don't print the linux-only suffix where it's not true. The
		// rule itself lives near clampThreshold, not in the log line.
		if runtime.GOOS == "linux" {
			log.Info("[Server] SO_RCVBUF set: requested %d bytes, effective %d bytes (linux kernel-doubled)", target, effective)
		} else {
			log.Info("[Server] SO_RCVBUF set: requested %d bytes, effective %d bytes", target, effective)
		}
		return
	}
	if errors.Is(err, errUDPRecvBufferClamped) {
		log.Warning("[Server] SO_RCVBUF clamped: requested %d bytes, effective %d bytes — raise net.core.rmem_max (see #1159)",
			target, effective)
		return
	}
	log.Warning("[Server] SO_RCVBUF readback failed: %v (continuing; buffer is set but unverified)", err)
}

// verifyUDPRecvBuffer compares the effective SO_RCVBUF (post-set)
// against the requested target. The Linux kernel internally tracks
// SO_RCVBUF as 2× the userspace value (it splits the buffer between
// data and bookkeeping), so getsockopt returns 2× whatever was set —
// and 2× whatever the rmem_max cap clamped the request to. macOS
// and other unices return the requested size directly with no
// doubling; the threshold below adapts at runtime so a successful
// 8-MiB SetReadBuffer on a developer Mac doesn't false-positive as
// "clamped." Production is Linux, where the doubling is the canonical
// signal that rmem_max is sufficient.
//
// The function mutates nothing. It returns the effective size and
// errUDPRecvBufferClamped when clamping is detected; the caller
// owns the log line so the boot path stays single-source-of-truth
// for operator-facing strings.
func verifyUDPRecvBuffer(conn *net.UDPConn, target int) (effective int, err error) {
	rawConn, rcErr := conn.SyscallConn()
	if rcErr != nil {
		return 0, fmt.Errorf("syscall conn: %w", rcErr)
	}
	var goErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		effective, goErr = getsockoptIntRcvBuf(fd)
	})
	if ctrlErr != nil {
		return 0, fmt.Errorf("control fd: %w", ctrlErr)
	}
	if goErr != nil {
		return 0, fmt.Errorf("getsockopt SO_RCVBUF: %w", goErr)
	}
	if effective < clampThreshold(target) {
		return effective, errUDPRecvBufferClamped
	}
	return effective, nil
}

// clampThreshold is the smallest effective SO_RCVBUF that counts as
// "honored" for a given userspace target. Linux doubles internally
// (so honored == 2×); other unices return the userspace value
// directly. Split out so the platform-detection lives in one place
// and is unit-testable without a real socket.
func clampThreshold(target int) int {
	if runtime.GOOS == "linux" {
		return 2 * target
	}
	return target
}
