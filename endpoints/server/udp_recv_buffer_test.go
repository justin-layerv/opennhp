package server

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
)

func TestParseUDPRecvBufferSize_DefaultWhenUnset(t *testing.T) {
	got, err := parseUDPRecvBufferSize("")
	if err != nil {
		t.Fatalf("unset value should not error, got %v", err)
	}
	if got != DefaultUDPRecvBufferBytes {
		t.Fatalf("default mismatch: want %d, got %d", DefaultUDPRecvBufferBytes, got)
	}
}

func TestParseUDPRecvBufferSize_AcceptsPositiveOverride(t *testing.T) {
	const want = 16 * 1024 * 1024
	got, err := parseUDPRecvBufferSize("16777216")
	if err != nil {
		t.Fatalf("positive integer should parse, got %v", err)
	}
	if got != want {
		t.Fatalf("override mismatch: want %d, got %d", want, got)
	}
}

func TestParseUDPRecvBufferSize_RejectsNonNumeric(t *testing.T) {
	if _, err := parseUDPRecvBufferSize("eight-megs"); err == nil {
		t.Fatal("non-numeric value should error so an operator typo cannot silently leave the default in place")
	}
}

func TestParseUDPRecvBufferSize_RejectsZero(t *testing.T) {
	if _, err := parseUDPRecvBufferSize("0"); err == nil {
		t.Fatal("zero should error: a 0-byte buffer would mean the operator wanted disable, but disable isn't supported here")
	}
}

func TestParseUDPRecvBufferSize_RejectsNegative(t *testing.T) {
	if _, err := parseUDPRecvBufferSize("-1"); err == nil {
		t.Fatal("negative should error")
	}
}

func TestParseUDPRecvBufferSize_TrimsSurroundingWhitespace(t *testing.T) {
	got, err := parseUDPRecvBufferSize("  16777216\n")
	if err != nil {
		t.Fatalf("whitespace-padded value should parse: got %v", err)
	}
	if got != 16*1024*1024 {
		t.Fatalf("trim mismatch: want 16 MiB, got %d", got)
	}
}

// TestVerifyUDPRecvBuffer_ReportsEffectiveSize asserts the success
// path: when the requested target is well below the platform's
// rmem_max, verifyUDPRecvBuffer returns the kernel-reported size
// (which the kernel doubles internally) and no error.
//
// We can't assume rmem_max on the test host (Darwin default is
// ~196 KiB; Linux default is ~208 KiB; CI may differ from both).
// Pass a target of 1 byte — every platform satisfies 2×1 — so the
// success branch is reachable everywhere without making assumptions
// about the host's sysctl. The clamp branch is exercised separately
// in TestVerifyUDPRecvBuffer_DetectsClamping below.
func TestVerifyUDPRecvBuffer_ReportsEffectiveSize(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("SO_RCVBUF readback only supported on linux/darwin in this codebase")
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	effective, err := verifyUDPRecvBuffer(conn, 1)
	if err != nil {
		t.Fatalf("verify should not error at trivial target: %v", err)
	}
	if effective <= 0 {
		t.Fatalf("kernel readback should be positive, got %d", effective)
	}
}

// TestVerifyUDPRecvBuffer_DetectsClamping forces the clamp branch by
// requesting an absurd buffer (1 GiB) that no developer or CI host
// will have rmem_max set high enough to satisfy. The clamp signal
// is what the boot path uses to alert operators that the sysctl
// drop-in is missing — without this test, a regression that breaks
// the clamp branch entirely (e.g. always returning nil) would
// silently never warn. The exact `< vs <=` boundary at
// effective == clampThreshold(target) isn't exercised here; that's
// covered by reading clampThreshold's definition.
func TestVerifyUDPRecvBuffer_DetectsClamping(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("SO_RCVBUF readback only supported on linux/darwin in this codebase")
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	const absurd = 1 << 30 // 1 GiB
	// SetReadBuffer is allowed to succeed even when the kernel
	// silently clamps; the whole point of verify is to catch that
	// case. So ignore the error here.
	_ = conn.SetReadBuffer(absurd)
	_, err = verifyUDPRecvBuffer(conn, absurd)
	if !errors.Is(err, errUDPRecvBufferClamped) {
		// On a host where rmem_max really is >= clampThreshold(1 GiB)
		// the kernel honors the request, no clamp fires, and this
		// fatal triggers — flagging a working host as broken. Wildly
		// improbable; if it happens, the assertion message points at
		// the cause so the failure is investigable rather than
		// mysterious.
		t.Fatalf("expected clamp at absurd target on a normal host, got err=%v", err)
	}
}

// TestTuneUDPRecvBuffer_NoPanicOnLargeTarget exercises tuneUDPRecvBuffer
// end-to-end against a real UDP socket with an absurd target. The
// branch reached depends on platform: linux/darwin take the clamp
// branch; other platforms hit the readback-failed branch via the
// stub `getsockoptIntRcvBuf`. The contract this test enforces is
// the cross-platform one — boot must not panic, must not return,
// must keep the server in rotation regardless of which branch
// fires. Precise per-branch behavior is covered by the underlying
// verify tests.
func TestTuneUDPRecvBuffer_NoPanicOnLargeTarget(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// 1 GiB target forces the clamp branch on any developer or CI
	// host (rmem_max is well below 1 GiB everywhere). Helper must
	// log + return cleanly with no panic — that's the whole boot
	// contract.
	tuneUDPRecvBuffer(conn, 1<<30)
}

// TestErrUDPRecvBufferClamped_RemainsWrappable locks the sentinel
// error so tuneUDPRecvBuffer's errors.Is check stays valid through
// future refactors. The boot-log string operators grep for
// ("raise net.core.rmem_max") lives in tuneUDPRecvBuffer's
// log.Warning call site, not on the sentinel — it's covered by code
// review, not unit test, since intercepting the project's log
// package isn't worth the harness.
func TestErrUDPRecvBufferClamped_RemainsWrappable(t *testing.T) {
	wrapped := errors.Join(errUDPRecvBufferClamped, errors.New("downstream wrap"))
	if !errors.Is(wrapped, errUDPRecvBufferClamped) {
		t.Fatal("errUDPRecvBufferClamped must remain wrappable so tuneUDPRecvBuffer's errors.Is check stays valid")
	}
	if !strings.Contains(errUDPRecvBufferClamped.Error(), "clamp") {
		t.Fatal("sentinel message should contain 'clamp' so log greps remain stable")
	}
}

// TestClampThreshold_LinuxDoubles asserts the platform table:
// Linux honors a target via the kernel-doubling rule (2×), every
// other unix uses the target as-is. The whole point of the helper
// is to keep the Darwin developer-laptop branch from false-
// positive-clamping at 8 MiB.
func TestClampThreshold_LinuxDoubles(t *testing.T) {
	got := clampThreshold(8 * 1024 * 1024)
	if runtime.GOOS == "linux" {
		if got != 16*1024*1024 {
			t.Fatalf("linux threshold should double: want 16 MiB, got %d", got)
		}
	} else {
		if got != 8*1024*1024 {
			t.Fatalf("non-linux threshold should equal target: want 8 MiB, got %d", got)
		}
	}
}
