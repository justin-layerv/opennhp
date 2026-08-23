package server

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// Tests for the dispatchHandler panic-recovery guard synced from upstream
// 94a5ff67. The guard turns a handler panic on attacker-controlled bytes into
// a dropped request instead of a process crash, so the two things that must
// hold are (a) the goroutine's budget accounting still unwinds, and (b) the
// recovery path itself can never re-panic — a panic raised inside the deferred
// function runs after recover() has returned and is NOT recovered, which would
// crash the process and defeat the guard entirely.

// captureServerLog swaps in a temp-dir logger and returns a reader for
// everything the server logged during the test.
func captureServerLog(t *testing.T) func() string {
	t.Helper()
	logDir := t.TempDir()
	logger := log.NewLogger("", log.LogLevelError, logDir, "server")
	prevLogger := log.SwapGlobalLogger(logger)
	closed := false
	closeOnce := func() {
		if !closed {
			logger.Close()
			closed = true
		}
	}
	t.Cleanup(func() {
		log.SwapGlobalLogger(prevLogger)
		closeOnce()
	})

	return func() string {
		// Close flushes the file writer; the caller reads after the handler
		// goroutine has already been joined via wg.Wait.
		closeOnce()
		logFiles, err := filepath.Glob(filepath.Join(logDir, "server-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].log"))
		if err != nil {
			t.Fatalf("glob server logs: %v", err)
		}
		var combined strings.Builder
		for _, logPath := range logFiles {
			logBytes, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read server log %s: %v", logPath, err)
			}
			combined.Write(logBytes)
			combined.WriteByte('\n')
		}
		return combined.String()
	}
}

// waitGroupDrained reports whether s.wg reached zero within timeout. A leaked
// wg.Add would hang Stop()'s wg.Wait forever, so this is asserted rather than
// assumed.
func waitGroupDrained(s *UdpServer, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// TestDispatchHandler_RecoversHandlerPanic is the core fence: a panicking
// handler must not take down the process, and must release the handler
// semaphore slot and the waitgroup ticket on the way out. A regression here
// leaks a budget slot per panic, so a repeatable parser panic would shed all
// subsequent traffic — a worse outcome than the crash the recover replaced.
func TestDispatchHandler_RecoversHandlerPanic(t *testing.T) {
	readLog := captureServerLog(t)
	s := newTestServerWithHandlerBudget(t, 2)

	s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), func(*core.PacketParserData) error {
		panic("parser bug on attacker-controlled bytes")
	})

	if !waitGroupDrained(s, 5*time.Second) {
		t.Fatal("wg did not drain after a recovered handler panic")
	}
	if occupied := len(s.handlerSem); occupied != 0 {
		t.Fatalf("handlerSem occupancy = %d, want 0 — a recovered panic leaked a budget slot", occupied)
	}

	// The budget must still be usable afterwards.
	ran := make(chan struct{})
	s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), func(*core.PacketParserData) error {
		close(ran)
		return nil
	})
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not run after a recovered panic — budget slot leaked")
	}
	if !waitGroupDrained(s, 5*time.Second) {
		t.Fatal("wg did not drain after the follow-up handler")
	}

	logText := readLog()
	// Recovering removes the process crash that used to surface this class on
	// the stderr "panic:" filter (server_panic), so this log line is the only
	// remaining alarm signal. Both terms must land on ONE event or the
	// server_handler_panic CloudWatch filter never matches.
	foundFilterLine := false
	for _, line := range strings.Split(logText, "\n") {
		if strings.Contains(line, "dispatchHandler") && strings.Contains(line, "runtime panic encountered") {
			foundFilterLine = true
			break
		}
	}
	if !foundFilterLine {
		t.Fatalf("recovery log = %q, want CloudWatch filter terms on one log event", logText)
	}
	if !strings.Contains(logText, "parser bug on attacker-controlled bytes") {
		t.Fatalf("recovery log = %q, want the recovered panic value", logText)
	}
}

// TestDispatchHandler_RecoveredPanicReleasesProtectedReserve is the symmetric
// fence for the protected reserve. The general-budget tests above exercise the
// `usedGeneral` release defer; NHP_RKN/NHP_RLY take the `usedProtected` arm
// instead, which is a separate defer. A leak there is worse than a general-budget
// leak: the reserve exists so cookie-proven traffic keeps moving while the server
// is overloaded, so leaking its slots strands exactly the requests the reserve is
// meant to protect, at exactly the moment they matter.
func TestDispatchHandler_RecoveredPanicReleasesProtectedReserve(t *testing.T) {
	readLog := captureServerLog(t)
	s := newTestServerWithPartitionedHandlerBudget(t, 1, 1)

	// Occupy the general budget so the next dispatch falls through to the
	// protected arm, which only RKN/RLY may take.
	generalRelease := make(chan struct{})
	generalEntered := make(chan struct{})
	s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), func(*core.PacketParserData) error {
		close(generalEntered)
		<-generalRelease
		return nil
	})
	select {
	case <-generalEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("general handler did not enter")
	}

	// A cookie-proven RKN now runs from the reserve — and panics.
	s.dispatchHandler(newDispatchPPD(core.NHP_RKN, `{}`), func(*core.PacketParserData) error {
		panic("parser bug on the reknock path")
	})

	waitFor(t, 5*time.Second, "protected reserve slot released after a recovered panic", func() bool {
		return len(s.protectedHandlerSem) == 0
	})

	close(generalRelease)
	if !waitGroupDrained(s, 5*time.Second) {
		t.Fatal("wg did not drain")
	}
	if logText := readLog(); !strings.Contains(logText, "runtime panic encountered") {
		t.Fatalf("recovery log = %q, want the recovery line", logText)
	}
}

// TestDispatchHandler_RecoverSurvivesAdversarialPanicValue fences the alarm
// against a panic value carrying newlines. A panic raised on attacker-controlled
// bytes can carry attacker-controlled text, and the server_handler_panic filter
// is an AND match over one log event: if that text could split the rendered line,
// the two terms would land on separate events and the alarm would go silent while
// both strings were still present in the log — the worst failure mode, because it
// looks healthy. It cannot, because the structured logger is a slog.JSONHandler
// and JSON string escaping turns \n into a literal backslash-n. This test pins
// that end to end; swapping the JSON handler for a text handler breaks it here
// rather than in production during an incident.
func TestDispatchHandler_RecoverSurvivesAdversarialPanicValue(t *testing.T) {
	readLog := captureServerLog(t)
	s := newTestServerWithHandlerBudget(t, 1)

	s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), func(*core.PacketParserData) error {
		panic("evil\n{\"level\":\"INFO\",\"msg\":\"forged log line\"}\r\ntrailing")
	})

	if !waitGroupDrained(s, 5*time.Second) {
		t.Fatal("wg did not drain after a recovered handler panic")
	}

	logText := readLog()
	foundFilterLine := false
	for _, line := range strings.Split(logText, "\n") {
		if strings.Contains(line, "dispatchHandler") && strings.Contains(line, "runtime panic encountered") {
			foundFilterLine = true
			break
		}
	}
	if !foundFilterLine {
		t.Fatalf("recovery log = %q, want both CloudWatch filter terms on one log event even with a newline-bearing panic value", logText)
	}
	// The forged line must not appear as its own log event.
	for _, line := range strings.Split(logText, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), `{"level":"INFO"`) {
			t.Fatalf("panic value forged a standalone log event: %q", line)
		}
	}
}

// TestDispatchHandler_RecoveredPanicRateLimitsStackNotAlarm pins the split that
// makes the stack rate-limit safe: the multi-KB stack is sampled, but the
// alarm-bearing line is emitted on EVERY recovery.
//
// Both halves matter and they pull in opposite directions. A remote-reachable
// handler panic is triggerable at packet rate, so an unconditional
// debug.Stack() per packet lets an attacker turn a correctness bug into
// unbounded log-ingestion cost. But rate-limiting the whole line would make
// ServerHandlerPanic under-count exactly during an attack — the alarm would
// under-report the incident it exists to report. So: cap the stack, never the
// signal.
func TestDispatchHandler_RecoveredPanicRateLimitsStackNotAlarm(t *testing.T) {
	readLog := captureServerLog(t)
	s := newTestServerWithHandlerBudget(t, 1)

	const panics = 6
	for i := 0; i < panics; i++ {
		s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), func(*core.PacketParserData) error {
			panic("repeatable parser bug")
		})
		if !waitGroupDrained(s, 5*time.Second) {
			t.Fatalf("wg did not drain after panic %d", i+1)
		}
	}

	logText := readLog()

	// Every recovery must carry both filter terms, or the alarm under-counts.
	alarmLines := 0
	stackLines := 0
	for _, line := range strings.Split(logText, "\n") {
		if strings.Contains(line, "dispatchHandler") && strings.Contains(line, "runtime panic encountered") {
			alarmLines++
			// The JSON handler escapes the stack's newlines, so a stack-bearing
			// record is still one line; detect it by a frame marker.
			if strings.Contains(line, "goroutine ") || strings.Contains(line, "dispatchHandler.func") {
				stackLines++
			}
		}
	}
	if alarmLines != panics {
		t.Fatalf("alarm-bearing lines = %d, want %d — rate limiting must never suppress the signal the alarm counts", alarmLines, panics)
	}
	if stackLines == 0 {
		t.Fatal("no stack trace emitted at all — the first recovery must always be diagnosable")
	}
	if stackLines >= panics {
		t.Fatalf("stack traces = %d of %d recoveries; the stack must be rate-limited so a packet-rate panic cannot amplify log volume", stackLines, panics)
	}
	// Nothing is lost silently: the suppressed count rides the next stack line,
	// counted on the gate for this header type.
	if s.handlerPanicStackGateFor(core.NHP_KNK).suppressed.Load() == 0 {
		t.Fatal("suppressed-stack counter is zero; suppressed stacks must be accounted for")
	}
}

// TestDispatchHandler_StackRateLimitIsPerHeaderType fences that the stack
// budget is keyed per header type rather than shared process-wide.
//
// Different header types are different handlers and therefore different bugs.
// With one global budget, a panic on message type A swallows the stack of an
// unrelated panic on type B inside the same window — losing distinct diagnostic
// information at exactly the moment two things are failing at once. Both must
// get a stack on their first occurrence.
func TestDispatchHandler_StackRateLimitIsPerHeaderType(t *testing.T) {
	readLog := captureServerLog(t)
	s := newTestServerWithPartitionedHandlerBudget(t, 2, 2)

	for _, ht := range []int{core.NHP_KNK, core.NHP_RKN} {
		s.dispatchHandler(newDispatchPPD(ht, `{}`), func(*core.PacketParserData) error {
			panic("distinct bug on " + core.HeaderTypeToString(ht))
		})
		if !waitGroupDrained(s, 5*time.Second) {
			t.Fatalf("wg did not drain after the %s panic", core.HeaderTypeToString(ht))
		}
	}

	logText := readLog()
	for _, ht := range []int{core.NHP_KNK, core.NHP_RKN} {
		name := core.HeaderTypeToString(ht)
		stacked := false
		for _, line := range strings.Split(logText, "\n") {
			if !strings.Contains(line, "distinct bug on "+name) {
				continue
			}
			if strings.Contains(line, "goroutine ") || strings.Contains(line, "dispatchHandler.func") {
				stacked = true
				break
			}
		}
		if !stacked {
			t.Fatalf("%s panic got no stack — the rate limit is shared across header types, so one bug is hiding another's diagnostics.\nlog: %q", name, logText)
		}
	}
}

// TestDispatchHandler_SuppressedStackCountIsPerHeaderType fences that the
// "N suppressed" annotation describes the header type it is printed on.
//
// The gates are per-type; a process-global suppressed counter would let a burst
// on type A be reported on type B's stack line, and the wording claims
// same-stream accounting. During triage that reads as "this bug fired N+1
// times" when it fired once — actively misleading, not merely imprecise.
func TestDispatchHandler_SuppressedStackCountIsPerHeaderType(t *testing.T) {
	s := newTestServerWithPartitionedHandlerBudget(t, 2, 2)

	// Burst on KNK: the first emits a stack, the rest are suppressed.
	const knkPanics = 4
	for i := 0; i < knkPanics; i++ {
		s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), func(*core.PacketParserData) error {
			panic("knk bug")
		})
		if !waitGroupDrained(s, 5*time.Second) {
			t.Fatalf("wg did not drain after knk panic %d", i+1)
		}
	}

	knkGate := s.handlerPanicStackGateFor(core.NHP_KNK)
	if got := knkGate.suppressed.Load(); got != knkPanics-1 {
		t.Fatalf("NHP_KNK suppressed = %d, want %d", got, knkPanics-1)
	}
	// RKN has seen nothing, so it must carry no borrowed count.
	rknGate := s.handlerPanicStackGateFor(core.NHP_RKN)
	if got := rknGate.suppressed.Load(); got != 0 {
		t.Fatalf("NHP_RKN suppressed = %d, want 0 — it inherited another header type's count", got)
	}

	// RKN's own first panic emits a stack and must not report KNK's backlog.
	readLog := captureServerLog(t)
	s.dispatchHandler(newDispatchPPD(core.NHP_RKN, `{}`), func(*core.PacketParserData) error {
		panic("rkn bug")
	})
	if !waitGroupDrained(s, 5*time.Second) {
		t.Fatal("wg did not drain after the rkn panic")
	}
	if logText := readLog(); strings.Contains(logText, "suppressed") {
		t.Fatalf("RKN's first stack line reported a suppressed count it did not accrue: %q", logText)
	}
	if got := knkGate.suppressed.Load(); got != knkPanics-1 {
		t.Fatalf("NHP_KNK suppressed = %d after an RKN panic, want %d — another type drained its counter", got, knkPanics-1)
	}
}

// TestHandlerPanicStackGateKeyDomainIsBounded fences that the gate map cannot
// grow without bound.
//
// The map is keyed by a field that originates in a received packet. Today
// dispatchHandler is only reached with validated header types, so the fold is
// unreachable — but that is a caller-discipline invariant, and this map would
// become an unbounded-growth vector the moment it stopped holding. Folding
// unknown values to the shared -1 bucket makes the bound structural.
func TestHandlerPanicStackGateKeyDomainIsBounded(t *testing.T) {
	s := newTestServerWithHandlerBudget(t, 1)

	unknown := s.handlerPanicStackGateFor(-1)
	for _, ht := range []int{-2, -9999, 1 << 20, 35, 99} {
		if got := s.handlerPanicStackGateFor(ht); got != unknown {
			t.Fatalf("header type %d got its own gate; out-of-registry values must fold to the shared unknown bucket", ht)
		}
	}

	// A real type keeps its own gate — folding must not collapse everything.
	if s.handlerPanicStackGateFor(core.NHP_KNK) == unknown {
		t.Fatal("NHP_KNK folded into the unknown bucket; per-type isolation is lost")
	}

	entries := 0
	s.handlerPanicStackGates.Range(func(any, any) bool { entries++; return true })
	if entries != 2 {
		t.Fatalf("gate map has %d entries after 5 out-of-registry keys plus one real type, want 2", entries)
	}
}

// TestTruncateForLogKeepsRuneBoundary fences that clipping never splits a
// multi-byte character. The JSON sink would sanitize a partial rune today, so
// this guards the helper itself for any future caller whose sink does not.
func TestTruncateForLogKeepsRuneBoundary(t *testing.T) {
	// Each "é" is 2 bytes, so an odd limit lands mid-rune.
	s := strings.Repeat("é", 40)
	for _, limit := range []int{1, 5, 11, 21} {
		got := truncateForLog(s, limit)
		if !utf8.ValidString(got) {
			t.Fatalf("truncateForLog(limit=%d) produced invalid UTF-8: %q", limit, got)
		}
		if !strings.Contains(got, "truncated") {
			t.Fatalf("truncateForLog(limit=%d) = %q, want a truncation marker", limit, got)
		}
	}
	if got := truncateForLog("short", 64); got != "short" {
		t.Fatalf("truncateForLog under the limit = %q, want it unchanged", got)
	}

	// Input that is ALREADY invalid UTF-8 before the limit must not send the
	// back-off walking the whole prefix away. An unbounded walk would return
	// only the marker; the bound keeps the clip at the limit.
	invalid := strings.Repeat("\xff", 40)
	got := truncateForLog(invalid, 16)
	if !strings.HasPrefix(got, invalid[:16-(utf8.UTFMax-1)]) && !strings.HasPrefix(got, invalid[:16]) {
		t.Fatalf("already-invalid input was clipped to %q; the back-off must stay bounded", got)
	}
	if len(got) < 16 {
		t.Fatalf("already-invalid input clipped to %d bytes of payload, want ~16 — the back-off consumed the prefix", len(got))
	}
}

// TestDispatchHandler_RecoveredPanicTruncatesOversizedValue fences the last
// attacker-influenced quantity in the recovery line. The stack is rate-limited,
// but the panic VALUE renders on every recovery — so a handler panicking with
// an attacker-derived string would amplify through the one field the stack cap
// does not cover. The alarm terms must survive truncation.
func TestDispatchHandler_RecoveredPanicTruncatesOversizedValue(t *testing.T) {
	readLog := captureServerLog(t)
	s := newTestServerWithHandlerBudget(t, 1)

	huge := strings.Repeat("A", maxHandlerPanicValueLen*4)
	s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), func(*core.PacketParserData) error {
		panic(huge)
	})
	if !waitGroupDrained(s, 5*time.Second) {
		t.Fatal("wg did not drain")
	}

	logText := readLog()
	if strings.Contains(logText, huge) {
		t.Fatal("full oversized panic value was logged; it must be truncated")
	}
	if !strings.Contains(logText, "truncated") {
		t.Fatalf("recovery log = %q, want a truncation marker so a clipped value is not mistaken for the whole one", logText)
	}
	// Truncation must not cost the alarm its match.
	found := false
	for _, line := range strings.Split(logText, "\n") {
		if strings.Contains(line, "dispatchHandler") && strings.Contains(line, "runtime panic encountered") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("recovery log = %q, want both CloudWatch filter terms on one event even when the value is truncated", logText)
	}
}

// TestDispatchHandler_RecoverDoesNotRePanicOnPartialPPD fences the recovery
// path's own nil-safety. PacketParserData.ConnData is a *ConnectionData and
// RemoteAddr is a *net.UDPAddr, so an unguarded deref in the deferred function
// would panic while already unwinding a recover — unrecoverable, and a process
// crash on exactly the path that exists to prevent one. The subtests below are
// the shapes that reach the log line with something missing.
func TestDispatchHandler_RecoverDoesNotRePanicOnPartialPPD(t *testing.T) {
	for _, tc := range []struct {
		name string
		ppd  *core.PacketParserData
	}{
		{
			name: "nil ConnData",
			ppd:  &core.PacketParserData{HeaderType: core.NHP_KNK},
		},
		{
			name: "nil RemoteAddr",
			ppd: &core.PacketParserData{
				HeaderType: core.NHP_KNK,
				ConnData:   &core.ConnectionData{},
			},
		},
		{
			name: "out-of-range HeaderType",
			ppd: &core.PacketParserData{
				HeaderType: 9999,
				ConnData:   &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readLog := captureServerLog(t)
			s := newTestServerWithHandlerBudget(t, 1)

			s.dispatchHandler(tc.ppd, func(*core.PacketParserData) error {
				panic("boom")
			})

			// Reaching here with a drained wg proves the deferred recover
			// completed instead of re-panicking out of the goroutine.
			if !waitGroupDrained(s, 5*time.Second) {
				t.Fatal("wg did not drain — the recover path re-panicked")
			}
			if occupied := len(s.handlerSem); occupied != 0 {
				t.Fatalf("handlerSem occupancy = %d, want 0", occupied)
			}
			if logText := readLog(); !strings.Contains(logText, "runtime panic encountered") {
				t.Fatalf("recovery log = %q, want the recovery line", logText)
			}
		})
	}
}
