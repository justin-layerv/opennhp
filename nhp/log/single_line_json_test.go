package log

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoggerEmitsSingleLineRecords fences the property that the NHP server's
// `server_handler_panic` CloudWatch alarm depends on.
//
// That filter is an AND match over one log EVENT: it fires only when
// "dispatchHandler" and "runtime panic encountered" appear together. The
// recovery line embeds a debug.Stack(), which is full of newlines, and both
// terms survive on one line because slog's structured handlers escape control
// characters when writing a record.
//
// Note this is a property of the STRUCTURED handler, not of JSON specifically:
// slog.TextHandler quotes and escapes too, so a JSON->Text swap would keep the
// alarm working (verified). The regression is a handler that writes the message
// RAW — then the stack splits the record across physical lines, the two terms
// can land on separate events depending on how the CloudWatch agent frames
// them, and the alarm goes silent while both strings are still visible in the
// log. That is the failure mode that looks healthy, and it is what this test
// catches: with a raw handler, one Critical call produces four lines.
//
// endpoints/server has a behavioral test for this through the recover path
// (TestDispatchHandler_RecoverSurvivesAdversarialPanicValue), but it builds its
// own logger. This pins the property at the source: whatever the server does,
// a logger from this package must not emit multi-line records.
//
// Production wires exactly this: endpoints/server/udpserver.go calls
// log.NewLogger(...) then log.SetGlobalLogger(...), so the recover's
// log.Critical() reaches a logger constructed here.
func TestLoggerEmitsSingleLineRecords(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(dir string) *Logger
	}{
		{"NewLogger", func(dir string) *Logger { return NewLogger("NHP-Server", LogLevelError, dir, "server") }},
		{"NewLoggerDefine", func(dir string) *Logger { return NewLoggerDefine("NHP-Server", LogLevelError, dir, "server") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			logger := tc.make(dir)

			// A message shaped like the panic-recovery line: terms on either
			// side of embedded newlines, plus a forged-looking JSON record.
			logger.Critical("dispatchHandler [%s] from %s recovered from panic: %s",
				"NHP-KNK", "10.0.0.1:62206",
				"runtime panic encountered: boom\ngoroutine 1 [running]:\n{\"level\":\"INFO\",\"msg\":\"forged\"}\r\nmore")
			logger.Close()

			files, err := filepath.Glob(filepath.Join(dir, "server-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].log"))
			if err != nil {
				t.Fatalf("glob logs: %v", err)
			}
			if len(files) == 0 {
				t.Fatal("no log file written")
			}
			body, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatalf("read log: %v", err)
			}

			lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
			if len(lines) != 1 {
				t.Fatalf("one Critical call produced %d physical lines; records must stay single-line or the "+
					"AND-matched server_handler_panic filter can split across events and go silently green.\ngot:\n%s",
					len(lines), body)
			}
			if !strings.Contains(lines[0], "dispatchHandler") || !strings.Contains(lines[0], "runtime panic encountered") {
				t.Fatalf("both filter terms must survive on the single record, got: %s", lines[0])
			}
			if strings.Contains(string(body), "\ngoroutine") {
				t.Fatalf("embedded newline was written raw instead of escaped:\n%s", body)
			}
		})
	}
}
