package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	LogQueueSize       = 1024
	ShowCallerFileLine = true
)

// Log levels for use with NewLogger.
const (
	LogLevelSilent = iota
	LogLevelError
	LogLevelInfo
	LogLevelAudit
	LogLevelDebug
	LogLevelTrace
)

// Custom slog levels for NHP-specific log categories.
const (
	SlogLevelTrace       slog.Level = slog.LevelDebug - 8 // -12
	SlogLevelVerbose     slog.Level = slog.LevelDebug - 4 // -8
	SlogLevelDebug       slog.Level = slog.LevelDebug     // -4
	SlogLevelInfo        slog.Level = slog.LevelInfo      // 0
	SlogLevelAudit       slog.Level = slog.LevelInfo + 1  // 1
	SlogLevelStats       slog.Level = slog.LevelInfo + 2  // 2
	SlogLevelTransaction slog.Level = slog.LevelInfo + 3  // 3
	SlogLevelWarning     slog.Level = slog.LevelWarn      // 4
	SlogLevelEvaluate    slog.Level = slog.LevelWarn + 2  // 6
	SlogLevelError       slog.Level = slog.LevelError     // 8
	SlogLevelCritical    slog.Level = slog.LevelError + 4 // 12
)

// slogLevelName maps custom slog levels to their display names for JSON output.
func slogLevelName(l slog.Level) string {
	switch l {
	case SlogLevelTrace:
		return "TRACE"
	case SlogLevelVerbose:
		return "VERBOSE"
	case SlogLevelDebug:
		return "DEBUG"
	case SlogLevelInfo:
		return "INFO"
	case SlogLevelAudit:
		return "AUDIT"
	case SlogLevelStats:
		return "STATS"
	case SlogLevelTransaction:
		return "TRANSACTION"
	case SlogLevelWarning:
		return "WARNING"
	case SlogLevelEvaluate:
		return "EVALUATE"
	case SlogLevelError:
		return "ERROR"
	case SlogLevelCritical:
		return "CRITICAL"
	default:
		return l.String()
	}
}

// newJSONHandler creates a slog.JSONHandler configured for NHP structured logging.
func newJSONHandler(w io.Writer) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{
		AddSource: ShowCallerFileLine,
		Level:     SlogLevelTrace, // Allow all levels through; filtering is done by Logger
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				if level, ok := a.Value.Any().(slog.Level); ok {
					a.Value = slog.StringValue(slogLevelName(level))
				}
			}
			return a
		},
	})
}

type AsyncLogWriter struct {
	sync.Mutex
	wg sync.WaitGroup

	DirPath  string
	Name     string
	currDate string

	dateUpdatedCh chan string
	msg           chan []byte
}

func (lw *AsyncLogWriter) Start() {
	lw.currDate = time.Now().Format("2006-01-02")

	if lw.msg == nil {
		if len(lw.DirPath) > 0 {
			err := os.MkdirAll(lw.DirPath, os.ModePerm)
			if err != nil {
				fmt.Printf("Warning: AsyncLogWriter cannot create directory %s (%v). Using current working directory instead.\n", lw.DirPath, err)
				lw.DirPath = ""
			}
		}

		lw.msg = make(chan []byte, LogQueueSize)
		lw.wg.Add(1)
		go lw.writeRoutine()
	}
}

// async writer
// must be initiated first, implements atomic write
func (lw *AsyncLogWriter) Write(buf []byte) (n int, err error) {
	lw.Lock()
	defer lw.Unlock()

	if lw.msg == nil {
		return 0, nil // writer closed; discard silently during shutdown
	}

	msg := slices.Clone(buf)
	lw.msg <- msg

	return len(buf), nil
}

func (lw *AsyncLogWriter) writeRoutine() {
	defer lw.wg.Done()

	useStdout := len(lw.DirPath) == 0 && len(lw.Name) == 0

	for {
		var quit bool
		var err error
		msgArr := make([][]byte, 0, LogQueueSize)

		select {
		// block to wait for incoming log messages
		case msg := <-lw.msg:
			if msg == nil {
				quit = true
			} else {
				msgArr = append(msgArr, msg)
			}
			// collect all remaining messages if there are any
		collectRest:
			for {
				select {
				case msg = <-lw.msg:
					if msg == nil {
						quit = true
					} else {
						msgArr = append(msgArr, msg)
					}
				default:
					break collectRest
				}
			}

		case <-time.After(100 * time.Millisecond):
		}

		// check date update
		date := time.Now().Format("2006-01-02")

		// check if date has been updated
		if lw.dateUpdatedCh != nil && date != lw.currDate {
			// non-blocking update with the old date
			if len(lw.dateUpdatedCh) > 0 {
				<-lw.dateUpdatedCh
			}
			lw.dateUpdatedCh <- lw.currDate
			lw.currDate = date
		}

		// write messages to file
		if len(msgArr) > 0 {
			var file *os.File
			if useStdout {
				file = os.Stdout
			} else {
				filename := fmt.Sprintf("%s-%s.log", lw.Name, date)
				if len(lw.DirPath) > 0 {
					filename = filepath.Join(lw.DirPath, filename)
				}
				file, err = os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
				if err != nil {
					fmt.Printf("Error: AsyncLogWriter cannot open file %s (%v)\n", filename, err)
					continue
				}
			}

			// O_CREATE: create file if it does not exist
			// O_APPEND: open at the end of file
			// O_SYNC: sync data right into disk at write. Don't use this flag to reduce file i/o
			//file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_SYNC, 0600)
			for _, m := range msgArr {
				_, err := file.Write(m)
				if err != nil {
					fmt.Printf("Error: AsyncLogWriter failed to write file %s (%v)\n", file.Name(), err)
					break
				}
			}

			// close after all writes
			if !useStdout {
				if err := file.Sync(); err != nil {
					fmt.Printf("Error: AsyncLogWriter failed to sync file %s (%v)\n", file.Name(), err)
				}
				if err := file.Close(); err != nil {
					fmt.Printf("Error: AsyncLogWriter failed to close file %s (%v)\n", file.Name(), err)
				}
			}
		}

		if quit {
			return
		}
	}
}

func (lw *AsyncLogWriter) Close() {
	lw.Lock()
	defer lw.Unlock()

	if lw.msg != nil {
		lw.msg <- nil
		lw.wg.Wait()
		close(lw.msg)
		lw.msg = nil
	}
	if lw.dateUpdatedCh != nil {
		close(lw.dateUpdatedCh)
		lw.dateUpdatedCh = nil
	}

}

// A logger that outputs structured JSON using slog.JSONHandler backed by AsyncLogWriter.
// It preserves the existing printf-style API for backward compatibility with all call sites.
// At default implementation, it is recommended to call Close() at program termination.
type Logger struct {
	sync.Mutex
	lw         *AsyncLogWriter
	lwEvaluate *AsyncLogWriter
	lwAudit    *AsyncLogWriter

	handler      slog.Handler // JSON handler for main log
	evalHandler  slog.Handler // JSON handler for evaluate log
	auditHandler slog.Handler // JSON handler for audit log
	component    string       // component name included in each JSON record

	Warning     func(format string, args ...any)
	Error       func(format string, args ...any)
	Critical    func(format string, args ...any)
	Evaluate    func(format string, args ...any)
	Info        func(format string, args ...any)
	Stats       func(format string, args ...any)
	Audit       func(format string, args ...any)
	Transaction func(format string, args ...any)
	Debug       func(format string, args ...any)
	Trace       func(format string, args ...any)
	Verbose     func(format string, args ...any)

	logLevel    int
	callDepth   int // call depth for runtime.Callers to report correct source location
	isSubLogger bool
	stopped     atomic.Bool

	subLoggers []*Logger
}

// Function for use in Logger for discarding logged lines.
func BlackholeLogf(format string, args ...any) {}

// logJSON writes a structured JSON log record to the given handler.
func (l *Logger) logJSON(handler slog.Handler, level slog.Level, format string, args ...any) {
	if l.stopped.Load() {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(l.callDepth+1, pcs[:])
	r := slog.NewRecord(time.Now(), level, fmt.Sprintf(format, args...), pcs[0])
	if l.component != "" {
		r.AddAttrs(slog.String("component", l.component))
	}
	_ = handler.Handle(context.Background(), r)
}

// NewLogger constructs a Logger that logs at the specified log level and above.
// Output is structured JSON with time, level, source, message, and component fields.
func NewLogger(prepend string, level int, dir string, filename string) *Logger {
	l := &Logger{
		logLevel:  level,
		callDepth: 2,
	}

	// start generic log writer
	l.lw = &AsyncLogWriter{
		DirPath:       dir,
		Name:          filename,
		dateUpdatedCh: make(chan string, 1),
	}
	l.lw.Start()

	// start evaluate log writer
	l.lwEvaluate = &AsyncLogWriter{
		DirPath: dir,
		Name:    filename + "-evaluate",
	}
	l.lwEvaluate.Start()

	// start audit log writer
	l.lwAudit = &AsyncLogWriter{
		DirPath: dir,
		Name:    filename + "-audit",
	}
	l.lwAudit.Start()

	l.initActions(prepend)
	return l
}

func (l *Logger) initActions(prepend string) {
	l.handler = newJSONHandler(l.lw)
	l.evalHandler = newJSONHandler(l.lwEvaluate)
	l.auditHandler = newJSONHandler(l.lwAudit)
	l.component = prepend

	l.Warning = func(format string, args ...any) {
		if l.logLevel >= LogLevelError {
			l.logJSON(l.handler, SlogLevelWarning, format, args...)
		}
	}

	l.Error = func(format string, args ...any) {
		if l.logLevel >= LogLevelError {
			l.logJSON(l.handler, SlogLevelError, format, args...)
		}
	}

	l.Critical = func(format string, args ...any) {
		if l.logLevel >= LogLevelError {
			l.logJSON(l.handler, SlogLevelCritical, format, args...)
		}
	}

	l.Evaluate = func(format string, args ...any) {
		if l.logLevel >= LogLevelError {
			l.logJSON(l.evalHandler, SlogLevelEvaluate, format, args...)
		}
	}

	l.Info = func(format string, args ...any) {
		if l.logLevel >= LogLevelInfo {
			l.logJSON(l.handler, SlogLevelInfo, format, args...)
		}
	}

	l.Stats = func(format string, args ...any) {
		if l.logLevel >= LogLevelInfo {
			l.logJSON(l.handler, SlogLevelStats, format, args...)
		}
	}

	// output to audit log handler
	l.Audit = func(format string, args ...any) {
		if l.logLevel >= LogLevelAudit {
			l.logJSON(l.auditHandler, SlogLevelAudit, format, args...)
		}
	}

	l.Transaction = func(format string, args ...any) {
		if l.logLevel >= LogLevelAudit {
			l.logJSON(l.auditHandler, SlogLevelTransaction, format, args...)
		}
	}

	l.Debug = func(format string, args ...any) {
		if l.logLevel >= LogLevelDebug {
			l.logJSON(l.handler, SlogLevelDebug, format, args...)
		}
	}

	l.Verbose = func(format string, args ...any) {
		if l.logLevel >= LogLevelTrace {
			l.logJSON(l.handler, SlogLevelVerbose, format, args...)
		}
	}

	l.Trace = func(format string, args ...any) {
		if l.logLevel >= LogLevelTrace {
			l.logJSON(l.handler, SlogLevelTrace, format, args...)
		}
	}
}

func (l *Logger) SetLogLevel(level int) {
	l.Lock()
	l.logLevel = level
	l.Unlock()

	if l.isSubLogger {
		return
	}

	for _, subl := range l.subLoggers {
		subl.SetLogLevel(level)
	}
}

func (l *Logger) Close() {
	if l.stopped.Swap(true) {
		return // already stopped
	}

	if l.isSubLogger {
		// sublogger reuses writer so must not close the writer routine
		return
	}

	for _, subl := range l.subLoggers {
		subl.Close()
	}
	if l.lw != nil {
		l.lw.Close()
	}
	if l.lwEvaluate != nil {
		l.lwEvaluate.Close()
	}
	if l.lwAudit != nil {
		l.lwAudit.Close()
	}
}

func (l *Logger) Writer() io.Writer {
	return l.lw
}

func (l *Logger) NewSubLogger(prepend string, level int) *Logger {
	newl := &Logger{
		logLevel:    level,
		callDepth:   2,
		isSubLogger: true,
		lw:          l.lw,
		lwEvaluate:  l.lwEvaluate,
		lwAudit:     l.lwAudit,
	}

	// reuse parent's log writer
	newl.initActions(prepend)
	l.Lock()
	l.subLoggers = append(l.subLoggers, newl)
	l.Unlock()

	return newl
}

func (l *Logger) DateUpdateChan() chan string {
	return l.lw.dateUpdatedCh
}

// SetFlags is a no-op for structured JSON logging.
// Retained for backward compatibility with callers that set stdlib log flags.
func (l *Logger) SetFlags(flag int) {}

func NewLoggerDefine(prepend string, level int, dir string, filename string) *Logger {
	l := &Logger{
		logLevel:  level,
		callDepth: 2,
	}

	// start generic log writer
	l.lw = &AsyncLogWriter{
		DirPath:       dir,
		Name:          filename,
		dateUpdatedCh: make(chan string, 1),
	}
	l.lw.Start()

	// start evaluate log writer
	l.lwEvaluate = &AsyncLogWriter{
		DirPath: dir,
		Name:    filename + "-evaluate",
	}
	l.lwEvaluate.Start()

	// start audit log writer
	l.lwAudit = &AsyncLogWriter{
		DirPath: dir,
		Name:    filename + "-audit",
	}
	l.lwAudit.Start()

	l.initActionsNoInfoPrepend(prepend)
	return l
}

func (l *Logger) initActionsNoInfoPrepend(prepend string) {
	l.handler = newJSONHandler(l.lw)
	l.evalHandler = newJSONHandler(l.lwEvaluate)
	l.auditHandler = newJSONHandler(l.lwAudit)
	l.component = prepend

	// Info uses no prepend in this variant (used by ebpf deny/accept loggers)
	l.Info = func(format string, args ...any) {
		if l.logLevel >= LogLevelInfo {
			l.logJSON(l.handler, SlogLevelInfo, format, args...)
		}
	}

	// Initialize remaining methods to prevent nil function panics
	l.Warning = func(format string, args ...any) {
		if l.logLevel >= LogLevelError {
			l.logJSON(l.handler, SlogLevelWarning, format, args...)
		}
	}
	l.Error = func(format string, args ...any) {
		if l.logLevel >= LogLevelError {
			l.logJSON(l.handler, SlogLevelError, format, args...)
		}
	}
	l.Critical = func(format string, args ...any) {
		if l.logLevel >= LogLevelError {
			l.logJSON(l.handler, SlogLevelCritical, format, args...)
		}
	}
	l.Evaluate = func(format string, args ...any) {
		if l.logLevel >= LogLevelError {
			l.logJSON(l.evalHandler, SlogLevelEvaluate, format, args...)
		}
	}
	l.Stats = func(format string, args ...any) {
		if l.logLevel >= LogLevelInfo {
			l.logJSON(l.handler, SlogLevelStats, format, args...)
		}
	}
	l.Audit = func(format string, args ...any) {
		if l.logLevel >= LogLevelAudit {
			l.logJSON(l.auditHandler, SlogLevelAudit, format, args...)
		}
	}
	l.Transaction = func(format string, args ...any) {
		if l.logLevel >= LogLevelAudit {
			l.logJSON(l.auditHandler, SlogLevelTransaction, format, args...)
		}
	}
	l.Debug = func(format string, args ...any) {
		if l.logLevel >= LogLevelDebug {
			l.logJSON(l.handler, SlogLevelDebug, format, args...)
		}
	}
	l.Verbose = func(format string, args ...any) {
		if l.logLevel >= LogLevelTrace {
			l.logJSON(l.handler, SlogLevelVerbose, format, args...)
		}
	}
	l.Trace = func(format string, args ...any) {
		if l.logLevel >= LogLevelTrace {
			l.logJSON(l.handler, SlogLevelTrace, format, args...)
		}
	}
}
