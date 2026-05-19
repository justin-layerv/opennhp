package log

var glbLogger *Logger

func init() {
	l := NewLogger("", 3, "", "")
	SetGlobalLogger(l)
}

// SetGlobalLogger installs l as the global logger, closes the
// previous one, and adjusts callDepth so a caller invoking the
// package-level Info/Warning/Error/... wrappers gets correct
// runtime.Caller frames. Panics on nil l: the package-level
// wrappers (Info/Warning/...) dereference glbLogger directly with
// no nil check, so a silent install of nil would surface as a
// confusing NPE at the next log site rather than at the caller
// that broke things. Use SwapGlobalLogger if you need to install
// nil intentionally (e.g., as part of an explicit shutdown).
func SetGlobalLogger(l *Logger) {
	if l == nil {
		panic("log.SetGlobalLogger: nil logger; use SwapGlobalLogger if uninstall is intended")
	}
	if glbLogger != nil {
		glbLogger.Close()
	}
	glbLogger = l
	glbLogger.callDepth += 1
}

// GlobalLogger returns the current global logger without taking
// ownership. Used with SwapGlobalLogger for snapshot/restore.
func GlobalLogger() *Logger {
	return glbLogger
}

// SwapGlobalLogger installs l as the global logger and returns the
// previous one. Lifecycle of both is the caller's responsibility:
// the previous logger is not closed, and callDepth is not adjusted
// on either logger — restoring a previously-installed logger via
// Swap therefore keeps its existing callDepth (avoiding the drift
// that Set+Set would introduce). If l is a fresh logger that should
// emit, the caller is responsible for its callDepth offset.
func SwapGlobalLogger(l *Logger) *Logger {
	prev := glbLogger
	glbLogger = l
	return prev
}

// must be called after SetGlobalLogger()
func Warning(format string, args ...any) {
	glbLogger.Warning(format, args...)
}

func Error(format string, args ...any) {
	glbLogger.Error(format, args...)
}

func Critical(format string, args ...any) {
	glbLogger.Critical(format, args...)
}

func Evaluate(format string, args ...any) {
	glbLogger.Evaluate(format, args...)
}

func Info(format string, args ...any) {
	glbLogger.Info(format, args...)
}

func Stats(format string, args ...any) {
	glbLogger.Stats(format, args...)
}

func Audit(format string, args ...any) {
	glbLogger.Audit(format, args...)
}

func Transaction(format string, args ...any) {
	glbLogger.Transaction(format, args...)
}

func Debug(format string, args ...any) {
	glbLogger.Debug(format, args...)
}

func Trace(format string, args ...any) {
	glbLogger.Trace(format, args...)
}

func Verbose(format string, args ...any) {
	glbLogger.Verbose(format, args...)
}

func Close() {
	if glbLogger != nil {
		glbLogger.Close()
	}
}
