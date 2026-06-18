package log

import "sync/atomic"

var glbLogger atomic.Pointer[Logger]

func init() {
	l := NewLogger("", 3, "", "")
	SetGlobalLogger(l)
}

// SetGlobalLogger installs l as the global logger, closes the
// previous one, and adjusts callDepth so a caller invoking the
// package-level Info/Warning/Error/... wrappers gets correct
// runtime.Caller frames. Panics on nil l: the package-level
// wrappers (Info/Warning/...) dereference the loaded global logger
// directly with no nil check, so a silent install of nil would surface as a
// confusing NPE at the next log site rather than at the caller
// that broke things. Use SwapGlobalLogger if you need to install
// nil intentionally (e.g., as part of an explicit shutdown).
func SetGlobalLogger(l *Logger) {
	if l == nil {
		panic("log.SetGlobalLogger: nil logger; use SwapGlobalLogger if uninstall is intended")
	}
	l.callDepth += 1
	if prev := glbLogger.Swap(l); prev != nil {
		prev.Close()
	}
}

// GlobalLogger returns the current global logger without taking
// ownership. Used with SwapGlobalLogger for snapshot/restore.
func GlobalLogger() *Logger {
	return glbLogger.Load()
}

// SwapGlobalLogger installs l as the global logger and returns the
// previous one. Lifecycle of both is the caller's responsibility:
// the previous logger is not closed, and callDepth is not adjusted
// on either logger — restoring a previously-installed logger via
// Swap therefore keeps its existing callDepth (avoiding the drift
// that Set+Set would introduce). If l is a fresh logger that should
// emit, the caller is responsible for its callDepth offset.
func SwapGlobalLogger(l *Logger) *Logger {
	return glbLogger.Swap(l)
}

// must be called after SetGlobalLogger()
func Warning(format string, args ...any) {
	glbLogger.Load().Warning(format, args...)
}

func Error(format string, args ...any) {
	glbLogger.Load().Error(format, args...)
}

func Critical(format string, args ...any) {
	glbLogger.Load().Critical(format, args...)
}

func Evaluate(format string, args ...any) {
	glbLogger.Load().Evaluate(format, args...)
}

func Info(format string, args ...any) {
	glbLogger.Load().Info(format, args...)
}

func Stats(format string, args ...any) {
	glbLogger.Load().Stats(format, args...)
}

func Audit(format string, args ...any) {
	glbLogger.Load().Audit(format, args...)
}

func Transaction(format string, args ...any) {
	glbLogger.Load().Transaction(format, args...)
}

func Debug(format string, args ...any) {
	glbLogger.Load().Debug(format, args...)
}

func Trace(format string, args ...any) {
	glbLogger.Load().Trace(format, args...)
}

func Verbose(format string, args ...any) {
	glbLogger.Load().Verbose(format, args...)
}

func Close() {
	if l := glbLogger.Load(); l != nil {
		l.Close()
	}
}
