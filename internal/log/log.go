package log

import (
	"github.com/nextlinux/go-logger"
	"github.com/nextlinux/go-logger/adapter/discard"
	"github.com/nextlinux/go-logger/adapter/redact"
)

var (
	log   = discard.New()
	store = redact.NewStore()
)

func init() {
	// why redact the default discard logger? there may be sensitive information added to the redact store
	// before the logger is set. This ensures that any future loggers will still redact the sensitive information.
	// from previous Redact() calls.
	log = redact.New(log, store)
}

func Set(l logger.Logger) {
	log = redact.New(l, store)
}

func Redact(value ...string) {
	store.Add(value...)
}

// Errorf takes a formatted template string and template arguments for the error logging level.
func Errorf(format string, args ...interface{}) {
	log.Errorf(format, args...)
}

// Error logs the given arguments at the error logging level.
func Error(args ...interface{}) {
	log.Error(args...)
}

// Warnf takes a formatted template string and template arguments for the warning logging level.
func Warnf(format string, args ...interface{}) {
	log.Warnf(format, args...)
}

// Warn logs the given arguments at the warning logging level.
func Warn(args ...interface{}) {
	log.Warn(args...)
}

// Infof takes a formatted template string and template arguments for the info logging level.
func Infof(format string, args ...interface{}) {
	log.Infof(format, args...)
}

// Info logs the given arguments at the info logging level.
func Info(args ...interface{}) {
	log.Info(args...)
}

// Debugf takes a formatted template string and template arguments for the debug logging level.
func Debugf(format string, args ...interface{}) {
	log.Debugf(format, args...)
}

// Debug logs the given arguments at the debug logging level.
func Debug(args ...interface{}) {
	log.Debug(args...)
}

// Tracef takes a formatted template string and template arguments for the trace logging level.
func Tracef(format string, args ...interface{}) {
	log.Tracef(format, args...)
}

// Trace logs the given arguments at the trace logging level.
func Trace(args ...interface{}) {
	log.Trace(args...)
}

// WithFields returns a message logger with multiple key-value fields.
func WithFields(fields ...interface{}) logger.MessageLogger {
	return log.WithFields(fields...)
}

// Nested returns a new logger with hard coded key-value pairs
func Nested(fields ...interface{}) logger.Logger {
	return log.Nested(fields...)
}
