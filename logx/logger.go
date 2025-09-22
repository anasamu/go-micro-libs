package logx

import (
	"context"

	"github.com/sirupsen/logrus"
)

// Level represents log level in facade
type Level string

const (
	Trace Level = "trace"
	Debug Level = "debug"
	Info  Level = "info"
	Warn  Level = "warn"
	Error Level = "error"
	Fatal Level = "fatal"
	Panic Level = "panic"
)

// Logger is a minimal standard logging facade
type Logger interface {
	WithFields(fields map[string]interface{}) Logger
	WithError(err error) Logger
	WithContext(ctx context.Context) Logger

	Log(level Level, msg string)
	Trace(msg string)
	Debug(msg string)
	Info(msg string)
	Warn(msg string)
	Error(msg string)
	Fatal(msg string)
	Panic(msg string)

	// Formatted
	Tracef(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Panicf(format string, args ...interface{})
}

// LogrusAdapter adapts logrus.Logger to the Logger interface
type LogrusAdapter struct{ l *logrus.Logger }

func NewLogrusAdapter(l *logrus.Logger) *LogrusAdapter { return &LogrusAdapter{l: l} }

func (a *LogrusAdapter) WithFields(fields map[string]interface{}) Logger {
	return &LogrusEntryAdapter{e: a.l.WithFields(logrus.Fields(fields))}
}

func (a *LogrusAdapter) WithError(err error) Logger {
	return &LogrusEntryAdapter{e: a.l.WithError(err)}
}
func (a *LogrusAdapter) WithContext(ctx context.Context) Logger {
	return &LogrusEntryAdapter{e: a.l.WithContext(ctx)}
}

func (a *LogrusAdapter) Log(level Level, msg string) {
	entryLog(a.l.WithContext(context.Background()), level, msg)
}
func (a *LogrusAdapter) Trace(msg string)                          { a.l.Trace(msg) }
func (a *LogrusAdapter) Debug(msg string)                          { a.l.Debug(msg) }
func (a *LogrusAdapter) Info(msg string)                           { a.l.Info(msg) }
func (a *LogrusAdapter) Warn(msg string)                           { a.l.Warn(msg) }
func (a *LogrusAdapter) Error(msg string)                          { a.l.Error(msg) }
func (a *LogrusAdapter) Fatal(msg string)                          { a.l.Fatal(msg) }
func (a *LogrusAdapter) Panic(msg string)                          { a.l.Panic(msg) }
func (a *LogrusAdapter) Tracef(format string, args ...interface{}) { a.l.Tracef(format, args...) }
func (a *LogrusAdapter) Debugf(format string, args ...interface{}) { a.l.Debugf(format, args...) }
func (a *LogrusAdapter) Infof(format string, args ...interface{})  { a.l.Infof(format, args...) }
func (a *LogrusAdapter) Warnf(format string, args ...interface{})  { a.l.Warnf(format, args...) }
func (a *LogrusAdapter) Errorf(format string, args ...interface{}) { a.l.Errorf(format, args...) }
func (a *LogrusAdapter) Fatalf(format string, args ...interface{}) { a.l.Fatalf(format, args...) }
func (a *LogrusAdapter) Panicf(format string, args ...interface{}) { a.l.Panicf(format, args...) }

// LogrusEntryAdapter adapts logrus.Entry to Logger
type LogrusEntryAdapter struct{ e *logrus.Entry }

func (a *LogrusEntryAdapter) WithFields(fields map[string]interface{}) Logger {
	return &LogrusEntryAdapter{e: a.e.WithFields(logrus.Fields(fields))}
}
func (a *LogrusEntryAdapter) WithError(err error) Logger {
	return &LogrusEntryAdapter{e: a.e.WithError(err)}
}
func (a *LogrusEntryAdapter) WithContext(ctx context.Context) Logger {
	return &LogrusEntryAdapter{e: a.e.WithContext(ctx)}
}

func (a *LogrusEntryAdapter) Log(level Level, msg string)               { entryLog(a.e, level, msg) }
func (a *LogrusEntryAdapter) Trace(msg string)                          { a.e.Trace(msg) }
func (a *LogrusEntryAdapter) Debug(msg string)                          { a.e.Debug(msg) }
func (a *LogrusEntryAdapter) Info(msg string)                           { a.e.Info(msg) }
func (a *LogrusEntryAdapter) Warn(msg string)                           { a.e.Warn(msg) }
func (a *LogrusEntryAdapter) Error(msg string)                          { a.e.Error(msg) }
func (a *LogrusEntryAdapter) Fatal(msg string)                          { a.e.Fatal(msg) }
func (a *LogrusEntryAdapter) Panic(msg string)                          { a.e.Panic(msg) }
func (a *LogrusEntryAdapter) Tracef(format string, args ...interface{}) { a.e.Tracef(format, args...) }
func (a *LogrusEntryAdapter) Debugf(format string, args ...interface{}) { a.e.Debugf(format, args...) }
func (a *LogrusEntryAdapter) Infof(format string, args ...interface{})  { a.e.Infof(format, args...) }
func (a *LogrusEntryAdapter) Warnf(format string, args ...interface{})  { a.e.Warnf(format, args...) }
func (a *LogrusEntryAdapter) Errorf(format string, args ...interface{}) { a.e.Errorf(format, args...) }
func (a *LogrusEntryAdapter) Fatalf(format string, args ...interface{}) { a.e.Fatalf(format, args...) }
func (a *LogrusEntryAdapter) Panicf(format string, args ...interface{}) { a.e.Panicf(format, args...) }

func entryLog(e *logrus.Entry, level Level, msg string) {
	switch level {
	case Trace:
		e.Trace(msg)
	case Debug:
		e.Debug(msg)
	case Info:
		e.Info(msg)
	case Warn:
		e.Warn(msg)
	case Error:
		e.Error(msg)
	case Fatal:
		e.Fatal(msg)
	case Panic:
		e.Panic(msg)
	default:
		e.Info(msg)
	}
}
