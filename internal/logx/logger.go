package logx

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
)

const (
	levelDebug int32 = iota
	levelInfo
	levelError
)

type Logger struct {
	level      int32
	logQueries bool
	std        *log.Logger
}

func New(level string, logQueries bool) *Logger {
	l := &Logger{
		level:      parseLevel(level),
		logQueries: logQueries,
		std:        log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	return l
}

func parseLevel(level string) int32 {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return levelDebug
	case "error":
		return levelError
	default:
		return levelInfo
	}
}

func (l *Logger) Debugf(format string, args ...any) {
	if atomic.LoadInt32(&l.level) <= levelDebug {
		l.std.Printf("DEBUG %s", fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Infof(format string, args ...any) {
	if atomic.LoadInt32(&l.level) <= levelInfo {
		l.std.Printf("INFO %s", fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Errorf(format string, args ...any) {
	if atomic.LoadInt32(&l.level) <= levelError {
		l.std.Printf("ERROR %s", fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Queryf(format string, args ...any) {
	if !l.logQueries {
		return
	}
	l.Infof(format, args...)
}
