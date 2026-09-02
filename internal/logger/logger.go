package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger provides structured JSON logging.
type Logger struct {
	mu    sync.Mutex
	level string
}

// New creates a Logger with the specified level (debug, info, warn, error).
func New(level string) *Logger {
	if level == "" {
		level = "info"
	}
	return &Logger{level: level}
}

func (l *Logger) shouldLog(level string) bool {
	order := map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}
	return order[level] >= order[l.level]
}

func (l *Logger) log(level, msg string, fields map[string]any) {
	if !l.shouldLog(level) {
		return
	}
	entry := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": level,
		"msg":   msg,
	}
	for k, v := range fields {
		entry[k] = v
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := json.Marshal(entry)
	if err != nil {
		// A field that cannot be marshalled used to discard the whole entry:
		// json.Marshal returned nil and the logger printed an empty line. A
		// security event would vanish leaving no trace at all — not a truncated
		// record, not an error, nothing. Reachable from any non-finite float
		// (an Inf or NaN fails encoding), which a future ratio or average can
		// produce without anyone noticing.
		//
		// Drop the fields, keep the event. What the entry says may be poorer;
		// that an entry happened must never be in doubt.
		data, err = json.Marshal(map[string]any{
			"ts":          entry["ts"],
			"level":       level,
			"msg":         msg,
			"log_error":   err.Error(),
			"log_dropped": "fields could not be encoded",
		})
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout, "{\"level\":%q,\"msg\":%q,\"log_error\":\"encode failed\"}\n", level, msg)
			return
		}
	}
	_, _ = fmt.Fprintln(os.Stdout, string(data))
}

// Info logs an informational message.
func (l *Logger) Info(msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log("info", msg, f)
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log("warn", msg, f)
}

// Error logs an error message.
func (l *Logger) Error(msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log("error", msg, f)
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log("debug", msg, f)
}

// BlockEvent logs a security block event.
func (l *Logger) BlockEvent(reason, ip, path, method string, extra map[string]any) {
	fields := map[string]any{
		"event":  "security_block",
		"reason": reason,
		"ip":     ip,
		"path":   path,
		"method": method,
	}
	for k, v := range extra {
		fields[k] = v
	}
	l.log("warn", "request blocked", fields)
}

func mergeFields(fields []map[string]any) map[string]any {
	result := make(map[string]any)
	for _, f := range fields {
		for k, v := range f {
			result[k] = v
		}
	}
	return result
}
