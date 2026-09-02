package logger

import (
	"encoding/json"
	"io"
	"math"
	"os"
	"strings"
	"testing"
)

// capture runs fn with stdout redirected and returns the non-empty lines it
// produced.
func capture(t *testing.T, fn func()) []string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()
	_ = w.Close()
	os.Stdout = old

	var out []string
	for _, l := range strings.Split(<-done, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// A field that cannot be encoded used to discard the whole entry: json.Marshal
// returned nil and the logger printed an empty line, so a security event
// vanished leaving no trace — not a truncated record, not an error, nothing.
// Any non-finite float does it, which a future ratio or average can produce
// without anyone noticing.
func TestLog_NonEncodableFieldDoesNotLoseTheEntry(t *testing.T) {
	for _, bad := range []any{math.Inf(1), math.Inf(-1), math.NaN(), make(chan int)} {
		lines := capture(t, func() {
			New("info").Warn("request blocked", map[string]any{"reason": "bola_enumeration", "x": bad})
		})
		if len(lines) != 1 {
			t.Fatalf("value %v: got %d lines, want exactly 1 — the event was lost", bad, len(lines))
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
			t.Fatalf("value %v: emitted line is not JSON: %q", bad, lines[0])
		}
		if entry["msg"] != "request blocked" || entry["level"] != "warn" {
			t.Errorf("value %v: the surviving entry lost its identity: %v", bad, entry)
		}
		if entry["log_error"] == nil {
			t.Errorf("value %v: nothing marks the entry as degraded, so a reader cannot tell fields are missing", bad)
		}
	}
}

// The ordinary path must stay a single well-formed JSON object carrying its
// fields — the degraded path above is a fallback, not the norm.
func TestLog_NormalEntryCarriesItsFields(t *testing.T) {
	lines := capture(t, func() {
		New("info").Warn("request blocked", map[string]any{"reason": "waf", "code": 403})
	})
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("not JSON: %q", err)
	}
	if entry["reason"] != "waf" || entry["msg"] != "request blocked" {
		t.Errorf("entry = %v, want the message and fields preserved", entry)
	}
	if entry["log_error"] != nil {
		t.Error("an encodable entry must not be marked degraded")
	}
}

// Values a client controls reach these fields (paths, headers, reasons). JSON
// encoding is what stops a newline or a quote from forging a second record;
// assert it rather than assume it.
func TestLog_ClientControlledValuesCannotForgeARecord(t *testing.T) {
	evil := "x\n{\"level\":\"info\",\"msg\":\"nothing happened\"}"
	lines := capture(t, func() {
		New("info").BlockEvent("waf", "1.2.3.4", evil, "GET", nil)
	})
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1 — a newline in a field split the record", len(lines))
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if entry["path"] != evil {
		t.Errorf("path = %v, want the raw value preserved (escaped, not altered)", entry["path"])
	}
}

// Below-threshold levels must produce nothing at all.
func TestLog_LevelGate(t *testing.T) {
	lines := capture(t, func() {
		l := New("error")
		l.Debug("d")
		l.Info("i")
		l.Warn("w")
		l.Error("e")
	})
	if len(lines) != 1 {
		t.Fatalf("got %d lines at level=error, want 1", len(lines))
	}
	if !strings.Contains(lines[0], `"msg":"e"`) {
		t.Errorf("wrong entry survived the gate: %q", lines[0])
	}
}
