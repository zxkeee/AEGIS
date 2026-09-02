package forensic

import (
	"testing"

	"api-gateway/internal/store"
)

// The buffer fills exactly when the forensic record matters most — a burst of
// blocks is an attack in progress. Dropping there is the right trade (the
// alternative is stalling the request path), but dropping SILENTLY leaves an
// operator unable to tell a complete evidence trail from one missing most of
// the incident.
//
// The drop used to be unreported, justified in a comment by "Redis still has
// the event, so no data is truly lost". That does not hold: store.PushForensic
// trims its ring to 1000 entries, so the same burst that overflows this
// 4096-entry buffer rolls the ring several times over and both copies go
// together.
func TestPGSink_DropsAreCounted(t *testing.T) {
	s := &PGSink{ch: make(chan store.ForensicEntry, 8)}

	const burst = 100
	for i := 0; i < burst; i++ {
		s.Push(store.ForensicEntry{Reason: "waf_blocked", IP: "1.2.3.4"})
	}

	buffered := len(s.ch)
	if buffered != cap(s.ch) {
		t.Fatalf("buffered %d of %d: the fixture did not actually overflow", buffered, cap(s.ch))
	}
	want := int64(burst - buffered)
	if got := s.Dropped(); got != want {
		t.Fatalf("Dropped() = %d, want %d — a silent gap in the evidence trail", got, want)
	}
}

// Entries that fit must not be counted as dropped, or the signal is noise.
func TestPGSink_NoDropsWhenBufferFits(t *testing.T) {
	s := &PGSink{ch: make(chan store.ForensicEntry, 64)}
	for i := 0; i < 10; i++ {
		s.Push(store.ForensicEntry{Reason: "waf_blocked"})
	}
	if got := s.Dropped(); got != 0 {
		t.Fatalf("Dropped() = %d with room to spare, want 0", got)
	}
}

// A nil sink is what a deployment without forensic_dsn has; asking it for the
// count must not panic.
func TestPGSink_DroppedOnNilSink(t *testing.T) {
	var s *PGSink
	if got := s.Dropped(); got != 0 {
		t.Fatalf("Dropped() on nil sink = %d, want 0", got)
	}
}
