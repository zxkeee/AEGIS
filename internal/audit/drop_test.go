package audit

import "testing"

// The admin action trail has the same shape as the forensic one: a full buffer
// drops rather than blocking, so the loss has to be counted or an incomplete
// trail is indistinguishable from a quiet period. Reporting moved off the
// per-entry path because the overflow is a burst, and a line per dropped entry
// answers a flood of events with a flood of logs.
func TestStore_DropsAreCounted(t *testing.T) {
	s := &Store{ch: make(chan Entry, 4)}

	const burst = 40
	for i := 0; i < burst; i++ {
		s.Record(Entry{Action: "mutation", Path: "/api/x"})
	}
	buffered := len(s.ch)
	if buffered != cap(s.ch) {
		t.Fatalf("buffered %d of %d: the fixture did not actually overflow", buffered, cap(s.ch))
	}
	if got, want := s.Dropped(), int64(burst-buffered); got != want {
		t.Fatalf("Dropped() = %d, want %d", got, want)
	}
}

func TestStore_DroppedOnNilStore(t *testing.T) {
	var s *Store
	if got := s.Dropped(); got != 0 {
		t.Fatalf("Dropped() on nil store = %d, want 0", got)
	}
}
