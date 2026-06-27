package store

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func miniStore(t *testing.T) *Store {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	st, err := New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TrackBaseline returns the pre-update EWMA and folds the observation in only
// when learning. Verifies the Lua script runs on (mini)redis and the maths hold.
func TestTrackBaseline_EWMA(t *testing.T) {
	st := miniStore(t)
	ctx := context.Background()
	ttl := time.Hour

	// First observation: baseline starts at 0 (returned), then learns toward 100.
	b0, err := st.TrackBaseline(ctx, "c1", "GET /x", 100, true, ttl)
	if err != nil {
		t.Fatalf("track: %v", err)
	}
	if b0 != 0 {
		t.Fatalf("first baseline = %v, want 0", b0)
	}
	// After one learn step with alpha=0.05: 0.05*100 + 0.95*0 = 5.
	b1, _ := st.TrackBaseline(ctx, "c1", "GET /x", 100, false, ttl) // no-learn read
	if b1 < 4.9 || b1 > 5.1 {
		t.Fatalf("baseline after one learn = %v, want ~5", b1)
	}

	// learn=false must NOT move the baseline.
	b2, _ := st.TrackBaseline(ctx, "c1", "GET /x", 9999, false, ttl)
	if b2 < 4.9 || b2 > 5.1 {
		t.Fatalf("baseline drifted on no-learn read = %v, want ~5", b2)
	}
}

// Baselines are isolated per consumer+endpoint and per tenant.
func TestTrackBaseline_Isolation(t *testing.T) {
	st := miniStore(t)
	ctx := context.Background()
	ttl := time.Hour
	_, _ = st.TrackBaseline(ctx, "c1", "GET /x", 100, true, ttl)
	// Different consumer starts fresh.
	if b, _ := st.TrackBaseline(ctx, "c2", "GET /x", 0, false, ttl); b != 0 {
		t.Fatalf("c2 baseline = %v, want 0 (isolated from c1)", b)
	}
	// Different endpoint starts fresh.
	if b, _ := st.TrackBaseline(ctx, "c1", "GET /y", 0, false, ttl); b != 0 {
		t.Fatalf("c1 GET /y baseline = %v, want 0 (isolated per endpoint)", b)
	}
}
