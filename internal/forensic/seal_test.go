package forensic

import (
	"testing"
	"time"
)

var sealT0 = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func digestsFor(n int) [][]byte {
	out := make([][]byte, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, entryDigest(int64(i), sealT0, "acme", "1.2.3.4",
			"/api/orders", "GET", "waf_blocked", 403))
	}
	return out
}

// The property the whole mechanism exists for: remove an entry and the root
// stops matching. Everything else here is in service of this one line.
func TestMerkleRoot_DetectsADeletedEntry(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 8, 9, 17, 100} {
		full := digestsFor(n)
		before := merkleRoot(full)

		if n == 1 {
			// A single entry removed leaves the empty root, which must still
			// differ.
			if merkleRoot(nil) == before {
				t.Errorf("n=1: deleting the only entry left the root unchanged")
			}
			continue
		}
		// Drop one from the middle — the case an operator would choose.
		cut := make([][]byte, 0, n-1)
		cut = append(cut, full[:n/2]...)
		cut = append(cut, full[n/2+1:]...)
		if after := merkleRoot(cut); after == before {
			t.Errorf("n=%d: removing entry %d left the root unchanged", n, n/2)
		}
	}
}

// Reordering must change the root too: the order is part of what was sealed,
// and "the same rows in a different order" is a different log.
func TestMerkleRoot_DetectsReordering(t *testing.T) {
	d := digestsFor(6)
	before := merkleRoot(d)
	d[1], d[4] = d[4], d[1]
	if merkleRoot(d) == before {
		t.Error("swapping two entries left the root unchanged")
	}
}

// An odd node is promoted, never duplicated. Duplicating it is CVE-2012-2459:
// a tree of N entries and one of N+1 (the last repeated) produce the same root,
// so an entry can be added without changing it.
func TestMerkleRoot_OddNodeIsNotDuplicated(t *testing.T) {
	three := digestsFor(3)
	four := append(digestsFor(3), three[2]) // the last entry repeated
	if merkleRoot(three) == merkleRoot(four) {
		t.Error("a duplicated tail produces the same root as the original tree; " +
			"an entry can be appended without changing the seal")
	}
}

// Recomputing the same period must give the same bytes — a seal is verified by
// recomputation, so an unstable root would make every honest log look tampered.
func TestMerkleRoot_IsStable(t *testing.T) {
	a := merkleRoot(digestsFor(9))
	for i := 0; i < 50; i++ {
		if merkleRoot(digestsFor(9)) != a {
			t.Fatal("the root is not stable across recomputation")
		}
	}
}

// The digest is length-prefixed so field content cannot move a boundary.
//
// The pair below is an actual collision under the delimiter-joined encoding
// this replaced: with each field written as `value:`, ip="1.2.3.4" + path=":x"
// and ip="1.2.3.4:" + path="x" both produce `1.2.3.4::x:`. Two different rows,
// one digest — so an entry could be swapped for another without disturbing the
// seal.
//
// The first version of this test used ip/method instead, which are NOT adjacent
// in the field order, so the two encodings differed anyway and the test passed
// with length-prefixing removed. It was green for the wrong reason; the
// mutation that should have caught that is what caught this.
func TestEntryDigest_FieldsCannotBeShifted(t *testing.T) {
	// ip and path are adjacent — the boundary an attacker-supplied path can
	// reach.
	a := entryDigest(1, sealT0, "acme", "1.2.3.4", ":x", "GET", "waf_blocked", 403)
	b := entryDigest(1, sealT0, "acme", "1.2.3.4:", "x", "GET", "waf_blocked", 403)
	if string(a) == string(b) {
		t.Error("two different entries produced the same digest: a field boundary moved")
	}

	// The same shape across tenant and ip.
	c := entryDigest(1, sealT0, "acme", ":1.2.3.4", "/x", "GET", "waf_blocked", 403)
	d := entryDigest(1, sealT0, "acme:", "1.2.3.4", "/x", "GET", "waf_blocked", 403)
	if string(c) == string(d) {
		t.Error("tenant and ip collided")
	}

	// And across method and reason, which bracket the numeric code.
	e := entryDigest(1, sealT0, "acme", "1.2.3.4", "/x", "GET", ":r", 403)
	f := entryDigest(1, sealT0, "acme", "1.2.3.4", "/x", "GET:", "r", 403)
	if string(e) == string(f) {
		t.Error("method and reason collided")
	}
}

// Timezone must not change the digest: a seal recomputed in another session
// has to produce the same bytes.
func TestEntryDigest_IsTimezoneIndependent(t *testing.T) {
	utc := entryDigest(1, sealT0, "acme", "1.2.3.4", "/x", "GET", "r", 403)
	kyiv, err := time.LoadLocation("Europe/Kyiv")
	if err != nil {
		t.Skipf("no tzdata: %v", err)
	}
	local := entryDigest(1, sealT0.In(kyiv), "acme", "1.2.3.4", "/x", "GET", "r", 403)
	if string(utc) != string(local) {
		t.Error("the same instant in another timezone produced a different digest")
	}
}

// The previous root is inside the signed payload. Without that the seals are
// independent claims and a single period can be re-sealed in isolation.
func TestSealPayload_CommitsToThePreviousRoot(t *testing.T) {
	a := sealPayload("acme", sealT0, sealT0.Add(time.Hour), 10, "root", "prevA")
	b := sealPayload("acme", sealT0, sealT0.Add(time.Hour), 10, "root", "prevB")
	if string(a) == string(b) {
		t.Error("the payload ignores prev_root; the chain is not a chain")
	}
}

func TestSealPayload_CommitsToEveryField(t *testing.T) {
	base := sealPayload("acme", sealT0, sealT0.Add(time.Hour), 10, "root", "prev")
	for name, got := range map[string][]byte{
		"tenant": sealPayload("globex", sealT0, sealT0.Add(time.Hour), 10, "root", "prev"),
		"from":   sealPayload("acme", sealT0.Add(time.Minute), sealT0.Add(time.Hour), 10, "root", "prev"),
		"to":     sealPayload("acme", sealT0, sealT0.Add(2*time.Hour), 10, "root", "prev"),
		"count":  sealPayload("acme", sealT0, sealT0.Add(time.Hour), 11, "root", "prev"),
		"root":   sealPayload("acme", sealT0, sealT0.Add(time.Hour), 10, "other", "prev"),
	} {
		if string(got) == string(base) {
			t.Errorf("changing %s did not change the signed payload", name)
		}
	}
}

// short truncates a root for a message a human reads. It is in the failure
// path of every chain-break report, so a panic here would replace "the chain is
// broken" with a crash at the moment an operator most needs the message.
func TestShort(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"abc":           "abc",
		"123456789012":  "123456789012",
		"1234567890123": "123456789012…",
	}
	for in, want := range cases {
		if got := short(in); got != want {
			t.Errorf("short(%q) = %q, want %q", in, got, want)
		}
	}
}

// An empty period still gets a root. "Nothing happened in this hour" is a claim
// worth committing to: without it, a period with no entries is
// indistinguishable from a period whose entries were all deleted.
func TestMerkleRoot_EmptyPeriodHasAStableRoot(t *testing.T) {
	a := merkleRoot(nil)
	b := merkleRoot([][]byte{})
	if a == "" {
		t.Fatal("an empty period produced no root")
	}
	if a != b {
		t.Error("nil and empty produced different roots")
	}
	// And it must differ from a period that has one entry.
	if a == merkleRoot(digestsFor(1)) {
		t.Error("an empty period and a one-entry period share a root")
	}
}

// SealSchedule defaults are applied by the constructor, not assumed by callers.
func TestNewSealWorker_AppliesDefaults(t *testing.T) {
	for _, in := range []SealSchedule{
		{},
		{Period: -time.Hour, Lag: -time.Minute},
		{Period: 0, Lag: 0},
	} {
		w := NewSealWorker(nil, in, nil, nil, nopLogger{})
		if w.cfg.Period <= 0 || w.cfg.Lag <= 0 {
			t.Errorf("NewSealWorker(%+v) left period=%v lag=%v; a non-positive period "+
				"makes the ticker panic and a non-positive lag seals an open window",
				in, w.cfg.Period, w.cfg.Lag)
		}
	}
}
