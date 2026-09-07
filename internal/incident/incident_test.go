package incident

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)

func inc(detected time.Time, notifs ...Notification) *Incident {
	return &Incident{DetectedAt: detected, LastEventAt: detected, Notifications: notifs}
}

func deadline(t *testing.T, ds []Deadline, kind DeadlineKind) Deadline {
	t.Helper()
	for _, d := range ds {
		if d.Kind == kind {
			return d
		}
	}
	t.Fatalf("no %s deadline in %+v", kind, ds)
	return Deadline{}
}

// The three obligations NIS2 Art. 23(4) states, from the moment of detection.
func TestDeadlines_NIS2Timetable(t *testing.T) {
	ds := inc(t0).Deadlines(DefaultSchedule, t0)

	if got := deadline(t, ds, KindEarlyWarning).Due; !got.Equal(t0.Add(24 * time.Hour)) {
		t.Errorf("early warning due %s, want detection + 24h", got)
	}
	if got := deadline(t, ds, KindNotification).Due; !got.Equal(t0.Add(72 * time.Hour)) {
		t.Errorf("notification due %s, want detection + 72h", got)
	}
	for _, d := range ds {
		if d.Article == "" {
			t.Errorf("%s carries no article reference; a reader has to go look it up", d.Kind)
		}
	}
}

// Art. 23(4)(d) runs the final report from the SUBMISSION of the notification,
// not from detection. Anchoring it to detection hands an operator up to three
// days they do not have.
func TestDeadlines_FinalReportRunsFromTheSubmission(t *testing.T) {
	t.Run("notification not yet sent", func(t *testing.T) {
		ds := inc(t0).Deadlines(DefaultSchedule, t0)
		want := t0.Add(72 * time.Hour).Add(30 * 24 * time.Hour)
		if got := deadline(t, ds, KindFinalReport).Due; !got.Equal(want) {
			t.Errorf("final due %s, want %s (notification deadline + one month)", got, want)
		}
	})

	t.Run("notification sent early", func(t *testing.T) {
		sent := t0.Add(2 * time.Hour)
		ds := inc(t0, Notification{Kind: KindNotification, SentAt: sent}).Deadlines(DefaultSchedule, t0)
		want := sent.Add(30 * 24 * time.Hour)
		got := deadline(t, ds, KindFinalReport).Due
		if !got.Equal(want) {
			t.Fatalf("final due %s, want %s (submission + one month)", got, want)
		}
		// Submitting early must bring the final report FORWARD, not leave it
		// anchored to a deadline that never applied.
		if !got.Before(t0.Add(72 * time.Hour).Add(30 * 24 * time.Hour)) {
			t.Error("an early submission did not move the final report forward")
		}
	})
}

func TestDeadlines_OverdueAndSubmitted(t *testing.T) {
	late := t0.Add(25 * time.Hour)

	t.Run("nothing submitted", func(t *testing.T) {
		d := deadline(t, inc(t0).Deadlines(DefaultSchedule, late), KindEarlyWarning)
		if !d.Overdue {
			t.Error("24h passed with no early warning and it is not marked overdue")
		}
		if !inc(t0).Overdue(DefaultSchedule, late) {
			t.Error("the incident does not report itself overdue")
		}
	})

	t.Run("submitted in time", func(t *testing.T) {
		sent := t0.Add(3 * time.Hour)
		i := inc(t0, Notification{Kind: KindEarlyWarning, SentAt: sent})
		d := deadline(t, i.Deadlines(DefaultSchedule, late), KindEarlyWarning)
		if d.Overdue {
			t.Error("a submitted obligation is still marked overdue")
		}
		if d.SentAt == nil || !d.SentAt.Equal(sent) {
			t.Errorf("sent_at = %v, want %s", d.SentAt, sent)
		}
	})
}

// A missed obligation does not stop having been missed because someone closed
// the incident afterwards. Hiding that would be the most dangerous kind of
// wrong this package could be.
func TestDeadlines_ClosingDoesNotEraseAMissedObligation(t *testing.T) {
	closed := t0.Add(40 * time.Hour)
	i := inc(t0)
	i.Status = StatusClosed
	i.ClosedAt = &closed

	if !i.Overdue(DefaultSchedule, closed) {
		t.Fatal("closing the incident cleared a missed 24h early warning")
	}
}

// Two submissions of the same kind: the earliest is the one that met the
// deadline, so it is the one reported.
func TestDeadlines_EarliestSubmissionWins(t *testing.T) {
	early := t0.Add(2 * time.Hour)
	// The later submission comes SECOND in the slice on purpose. With the
	// earliest-wins comparison removed, a "last one wins" implementation would
	// pick it — and an ordering that let that pass would make this test
	// decorative.
	i := inc(t0,
		Notification{Kind: KindEarlyWarning, SentAt: early},
		Notification{Kind: KindEarlyWarning, SentAt: t0.Add(20 * time.Hour)},
	)
	d := deadline(t, i.Deadlines(DefaultSchedule, t0.Add(48*time.Hour)), KindEarlyWarning)
	if d.SentAt == nil || !d.SentAt.Equal(early) {
		t.Errorf("sent_at = %v, want the earliest submission %s", d.SentAt, early)
	}
}

// Art. 18 lists six criteria; a gateway can observe three. A report that does
// not distinguish "zero" from "we did not measure this" invites a reader to
// treat a blank as a finding.
func TestClassification_NamesWhatOnlyAHumanCanSupply(t *testing.T) {
	var c Classification
	missing := c.Missing()
	if len(missing) != 3 {
		t.Fatalf("missing = %v, want the three operator-supplied criteria", missing)
	}
	for _, want := range []string{"clients_affected", "geographic_spread", "economic_impact_eur"} {
		var found bool
		for _, m := range missing {
			if len(m) >= len(want) && m[:len(want)] == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not listed as missing: %v", want, missing)
		}
	}
	for _, m := range missing {
		if !containsArticle(m) {
			t.Errorf("%q does not name its DORA article", m)
		}
	}
	if c.Complete() {
		t.Error("an empty classification reports itself complete")
	}
}

func containsArticle(s string) bool {
	for i := 0; i+8 <= len(s); i++ {
		if s[i:i+8] == "Art. 18(" {
			return true
		}
	}
	return false
}

func TestClassification_CompleteOnceFilled(t *testing.T) {
	n, geo, eur := 12, "EU", 4000.0
	c := Classification{ClientsAffected: &n, GeographicSpread: &geo, EconomicImpactEUR: &eur}
	if !c.Complete() {
		t.Fatalf("still incomplete: %v", c.Missing())
	}
	// Zero is a real answer and must count as supplied.
	zero := 0
	c2 := Classification{ClientsAffected: &zero, GeographicSpread: &geo, EconomicImpactEUR: &eur}
	if !c2.Complete() {
		t.Error("clients_affected = 0 was treated as unanswered")
	}
}

func TestProposeSeverity(t *testing.T) {
	cases := []struct {
		name  string
		c     Classification
		count int
		want  Severity
	}{
		{"critical service holding data", Classification{CriticalService: true, DataAtRisk: []string{"email"}}, 1, SeverityMajor},
		{"critical service alone", Classification{CriticalService: true}, 1, SeveritySignificant},
		{"data alone", Classification{DataAtRisk: []string{"card"}}, 1, SeveritySignificant},
		{"wide across endpoints", Classification{EndpointsAffected: 5}, 1, SeveritySignificant},
		{"sustained volume", Classification{}, 100, SeveritySignificant},
		{"a handful of probes", Classification{EndpointsAffected: 1}, 3, SeverityMinor},
	}
	for _, tc := range cases {
		if got := ProposeSeverity(tc.c, tc.count); got != tc.want {
			t.Errorf("%s: severity = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestStatusAndSeverityValidation(t *testing.T) {
	for _, s := range []Status{StatusOpen, StatusContained, StatusClosed} {
		if !s.Valid() {
			t.Errorf("%s rejected", s)
		}
	}
	for _, s := range []Status{"", "resolved", "OPEN", "deleted"} {
		if s.Valid() {
			t.Errorf("%q accepted as a status", s)
		}
	}
	for _, s := range []Severity{SeverityMinor, SeveritySignificant, SeverityMajor} {
		if !s.Valid() {
			t.Errorf("%s rejected", s)
		}
	}
	for _, s := range []Severity{"", "critical", "MAJOR"} {
		if s.Valid() {
			t.Errorf("%q accepted as a severity", s)
		}
	}
	if severityRank(SeverityMajor) <= severityRank(SeveritySignificant) ||
		severityRank(SeveritySignificant) <= severityRank(SeverityMinor) {
		t.Error("severity ranking is not ordered")
	}
}

func TestSummarise(t *testing.T) {
	late := t0.Add(100 * time.Hour)
	n, geo, eur := 1, "EU", 0.0
	full := Classification{ClientsAffected: &n, GeographicSpread: &geo, EconomicImpactEUR: &eur}

	list := []Incident{
		{DetectedAt: t0, Status: StatusOpen},                           // overdue, unclassified
		{DetectedAt: late, Status: StatusClosed, Classification: full}, // classified
		{DetectedAt: late, Status: StatusContained, SeverityConfirmed: true, // notified
			Notifications: []Notification{{Kind: KindEarlyWarning, SentAt: late}}},
	}
	st := Summarise(list, DefaultSchedule, late)

	// Contained is its own count. Folding it into "open" would describe a queue
	// where DORA Art. 17 asks about a process.
	want := Stats{Total: 3, Open: 1, Contained: 1, Closed: 1, Classified: 1, Notified: 1, Overdue: 1, SeverityByHand: 1}
	if st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
}

func TestTitle(t *testing.T) {
	if got := Title("bola", "jwt:alice"); got != "Object-level authorization abuse from jwt:alice" {
		t.Errorf("title = %q", got)
	}
	// An unmapped class must still read as English, not as an identifier.
	if got := Title("some_new_class", "1.2.3.4"); got != "some new class from 1.2.3.4" {
		t.Errorf("unmapped class title = %q", got)
	}
	if got := Title("bola", ""); got != "Object-level authorization abuse" {
		t.Errorf("subjectless title = %q", got)
	}
}
