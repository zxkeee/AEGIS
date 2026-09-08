// Package incident turns a stream of security events into incidents that can be
// managed and reported.
//
// It exists because AEGIS could detect and record, but not account. Regulators
// do not ask "how many events did you log"; they ask what happened, how bad it
// was, and whether you told them in time. NIS2 Art. 23 and DORA Art. 17-19 are
// about an object with a lifecycle, a classification and deadlines — none of
// which a log line has.
//
// Two honesty rules run through this package:
//
//   - Anything the gateway cannot observe is a field a human fills in, never a
//     number this code invents. A tool that guesses at economic impact is worse
//     than one that leaves it blank, because the guess reaches a regulator.
//   - The only deadlines hard-coded here are the ones written in the NIS2
//     directive itself. DORA's limits are set by the regulatory technical
//     standards under Art. 20, not by the regulation, so its schedule is
//     configuration — see Schedule.
package incident

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Status is where an incident sits in its lifecycle (DORA Art. 17: incidents
// are identified, tracked and closed, not merely logged).
type Status string

const (
	// StatusOpen means the activity is still being observed, or nobody has
	// declared it contained.
	StatusOpen Status = "open"
	// StatusContained means the activity has stopped or is being blocked, but
	// the reporting obligations are not yet discharged.
	StatusContained Status = "contained"
	// StatusClosed means handled and reported; deadlines no longer accrue.
	StatusClosed Status = "closed"
)

// Valid reports whether s is a status this package recognises.
func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusContained, StatusClosed:
		return true
	}
	return false
}

// Severity is the proposed significance of an incident.
//
// It is a PROPOSAL. Whether an incident is "significant" under NIS2 Art. 23(3)
// or "major" under DORA Art. 18 depends on facts about the entity — how many
// clients it serves, what the service is worth — that a gateway cannot see. This
// is what the observed signals suggest; the operator confirms or overrides it,
// and Incident.SeverityConfirmed records which of the two you are looking at.
type Severity string

const (
	SeverityMinor       Severity = "minor"
	SeveritySignificant Severity = "significant"
	SeverityMajor       Severity = "major"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityMinor, SeveritySignificant, SeverityMajor:
		return true
	}
	return false
}

func severityRank(s Severity) int {
	switch s {
	case SeverityMajor:
		return 3
	case SeveritySignificant:
		return 2
	case SeverityMinor:
		return 1
	}
	return 0
}

// Classification carries DORA Art. 18's criteria, split by who can know them.
//
// The split is the whole point. Art. 18 lists six criteria; a gateway sitting in
// front of an API can observe three of them and has no way to know the other
// three. Reporting a classification that silently omits that distinction invites
// the reader to treat a blank as a zero — "no clients affected", "no economic
// impact" — which is a materially different statement from "we did not measure
// this". Complete() says which half is missing.
type Classification struct {
	// ── Observed by the gateway ──────────────────────────────────────────────

	// DurationMinutes is Art. 18(1)(b): how long the activity ran, from the
	// first correlated event to the last.
	DurationMinutes int `json:"duration_minutes"`
	// EndpointsAffected is how many distinct API endpoints the activity touched.
	EndpointsAffected int `json:"endpoints_affected"`
	// CriticalService is Art. 18(1)(e): whether any affected endpoint is one the
	// catalog scores as critical.
	CriticalService bool `json:"critical_service"`
	// DataAtRisk is Art. 18(1)(d): the classes of personal or sensitive data the
	// affected endpoints are known to return. It is the data that was REACHABLE,
	// not proof that any of it left — say so when reporting.
	DataAtRisk []string `json:"data_at_risk,omitempty"`
	// SourceCount is how many distinct source addresses took part.
	SourceCount int `json:"source_count"`

	// ── Supplied by the operator ─────────────────────────────────────────────

	// ClientsAffected is Art. 18(1)(a). The gateway sees API callers, which are
	// not clients: one caller may serve a million users or none.
	ClientsAffected *int `json:"clients_affected,omitempty"`
	// GeographicSpread is Art. 18(1)(c). Deriving it from source addresses would
	// need geolocation the gateway does not have, and attacker-controlled source
	// addresses are poor evidence of geography anyway.
	GeographicSpread *string `json:"geographic_spread,omitempty"`
	// EconomicImpactEUR is Art. 18(1)(f). Not observable from traffic at all.
	EconomicImpactEUR *float64 `json:"economic_impact_eur,omitempty"`
	// Notes is the operator's own assessment.
	Notes string `json:"notes,omitempty"`
}

// operatorCriteria names the Art. 18 criteria only a human can supply, in the
// order the article lists them.
var operatorCriteria = []struct {
	field   string
	article string
	filled  func(Classification) bool
}{
	{"clients_affected", "Art. 18(1)(a)", func(c Classification) bool { return c.ClientsAffected != nil }},
	{"geographic_spread", "Art. 18(1)(c)", func(c Classification) bool { return c.GeographicSpread != nil }},
	{"economic_impact_eur", "Art. 18(1)(f)", func(c Classification) bool { return c.EconomicImpactEUR != nil }},
}

// Missing lists the Art. 18 criteria still awaiting an operator's input, as
// "field (article)" strings. Empty means the classification is complete.
func (c Classification) Missing() []string {
	var out []string
	for _, oc := range operatorCriteria {
		if !oc.filled(c) {
			out = append(out, oc.field+" ("+oc.article+")")
		}
	}
	return out
}

// Complete reports whether every criterion an operator must supply has been.
func (c Classification) Complete() bool { return len(c.Missing()) == 0 }

// DeadlineKind identifies one reporting obligation.
type DeadlineKind string

const (
	// KindEarlyWarning is NIS2 Art. 23(4)(a) — within 24 hours of becoming aware.
	KindEarlyWarning DeadlineKind = "early_warning"
	// KindNotification is NIS2 Art. 23(4)(b) — within 72 hours.
	KindNotification DeadlineKind = "notification"
	// KindFinalReport is NIS2 Art. 23(4)(d) — within one month of submitting the
	// notification.
	KindFinalReport DeadlineKind = "final_report"
)

// Schedule is the reporting timetable.
//
// The defaults are NIS2 Art. 23(4), which states them in the directive text.
// DORA Art. 19 also requires an initial notification, an intermediate report and
// a final report, but its time limits are set by the regulatory technical
// standards adopted under Art. 20 rather than by the regulation — so they are
// configuration here, not constants. Confirm the applicable limits with your
// competent authority and set them; do not assume these defaults apply to you.
type Schedule struct {
	EarlyWarning time.Duration
	Notification time.Duration
	// FinalReport runs from the moment the notification is submitted, not from
	// detection. Art. 23(4)(d) says "not later than one month after the
	// submission of the incident notification", and getting this wrong gives an
	// operator up to three extra days they do not have.
	FinalReport time.Duration
}

// DefaultSchedule is NIS2 Art. 23(4).
var DefaultSchedule = Schedule{
	EarlyWarning: 24 * time.Hour,
	Notification: 72 * time.Hour,
	FinalReport:  30 * 24 * time.Hour,
}

// Notification records that a report was submitted to a competent authority.
type Notification struct {
	Kind DeadlineKind `json:"kind"`
	// SentAt is the operator's CLAIM about when they filed. AEGIS cannot
	// observe a submission to a regulator, so this is testimony, not evidence.
	SentAt time.Time `json:"sent_at"`
	// RecordedAt is when the gateway was told — set server-side, never by the
	// caller. It is the witness to the claim above.
	//
	// Without it, "append-only" was not the guarantee its own comment claimed.
	// Editing a submission time was blocked, but APPENDING a backdated entry
	// achieved the same outcome, and the earliest-wins reduction made the new
	// entry authoritative. An operator could clear a missed NIS2 Art. 23
	// deadline after the fact and the record showed nothing.
	RecordedAt time.Time `json:"recorded_at"`
	Authority  string    `json:"authority,omitempty"`
	Reference  string    `json:"reference,omitempty"`
}

// Deadline is one obligation with its due time and current state.
type Deadline struct {
	Kind   DeadlineKind `json:"kind"`
	Due    time.Time    `json:"due"`
	SentAt *time.Time   `json:"sent_at,omitempty"`
	// Overdue means the obligation was NOT met on time — either nothing was
	// submitted and the deadline has passed, or something was submitted after
	// it.
	//
	// The second case used to be missing: any recorded submission cleared the
	// flag without ever comparing its time to the due time, so an early warning
	// filed at hour 100 against a 24-hour obligation reported clean. That is a
	// breach of the obligation being presented to a regulator as compliance.
	Overdue bool `json:"overdue"`
	// Late is true when a submission was made, but after the deadline. It is
	// separate from Overdue so a report can distinguish "filed, 76h late" from
	// "never filed" — both are failures, and they are not the same failure.
	Late bool `json:"late,omitempty"`
	// Article names the obligation, so a reader does not have to look it up.
	Article string `json:"article"`
}

var deadlineArticles = map[DeadlineKind]string{
	KindEarlyWarning: "NIS2 Art. 23(4)(a)",
	KindNotification: "NIS2 Art. 23(4)(b)",
	KindFinalReport:  "NIS2 Art. 23(4)(d)",
}

// Incident is a correlated group of security events with a lifecycle.
type Incident struct {
	ID     string `json:"id"`
	Tenant string `json:"-"`
	Title  string `json:"title"`
	// Class is the kind of activity that opened it (the event reason family,
	// e.g. "bola"), and with Subject forms the correlation key.
	Class string `json:"class"`
	// Subject is who the activity came from: a consumer identity where one was
	// present, otherwise a source address.
	Subject string `json:"subject"`

	Status   Status   `json:"status"`
	Severity Severity `json:"severity"`
	// SeverityConfirmed distinguishes an operator's assessment from this
	// package's proposal. A report must not present the second as the first.
	SeverityConfirmed bool `json:"severity_confirmed"`

	DetectedAt  time.Time  `json:"detected_at"`
	LastEventAt time.Time  `json:"last_event_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`

	EventCount int      `json:"event_count"`
	Endpoints  []string `json:"endpoints,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`

	Classification Classification `json:"classification"`
	Notifications  []Notification `json:"notifications,omitempty"`
}

// Deadlines computes the reporting obligations for this incident as of now.
//
// A closed incident still reports its deadlines — an obligation that was missed
// does not stop having been missed because the incident was later closed, and a
// report that hid that would be the most dangerous kind of wrong.
func (i *Incident) Deadlines(s Schedule, now time.Time) []Deadline {
	// Resolved by earliest RECORDED time, not earliest claimed time: the first
	// submission the gateway witnessed is the authoritative one. Taking the
	// earliest claim instead let a later, backdated entry rewrite history —
	// which is precisely the forgery an append-only log is supposed to prevent.
	//
	// Rows written before recorded_at existed have a zero value; they fall back
	// to the claim so an upgrade does not silently reorder old history.
	type record struct{ sent, recorded time.Time }
	first := map[DeadlineKind]record{}
	for _, n := range i.Notifications {
		rec := n.RecordedAt
		if rec.IsZero() {
			rec = n.SentAt
		}
		if prev, ok := first[n.Kind]; !ok || rec.Before(prev.recorded) {
			first[n.Kind] = record{sent: n.SentAt, recorded: rec}
		}
	}
	sent := map[DeadlineKind]time.Time{}
	for k, r := range first {
		sent[k] = r.sent
	}

	mk := func(kind DeadlineKind, due time.Time) Deadline {
		d := Deadline{Kind: kind, Due: due, Article: deadlineArticles[kind]}
		if t, ok := sent[kind]; ok {
			tt := t
			d.SentAt = &tt
			// A submission does not by itself discharge the obligation — it has
			// to have been on time. Returning here without this comparison, as
			// this used to, reported a deadline missed by four days as met.
			d.Late = t.After(due)
			d.Overdue = d.Late
			return d
		}
		d.Overdue = now.After(due)
		return d
	}

	notificationDue := i.DetectedAt.Add(s.Notification)
	// The final report runs from when the notification was ACTUALLY submitted;
	// only if it has not been does the deadline fall back to when it was due.
	finalFrom := notificationDue
	if t, ok := sent[KindNotification]; ok {
		finalFrom = t
	}

	return []Deadline{
		mk(KindEarlyWarning, i.DetectedAt.Add(s.EarlyWarning)),
		mk(KindNotification, notificationDue),
		mk(KindFinalReport, finalFrom.Add(s.FinalReport)),
	}
}

// Overdue reports whether any obligation has passed unmet.
func (i *Incident) Overdue(s Schedule, now time.Time) bool {
	for _, d := range i.Deadlines(s, now) {
		if d.Overdue {
			return true
		}
	}
	return false
}

// ProposeSeverity derives a severity from what the gateway observed.
//
// Deliberately coarse. The inputs it has — how long the activity ran, how much
// of the API it touched, whether it reached data that matters — support a
// triage hint and nothing finer. Pretending to more precision than that would
// invite an operator to file it as an assessment, which it is not.
func ProposeSeverity(c Classification, eventCount int) Severity {
	switch {
	case c.CriticalService && len(c.DataAtRisk) > 0:
		return SeverityMajor
	case c.CriticalService, len(c.DataAtRisk) > 0, c.EndpointsAffected >= 5, eventCount >= 100:
		return SeveritySignificant
	default:
		return SeverityMinor
	}
}

// Title composes a human-readable one-liner for an incident.
func Title(class, subject string) string {
	name := classTitles[class]
	if name == "" {
		name = strings.ReplaceAll(class, "_", " ")
	}
	if subject == "" {
		return name
	}
	return fmt.Sprintf("%s from %s", name, subject)
}

var classTitles = map[string]string{
	"bola":      "Object-level authorization abuse",
	"bfla":      "Function-level authorization abuse",
	"waf":       "Web application attack",
	"behavior":  "Anomalous caller behaviour",
	"threat":    "Traffic from a known-bad source",
	"bot":       "Automated client activity",
	"ratelimit": "Sustained request flooding",
}

// sortedUnique returns the distinct values of in, ordered, capped at max.
//
// The cap is not cosmetic: these lists are grown from attacker-controlled input
// (source addresses, paths), and an unbounded one is a memory-growth lever an
// attacker pulls by rotating them.
func sortedUnique(in []string, max int) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}
