package api

import (
	"context"
	"net/http"
	"time"

	"api-gateway/internal/incident"
	"api-gateway/internal/tenant"
)

// ledgerReportDoc is the auditor-facing form of an incident-register
// verification.
//
// Same shape and the same reasoning as sealReportDoc: the raw LedgerReport is a
// developer's structure, this is the artifact somebody hands over. It carries
// its own provenance, because a deployment sharing one signing key could not
// otherwise tell one tenant's signed answer from another's, and it carries its
// own limits inside the signed body rather than in the API docs, because the
// document is what leaves the building.
type ledgerReportDoc struct {
	GeneratedAt string `json:"generated_at"`
	Tenant      string `json:"tenant"`

	// Intact is the whole answer: nothing deleted, nothing edited, nothing
	// unrecorded, and the ledger's own chain recomputes.
	Intact bool `json:"intact"`

	// Missing, Altered and Unledgered name what is wrong, because "the
	// register was tampered with" is not actionable and "incident
	// bola-jwt:alice-2026-09-23 is gone" is.
	Missing    []string `json:"missing"`
	Altered    []string `json:"altered"`
	Unledgered []string `json:"unledgered"`
	// ChainBroken names ledger positions that no longer recompute — an edit or
	// an interior deletion of the ledger itself.
	ChainBroken []int64 `json:"chain_broken"`
	// Entries is how many ledger rows were examined, so "verified, nothing
	// wrong" can be told apart from "there was nothing to verify". An intact
	// answer over zero entries is not evidence of anything.
	Entries int `json:"entries"`

	Limits []string `json:"limits"`
}

// GET /api/incidents/ledger?sign=1
//
// Recomputes the incident register against its append-only ledger and reports
// what no longer matches.
//
// The route exists at the same time as the mechanism, deliberately. The seals
// shipped without one and spent two sessions being improved while remaining
// impossible to invoke — VerifySeals had no production caller at all, so the
// only way to ask the question was to write Go against the database. A
// detection nobody can run does not detect anything, and this package has paid
// for that lesson once already (#76).
//
// Signable for the reason the route is worth having: the compliance report
// draws on this register for DORA Art. 17-19 and NIS2 Art. 23, and an auditor
// who is handed that report can now be handed a separate, independently
// verifiable statement about whether the register behind it was altered. Both
// are verified away from the system that produced them with cmd/reportverify
// and a key pinned out of band.
func (h *handlers) getIncidentLedgerReport(w http.ResponseWriter, r *http.Request) {
	if !h.incidentsReady(w) {
		return
	}
	verifier, ok := h.incidents.(incidentLedgerVerifier)
	if !ok {
		// Not an error the operator can fix by configuration, so it does not
		// pretend to be one: an incident store that cannot verify itself is a
		// build without the PostgreSQL store, and saying "disabled" would send
		// the reader to check forensic_dsn, which is set.
		writeError(w, http.StatusNotImplemented,
			"this incident store does not keep an integrity ledger")
		return
	}

	tid := tenant.From(r.Context())
	report, err := verifier.VerifyLedger(r.Context(), tid)
	if err != nil {
		h.writeStoreError(w, "admin: incident ledger verification failed",
			"failed to verify the incident register", err)
		return
	}

	doc := ledgerReportDoc{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Tenant:      tid,
		Intact:      report.Intact,
		Missing:     report.Missing,
		Altered:     report.Altered,
		Unledgered:  report.Unledgered,
		ChainBroken: report.ChainBroken,
		Entries:     report.Entries,
		Limits:      report.Limits,
	}

	// Never null in a signed body. A JSON null and an empty list read the same
	// to a careless reader, and here the careless reading is the dangerous one:
	// "no incident is missing" and "the question was not answered" would look
	// identical in a document an auditor keeps.
	if doc.Missing == nil {
		doc.Missing = []string{}
	}
	if doc.Altered == nil {
		doc.Altered = []string{}
	}
	if doc.Unledgered == nil {
		doc.Unledgered = []string{}
	}
	if doc.ChainBroken == nil {
		doc.ChainBroken = []int64{}
	}

	h.writeSignable(w, r, doc)
}

// incidentLedgerVerifier is the half of the PostgreSQL store that answers
// "has this register been tampered with".
//
// Kept separate from incidentOps rather than added to it: the in-memory and
// fake stores used by other tests implement incidentOps and have no ledger,
// and widening the port would force every one of them to grow a method that
// returns a meaningless answer. A type assertion states the truth — some
// stores can answer this and some cannot.
type incidentLedgerVerifier interface {
	VerifyLedger(ctx context.Context, tenant string) (incident.LedgerReport, error)
}
