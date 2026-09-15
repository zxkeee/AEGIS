package api

import (
	"net/http"
	"time"

	"api-gateway/internal/forensic"
	"api-gateway/internal/tenant"
)

// sealReportDoc is the auditor-facing form of a seal verification.
//
// The raw forensic.SealReport is a developer's structure; this is the document
// somebody hands over. It carries its own provenance (generated_at, tenant) for
// the same reason the compliance report does — a shared-key deployment could
// not otherwise tell one tenant's signed report from another's — and it carries
// its own limits, because a verification result is exactly the kind of artifact
// a reader over-interprets.
type sealReportDoc struct {
	GeneratedAt string `json:"generated_at"`
	Tenant      string `json:"tenant"`

	// Intact is the whole answer: every sealed period still recomputes AND no
	// seal is missing. Both halves are required — a chain can be internally
	// perfect and three periods short.
	Intact bool                    `json:"intact"`
	Chain  forensic.ChainCheck     `json:"chain"`
	Seals  []forensic.SealCheck    `json:"seals"`
	Sealed sealReportSummaryCounts `json:"summary"`

	// Limits states what this document does NOT establish. Shipped inside the
	// signed body rather than in the API docs, because the document is what
	// leaves the building.
	Limits []string `json:"limits"`
}

type sealReportSummaryCounts struct {
	Periods int `json:"periods"`
	Intact  int `json:"intact"`
	Altered int `json:"altered"`
}

// GET /api/forensic/seals?sign=1
//
// Recomputes every seal for the caller's tenant against the log as it stands
// and reports what no longer matches, including seals that are missing outright.
//
// This endpoint exists because the mechanism did not have one. Seals were
// written by a worker and verified by nothing reachable: VerifySeals had no
// production caller at all, so the only way to ask "has this log been tampered
// with" was to write Go against the database. A detection that cannot be
// invoked does not detect anything, and shipping the claim without the path is
// the over-promise this project keeps correcting elsewhere.
//
// Signable, and that is the point of the route rather than a decoration: the
// artifact an auditor keeps has to be verifiable away from the system that
// produced it, with cmd/reportverify and a key pinned out of band.
func (h *handlers) getSealReport(w http.ResponseWriter, r *http.Request) {
	if h.forensic == nil {
		writeError(w, http.StatusServiceUnavailable,
			"forensic seals are disabled; set forensic_dsn (PostgreSQL) to enable the durable log and its seals")
		return
	}

	tid := tenant.From(r.Context())
	report, err := h.forensic.VerifySeals(r.Context(), tid)
	if err != nil {
		h.writeStoreError(w, "admin: seal verification failed", "failed to verify forensic seals", err)
		return
	}

	doc := sealReportDoc{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Tenant:      tid,
		Intact:      report.Intact,
		Chain:       report.Chain,
		Seals:       report.Checks,
		Limits:      sealReportLimits(),
	}
	doc.Sealed.Periods = len(report.Checks)
	for _, c := range report.Checks {
		if c.Intact {
			doc.Sealed.Intact++
		} else {
			doc.Sealed.Altered++
		}
	}

	// Seals is never null in the signed body: a JSON null and an empty list read
	// the same to a careless reader, and "no periods are sealed yet" is a
	// materially different statement from "every sealed period verified".
	if doc.Seals == nil {
		doc.Seals = []forensic.SealCheck{}
	}

	h.writeSignable(w, r, doc)
}
