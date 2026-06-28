package discovery

import "sort"

// DriftItem is one entry in a drift report: a single (method, path) operation
// that is out of sync between the documented spec and observed traffic.
type DriftItem struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	// PathDocumented is meaningful for undocumented items: true means the path
	// is in the spec but this *method* is not (an undocumented verb on a known
	// resource), false means the whole path is absent from the spec (a true
	// shadow endpoint). It is always false for zombies.
	PathDocumented bool `json:"path_documented,omitempty"`
	// RiskScore / RequestCount are carried for undocumented items so the report
	// can be sorted by severity; zero for zombies (never observed).
	RiskScore    int   `json:"risk_score,omitempty"`
	RequestCount int64 `json:"request_count,omitempty"`
}

// DriftReport is the documented-vs-observed comparison for one tenant.
type DriftReport struct {
	SpecPresent     bool   `json:"spec_present"`
	SpecVersion     string `json:"spec_version,omitempty"`
	DocumentedCount int    `json:"documented_count"`
	ObservedCount   int    `json:"observed_count"`
	// Undocumented: observed in traffic but not in the spec (OWASP API9:2023,
	// Improper Inventory Management). The highest-value drift signal.
	Undocumented []DriftItem `json:"undocumented"`
	// Zombie: documented in the spec but never observed. Inventory hygiene —
	// stale docs, retired endpoints, or coverage gaps in observation.
	Zombie []DriftItem `json:"zombie"`
	// Counts mirror the slice lengths for cheap dashboard consumption.
	UndocumentedCount int `json:"undocumented_count"`
	ZombieCount       int `json:"zombie_count"`
}

// ComputeDrift compares a documented spec against the observed catalog endpoints
// for a tenant. It is a pure function of its inputs so it is fully unit-testable
// without a database. A nil spec yields SpecPresent=false and no drift (we do
// not flag everything as undocumented when nothing is documented).
func ComputeDrift(spec *Spec, eps []Endpoint) DriftReport {
	r := DriftReport{
		Undocumented: []DriftItem{},
		Zombie:       []DriftItem{},
	}
	if spec == nil {
		return r
	}
	r.SpecPresent = true
	r.SpecVersion = spec.Version
	r.DocumentedCount = spec.OpCount()
	r.ObservedCount = len(eps)

	// Observed set, for the zombie pass.
	observed := make(map[string]bool, len(eps))

	for _, e := range eps {
		key := e.Method + " " + e.PathTemplate
		observed[key] = true
		if spec.HasOp(e.Method, e.PathTemplate) {
			continue
		}
		r.Undocumented = append(r.Undocumented, DriftItem{
			Method:         e.Method,
			Path:           e.PathTemplate,
			PathDocumented: spec.HasPath(e.PathTemplate),
			RiskScore:      e.RiskScore,
			RequestCount:   e.RequestCount,
		})
	}

	for _, op := range spec.operations() {
		if observed[op.Method+" "+op.Template] {
			continue
		}
		r.Zombie = append(r.Zombie, DriftItem{Method: op.Method, Path: op.Template})
	}

	// Undocumented sorted by risk then traffic (most dangerous first); zombie
	// items are already sorted by operations().
	sort.SliceStable(r.Undocumented, func(i, j int) bool {
		if r.Undocumented[i].RiskScore != r.Undocumented[j].RiskScore {
			return r.Undocumented[i].RiskScore > r.Undocumented[j].RiskScore
		}
		return r.Undocumented[i].RequestCount > r.Undocumented[j].RequestCount
	})

	r.UndocumentedCount = len(r.Undocumented)
	r.ZombieCount = len(r.Zombie)
	return r
}

// driftFinding returns an "undocumented endpoint" finding for a single endpoint
// when a spec is present and the endpoint is not documented. It is kept separate
// from DetectFindings so the spec-aware enrichment is opt-in at the call site
// (DetectFindings stays a pure function of an endpoint's own counters).
func driftFinding(e Endpoint, spec *Spec) (Finding, bool) {
	if spec == nil || spec.HasOp(e.Method, e.PathTemplate) {
		return Finding{}, false
	}
	if spec.HasPath(e.PathTemplate) {
		// Path is documented, this verb is not: an undocumented method.
		return Finding{
			Code:     "undocumented_method",
			OWASP:    "API9:2023",
			Severity: "warning",
			Title:    "Undocumented HTTP method on a documented endpoint",
			Why: e.Method + " is served on " + e.PathTemplate +
				" but the API spec documents this path only for other methods",
		}, true
	}
	return Finding{
		Code:     "undocumented_endpoint",
		OWASP:    "API9:2023",
		Severity: "warning",
		Title:    "Undocumented (shadow) endpoint not present in the API spec",
		Why: e.Method + " " + e.PathTemplate +
			" is served in production but is absent from the imported API spec",
	}, true
}
