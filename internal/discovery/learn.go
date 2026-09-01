package discovery

import (
	"strings"
	"sync"
)

// PathLearner infers which path segments are identifiers by watching traffic,
// for the ones NormalizePath cannot recognise by shape.
//
// Why shape alone is not enough
// -----------------------------
// NormalizePath collapses a segment that LOOKS like an id: all digits, a UUID,
// long hex, a long opaque token. That covers /orders/42 and misses everything
// keyed by a human-readable name — which is most of the web. Pointed at a live
// Forgejo, the catalog recorded 152 distinct "endpoints" for 161 requests,
// because /api/v1/repos/fsasm/bm_monitor is three ordinary words as far as a
// regex is concerned (assessment, 2026-08-31). At that point the catalog is not
// an inventory, it is a request log: posture is computed per object, every
// finding is repeated once per object, and drift detection reports the entire
// API as undocumented, because the documented /repos/{owner}/{repo} never
// matches anything observed.
//
// The signal: vocabulary saturation
// ---------------------------------
// A resource name is written by the API's author, so a position holding
// resource names draws from a FIXED vocabulary: once "users", "repos" and
// "orgs" have been seen, no fourth name ever appears. An identifier is supplied
// by the caller, so that position keeps producing values it has never seen, for
// as long as traffic continues. Saturation is the discriminator, and it is the
// only one that holds at both ends of the scale.
//
// A snapshot of "many values, few hits each" is NOT the discriminator, though
// it looks like one. Evaluated at the moment a new value arrives, hits and
// distinct values are equal by construction — every position looks like
// identifiers on its way up, and a twenty-resource API collapses entirely on
// its first pass through those twenty names. That mistake is not recoverable:
// merged endpoints cannot be reported separately again.
//
// So a position is judged only after it has shown MinDistinct values AND run
// for a further EvalWindow requests. The share of that window that introduced a
// value never seen before is the measurement. Below NewValueRate the vocabulary
// has saturated and these are names; at or above it, values keep arriving and
// these are identifiers. A position that reads as names has its window restarted
// rather than being settled forever, so a path that only later starts carrying
// identifiers is still caught.
//
// Statistics are pooled per TEMPLATE PREFIX rather than per concrete parent.
// This is the part that makes it work at realistic traffic volumes: keyed by
// concrete parent, /repos/alice/… and /repos/bob/… each accumulate evidence
// separately and neither reaches a threshold, so nothing is ever learned from a
// short run. Keyed by the prefix /repos/{id}, every owner's repositories count
// toward the same decision.
//
// Properties this deliberately has
// --------------------------------
//   - Monotonic. A position that has collapsed never un-collapses, so a
//     template is stable once learned rather than flapping as traffic shifts.
//   - Bounded. Both the number of tracked positions and the values remembered
//     per position are capped; at a cap the position collapses rather than
//     allocating, so a path flood costs memory that is already accounted for.
//   - Per tenant. One tenant's traffic never shapes another's templates.
//   - In-memory. Templates are relearned after a restart; until the thresholds
//     are met again paths normalise by shape alone, which is exactly the
//     pre-existing behaviour.
//
// What it does not solve
// ----------------------
// A fixed sub-resource that shares a position with identifiers is absorbed:
// Forgejo's /repos/search sits where owner names sit, so once that position
// collapses, search is catalogued as /repos/{id}. Distinguishing the two needs
// response-shape or schema evidence, not path statistics.
type PathLearner struct {
	mu    sync.Mutex
	pos   map[string]*posStats
	cfg   LearnerConfig
	count int

	// collapsed records positions ruled variable since the last drain, so the
	// catalog can retemplate the rows it wrote before the rule was learned.
	// Without that, everything observed during the warm-up stays in the console
	// as concrete paths forever and the operator sees the very mess this exists
	// to remove — the templates only become right for FUTURE traffic.
	collapsed []CollapsedPosition
}

// CollapsedPosition names a path position that has just been ruled to hold
// identifiers: Prefix is the template up to (not including) that position.
type CollapsedPosition struct {
	Tenant string
	Prefix string
}

// LearnerConfig tunes when a path position is judged to hold identifiers. The
// defaults were fitted against a real API's traffic, not chosen by eye — see
// DefaultLearnerConfig.
type LearnerConfig struct {
	// MinDistinct is how many different values a position must have shown before
	// it can be considered variable at all. Setting it below the number of
	// resources an API exposes at one level makes genuine resource names collapse
	// into {id}, which is worse than not collapsing at all: the catalog then
	// merges unrelated endpoints, and an endpoint merged away cannot be reported.
	MinDistinct int
	// EvalWindow is how many further requests a position must serve, after
	// reaching MinDistinct values, before its vocabulary is judged. It is the
	// warm-up that makes the measurement mean anything: judged immediately, a
	// position that is merely filling up its fixed vocabulary is indistinguishable
	// from one receiving identifiers.
	EvalWindow int
	// NewValueRate is the share of a window that must introduce a previously
	// unseen value for the position to be judged an identifier position.
	NewValueRate float64
	// HardCeiling collapses a position once it has shown this many distinct
	// values regardless of the ratio. No API names this many resources at one
	// level, and it is what bounds the memory a single position can consume.
	HardCeiling int
	// MaxPositions bounds the number of tracked positions.
	MaxPositions int
}

// DefaultLearnerConfig was fitted against real traffic — the Codeberg
// assessment of 2026-08-31 — not chosen by eye. A twenty-resource level running
// ten passes introduces about 8 new names across a 100-request window (0.08),
// while that API's repository-owner position introduced 19 (0.19); 0.15 sits
// between them with room on both sides.
//
// This carries a real operational consequence, and it is a property of the
// problem rather than of this implementation: a position cannot be judged until
// it has served roughly MinDistinct+EvalWindow requests. Below that the learner
// has no basis to act on and paths normalise by shape alone. A few hundred
// requests is not a pilot; a day of production traffic is.
var DefaultLearnerConfig = LearnerConfig{
	MinDistinct:  12,
	EvalWindow:   100,
	NewValueRate: 0.15,
	HardCeiling:  512,
	MaxPositions: 100_000,
}

type posStats struct {
	values   map[string]bool
	hits     int
	variable bool
	// Evaluation window. evalHits is the hit count when the position last became
	// eligible to be judged; evalDistinct is its vocabulary size at that moment.
	// evalHits == 0 means the position has not yet shown MinDistinct values.
	evalHits     int
	evalDistinct int
}

// NewPathLearner returns a learner using cfg, with unset fields defaulted.
func NewPathLearner(cfg LearnerConfig) *PathLearner {
	d := DefaultLearnerConfig
	if cfg.MinDistinct <= 0 {
		cfg.MinDistinct = d.MinDistinct
	}
	if cfg.EvalWindow <= 0 {
		cfg.EvalWindow = d.EvalWindow
	}
	if cfg.NewValueRate <= 0 {
		cfg.NewValueRate = d.NewValueRate
	}
	if cfg.HardCeiling <= 0 {
		cfg.HardCeiling = d.HardCeiling
	}
	if cfg.MaxPositions <= 0 {
		cfg.MaxPositions = d.MaxPositions
	}
	return &PathLearner{pos: map[string]*posStats{}, cfg: cfg}
}

// Template records path as observed for tenant and returns its endpoint
// template. NormalizePath runs first, so anything recognisable by shape is
// templated on the very first request and the learner only decides what is left.
//
// Recording and lookup are one call because they must not disagree: reading a
// template without counting it would leave a position sitting one hit below its
// threshold forever.
func (l *PathLearner) Template(tenantID, path string) string {
	normalized := NormalizePath(path)
	if l == nil || normalized == "/" {
		return normalized
	}

	segs := strings.Split(strings.TrimPrefix(normalized, "/"), "/")

	l.mu.Lock()
	defer l.mu.Unlock()

	var b strings.Builder
	for _, seg := range segs {
		prefix := b.String()
		st := l.statsFor(tenantID, prefix)
		st.hits++

		b.WriteByte('/')
		if st.variable {
			b.WriteString(placeholder)
			continue
		}
		if !st.values[seg] {
			if len(st.values)+1 >= l.cfg.HardCeiling {
				// No API names this many resources at one level, and the value set
				// is the memory this position consumes. Collapse without waiting
				// for a window.
				l.markVariable(st, tenantID, prefix)
				b.WriteString(placeholder)
				continue
			}
			st.values[seg] = true
		}
		if l.judge(st, tenantID, prefix) {
			b.WriteString(placeholder)
			continue
		}
		b.WriteString(seg)
	}
	return b.String()
}

// judge evaluates a position's vocabulary once its window has elapsed, and
// reports whether it has just been ruled an identifier position. A position
// that reads as resource names has its window restarted, so the question is
// asked again of later traffic rather than settled forever on the first answer.
func (l *PathLearner) judge(st *posStats, tenantID, prefix string) bool {
	distinct := len(st.values)
	if st.evalHits == 0 {
		if distinct >= l.cfg.MinDistinct {
			st.evalHits, st.evalDistinct = st.hits, distinct
		}
		return false
	}
	elapsed := st.hits - st.evalHits
	if elapsed < l.cfg.EvalWindow {
		return false
	}
	introduced := distinct - st.evalDistinct
	if float64(introduced) >= l.cfg.NewValueRate*float64(elapsed) {
		l.markVariable(st, tenantID, prefix)
		return true
	}
	st.evalHits, st.evalDistinct = st.hits, distinct
	return false
}

// markVariable settles a position as holding identifiers. The decision is
// permanent: a template that flapped between concrete and collapsed would split
// one endpoint's history across two catalog rows every time traffic shifted.
func (l *PathLearner) markVariable(st *posStats, tenantID, prefix string) {
	st.variable = true
	st.values = nil // the value set is the memory; release it
	l.collapsed = append(l.collapsed, CollapsedPosition{Tenant: tenantID, Prefix: prefix})
}

// TakeCollapsed returns the positions ruled variable since the last call and
// clears the list. The caller is expected to retemplate stored rows; anything it
// drops is not retried.
func (l *PathLearner) TakeCollapsed() []CollapsedPosition {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.collapsed
	l.collapsed = nil
	return out
}

// statsFor returns the statistics for one position, identified by the tenant
// and the TEMPLATE of the path so far. At the position cap it returns a
// permanently-variable entry: memory stops growing and templates degrade toward
// coarser ones rather than the map growing without limit.
func (l *PathLearner) statsFor(tenantID, prefix string) *posStats {
	key := tenantID + "\x00" + prefix
	if st, ok := l.pos[key]; ok {
		return st
	}
	if l.count >= l.cfg.MaxPositions {
		return &posStats{variable: true}
	}
	st := &posStats{values: map[string]bool{}}
	l.pos[key] = st
	l.count++
	return st
}

// Positions returns the number of tracked path positions. Exposed for the
// memory-bound test and for operational visibility.
func (l *PathLearner) Positions() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}
