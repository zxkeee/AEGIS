package discovery

import (
	"context"
	"sync"
	"time"
)

// Logger is the minimal logging interface the catalog needs.
type Logger interface {
	Info(msg string, fields ...map[string]any)
	Error(msg string, fields ...map[string]any)
}

// Observation is a single recorded API call, produced by the Discovery
// middleware after the request has been served. It is the unit fed to the
// catalog for aggregation.
type Observation struct {
	Method      string
	Path        string // raw path; normalized inside the catalog
	Status      int
	LatencyMs   int64
	AuthPresent bool // a valid identity (JWT/API key) accompanied the request
	PII         bool // DLP detected sensitive data in the response

	// Consumer identity. Any non-empty field contributes a consumer record.
	ConsumerSubject string // from JWT "sub"/claims  -> "jwt:<sub>"
	ConsumerKey     string // from API key header     -> "key:<id>"
	ConsumerIP      string // RealIP fallback          -> "ip:<addr>"
}

// Endpoint is the catalog view of one normalized API endpoint.
type Endpoint struct {
	ID               string           `json:"id"`
	Method           string           `json:"method"`
	PathTemplate     string           `json:"path_template"`
	FirstSeen        time.Time        `json:"first_seen"`
	LastSeen         time.Time        `json:"last_seen"`
	RequestCount     int64            `json:"request_count"`
	ErrorCount       int64            `json:"error_count"`
	AuthPresentCount int64            `json:"auth_present_count"`
	AnonCount        int64            `json:"anon_count"`
	PIICount         int64            `json:"pii_count"`
	AvgLatencyMs     int64            `json:"avg_latency_ms"`
	StatusDist       map[string]int64 `json:"status_dist,omitempty"`
	Posture          string           `json:"posture"`
	RiskScore        int              `json:"risk_score"`
	RoutePath        string           `json:"route_path"`
	Controls         *Controls        `json:"controls,omitempty"`

	latencyMsSum   int64
	latencySamples int64
}

// Consumer is the catalog view of an API consumer (who calls the APIs).
type Consumer struct {
	ID               string    `json:"id"`
	Kind             string    `json:"kind"` // jwt | key | ip
	Label            string    `json:"label"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	RequestCount     int64     `json:"request_count"`
	ErrorCount       int64     `json:"error_count"`
	EndpointsTouched int       `json:"endpoints_touched"`
}

// EndpointConsumer links a consumer to an endpoint with a call count.
type EndpointConsumer struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	Label        string    `json:"label"`
	RequestCount int64     `json:"request_count"`
	LastSeen     time.Time `json:"last_seen"`
}

// PostureSummary is the coverage roll-up for the dashboard.
type PostureSummary struct {
	Total       int        `json:"total"`
	Protected   int        `json:"protected"`
	Partial     int        `json:"partial"`
	Unprotected int        `json:"unprotected"`
	Shadow      int        `json:"shadow"`
	CoveragePct int        `json:"coverage_pct"`
	TopRisky    []Endpoint `json:"top_risky"`
}

// EndpointFilter parameterises catalog list queries.
type EndpointFilter struct {
	Posture string
	Search  string
	MinRisk int
	Limit   int
}

// ── Aggregation state (per flush window) ────────────────────────────────────

type epAgg struct {
	id, method, pathTemplate, routePath, posture string
	requestCount, errorCount                     int64
	authPresent, anonCount, piiCount             int64
	latencyMsSum, latencySamples                 int64
	riskScore                                    int
	statusDist                                   map[int]int64
}

type consumerAgg struct {
	id, kind, label          string
	requestCount, errorCount int64
}

// Catalog is the passive API discovery engine. It accepts Observations on a
// non-blocking channel, aggregates them in-memory per flush window, and persists
// rolled-up deltas to PostgreSQL. Reads for the admin API are served from PG.
type Catalog struct {
	pg  *pgStore
	log Logger
	ch  chan Observation

	mu      sync.RWMutex
	posture *PostureEngine // swapped on config hot-reload

	wg   sync.WaitGroup
	quit chan struct{}
}

// NewCatalog connects to PostgreSQL, migrates the schema, and starts the
// background aggregation worker.
func NewCatalog(dsn string, posture *PostureEngine, log Logger) (*Catalog, error) {
	pg, err := newPGStore(dsn, log)
	if err != nil {
		return nil, err
	}
	c := &Catalog{
		pg:      pg,
		log:     log,
		ch:      make(chan Observation, 8192),
		posture: posture,
		quit:    make(chan struct{}),
	}
	c.wg.Add(1)
	go c.worker()
	return c, nil
}

// SetPostureEngine swaps the posture engine after a config hot-reload so newly
// recorded endpoints are classified against the latest configuration.
func (c *Catalog) SetPostureEngine(p *PostureEngine) {
	c.mu.Lock()
	c.posture = p
	c.mu.Unlock()
}

func (c *Catalog) engine() *PostureEngine {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.posture
}

// Record enqueues an observation. Non-blocking: drops on a full buffer so the
// request path is never stalled by catalog back-pressure.
func (c *Catalog) Record(obs Observation) {
	if obs.Method == "" || obs.Path == "" {
		return
	}
	select {
	case c.ch <- obs:
	default:
		// Buffer full — drop. Discovery is best-effort analytics, not the
		// security control path.
	}
}

// Close drains the buffer and shuts down.
func (c *Catalog) Close() error {
	close(c.quit)
	c.wg.Wait()
	return c.pg.Close()
}

// worker aggregates observations and flushes every 5s (or earlier on shutdown).
func (c *Catalog) worker() {
	defer c.wg.Done()

	eps := map[string]*epAgg{}
	cons := map[string]*consumerAgg{}
	epCons := map[[2]string]int64{} // {endpointID, consumerID} -> count

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(eps) == 0 && len(cons) == 0 {
			return
		}
		c.flush(eps, cons, epCons)
		eps = map[string]*epAgg{}
		cons = map[string]*consumerAgg{}
		epCons = map[[2]string]int64{}
	}

	for {
		select {
		case obs := <-c.ch:
			c.aggregate(obs, eps, cons, epCons)
			if len(eps) >= 2000 { // bound memory between ticks
				flush()
			}
		case <-ticker.C:
			flush()
		case <-c.quit:
			// Final drain.
			for {
				select {
				case obs := <-c.ch:
					c.aggregate(obs, eps, cons, epCons)
				default:
					flush()
					return
				}
			}
		}
	}
}

// aggregate folds one observation into the in-memory window.
func (c *Catalog) aggregate(obs Observation, eps map[string]*epAgg,
	cons map[string]*consumerAgg, epCons map[[2]string]int64) {

	eng := c.engine()
	tmpl := NormalizePath(obs.Path)
	id := EndpointKey(obs.Method, obs.Path)

	a := eps[id]
	if a == nil {
		a = &epAgg{
			id:           id,
			method:       obs.Method,
			pathTemplate: tmpl,
			statusDist:   map[int]int64{},
		}
		if route := eng.matchRoute(tmpl); route != nil {
			a.routePath = route.Path
		}
		eps[id] = a
	}
	a.requestCount++
	if obs.Status >= 400 {
		a.errorCount++
	}
	if obs.AuthPresent {
		a.authPresent++
	} else {
		a.anonCount++
	}
	if obs.PII {
		a.piiCount++
	}
	a.latencyMsSum += obs.LatencyMs
	a.latencySamples++
	a.statusDist[obs.Status]++

	// Posture + risk recomputed from the window's running totals so the persisted
	// values reflect the latest observed traffic.
	a.posture = eng.Classify(tmpl)
	a.riskScore = RiskScore(tmpl, eng, EndpointStats{
		RequestCount: a.requestCount,
		ErrorCount:   a.errorCount,
		AnonCount:    a.anonCount,
		PIICount:     a.piiCount,
	})

	// Consumers: prefer the strongest identity available.
	for _, cid := range consumerIdentities(obs) {
		ca := cons[cid.id]
		if ca == nil {
			ca = &consumerAgg{id: cid.id, kind: cid.kind, label: cid.label}
			cons[cid.id] = ca
		}
		ca.requestCount++
		if obs.Status >= 400 {
			ca.errorCount++
		}
		epCons[[2]string{id, cid.id}]++
	}
}

type consumerID struct{ id, kind, label string }

// consumerIdentities derives consumer records from an observation. JWT subject
// is the primary identity; API key and IP are recorded too so unauthenticated
// or service traffic is still attributable.
func consumerIdentities(obs Observation) []consumerID {
	var out []consumerID
	if obs.ConsumerSubject != "" {
		out = append(out, consumerID{"jwt:" + obs.ConsumerSubject, "jwt", obs.ConsumerSubject})
	}
	if obs.ConsumerKey != "" {
		out = append(out, consumerID{"key:" + obs.ConsumerKey, "key", obs.ConsumerKey})
	}
	// IP is recorded only when there is no stronger identity, to avoid double
	// counting the same caller as both a JWT subject and an IP.
	if len(out) == 0 && obs.ConsumerIP != "" {
		out = append(out, consumerID{"ip:" + obs.ConsumerIP, "ip", obs.ConsumerIP})
	}
	return out
}

// flush persists the aggregated window to PostgreSQL.
func (c *Catalog) flush(eps map[string]*epAgg, cons map[string]*consumerAgg, epCons map[[2]string]int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, a := range eps {
		if err := c.pg.upsertEndpoint(ctx, a); err != nil {
			c.log.Error("discovery: endpoint flush failed", map[string]any{"error": err.Error(), "id": a.id})
		}
	}
	for _, ca := range cons {
		if err := c.pg.upsertConsumer(ctx, ca); err != nil {
			c.log.Error("discovery: consumer flush failed", map[string]any{"error": err.Error()})
		}
	}
	for k, n := range epCons {
		if err := c.pg.upsertEndpointConsumer(ctx, k[0], k[1], n); err != nil {
			c.log.Error("discovery: endpoint-consumer flush failed", map[string]any{"error": err.Error()})
		}
	}
	c.log.Info("discovery: catalog flushed", map[string]any{
		"endpoints": len(eps), "consumers": len(cons),
	})
}

// ── Read API (delegates to PG, enriches with live controls) ─────────────────

// ListEndpoints returns catalog endpoints matching the filter.
func (c *Catalog) ListEndpoints(ctx context.Context, f EndpointFilter) ([]Endpoint, error) {
	eps, err := c.pg.listEndpoints(ctx, f)
	if err != nil {
		return nil, err
	}
	eng := c.engine()
	for i := range eps {
		ctrl, _ := eng.ControlsFor(eps[i].PathTemplate)
		eps[i].Controls = &ctrl
	}
	return eps, nil
}

// GetEndpoint returns one endpoint plus its consumers, or nil if unknown.
func (c *Catalog) GetEndpoint(ctx context.Context, id string) (*Endpoint, []EndpointConsumer, error) {
	e, consumers, err := c.pg.getEndpoint(ctx, id)
	if err != nil || e == nil {
		return e, consumers, err
	}
	ctrl, _ := c.engine().ControlsFor(e.PathTemplate)
	e.Controls = &ctrl
	return e, consumers, nil
}

// ListConsumers returns the top API consumers.
func (c *Catalog) ListConsumers(ctx context.Context, limit int) ([]Consumer, error) {
	return c.pg.listConsumers(ctx, limit)
}

// PostureSummary returns the coverage roll-up.
func (c *Catalog) PostureSummary(ctx context.Context) (PostureSummary, error) {
	return c.pg.postureSummary(ctx)
}
