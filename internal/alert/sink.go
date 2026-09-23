// SIEM delivery.
//
// The webhook that existed before this file answers "tell a human now" —
// Slack, PagerDuty, an on-call rotation. A SIEM answers a different question:
// it is where a security team already correlates everything else, and "can you
// send events to our Splunk" is the sentence that decides a technical
// evaluation. The two are not substitutes: a webhook formatted for Slack is
// unusable as an event source, and an event stream paged to on-call is noise.
//
// So sinks are additive rather than a replacement. The existing webhook keeps
// working, unchanged and unaware, and any number of SIEM sinks receive the same
// alerts in the shape their ingester expects.
//
// WHAT THIS IS NOT. It is not a forensic-log export: the SIEM receives alerts,
// which are the events a control decided were worth raising, not every request
// the gateway saw. A team that wants the full record reads forensic_logs
// directly or pulls /api/block-log. Saying "AEGIS integrates with Splunk"
// without that distinction would oversell it by an order of magnitude in
// volume, and the difference is exactly what a SIEM is priced on.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"api-gateway/internal/safefetch"
)

// Sink types. The wire format and the authentication header differ per system;
// nothing else does.
const (
	SinkSplunkHEC = "splunk_hec"
	SinkElastic   = "elastic"
)

// Sink is one configured SIEM destination.
type Sink struct {
	Type string
	URL  string
	// Token authenticates to the collector. It comes from the environment,
	// never from the config file, like every other secret here.
	Token string
	// Index is Splunk's index name. Elastic addresses the index in the URL
	// path, so it ignores this.
	Index string
	// MinRank gates this destination independently of the webhook's threshold:
	// a SIEM usually wants everything while on-call wants only criticals.
	MinRank int

	client *http.Client
}

// NewSinkOptions is what NewSink needs beyond the obvious. Split out rather
// than added as two more positional arguments, because a bool parameter at a
// call site reads as nothing at all.
type NewSinkOptions struct {
	// AllowPrivate lets this sink reach an address on the operator's own
	// network. Off by default: on for a Splunk at 10.0.0.5, which is the normal
	// case, and the operator says so per sink rather than inheriting it.
	AllowPrivate bool
}

// NewSink builds a delivery client for one destination.
//
// The HTTP client is safefetch's, for the same reason the webhook's is: the
// body names what was detected and about whom, a collector hostname that
// resolves to an internal address needs no redirect to be dangerous, and the
// check therefore has to live in the dialer rather than in a redirect policy.
func NewSink(sinkType, url, token, index, minSeverity string, opts ...NewSinkOptions) Sink {
	var o NewSinkOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	// A SIEM on the operator's own network is the ordinary deployment, and the
	// blanket rule that serves the webhook refuses exactly that. InternalClient
	// still refuses loopback, link-local and multicast — cloud metadata is not
	// reachable either way, and a collector on 127.0.0.1 would be the gateway
	// posting alerts to its own admin API.
	newClient := safefetch.Client
	if o.AllowPrivate {
		newClient = safefetch.InternalClient
	}
	return Sink{
		Type:    sinkType,
		URL:     url,
		Token:   token,
		Index:   index,
		MinRank: severityRank(minSeverity),
		client:  newClient("siem_"+sinkType, 10*time.Second),
	}
}

// encode renders one alert in the destination's wire format.
func (s Sink) encode(level, title, body string, now time.Time) ([]byte, error) {
	switch s.Type {
	case SinkSplunkHEC:
		// HEC wraps the payload in an envelope it indexes by. `time` is
		// seconds since the epoch as a number — Splunk rejects RFC3339 here,
		// and a rejected batch is dropped silently at the collector, which is
		// the failure mode hardest to notice from this side.
		event := map[string]any{
			"source":   "aegis",
			"severity": level,
			"title":    title,
			"body":     body,
		}
		envelope := map[string]any{
			"time":       float64(now.UnixNano()) / float64(time.Second),
			"host":       "aegis",
			"source":     "aegis:alert",
			"sourcetype": "aegis:alert",
			"event":      event,
		}
		if s.Index != "" {
			envelope["index"] = s.Index
		}
		return json.Marshal(envelope)

	case SinkElastic:
		// Elastic Common Schema field names, so the events land in the same
		// dashboards as everything else rather than needing a bespoke mapping.
		// A document that needs its own mapping is a document nobody queries.
		return json.Marshal(map[string]any{
			"@timestamp":    now.UTC().Format(time.RFC3339Nano),
			"event.kind":    "alert",
			"event.module":  "aegis",
			"event.dataset": "aegis.alert",
			"event.severity": map[string]int{
				SeverityInfo: 1, SeverityWarning: 5, SeverityCritical: 9,
			}[level],
			"log.level":       level,
			"message":         title,
			"error.message":   body,
			"observer.vendor": "AEGIS",
			"observer.type":   "api-gateway",
		})

	default:
		return nil, fmt.Errorf("alert: unknown sink type %q", s.Type)
	}
}

// deliver POSTs one alert. Errors are returned rather than logged here so the
// caller can name the destination in one place.
func (s Sink) deliver(ctx context.Context, level, title, body string, now time.Time) error {
	data, err := s.encode(level, title, body, now)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	switch s.Type {
	case SinkSplunkHEC:
		req.Header.Set("Authorization", "Splunk "+s.Token)
	case SinkElastic:
		// Elastic accepts an API key this way; a deployment with security
		// disabled passes no token and the header is omitted entirely rather
		// than sent empty, which some proxies treat as a malformed credential.
		if s.Token != "" {
			req.Header.Set("Authorization", "ApiKey "+s.Token)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %d", s.Type, resp.StatusCode)
	}
	return nil
}

// fanOut delivers one alert to every sink that wants it.
//
// Concurrent, because the sinks share the caller's deadline: delivered in
// sequence, one collector that always times out would spend the entire budget
// and the sinks after it would never be attempted — an outage in a system
// nobody is watching would silently disable the one somebody is.
//
// One failure never affects another, and none of them affects the request that
// produced the alert: this already runs on a detached goroutine.
func (e *Engine) fanOut(ctx context.Context, level, title, body string) {
	if len(e.sinks) == 0 {
		return
	}
	rank := severityRank(level)
	now := time.Now()

	var wg sync.WaitGroup
	for _, s := range e.sinks {
		if rank < s.MinRank {
			continue
		}
		wg.Add(1)
		go func(s Sink) {
			defer wg.Done()
			if err := s.deliver(ctx, level, title, body, now); err != nil {
				e.log.Error("alert: SIEM delivery failed", map[string]any{
					"sink": s.Type, "error": err.Error(),
				})
			}
		}(s)
	}
	wg.Wait()
}

// ValidSinkType reports whether a configured sink type is one this package can
// deliver to. Config validation uses it so an unknown type is refused at
// startup rather than discovered as a log line after the first incident.
func ValidSinkType(t string) bool {
	switch strings.ToLower(t) {
	case SinkSplunkHEC, SinkElastic:
		return true
	default:
		return false
	}
}
