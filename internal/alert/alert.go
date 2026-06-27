package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"api-gateway/internal/logger"
)

// Severity levels for alerts, ordered by increasing urgency.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// severityRank maps a severity string to a comparable rank. Unknown values
// rank as warning so a typo never silently suppresses an alert.
func severityRank(level string) int {
	switch level {
	case SeverityInfo:
		return 0
	case SeverityCritical:
		return 2
	default: // warning and anything unrecognised
		return 1
	}
}

// Engine delivers alerts to an external destination (Slack / PagerDuty / SIEM
// webhook) and always mirrors them to the local log. Delivery is gated by a
// minimum severity so low-value noise never reaches on-call.
type Engine struct {
	webhookURL string
	format     string // "generic" or "slack"
	minRank    int
	log        *logger.Logger
	client     *http.Client
}

// New creates an alert Engine with sane defaults (generic format, warning
// threshold). Prefer NewWithConfig for full control.
func New(webhookURL string, log *logger.Logger) *Engine {
	return NewWithConfig(webhookURL, "generic", SeverityWarning, log)
}

// NewWithConfig creates an alert Engine. An empty webhookURL disables outbound
// delivery; alerts are still logged locally.
func NewWithConfig(webhookURL, format, minSeverity string, log *logger.Logger) *Engine {
	if format == "" {
		format = "generic"
	}
	return &Engine{
		webhookURL: webhookURL,
		format:     format,
		minRank:    severityRank(minSeverity),
		log:        log,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Fire delivers an alert. It is always logged; it is POSTed to the webhook only
// when one is configured and the level meets the minimum severity.
func (e *Engine) Fire(ctx context.Context, level, title, body string) {
	if level == "" {
		level = SeverityWarning
	}

	fields := map[string]any{"level": level, "title": title, "body": body}

	// Below threshold: log at debug-ish info level and skip outbound delivery.
	if severityRank(level) < e.minRank {
		e.log.Info("alert suppressed (below min_severity)", fields)
		return
	}

	if e.webhookURL == "" {
		e.log.Info("alert fired (no webhook configured)", fields)
		return
	}
	e.log.Info("alert fired", fields)

	data, err := e.encode(level, title, body)
	if err != nil {
		e.log.Error("alert: encode payload failed", map[string]any{"error": err.Error()})
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.webhookURL, bytes.NewReader(data))
	if err != nil {
		e.log.Error("alert: build request failed", map[string]any{"error": err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		e.log.Error("alert: webhook failed", map[string]any{"error": err.Error()})
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		e.log.Error("alert: webhook returned non-2xx", map[string]any{"status": resp.StatusCode})
	}
}

// encode renders the alert payload in the configured wire format.
func (e *Engine) encode(level, title, body string) ([]byte, error) {
	if e.format == "slack" {
		// Slack incoming-webhook shape: a single rendered text block.
		text := strings.ToUpper(level) + " — " + title
		if body != "" {
			text += "\n" + body
		}
		return json.Marshal(map[string]string{"text": text})
	}
	// Generic AEGIS envelope.
	return json.Marshal(map[string]string{
		"source": "aegis",
		"level":  level,
		"title":  title,
		"body":   body,
		"ts":     time.Now().UTC().Format(time.RFC3339),
	})
}
