package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"api-gateway/internal/logger"
)

// Engine sends alerts via webhooks.
type Engine struct {
	webhookURL string
	log        *logger.Logger
	client     *http.Client
}

// New creates a new alert Engine.
func New(webhookURL string, log *logger.Logger) *Engine {
	return &Engine{
		webhookURL: webhookURL,
		log:        log,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Fire sends an alert.
func (e *Engine) Fire(ctx context.Context, level, title, body string) {
	if e.webhookURL == "" {
		e.log.Info("alert fired (no webhook configured)", map[string]any{
			"level": level,
			"title": title,
			"body":  body,
		})
		return
	}

	payload := map[string]string{
		"level": level,
		"title": title,
		"body":  body,
		"ts":    time.Now().UTC().Format(time.RFC3339),
	}

	data, _ := json.Marshal(payload)
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
	_ = resp.Body.Close()
}
