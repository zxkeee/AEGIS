package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// prometheus serves the AEGIS counters in Prometheus text exposition format
// (version 0.0.4). The counters live in Redis under "gw:metrics:*" and are
// surfaced here as `aegis_<name>` gauges so they can be scraped natively
// without the JSON admin endpoint.
//
// The endpoint sits behind AdminAuth like the rest of the admin plane; point
// Prometheus at it with a `bearer_token` (the admin secret) in the scrape job.
func (h *handlers) prometheus(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.store.GetMetrics(r.Context())
	if err != nil {
		h.log.Error("admin: prometheus metrics fetch failed", map[string]any{"error": err.Error()})
		http.Error(w, "# failed to fetch metrics\n", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(renderProm(metrics)))
}

// renderProm renders counters into Prometheus text exposition format with
// stable (sorted) ordering.
func renderProm(metrics map[string]int64) string {
	names := make([]string, 0, len(metrics))
	for name := range metrics {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		metric := "aegis_" + sanitizeMetricName(name)
		b.WriteString("# HELP ")
		b.WriteString(metric)
		b.WriteString(" AEGIS counter ")
		b.WriteString(name)
		b.WriteByte('\n')
		b.WriteString("# TYPE ")
		b.WriteString(metric)
		b.WriteString(" counter\n")
		b.WriteString(metric)
		b.WriteByte(' ')
		b.WriteString(strconv.FormatInt(metrics[name], 10))
		b.WriteByte('\n')
	}
	return b.String()
}

// sanitizeMetricName coerces an arbitrary counter name into a valid Prometheus
// metric-name suffix: [a-zA-Z0-9_], everything else collapsed to '_'.
func sanitizeMetricName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
