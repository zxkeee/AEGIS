package middleware

import (
	"net/http"

	"api-gateway/internal/config"
)

// APIInventory records every endpoint and optionally alerts on new discoveries.
func APIInventory(cfg config.APIInventoryConfig, st Store, log Logger, alerts AlertEngine) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			endpoint := r.Method + " " + r.URL.Path

			isNew, err := st.RecordEndpoint(r.Context(), endpoint)
			if err != nil {
				log.Error("api_inventory: record error", map[string]any{"error": err.Error()})
			}

			if isNew {
				log.Info("api_inventory: new endpoint discovered", map[string]any{
					"endpoint": endpoint,
					"ip":       RealIP(r),
				})
				st.IncrMetric(r.Context(), "api_new_endpoint")

				if cfg.AlertOnNew && alerts != nil {
					alerts.Fire(r.Context(), "warning",
						"New API Endpoint Discovered",
						"Endpoint: "+endpoint+" from IP: "+RealIP(r))
				}
			}

			// Shadow Parameter Discovery
			queryParams := make([]string, 0)
			for key := range r.URL.Query() {
				queryParams = append(queryParams, key)
			}
			if len(queryParams) > 0 {
				newParams, err := st.RecordParameters(r.Context(), endpoint, queryParams)
				if err != nil {
					log.Error("api_inventory: param record error", map[string]any{"error": err.Error()})
				}
				for _, p := range newParams {
					log.Info("api_inventory: new parameter discovered", map[string]any{
						"endpoint":  endpoint,
						"parameter": p,
						"ip":        RealIP(r),
					})
					st.IncrMetric(r.Context(), "api_new_parameter")
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
