package api

import (
	"net/http"

	"api-gateway/internal/alert"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
	"api-gateway/internal/proxy"
	"api-gateway/internal/store"
)

// Server is the Admin Management API.
type Server struct {
	mux     *http.ServeMux
	store   *store.Store
	log     *logger.Logger
	cfg     config.GatewayConfig
	gateway *proxy.Gateway
	alerts  *alert.Engine
	catalog *discovery.Catalog
}

// NewServer creates a new admin API server.
func NewServer(st *store.Store, log *logger.Logger, cfg config.GatewayConfig, gw *proxy.Gateway, alerts *alert.Engine, catalog *discovery.Catalog) *Server {
	s := &Server{
		mux:     http.NewServeMux(),
		store:   st,
		log:     log,
		cfg:     cfg,
		gateway: gw,
		alerts:  alerts,
		catalog: catalog,
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	h := &handlers{store: s.store, log: s.log, cfg: s.cfg, gateway: s.gateway, alerts: s.alerts, catalog: s.catalog}

	// Dashboard (unauthenticated — auth handled via JS prompt)
	s.mux.HandleFunc("GET /", h.serveDashboard)

	// Probes (unauthenticated)
	s.mux.HandleFunc("GET /health", h.health)
	s.mux.HandleFunc("GET /readyz", h.readyz)

	// Console session auth
	s.mux.HandleFunc("POST /api/login", h.login)
	s.mux.HandleFunc("POST /api/logout", h.logout)

	// Admin endpoints (protected by AdminAuth middleware)
	s.mux.HandleFunc("GET /api/metrics", h.getMetrics)
	s.mux.HandleFunc("GET /api/config", h.getConfig)
	s.mux.HandleFunc("GET /api/routes", h.getRoutes)
	s.mux.HandleFunc("GET /api/block-log", h.getBlockLog)
	s.mux.HandleFunc("GET /api/inventory", h.getInventory)

	// API Security: discovery catalog, consumers, posture, effectiveness, report
	s.mux.HandleFunc("GET /api/catalog", h.getCatalog)
	s.mux.HandleFunc("GET /api/catalog/{id}", h.getCatalogEndpoint)
	s.mux.HandleFunc("GET /api/consumers", h.getConsumers)
	s.mux.HandleFunc("GET /api/posture/summary", h.getPostureSummary)
	s.mux.HandleFunc("GET /api/effectiveness", h.getEffectiveness)
	s.mux.HandleFunc("GET /api/report", h.getReport)

	// IP management
	s.mux.HandleFunc("GET /api/blocked-ips", h.getBlockedIPs)
	s.mux.HandleFunc("POST /api/blocked-ips", h.blockIPHandler)
	s.mux.HandleFunc("DELETE /api/blocked-ips/{ip}", h.unblockIPHandler)

	// JWT management
	s.mux.HandleFunc("POST /api/jwt/revoke", h.revokeJWT)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
