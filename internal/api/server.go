package api

import (
	"net/http"

	"api-gateway/internal/alert"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/iam"
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
	users   *iam.Store
}

// NewServer creates a new admin API server. users may be nil if forensic_dsn is
// unset — in that case only the legacy bearer/secret login is available.
func NewServer(st *store.Store, log *logger.Logger, cfg config.GatewayConfig, gw *proxy.Gateway, alerts *alert.Engine, catalog *discovery.Catalog, users *iam.Store) *Server {
	s := &Server{
		mux:     http.NewServeMux(),
		store:   st,
		log:     log,
		cfg:     cfg,
		gateway: gw,
		alerts:  alerts,
		catalog: catalog,
		users:   users,
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	h := &handlers{store: s.store, log: s.log, cfg: s.cfg, gateway: s.gateway, alerts: s.alerts, catalog: s.catalog, users: s.users}

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
	s.mux.HandleFunc("GET /metrics", h.prometheus) // Prometheus-native exposition
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
	s.mux.HandleFunc("GET /api/findings", h.getFindings)
	s.mux.HandleFunc("GET /api/report", h.getReport)

	// IP management
	s.mux.HandleFunc("GET /api/blocked-ips", h.getBlockedIPs)
	s.mux.HandleFunc("POST /api/blocked-ips", h.blockIPHandler)
	s.mux.HandleFunc("DELETE /api/blocked-ips/{ip}", h.unblockIPHandler)

	// JWT management
	s.mux.HandleFunc("POST /api/jwt/revoke", h.revokeJWT)

	// Multi-tenancy management (P0-3 / MT phase 5).
	s.mux.HandleFunc("GET /api/tenants", h.listTenants)
	s.mux.HandleFunc("POST /api/tenants", h.createTenant)
	s.mux.HandleFunc("DELETE /api/tenants/{id}", h.deleteTenant)
	s.mux.HandleFunc("GET /api/users", h.listUsers)
	s.mux.HandleFunc("POST /api/users", h.createUser)
	s.mux.HandleFunc("DELETE /api/users/{id}", h.deleteUser)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
