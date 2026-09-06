package api

import (
	"net/http"
	"sync/atomic"

	"api-gateway/internal/alert"
	"api-gateway/internal/attest"
	"api-gateway/internal/audit"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/forensic"
	"api-gateway/internal/iam"
	"api-gateway/internal/license"
	"api-gateway/internal/logger"
	"api-gateway/internal/proxy"
	"api-gateway/internal/store"
)

// Server is the Admin Management API.
type Server struct {
	mux      *http.ServeMux
	store    *store.Store
	log      *logger.Logger
	cfg      config.GatewayConfig
	gateway  *proxy.Gateway
	alerts   *alert.Engine
	catalog  *discovery.Catalog
	forensic *forensic.PGSink
	users    *iam.Store
	audit    *audit.Store
	oidc     OIDCAuthenticator
	// draining is set on shutdown so /readyz reports 503 (lame-duck) while the
	// gateway is still serving established connections — see cmd/gateway drain grace.
	draining atomic.Bool
	// licenseStatus holds the most recent license.Status computed by main.go's
	// loadValidatedConfig (boot, and every hot-reload — see SetLicenseStatus).
	// atomic.Value so a concurrent GET /api/license never races a reload.
	licenseStatus atomic.Value
}

// SetDraining flips the readiness state. When true, /readyz returns 503 so a
// load balancer / k8s readiness probe stops routing new traffic before the
// gateway actually stops accepting connections.
func (s *Server) SetDraining(v bool) { s.draining.Store(v) }

// SetLicenseStatus records the license outcome from the most recent boot or
// hot-reload, so GET /api/license and the console banner reflect it without
// reading gateway logs. Called from cmd/gateway/main.go.
func (s *Server) SetLicenseStatus(st license.Status) { s.licenseStatus.Store(st) }

// NewServer creates a new admin API server. users / auditStore may be nil if
// forensic_dsn is unset — in that case only the legacy bearer/secret login is
// available and the admin audit trail is not persisted. oidc may be nil when
// SSO is disabled or the provider discovery failed at startup.
func NewServer(st *store.Store, log *logger.Logger, cfg config.GatewayConfig, gw *proxy.Gateway, alerts *alert.Engine, catalog *discovery.Catalog, forensicSink *forensic.PGSink, users *iam.Store, auditStore *audit.Store, oidc OIDCAuthenticator) *Server {
	s := &Server{
		mux:      http.NewServeMux(),
		store:    st,
		log:      log,
		cfg:      cfg,
		gateway:  gw,
		alerts:   alerts,
		catalog:  catalog,
		forensic: forensicSink,
		users:    users,
		audit:    auditStore,
		oidc:     oidc,
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	h := &handlers{store: s.store, log: s.log, cfg: s.cfg, gateway: s.gateway, alerts: s.alerts, catalog: s.catalog, forensic: s.forensic, users: s.users, audit: s.audit, oidc: s.oidc, draining: &s.draining, licenseStatus: &s.licenseStatus}
	// Assign the spec interface only for a real catalog, so a nil *discovery.
	// Catalog does not become a non-nil interface holding a typed-nil pointer.
	if s.catalog != nil {
		h.specCat = s.catalog
	}

	// config.Validate has already proved this key parses, so a failure here can
	// only be a programming error — but the report path must never be handed a
	// half-built signer, so it stays nil and says so rather than panicking on
	// the first audit request.
	if s.cfg.ReportSigningKey != "" {
		signer, err := attest.NewSigner(s.cfg.ReportSigningKey)
		if err != nil {
			s.log.Error("admin: report signing key rejected; signed reports are unavailable",
				map[string]any{"error": err.Error()})
		} else {
			h.reportSigner = signer
		}
	}

	// Console SPA shell (unauthenticated shell; the data APIs below are guarded).
	s.mux.HandleFunc("GET /", h.serveDashboard)
	// Hashed bundle assets (JS/CSS/svg).
	s.mux.HandleFunc("GET /assets/", h.serveConsoleAsset)
	// Public bootstrap: tells the login screen whether admin_auth / SSO are on.
	s.mux.HandleFunc("GET /api/console/env", h.consoleEnv)

	// Probes (unauthenticated)
	s.mux.HandleFunc("GET /health", h.health)
	s.mux.HandleFunc("GET /readyz", h.readyz)

	// Console session auth
	s.mux.HandleFunc("POST /api/login", h.login)
	s.mux.HandleFunc("POST /api/logout", h.logout)

	// OIDC single sign-on (public: the flow itself is the authentication).
	s.mux.HandleFunc("GET /api/auth/oidc/login", h.oidcLogin)
	s.mux.HandleFunc("GET /api/auth/oidc/callback", h.oidcCallback)

	// Admin endpoints (protected by AdminAuth middleware)
	s.mux.HandleFunc("GET /api/session", h.getSession)
	s.mux.HandleFunc("GET /api/license", h.getLicense)
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
	s.mux.HandleFunc("GET /api/graph", h.getGraph)
	s.mux.HandleFunc("GET /api/posture/summary", h.getPostureSummary)
	s.mux.HandleFunc("GET /api/effectiveness", h.getEffectiveness)
	s.mux.HandleFunc("GET /api/findings", h.getFindings)
	s.mux.HandleFunc("GET /api/compliance", h.getCompliance)
	s.mux.HandleFunc("GET /api/report", h.getReport)
	s.mux.HandleFunc("GET /api/report/signing-key", h.getSigningKey)

	// OpenAPI spec import + documented-vs-observed drift (per-tenant).
	s.mux.HandleFunc("GET /api/discovery/spec", h.getSpec)
	s.mux.HandleFunc("PUT /api/discovery/spec", h.putSpec)
	s.mux.HandleFunc("DELETE /api/discovery/spec", h.deleteSpec)
	s.mux.HandleFunc("GET /api/discovery/drift", h.getDrift)

	// Admin action audit trail (per-tenant; super-admin can span with ?all=true).
	s.mux.HandleFunc("GET /api/audit", h.getAudit)

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
