package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"api-gateway/internal/alert"
	"api-gateway/internal/api"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/forensic"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/proxy"
	"api-gateway/internal/store"

	"github.com/fsnotify/fsnotify"
)

// Build-time variables set via -ldflags
var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
	cfgPath := flag.String("config", "config/gateway.yaml", "path to gateway config")
	flag.Parse()

	// ── Load Configuration ────────────────────────────────────────────────────
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		panic("failed to load config: " + err.Error())
	}
	if err := config.Validate(cfg); err != nil {
		panic("unsafe configuration: " + err.Error())
	}

	// Pre-parse trusted proxy CIDRs once so RealIP() never does it per-request.
	if err := middleware.InitTrustedProxies(cfg.TrustedProxies); err != nil {
		panic("invalid trusted_proxies config: " + err.Error())
	}

	// ── Logger ────────────────────────────────────────────────────────────────
	log := logger.New(cfg.Logging.Level)
	log.Info("AEGIS API Security Gateway starting", map[string]any{
		"listen":       cfg.Listen,
		"admin_listen": cfg.AdminListen,
		"version":      version,
		"commit":       commit,
		"build_time":   buildTime,
	})

	// ── Redis Store ───────────────────────────────────────────────────────────
	st, err := store.New(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		log.Error("failed to connect to Redis", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	// ── Alert Engine ──────────────────────────────────────────────────────────
	alerts := alert.New("", log) // Webhook URL from config if available

	// ── Forensic Log Sink (PostgreSQL persistence) ──────────────────────────
	var fSink *forensic.PGSink
	if cfg.ForensicDSN != "" {
		fSink, err = forensic.NewPGSink(cfg.ForensicDSN, log)
		if err != nil {
			log.Error("forensic sink init failed (falling back to Redis-only)", map[string]any{"error": err.Error()})
		} else {
			defer fSink.Close()
			st.SetForensicSink(fSink)
			log.Info("forensic log persistence enabled", map[string]any{"backend": "postgresql"})
		}
	}

	// ── API Discovery Catalog (passive posture management) ──────────────────
	// Reuses the forensic PostgreSQL instance. When no DSN is configured the
	// catalog is nil and the Discovery middleware degrades to a passthrough.
	postureEng := discovery.NewPostureEngine(cfg)
	var catalog *discovery.Catalog
	if cfg.ForensicDSN != "" {
		catalog, err = discovery.NewCatalog(cfg.ForensicDSN, postureEng, log)
		if err != nil {
			log.Error("api catalog init failed (discovery disabled)", map[string]any{"error": err.Error()})
			catalog = nil
		} else {
			defer func() { _ = catalog.Close() }()
			log.Info("api discovery catalog enabled", map[string]any{"backend": "postgresql"})
		}
	} else {
		log.Warn("forensic_dsn not set — API discovery catalog disabled")
	}

	// ── Build Handler Chain ───────────────────────────────────────────────────
	var activeHandler atomic.Value
	handler, gw, err := buildHandlerChain(cfg, log, st, alerts, catalog)
	if err != nil {
		log.Error("failed to build handler chain", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	activeHandler.Store(handler)

	// ── Gateway Server (Hot Reload via atomic swap) ───────────────────────────
	gwServer := &http.Server{
		Addr: cfg.Listen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			activeHandler.Load().(http.Handler).ServeHTTP(w, r)
		}),
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second, // ARCH: prevent slowloris
		MaxHeaderBytes:    1 << 20,         // 1MB max header
	}

	// ── Admin API Server ──────────────────────────────────────────────────────
	adminSrv := api.NewServer(st, log, cfg, gw, alerts, catalog)

	// FIX SEC: Protect admin API against brute force and DDoS
	adminRateLimit := config.RateLimitConfig{
		Enabled:    true,
		Requests:   5,
		Window:     time.Second,
		BurstLimit: 10,
	}

	if !cfg.AdminAuth {
		log.Warn("SECURITY WARNING: admin_auth is disabled — admin API is open to anyone", map[string]any{
			"admin_listen": cfg.AdminListen,
		})
	}

	adminHandler := middleware.Chain(adminSrv,
		middleware.RequestID(),       // innermost: stamp every request before anything else
		middleware.SecurityHeaders(), // must wrap AdminAuth so 401/403 responses carry CSP/HSTS
		middleware.AdminAuth(cfg, log, st),
		middleware.RateLimit(adminRateLimit, log, st),
		middleware.CORS(cfg.Security.CORS),
	)
	adminServer := &http.Server{
		Addr:              cfg.AdminListen,
		Handler:           adminHandler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// ── Hot Reload Watcher ────────────────────────────────────────────────────
	go watchConfigFile(*cfgPath, &activeHandler, log, st, alerts, catalog)

	// ── Start Servers ─────────────────────────────────────────────────────────
	go func() {
		log.Info("gateway listening", map[string]any{"addr": cfg.Listen})
		if err := gwServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("gateway server error", map[string]any{"error": err.Error()})
		}
	}()

	go func() {
		log.Info("admin API listening", map[string]any{"addr": cfg.AdminListen})
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("admin server error", map[string]any{"error": err.Error()})
		}
	}()

	// ── Graceful Shutdown ─────────────────────────────────────────────────────
	// FIX SEC-5: Use Shutdown(ctx) with deadline to drain in-flight requests
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	log.Info("shutdown signal received", map[string]any{"signal": sig.String()})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully drain existing connections
	if err := gwServer.Shutdown(ctx); err != nil {
		log.Error("gateway shutdown error", map[string]any{"error": err.Error()})
	}
	if err := adminServer.Shutdown(ctx); err != nil {
		log.Error("admin shutdown error", map[string]any{"error": err.Error()})
	}

	log.Info("AEGIS gateway stopped gracefully")
}

// buildHandlerChain constructs the full middleware chain for the gateway.
func buildHandlerChain(cfg config.GatewayConfig, log *logger.Logger, st *store.Store, alerts *alert.Engine, catalog *discovery.Catalog) (http.Handler, *proxy.Gateway, error) {
	// Build proxy
	gw, err := proxy.New(cfg.Routes, log)
	if err != nil {
		return nil, nil, err
	}

	// Build JWT auth
	jwtAuth := middleware.NewJWTAuth(cfg.Security.Auth, log, st)

	// A nil *discovery.Catalog must be passed as a nil interface so the Discovery
	// middleware's nil-check works (a typed-nil pointer in an interface is non-nil).
	var cat middleware.Catalog
	if catalog != nil {
		cat = catalog
	}

	// Assemble middleware chain (order matters: outermost first).
	// Discovery sits just inside the security perimeter (after WAF/rate-limit/bot
	// so attacks stay out of the catalog) and outside auth/DLP so it can enrich
	// the observation with identity and PII signals and capture the final status.
	handler := middleware.Chain(gw,
		middleware.CleanHeaders(),    // SEC: Strip spoofed X-Gateway-* headers
		middleware.SecurityHeaders(), // ARCH-6: Security headers on every response
		middleware.RequestID(),       // ARCH-4: Request ID for log correlation
		middleware.CORS(cfg.Security.CORS),
		middleware.IPGuard(cfg.Security.IPGuard, log, st),
		middleware.ThreatFeed(cfg.Security.ThreatFeed, log, st),
		middleware.RateLimit(cfg.Security.RateLimit, log, st),
		middleware.BotProtection(cfg.Security.Bot, log, st),
		middleware.Challenge(cfg.Security.Challenge, log, st),
		middleware.WAF(cfg.Security.WAF, log, st),
		middleware.Discovery(cfg.Security.Inventory, cat, log), // passive API discovery
		jwtAuth.Middleware(),
		middleware.AbuseDetection(cfg.Security.Abuse, log, st), // BOLA/BFLA (needs verified roles)
		middleware.DLP(cfg.Security.DLP, log, st),
		middleware.BehaviorAnalysis(cfg.Security.Behavior, log, st),
	)

	return handler, gw, nil
}

// watchConfigFile uses fsnotify for instant config hot-reload (zero-downtime).
// Falls back to 5s polling if fsnotify setup fails.
func watchConfigFile(path string, activeHandler *atomic.Value, log *logger.Logger, st *store.Store, alerts *alert.Engine, catalog *discovery.Catalog) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	reload := func() {
		log.Info("config change detected, hot-reloading...")

		newCfg, err := config.Load(absPath)
		if err != nil {
			log.Error("hot-reload: config parse error", map[string]any{"error": err.Error()})
			return
		}

		newHandler, _, err := buildHandlerChain(newCfg, log, st, alerts, catalog)
		if err != nil {
			log.Error("hot-reload: chain build error", map[string]any{"error": err.Error()})
			return
		}

		// Re-classify future traffic against the new configuration.
		if catalog != nil {
			catalog.SetPostureEngine(discovery.NewPostureEngine(newCfg))
		}

		activeHandler.Store(newHandler)
		log.Info("hot-reload: success", map[string]any{
			"routes": len(newCfg.Routes),
		})
	}

	// Try fsnotify for instant reload
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warn("fsnotify unavailable, falling back to polling", map[string]any{"error": err.Error()})
		pollConfigFile(absPath, reload)
		return
	}
	defer func() { _ = watcher.Close() }()

	// Watch the directory (handles atomic renames used by editors)
	dir := filepath.Dir(absPath)
	if err := watcher.Add(dir); err != nil {
		log.Warn("fsnotify watch failed, falling back to polling", map[string]any{"error": err.Error()})
		pollConfigFile(absPath, reload)
		return
	}

	log.Info("fsnotify: watching config for changes", map[string]any{"path": absPath})

	// Debounce: ignore rapid successive events
	var debounce *time.Timer

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Only react to writes/renames of our config file
			if filepath.Base(event.Name) != filepath.Base(absPath) {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			// Debounce 500ms to avoid rapid reloads
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(500*time.Millisecond, reload)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Error("fsnotify error", map[string]any{"error": err.Error()})
		}
	}
}

// pollConfigFile is the fallback watcher using 5s polling.
func pollConfigFile(path string, reload func()) {
	var lastMod time.Time
	if info, err := os.Stat(path); err == nil {
		lastMod = info.ModTime()
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.ModTime().After(lastMod) {
			lastMod = info.ModTime()
			reload()
		}
	}
}
