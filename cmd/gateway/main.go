package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"api-gateway/internal/alert"
	"api-gateway/internal/api"
	"api-gateway/internal/attest"
	"api-gateway/internal/audit"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/forensic"
	"api-gateway/internal/gateway"
	"api-gateway/internal/iam"
	"api-gateway/internal/incident"
	"api-gateway/internal/license"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/retention"
	"api-gateway/internal/sso"
	"api-gateway/internal/store"
	"api-gateway/internal/tlsfp"

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
	printFingerprint := flag.Bool("print-fingerprint", false,
		"print this machine's license hardware fingerprint and exit (run this BEFORE requesting a license, "+
			"on the box that will actually run the gateway — see docs/licensing.md)")
	flag.Parse()

	if *printFingerprint {
		fp, err := license.Fingerprint()
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot compute fingerprint: "+err.Error())
			os.Exit(1)
		}
		fmt.Println(fp)
		return
	}

	// ── Load Configuration ────────────────────────────────────────────────────
	cfg, trustedProxyNets, licStatus, coercions, err := loadValidatedConfig(*cfgPath)
	if err != nil {
		// Exit, don't panic: this is a rejected CONFIGURATION, not a bug in the
		// gateway, and a goroutine dump buries the one line the operator needs
		// under a stack trace that invites them to file an issue instead of
		// fixing their YAML. Matches the -print-fingerprint path just above.
		fmt.Fprintln(os.Stderr, "unsafe configuration: "+err.Error())
		os.Exit(1)
	}
	// No prior chain to protect on boot — commit immediately (see
	// loadValidatedConfig's doc comment for why hot-reload defers this).
	middleware.SetTrustedProxies(trustedProxyNets)

	// ── Logger ────────────────────────────────────────────────────────────────
	log := logger.New(cfg.Logging.Level)
	log.Info("AEGIS API Security Gateway starting", map[string]any{
		"listen":       cfg.Listen,
		"admin_listen": cfg.AdminListen,
		"version":      version,
		"commit":       commit,
		"build_time":   buildTime,
	})
	logLicenseStatus(log, licStatus)
	if cfg.Observe {
		log.Warn("OBSERVE MODE ACTIVE: passive pilot posture — the gateway inspects and records but blocks nothing, "+
			"modifies no response body, and never fails closed. Discovery, findings, WAF-detection, DLP-classification "+
			"and BOLA/BFLA still run. Do NOT rely on AEGIS for enforcement in this mode.",
			map[string]any{"coerced": coercions})
	}

	// ── Redis Store ───────────────────────────────────────────────────────────
	st, err := store.NewWithConfig(store.SentinelOptions{
		Addr:             cfg.Redis.Addr,
		Password:         cfg.Redis.Password,
		DB:               cfg.Redis.DB,
		MasterName:       cfg.Redis.Sentinel.MasterName,
		SentinelAddrs:    cfg.Redis.Sentinel.Addrs,
		SentinelPassword: cfg.Redis.Sentinel.SentinelPassword,
	})
	if err != nil {
		log.Error("failed to connect to Redis", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	// ── Alert Engine ──────────────────────────────────────────────────────────
	alerts := alert.NewWithConfig(cfg.Alerting.WebhookURL, cfg.Alerting.Format, cfg.Alerting.MinSeverity, log).
		WithSinks(siemSinks(cfg))
	if cfg.Alerting.WebhookURL != "" {
		log.Info("outbound alerting enabled", map[string]any{
			"format":       cfg.Alerting.Format,
			"min_severity": cfg.Alerting.MinSeverity,
		})
	}

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

	// ── Incident correlation (NIS2 Art. 23, DORA Art. 17-19) ────────────────
	// Groups security events into incidents with a lifecycle and reporting
	// deadlines. Installed as a WRAPPER around the forensic sink rather than
	// beside it: the durable record is written first and whatever happens here,
	// because the log is what happened and an incident is an interpretation of
	// it. Without a DSN there is nowhere to keep an incident, so this stays off
	// and the compliance report keeps saying the articles are not evidenced.
	var incidents *incident.PGStore
	var correlator *incident.Correlator
	if cfg.ForensicDSN != "" && fSink != nil {
		db, dberr := sql.Open("pgx", cfg.ForensicDSN)
		if dberr != nil {
			log.Error("incident store init failed (incident tracking disabled)",
				map[string]any{"error": dberr.Error()})
		} else if incidents, dberr = incident.NewPGStore(db, log); dberr != nil {
			log.Error("incident store init failed (incident tracking disabled)",
				map[string]any{"error": dberr.Error()})
			_ = db.Close()
			incidents = nil
		} else {
			defer func() { _ = db.Close() }()
			correlator = incident.New(incidents, log)
			defer func() { _ = correlator.Close() }()
			st.SetForensicSink(incident.NewSink(correlator, fSink, discovery.NormalizePath))
			log.Info("incident correlation enabled", map[string]any{
				"window": incident.DefaultWindow.String(),
			})
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
			loadConfigSpec(cfg, catalog, log)
		}
	} else {
		log.Warn("forensic_dsn not set — API discovery catalog disabled")
	}

	// ── IAM (tenants + admin users) ──────────────────────────────────────────
	// Shares the forensic PostgreSQL instance. Without it, the console can only
	// log in with the legacy bearer secret (no per-tenant operators).
	var iamStore *iam.Store
	if cfg.ForensicDSN != "" {
		iamStore, err = iam.NewStore(cfg.ForensicDSN, log)
		if err != nil {
			log.Error("iam store init failed (password login disabled)", map[string]any{"error": err.Error()})
			iamStore = nil
		} else {
			defer func() { _ = iamStore.Close() }()
			// First-boot bootstrap: if no users exist and AEGIS_ROOT_EMAIL +
			// AEGIS_ROOT_PASSWORD are set, create a super-admin so the operator
			// has a real account on day one without ever using the bearer secret.
			//
			// The pair is validated the way every other secret is. It was not
			// before: config.Validate refuses to start on a weak admin secret,
			// while a weak root password created the account that owns every
			// tenant and logged only that it had succeeded.
			rootEmail, rootPassword := os.Getenv("AEGIS_ROOT_EMAIL"), os.Getenv("AEGIS_ROOT_PASSWORD")
			if err := config.ValidateRootBootstrap(rootEmail, rootPassword); err != nil {
				log.Error("root bootstrap refused", map[string]any{"error": err.Error()})
				os.Exit(1)
			}
			if rootEmail != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := iamStore.BootstrapRoot(ctx, "default", rootEmail, rootPassword); err != nil {
					log.Error("iam root bootstrap failed", map[string]any{"error": err.Error()})
				}
				cancel()
			}
			log.Info("iam store enabled", map[string]any{"backend": "postgresql"})
		}
	}

	// ── Audit log (admin action trail) ────────────────────────────────────────
	// Shares the forensic PostgreSQL instance. Without it, admin actions are only
	// in the application log (not durable / queryable / tenant-scoped).
	var auditStore *audit.Store
	if cfg.ForensicDSN != "" {
		auditStore, err = audit.New(cfg.ForensicDSN, log)
		if err != nil {
			log.Error("audit store init failed (admin action trail disabled)", map[string]any{"error": err.Error()})
			auditStore = nil
		} else {
			defer func() { _ = auditStore.Close() }()
			log.Info("admin audit log enabled", map[string]any{"backend": "postgresql"})
		}
	}

	// ── Retention sweep (bounds durable-table growth) ─────────────────────────
	// Needs PostgreSQL (the tables it prunes). Runs on a cancelable context tied
	// to shutdown so the periodic sweep drains cleanly.
	retentionCtx, stopRetention := context.WithCancel(context.Background())
	defer stopRetention()
	if cfg.Retention.Enabled && cfg.ForensicDSN != "" {
		rw, rerr := retention.New(cfg.ForensicDSN, cfg.Retention, log)
		if rerr != nil {
			log.Error("retention init failed (sweep disabled)", map[string]any{"error": rerr.Error()})
		} else {
			defer func() { _ = rw.Close() }()
			go rw.Run(retentionCtx)
			log.Info("retention sweep enabled", map[string]any{
				"interval":           cfg.Retention.Interval.String(),
				"forensic_days":      cfg.Retention.ForensicDays,
				"audit_days":         cfg.Retention.AuditDays,
				"consumer_idle_days": cfg.Retention.ConsumerIdleDays,
			})
		}
	}

	// ── Forensic integrity seals ──────────────────────────────────────────────
	// The signed compliance report proves the DOCUMENT was not altered after it
	// was produced; it says nothing about the log the document was computed
	// from, and the retention sweep above deletes from that log on a schedule.
	// A seal commits to each period's contents so a later deletion, addition or
	// edit is detectable. See docs/forensic-seals.md for what that does and does
	// not prove.
	sealCtx, stopSeals := context.WithCancel(context.Background())
	defer stopSeals()
	if cfg.ForensicSeal.Enabled && fSink != nil {
		var sealSigner forensic.Signer
		if cfg.ReportSigningKey != "" {
			if sg, serr := attest.NewSigner(cfg.ReportSigningKey); serr == nil {
				sealSigner = sg
			} else {
				// Not fatal, and not silent: unsigned seals still detect an
				// edit made through the database, which is the common case.
				// They do not survive an operator who rewrites the chain.
				log.Error("forensic seals: signing key unusable, seals will be unsigned",
					map[string]any{"error": serr.Error()})
			}
		} else {
			log.Warn("forensic seals: no report signing key configured, seals are unsigned "+
				"(they detect edits made through the database, not a rewritten chain)", nil)
		}
		sw := forensic.NewSealWorker(fSink,
			forensic.SealSchedule{Period: cfg.ForensicSeal.Period, Lag: cfg.ForensicSeal.Lag},
			sealSigner, fSink.TenantsWithEntries, log)
		defer sw.Stop()
		go sw.Run(sealCtx)
		log.Info("forensic integrity seals enabled", map[string]any{
			"period": cfg.ForensicSeal.Period.String(),
			"lag":    cfg.ForensicSeal.Lag.String(),
			"signed": sealSigner != nil,
		})
	}

	// ── OIDC single sign-on (admin console) ───────────────────────────────────
	// Discovery is a network call; bound it and fail startup loudly if SSO is
	// configured but the provider is unreachable — a half-configured SSO is worse
	// than an obvious boot failure. Requires the iam store (validated in config).
	var ssoAuth *sso.Authenticator
	if cfg.OIDC.Enabled {
		// SSO just-in-time provisions operators in the iam store, so it cannot
		// function without one. Config validation requires forensic_dsn, but if
		// the iam store failed to initialise at runtime (DB unreachable) we must
		// NOT enable SSO — otherwise the callback would have no user store. Leave
		// ssoAuth nil so the endpoints stay 404 rather than 500.
		if iamStore == nil {
			log.Error("OIDC SSO configured but the iam store is unavailable; SSO disabled", nil)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			ssoAuth, err = sso.New(ctx, cfg.OIDC)
			cancel()
			if err != nil {
				log.Error("failed to initialise OIDC SSO", map[string]any{"error": err.Error(), "issuer": cfg.OIDC.Issuer})
				os.Exit(1)
			}
			log.Info("OIDC SSO enabled", map[string]any{"issuer": cfg.OIDC.Issuer})
		}
	}

	// ── Build Handler Chain ───────────────────────────────────────────────────
	var activeHandler atomic.Value
	handler, gw, err := gateway.BuildHandlerChain(cfg, log, st, catalog, postureEng, alerts)
	if err != nil {
		log.Error("failed to build handler chain", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	activeHandler.Store(handler)

	// currentLicensePath tracks cfg.LicensePath across hot-reloads (a reload
	// can change it), read by licenseRecheckLoop below. See that function's
	// doc comment for why this exists.
	var currentLicensePath atomic.Value
	currentLicensePath.Store(cfg.LicensePath)

	// ── Gateway Server (Hot Reload via atomic swap) ───────────────────────────
	// fpRegistry captures a real TLS fingerprint from each ClientHello when the
	// gateway terminates TLS, replacing the spoofable X-JA3-Fingerprint header.
	fpRegistry := tlsfp.NewRegistry()
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
		ConnContext:       fpRegistry.ConnContext,
		ConnState:         fpRegistry.ConnState,
	}
	if cfg.TLS.Enabled {
		gwServer.TLSConfig = fpRegistry.TLSConfig(nil)
	}

	// ── Admin API Server ──────────────────────────────────────────────────────
	// Assign the audit recorder only for a real store, so a nil *audit.Store does
	// not become a non-nil interface holding a typed-nil pointer.
	var auditRec audit.Recorder
	if auditStore != nil {
		auditRec = auditStore
	}
	// Pass a nil interface (not a typed-nil *sso.Authenticator) when SSO is off,
	// so the handlers' oidc != nil check works correctly.
	var ssoIface api.OIDCAuthenticator
	if ssoAuth != nil {
		ssoIface = ssoAuth
	}
	adminSrv := api.NewServer(st, log, cfg, gw, alerts, catalog, fSink, iamStore, auditStore, ssoIface)
	adminSrv.SetIncidents(incidents)
	adminSrv.SetLicenseStatus(licStatus) // GET /api/license + console banner reflect this boot's outcome

	if !cfg.AdminAuth {
		log.Warn("SECURITY WARNING: admin_auth is disabled — admin API is open to anyone", map[string]any{
			"admin_listen": cfg.AdminListen,
		})
	}

	if !cfg.TLS.Enabled {
		log.Warn("SECURITY WARNING: TLS is not terminated at the gateway — ensure a trusted upstream terminates TLS, or set tls.enabled (and require_tls) in production", nil)
	}

	if broad := middleware.OverlyBroadTrustedProxies(trustedProxyNets); len(broad) > 0 {
		log.Warn("SECURITY WARNING: trusted_proxies trusts whole networks, not specific proxies — "+
			"any host inside these ranges can set its own X-Forwarded-For, which does not just falsify logs: "+
			"the rate limiter, IP guard, behavioural scoring and (for callers with no JWT or API key) the "+
			"consumer identity BOLA enumeration counts against all resolve from that address, so every request "+
			"can look like a different caller. List the exact addresses of your load balancers instead", map[string]any{
			"ranges": broad,
		})
	}

	// Identity-propagation signature: in JWKS mode the JWT secret is unset, so
	// backends only get a signed X-Gateway-Signature if a separate
	// propagation_secret is configured. Flag this loudly — without a signature,
	// the gatewayverify SDK on backends will reject every request.
	if cfg.Security.Auth.Enabled && cfg.Security.Auth.JWKSURL != "" && cfg.Security.Auth.PropagationSecret == "" {
		log.Warn("SECURITY WARNING: JWKS auth is on but auth.propagation_secret is empty — "+
			"backends will not receive X-Gateway-Signature and the gatewayverify SDK will reject every request. "+
			"Set AEGIS_PROPAGATION_SECRET to a strong random value", nil)
	}

	adminHandler := gateway.BuildAdminChain(adminSrv, cfg, log, st, auditRec)
	adminServer := &http.Server{
		Addr:              cfg.AdminListen,
		Handler:           adminHandler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// ── Hot Reload Watcher ────────────────────────────────────────────────────
	go watchConfigFile(*cfgPath, &activeHandler, log, st, catalog, adminSrv, &currentLicensePath)

	// ── License Re-check ──────────────────────────────────────────────────────
	// See licenseRecheckLoop's doc comment: the hot-reload watcher above only
	// re-validates the license as a side effect of a gateway.yaml edit, so
	// without this a long-lived process (nobody touches its config — the
	// steady-state case) would keep serving on an expired license
	// indefinitely (audit finding, 2026-08-23).
	go licenseRecheckLoop(&currentLicensePath, log, adminSrv)

	// ── Start Servers ─────────────────────────────────────────────────────────
	go func() {
		if cfg.TLS.Enabled {
			log.Info("gateway listening (TLS terminated at gateway)", map[string]any{"addr": cfg.Listen})
			if err := gwServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Error("gateway server error", map[string]any{"error": err.Error()})
			}
			return
		}
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

	// Lame-duck grace: flip /readyz to 503 so an upstream load balancer / k8s
	// readiness probe removes this instance from rotation, then keep serving
	// established connections for the grace period before we stop accepting new
	// ones. Without it, closing the listener on SIGTERM races the LB and every
	// rolling update sheds a burst of connection errors.
	if cfg.ShutdownDrain > 0 {
		adminSrv.SetDraining(true)
		log.Info("lame-duck: /readyz now 503, draining before shutdown",
			map[string]any{"grace": cfg.ShutdownDrain.String()})
		time.Sleep(cfg.ShutdownDrain)
	}

	// Stop the retention sweep BEFORE the deferred rw.Close() runs, so an
	// in-flight sweep is cancelled while its connection pool is still open
	// (cancel-then-close, not the reverse the defer order would give).
	stopRetention()

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

// loadValidatedConfig parses the config file and runs the SAME safety gate for
// both startup and hot-reload: config.Validate (rejects insecure combinations
// such as placeholder secrets, wildcard CORS with auth, non-HTTPS threat feeds)
// and trusted_proxies parsing (so RealIP resolution tracks the config). Hot-
// reload previously skipped both, which let an unsafe edit go live and
// silently ignored trusted_proxies changes — the setting every per-IP control
// depends on.
//
// The parsed trusted-proxy set is returned rather than committed here
// (audit finding, 2026-08-22): committing eagerly meant a hot-reload that
// passed this gate but failed LATER — e.g. gateway.BuildHandlerChain
// rejecting an empty route's upstreams — had already overwritten the global
// RealIP trust boundary for the OLD, still-serving handler chain, silently
// contradicting the "previous config stays active" guarantee on error. The
// caller must call middleware.SetTrustedProxies with the returned set only
// once the ENTIRE reload (including BuildHandlerChain) has succeeded; on
// boot there is no prior chain to protect, so main() commits immediately.
//
// The fourth result lists the observe-mode coercions applied (empty when
// observe is off). It is returned rather than dropped because observe is the
// posture the shipped config/gateway.yaml starts in: an operator must be able
// to see WHICH controls were forced passive, not just that some were.
func loadValidatedConfig(path string) (config.GatewayConfig, []*net.IPNet, license.Status, []string, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.GatewayConfig{}, nil, license.Status{}, nil, err
	}
	if err := config.Validate(cfg); err != nil {
		return config.GatewayConfig{}, nil, license.Status{}, nil, err
	}
	// License is a hard boot gate, not a soft degrade: no valid license means
	// the gateway does not come up at all — same treatment as any other
	// config.Validate rejection (main() panics; a hot-reload with an invalid
	// license is rejected and the previous, already-running config stays
	// active, exactly like any other rejected reload). This is deliberate:
	// letting an unlicensed copy run for free in Observe mode still gives away
	// the discovery/posture/findings value for nothing, which defeats the
	// point. See docs/licensing.md for how to self-issue an internal license
	// for your own dev/eval use — that is the supported free path, not "no
	// license file at all."
	//
	// LoadWithGrace (not the plain Load) specifically so a hardware-lock
	// mismatch — the customer migrated/rebuilt the host the gateway runs on —
	// gets a bounded grace window instead of an immediate outage; see
	// license.LoadWithGrace's doc comment and docs/licensing.md.
	licStatus := license.LoadWithGrace(cfg.LicensePath, license.DefaultHardwareGrace)
	if !licStatus.Valid {
		return config.GatewayConfig{}, nil, licStatus, nil, fmt.Errorf(
			"no valid license: %s (see docs/licensing.md — issue one with cmd/licensegen)", licStatus.Reason)
	}
	// Tier entitlement: "trial"/"pilot" are pre-commercial and may only ever
	// run in Observe mode, regardless of what the operator's config says —
	// same hard-line treatment as an invalid license, just expressed as a
	// config coercion instead of a boot failure (a paying "production" tier
	// keeps whatever the operator configured).
	if licStatus.Claims.RequiresObserve() {
		cfg.Observe = true
	}
	// Feature entitlement: a config that turns on a paid feature (multi-
	// tenancy, SSO) the license doesn't include is a hard boot/reload
	// rejection, not a silent downgrade — an operator must never be able to
	// believe an unentitled feature is protecting live traffic when it
	// structurally isn't running.
	if err := license.CheckFeatureGates(licStatus.Claims, cfg.Multitenancy.Enabled, cfg.OIDC.Enabled); err != nil {
		return config.GatewayConfig{}, nil, licStatus, nil, fmt.Errorf("license feature entitlement: %w", err)
	}
	// Threaded into the chain as a runtime-only field (see its doc comment) so
	// middleware.LicenseRateLimit can enforce it without BuildHandlerChain
	// needing its own extra parameter.
	cfg.LicenseMaxRPS = licStatus.Claims.MaxRPS
	// Observe/pilot mode coercion runs AFTER validation, so the returned config is
	// already in its guaranteed non-disruptive shape before any chain is built —
	// on startup and on every hot-reload alike.
	coercions := cfg.ApplyObserveMode()
	trustedProxyNets, err := middleware.ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return config.GatewayConfig{}, nil, license.Status{}, nil, err
	}
	return cfg, trustedProxyNets, licStatus, coercions, nil
}

// logLicenseStatus reports a valid license's terms so licensee/tier/expiry
// are visible in every boot's and every hot-reload's logs, not just at issue
// time. loadValidatedConfig already turns an invalid license into a hard
// error before this is called (see there), so st.Valid is expected true here;
// the else branch is defensive only.
func logLicenseStatus(log *logger.Logger, st license.Status) {
	if !st.Valid {
		log.Error("license: INVALID OR MISSING (unexpected — loadValidatedConfig should have rejected this "+
			"before startup/hot-reload got this far)", map[string]any{"reason": st.Reason, "path": st.Path})
		return
	}
	if st.Grace {
		log.Warn("license: HARDWARE MISMATCH — running on a temporary grace period, NOT normally valid. "+
			"This machine's fingerprint does not match the license; the gateway will refuse to start once the "+
			"grace window ends. Contact the vendor for a free re-issue now — see docs/licensing.md.", map[string]any{
			"licensee":            st.Claims.Licensee,
			"tier":                st.Claims.Tier,
			"grace_until":         st.GraceUntil.Format(time.RFC3339),
			"current_fingerprint": st.CurrentFingerprint,
		})
		return
	}
	fields := map[string]any{"licensee": st.Claims.Licensee, "tier": st.Claims.Tier}
	if !st.Claims.ExpiresAt.IsZero() {
		fields["expires"] = st.Claims.ExpiresAt.Format("2006-01-02")
		fields["days_left"] = st.DaysLeft
	}
	log.Info("license: valid", fields)
}

// licenseRecheckInterval bounds how stale a running gateway's license status
// can get without a config-file edit or restart. Short enough that "the
// trial clock is real" (docs/licensing.md) holds within a bounded window
// rather than only "at the next incidental config touch or restart"; long
// enough that it is not itself a meaningful load source.
const licenseRecheckInterval = 15 * time.Minute

// licenseRecheckLoop independently re-validates the license on a fixed
// schedule, closing a gap watchConfigFile leaves open: that watcher only
// re-runs loadValidatedConfig (and therefore re-checks the license) as a
// side effect of a gateway.yaml change, so a long-lived process whose config
// is never edited again — the steady-state case for a production proxy —
// would otherwise keep serving on an expired or newly-hardware-mismatched
// license indefinitely, with `/api/license`/the console banner reporting a
// frozen boot-time snapshot the entire time (audit finding, 2026-08-23).
//
// This does NOT tear down the running chain or refuse traffic on its own
// when the license goes invalid mid-run: docs/licensing.md deliberately
// treats a same-minute production outage over licensing as a worse outcome
// than a bounded window of non-compliance (the same reasoning
// LoadWithGrace's hardware-grace period already applies to node-lock
// mismatches). It only makes the status LOUD and CURRENT — a fresh
// Load/LoadWithGrace result is logged and pushed to SetLicenseStatus every
// tick, so the console/API never lag boot-or-last-reload by more than
// licenseRecheckInterval, and an operator or log-based alerting sees the
// same "license: INVALID" signal a restart would have produced, without
// needing one.
func licenseRecheckLoop(currentLicensePath *atomic.Value, log *logger.Logger, adminSrv *api.Server) {
	ticker := time.NewTicker(licenseRecheckInterval)
	defer ticker.Stop()
	for range ticker.C {
		runLicenseRecheck(currentLicensePath, log, adminSrv)
	}
}

// runLicenseRecheck is licenseRecheckLoop's per-tick body, split out so a
// test can exercise one check deterministically without waiting on a real
// ticker.
func runLicenseRecheck(currentLicensePath *atomic.Value, log *logger.Logger, adminSrv *api.Server) {
	path, _ := currentLicensePath.Load().(string)
	st := license.LoadWithGrace(path, license.DefaultHardwareGrace)
	if !st.Valid {
		// Deliberately NOT logLicenseStatus here: its !Valid branch says
		// "unexpected — loadValidatedConfig should have rejected this
		// before startup/hot-reload got this far," which is wrong in this
		// context — this IS the expected place a mid-run expiry first
		// surfaces, not a bug.
		log.Error("license: periodic re-check found the running license NO LONGER VALID — "+
			"traffic keeps flowing (see docs/licensing.md's mid-run-expiry design note), but this is "+
			"now a licensing breach; renew and hot-reload (or restart) to clear it", map[string]any{
			"reason": st.Reason, "path": path,
		})
	} else {
		logLicenseStatus(log, st)
	}
	adminSrv.SetLicenseStatus(st)
}

// loadConfigSpec loads the optional config-level OpenAPI spec (discovery.
// spec_path) and installs it as the catalog's fallback for drift detection. A
// missing path clears the fallback; a read/parse error is logged and leaves the
// previous fallback in place rather than failing the gateway over a bad spec.
func loadConfigSpec(cfg config.GatewayConfig, catalog *discovery.Catalog, log *logger.Logger) {
	path := cfg.Discovery.SpecPath
	if path == "" {
		catalog.SetConfigSpec(nil)
		return
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path, not user input
	if err != nil {
		log.Error("discovery: spec_path read failed", map[string]any{"error": err.Error(), "path": path})
		return
	}
	spec, err := discovery.ParseSpec(raw)
	if err != nil {
		log.Error("discovery: spec_path parse failed", map[string]any{"error": err.Error(), "path": path})
		return
	}
	catalog.SetConfigSpec(spec)
	log.Info("discovery: config spec loaded", map[string]any{
		"path": path, "version": spec.Version, "operations": spec.OpCount(),
	})
}

// watchConfigFile uses fsnotify for instant config hot-reload (zero-downtime).
// Falls back to 5s polling if fsnotify setup fails.
func watchConfigFile(path string, activeHandler *atomic.Value, log *logger.Logger, st *store.Store, catalog *discovery.Catalog, adminSrv *api.Server, currentLicensePath *atomic.Value) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	reload := func() {
		// Backstop for the "previous config stays active" guarantee below: this
		// closure runs on a bare goroutine, so any panic it does not survive
		// takes the whole gateway down while the OLD config was serving fine.
		// A rejected reload must always degrade to "keep serving what we have".
		defer func() {
			if p := recover(); p != nil {
				log.Error("hot-reload: panicked, previous config stays active", map[string]any{
					"panic": fmt.Sprintf("%v", p),
					"stack": string(debug.Stack()),
				})
			}
		}()
		log.Info("config change detected, hot-reloading...")

		// The full startup gate (parse + Validate + trusted-proxy parsing) also
		// guards hot-reload: an edit that would be rejected at boot must not go
		// live either. On any error the previous configuration stays active —
		// newTrustedProxyNets is NOT committed yet (see loadValidatedConfig's
		// doc comment); it only takes effect once BuildHandlerChain below also
		// succeeds, so a later failure genuinely leaves the old chain's trust
		// boundary untouched too, not just its routing.
		newCfg, newTrustedProxyNets, newLicStatus, newCoercions, err := loadValidatedConfig(absPath)
		if err != nil {
			log.Error("hot-reload: rejected, previous config stays active", map[string]any{"error": err.Error()})
			return
		}
		logLicenseStatus(log, newLicStatus)
		adminSrv.SetLicenseStatus(newLicStatus)
		currentLicensePath.Store(newCfg.LicensePath)
		if newCfg.Observe {
			log.Warn("hot-reload: OBSERVE MODE ACTIVE — controls coerced to passive (record-only, no blocking/redaction)",
				map[string]any{"coerced": newCoercions})
		}

		// Rebuild the posture engine from the new config; it is the authority for
		// both posture classification and the per-route enforcement gates, so the
		// chain and the catalog must share the same fresh instance.
		newPosture := discovery.NewPostureEngine(newCfg)

		// Rebuild the alert engine from the new config so alerting.webhook_url,
		// format and min_severity are hot-reloadable like the rest of the data
		// plane, instead of being pinned to whatever was set at boot.
		// Rebuilt on every reload, so adding or removing a SIEM destination
		// takes effect the same way every other config change does.
		newAlerts := alert.NewWithConfig(newCfg.Alerting.WebhookURL, newCfg.Alerting.Format, newCfg.Alerting.MinSeverity, log).
			WithSinks(siemSinks(newCfg))

		newHandler, _, err := gateway.BuildHandlerChain(newCfg, log, st, catalog, newPosture, newAlerts)
		if err != nil {
			log.Error("hot-reload: chain build error", map[string]any{"error": err.Error()})
			return
		}

		// Re-classify future traffic against the new configuration.
		if catalog != nil {
			catalog.SetPostureEngine(newPosture)
			loadConfigSpec(newCfg, catalog, log)
		}

		// The ENTIRE reload has now succeeded — only now commit the new trust
		// boundary, immediately alongside the handler swap it belongs with.
		middleware.SetTrustedProxies(newTrustedProxyNets)
		activeHandler.Store(newHandler)
		// Only the data-plane chain is swapped. The admin server (admin_listen,
		// admin_auth/secret, admin_cors, session TTL) is built once at startup —
		// changes to those fields need a restart.
		log.Info("hot-reload: success (data plane swapped; admin-plane settings need a restart)", map[string]any{
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

// siemSinks turns the configured SIEM destinations into delivery clients.
//
// The token is fetched here, from the environment, rather than carried on the
// config struct: a collector token is a write credential to the customer's own
// security data store, and Helm renders that struct into an open ConfigMap.
// config.Validate has already refused a Splunk sink with no token, so an empty
// one here can only be Elastic with security disabled.
func siemSinks(cfg config.GatewayConfig) []alert.Sink {
	if len(cfg.Alerting.Sinks) == 0 {
		return nil
	}
	sinks := make([]alert.Sink, 0, len(cfg.Alerting.Sinks))
	for _, s := range cfg.Alerting.Sinks {
		min := s.MinSeverity
		if min == "" {
			min = cfg.Alerting.MinSeverity
		}
		sinks = append(sinks, alert.NewSink(s.Type, s.URL, config.SIEMToken(s.Type), s.Index, min,
			alert.NewSinkOptions{AllowPrivate: s.AllowPrivate}))
	}
	return sinks
}
