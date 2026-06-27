package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// PathHasPrefix reports whether path is covered by the prefix on a path-segment
// boundary. Unlike a raw strings.HasPrefix, "/public" matches "/public" and
// "/public/x" but NOT "/publicXYZ" — preventing an exclude/override rule from
// silently leaking onto a longer, unrelated path.
func PathHasPrefix(path, prefix string) bool {
	if prefix == "" {
		return false
	}
	if path == prefix {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	// Boundary check: either the prefix already ends with '/', or the next
	// character in path is the segment separator.
	return strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/'
}

// known insecure placeholder secrets — startup is rejected if any are in use
var insecurePlaceholders = []string{
	"change-me-to-a-strong-secret-in-production",
	"CHANGE-ME-IN-PRODUCTION",
	"your-jwt-secret-here",
	"changeme",
	"secret",
	"password",
}

// GatewayConfig is the root configuration.
type GatewayConfig struct {
	Listen      string `yaml:"listen"`
	AdminListen string `yaml:"admin_listen"`
	AdminAuth   bool   `yaml:"admin_auth"`
	AdminSecret string `yaml:"admin_secret"`
	// AdminSessionTTL is how long a console login session stays valid. Default 8h.
	AdminSessionTTL time.Duration `yaml:"admin_session_ttl"`
	// AdminCookieInsecure drops the Secure flag on the session cookie so the
	// console works over plain HTTP in local development. Never enable in
	// production: the session cookie would be sent over unencrypted connections.
	AdminCookieInsecure bool `yaml:"admin_cookie_insecure"`
	// RequireTLS makes startup fail unless TLS is terminated at the gateway
	// (tls.enabled). Set it in production. Leave false only when TLS is terminated
	// by a trusted upstream (ingress / load balancer) in front of AEGIS.
	RequireTLS     bool               `yaml:"require_tls"`
	ForensicDSN    string             `yaml:"forensic_dsn"` // PostgreSQL DSN for persistent forensic logs
	TrustedProxies []string           `yaml:"trusted_proxies"`
	TLS            TLSConfig          `yaml:"tls"`
	Security       SecurityConfig     `yaml:"security"`
	Routes         []RouteConfig      `yaml:"routes"`
	Registry       RegistryConfig     `yaml:"registry"`
	Redis          RedisConfig        `yaml:"redis"`
	Logging        LoggingConfig      `yaml:"logging"`
	Alerting       AlertingConfig     `yaml:"alerting"`
	Multitenancy   MultitenancyConfig `yaml:"multitenancy"`
}

// MultitenancyConfig enables hard data isolation between organisations. See
// docs/design/multitenancy.md (ADR-001). When disabled, AEGIS runs as a single
// "default" tenant (legacy behaviour).
type MultitenancyConfig struct {
	Enabled bool           `yaml:"enabled"`
	Tenants []TenantConfig `yaml:"tenants"`
}

// TenantConfig declares one organisation and the hosts that resolve to it.
type TenantConfig struct {
	ID    string   `yaml:"id"`
	Name  string   `yaml:"name"`
	Hosts []string `yaml:"hosts"` // Host/SNI values that map to this tenant (model A)
}

// DefaultTenant is the implicit tenant used when multi-tenancy is disabled, and
// for backfilling pre-existing single-tenant data.
const DefaultTenant = "default"

// AlertingConfig controls outbound delivery of security alerts (BOLA/BFLA,
// IP blocks, etc.) to an external destination such as Slack, PagerDuty or a
// generic SIEM webhook.
type AlertingConfig struct {
	// WebhookURL is the HTTPS endpoint alerts are POSTed to. Empty disables
	// outbound delivery (alerts are still logged locally).
	WebhookURL string `yaml:"webhook_url"`
	// Format shapes the JSON payload: "generic" (default) emits a flat AEGIS
	// envelope; "slack" emits a Slack-compatible {"text": ...} message.
	Format string `yaml:"format"`
	// MinSeverity gates delivery: only alerts at or above this level are sent.
	// One of "info", "warning", "critical". Default "warning".
	MinSeverity string `yaml:"min_severity"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type SecurityConfig struct {
	RateLimit  RateLimitConfig    `yaml:"rate_limit"`
	Auth       AuthConfig         `yaml:"auth"`
	WAF        WAFConfig          `yaml:"waf"`
	Bot        BotConfig          `yaml:"bot"`
	Behavior   BehaviorConfig     `yaml:"behavior"`
	IPGuard    IPGuardConfig      `yaml:"ip_guard"`
	DLP        DLPConfig          `yaml:"dlp"`
	CORS       CORSConfig         `yaml:"cors"`
	Challenge  ChallengeConfig    `yaml:"challenge"`
	Inventory  APIInventoryConfig `yaml:"api_inventory"`
	ThreatFeed ThreatFeedConfig   `yaml:"threat_feed"`
	Abuse      AbuseConfig        `yaml:"abuse"`
}

type RateLimitConfig struct {
	Enabled    bool          `yaml:"enabled"`
	Requests   int           `yaml:"requests"`
	Window     time.Duration `yaml:"window"`
	BurstLimit int           `yaml:"burst_limit"`
	// FailClosed denies requests when the rate-limit backing store (Redis) is
	// unavailable. Default false preserves availability (fail open); set true for
	// high-assurance deployments where a Redis outage must not drop enforcement.
	FailClosed bool `yaml:"fail_closed"`
}

type AuthConfig struct {
	Enabled  bool     `yaml:"enabled"`
	JWKSURL  string   `yaml:"jwks_url"`
	Issuer   string   `yaml:"issuer"`
	Audience string   `yaml:"audience"`
	Secret   string   `yaml:"secret"`
	Exclude  []string `yaml:"exclude"`
	// PropagationSecret is the HMAC key used to sign the identity headers
	// forwarded to upstream backends (X-Gateway-Signature). It is independent
	// of `Secret` so JWKS deployments (RSA/ECDSA token verification) can still
	// emit a signature backends can verify with the gatewayverify SDK. When
	// empty, falls back to Secret for backward compatibility with HMAC-only
	// installs. Set via env AEGIS_PROPAGATION_SECRET.
	PropagationSecret string `yaml:"propagation_secret"`
	// RevocationFailClosed denies a request when the JTI-revocation lookup fails
	// (e.g. Redis outage). Default false fails open (the request proceeds and the
	// failure is logged) to preserve availability; set true for high-assurance
	// deployments where a backing-store outage must not let a revoked token slip
	// through. Mirrors the per-control fail_closed convention used elsewhere.
	RevocationFailClosed bool `yaml:"revocation_fail_closed"`
}

type WAFConfig struct {
	Enabled     bool     `yaml:"enabled"`
	RulesetPath string   `yaml:"ruleset_path"`
	BlockMode   bool     `yaml:"block_mode"`
	Exclude     []string `yaml:"exclude_paths"`
}

type BotConfig struct {
	Enabled       bool     `yaml:"enabled"`
	BlockedJA3    []string `yaml:"blocked_ja3"`
	ChallengeMode bool     `yaml:"challenge_mode"`
	// TrustUpstreamJA3 lets a trusted upstream (e.g. Cloudflare, which terminates
	// TLS) supply the JA3 fingerprint via a header, since the gateway does not see
	// the TLS ClientHello in that topology. The value is only believed when the
	// immediate peer is a trusted proxy (see trusted_proxies); otherwise it is a
	// spoofable client header and is ignored.
	TrustUpstreamJA3 bool `yaml:"trust_upstream_ja3"`
	// UpstreamJA3Header is the header the upstream puts the JA3 hash in. Default
	// "Cf-Ja3-Hash" (set via a Cloudflare Transform Rule from
	// cf.bot_management.ja3_hash). Must NOT be X-JA3-Fingerprint (that is the
	// gateway's internal header and is always stripped from inbound requests).
	UpstreamJA3Header string `yaml:"upstream_ja3_header"`
}

type BehaviorConfig struct {
	Enabled        bool `yaml:"enabled"`
	ScoreThreshold int  `yaml:"score_threshold"`
	WindowSeconds  int  `yaml:"window_seconds"`
}

type IPGuardConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Whitelist []string `yaml:"whitelist"`
	Blacklist []string `yaml:"blacklist"`
	GeoBlock  []string `yaml:"geo_block"`
	// FailClosed denies a request when the dynamic block list (Redis) cannot be
	// consulted, instead of allowing it through. Set true in high-assurance
	// deployments where a Redis outage must not silently disable IP blocking.
	FailClosed bool `yaml:"fail_closed"`
}

type DLPConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Patterns []string `yaml:"patterns"`
}

type CORSConfig struct {
	Enabled      bool     `yaml:"enabled"`
	AllowOrigins []string `yaml:"allow_origins"`
	AllowMethods []string `yaml:"allow_methods"`
	AllowHeaders []string `yaml:"allow_headers"`
	MaxAge       int      `yaml:"max_age"`
}

type ChallengeConfig struct {
	Enabled        bool          `yaml:"enabled"`
	TTL            time.Duration `yaml:"ttl"`
	ScoreThreshold int           `yaml:"score_threshold"`
}

type APIInventoryConfig struct {
	Enabled    bool `yaml:"enabled"`
	AlertOnNew bool `yaml:"alert_on_new"`
}

type ThreatFeedConfig struct {
	Enabled  bool          `yaml:"enabled"`
	URL      string        `yaml:"url"`
	Interval time.Duration `yaml:"interval"`
}

// AbuseConfig configures object-level (BOLA) and function-level (BFLA)
// authorization-abuse detection. Detection is heuristic and passive: it runs on
// the live request using the verified identity propagated by JWT auth.
type AbuseConfig struct {
	Enabled bool `yaml:"enabled"`
	// EnumThreshold is the number of distinct object IDs a single consumer may
	// access on one endpoint within Window before it is flagged as enumeration
	// (a BOLA / IDOR signal). Default 50.
	EnumThreshold int           `yaml:"enum_threshold"`
	Window        time.Duration `yaml:"window"`
	// BlockMode denies flagged requests; when false (default) the gateway only
	// records the event, keeping false positives non-disruptive.
	BlockMode bool `yaml:"block_mode"`
	// Privileged lists path prefixes that require one of the given roles; a
	// consumer lacking all of them is a BFLA violation.
	Privileged []PrivilegedRule `yaml:"privileged"`
	// Allowlist names consumers that are exempt from abuse detection entirely.
	// Use it to silence known-benign high-cardinality callers (batch jobs,
	// search indexers, internal admins) that would otherwise trip BOLA
	// enumeration. Entries match the resolved consumer identity: a JWT subject
	// (e.g. "svc-indexer") or, for anonymous callers, the "ip:<addr>" form.
	// This is the primary false-positive control (RELEASE-CHECKLIST A6).
	Allowlist []string `yaml:"allowlist"`
	// Adaptive enables the per-consumer behavioural baseline (A2): instead of a
	// single global EnumThreshold, each consumer is compared against its own
	// learned norm (an EWMA of its distinct-object count per window). This catches
	// a consumer that normally touches 3 objects suddenly sweeping 40 — invisible
	// to a fixed threshold of 50 — while not flagging a consumer whose normal IS
	// 60. EnumThreshold still applies as an absolute hard ceiling.
	Adaptive bool `yaml:"adaptive"`
	// Sensitivity is the multiple of a consumer's baseline above which the current
	// window is anomalous (default 3.0). Higher = fewer, higher-confidence flags.
	Sensitivity float64 `yaml:"sensitivity"`
	// AdaptiveMinObjects is the absolute floor below which adaptive detection never
	// fires, so a tiny baseline (e.g. 0.5) cannot flag a benign handful of objects
	// (default 8).
	AdaptiveMinObjects int `yaml:"adaptive_min_objects"`
}

// PrivilegedRule binds a path prefix to the roles allowed to call it.
type PrivilegedRule struct {
	Path          string   `yaml:"path"`
	RequiredRoles []string `yaml:"required_roles"`
}

type RouteConfig struct {
	Path          string   `yaml:"path"`
	TenantID      string   `yaml:"tenant_id"` // owning tenant (model B); required when multitenancy.enabled
	Methods       []string `yaml:"methods"`
	Upstreams     []string `yaml:"upstreams"`
	LoadBalance   string   `yaml:"load_balance"`
	Timeout       string   `yaml:"timeout"`
	RetryAttempts int      `yaml:"retry_attempts"`
	StripPrefix   bool     `yaml:"strip_prefix"`
	ProbeURL      string   `yaml:"probe_url"`

	// Per-route security overrides. Pointers so "unset" (nil) is distinct from
	// an explicit false — when nil the global security.* setting applies. These
	// drive the posture engine ("which APIs are protected") and are also honoured
	// by the middleware chain.
	RequireAuth *bool            `yaml:"require_auth"`
	WAF         *bool            `yaml:"waf"`
	DLP         *bool            `yaml:"dlp"`
	RateLimit   *RateLimitConfig `yaml:"rate_limit"`
}

type RegistryConfig struct {
	Enabled      bool   `yaml:"enabled"`
	DSN          string `yaml:"dsn"`
	CacheTTLSecs int    `yaml:"cache_ttl_secs"`
	RotationDays int    `yaml:"rotation_days"`
}

type RedisConfig struct {
	// Addr is the single-instance address. Ignored when Sentinel.Addrs is set.
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	// Sentinel enables HA mode. When MasterName is non-empty, the gateway
	// connects via the listed Sentinel addresses instead of `addr`. See
	// docs/runbooks/ha.md for the topology.
	Sentinel SentinelConfig `yaml:"sentinel"`
}

// SentinelConfig wires the Redis Sentinel HA client. Leave MasterName empty to
// keep the legacy single-address client.
type SentinelConfig struct {
	MasterName       string   `yaml:"master_name"`
	Addrs            []string `yaml:"addrs"`
	SentinelPassword string   `yaml:"sentinel_password"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load reads gateway configuration from a YAML file and applies env overrides.
func Load(path string) (GatewayConfig, error) {
	// path is an operator-supplied config file path (CLI flag), not attacker input.
	data, err := os.ReadFile(path) // #nosec G304 -- config path is operator-controlled
	if err != nil {
		return GatewayConfig{}, err
	}

	var cfg GatewayConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return GatewayConfig{}, err
	}

	applyEnvOverrides(&cfg)

	// Defaults
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.AdminListen == "" {
		cfg.AdminListen = ":8081"
	}
	if cfg.Redis.Addr == "" {
		cfg.Redis.Addr = "localhost:6379"
	}
	if cfg.Security.RateLimit.Requests == 0 {
		cfg.Security.RateLimit.Requests = 100
	}
	if cfg.Security.RateLimit.Window == 0 {
		cfg.Security.RateLimit.Window = time.Minute
	}
	if cfg.Security.Behavior.ScoreThreshold == 0 {
		cfg.Security.Behavior.ScoreThreshold = 70
	}
	if cfg.Security.Behavior.WindowSeconds == 0 {
		cfg.Security.Behavior.WindowSeconds = 60
	}
	if cfg.Security.Abuse.EnumThreshold == 0 {
		cfg.Security.Abuse.EnumThreshold = 50
	}
	if cfg.Security.Abuse.Window == 0 {
		cfg.Security.Abuse.Window = time.Minute
	}
	if cfg.AdminSessionTTL == 0 {
		cfg.AdminSessionTTL = 8 * time.Hour
	}
	if cfg.Alerting.Format == "" {
		cfg.Alerting.Format = "generic"
	}
	if cfg.Alerting.MinSeverity == "" {
		cfg.Alerting.MinSeverity = "warning"
	}

	return cfg, nil
}

// applyEnvOverrides replaces sensitive config fields with environment variable
// values when set, so secrets never need to live in YAML files.
func applyEnvOverrides(cfg *GatewayConfig) {
	if v := os.Getenv("AEGIS_ADMIN_SECRET"); v != "" {
		cfg.AdminSecret = v
	}
	if v := os.Getenv("AEGIS_PROPAGATION_SECRET"); v != "" {
		cfg.Security.Auth.PropagationSecret = v
	}
	if v := os.Getenv("AEGIS_REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("AEGIS_JWT_SECRET"); v != "" {
		cfg.Security.Auth.Secret = v
	}
	if v := os.Getenv("AEGIS_FORENSIC_DSN"); v != "" {
		cfg.ForensicDSN = v
	}
	if v := os.Getenv("AEGIS_ALERT_WEBHOOK_URL"); v != "" {
		cfg.Alerting.WebhookURL = v
	}
}

// Validate returns an error if the configuration is unsafe to run in production.
// Call this after Load() before starting any servers.
func Validate(cfg GatewayConfig) error {
	if err := validateAdminSecret(cfg); err != nil {
		return err
	}
	if err := validateCORS(cfg); err != nil {
		return err
	}
	if err := validateRedis(cfg); err != nil {
		return err
	}
	if err := validateJWT(cfg); err != nil {
		return err
	}
	if err := validateTrustedProxies(cfg); err != nil {
		return err
	}
	if err := validateThreatFeed(cfg); err != nil {
		return err
	}
	if err := validateTLS(cfg); err != nil {
		return err
	}
	if err := validateAlerting(cfg); err != nil {
		return err
	}
	if err := validateMultitenancy(cfg); err != nil {
		return err
	}
	return nil
}

func validateMultitenancy(cfg GatewayConfig) error {
	mt := cfg.Multitenancy
	if !mt.Enabled {
		return nil // single-tenant: routes need no tenant_id
	}
	if len(mt.Tenants) == 0 {
		return errors.New("multitenancy.enabled is true but no tenants are declared")
	}

	ids := make(map[string]bool, len(mt.Tenants))
	hosts := make(map[string]string) // host -> tenant id (detect collisions)
	for _, t := range mt.Tenants {
		if t.ID == "" {
			return errors.New("multitenancy: a tenant has an empty id")
		}
		if t.ID == DefaultTenant {
			return fmt.Errorf("multitenancy: tenant id %q is reserved", DefaultTenant)
		}
		if ids[t.ID] {
			return fmt.Errorf("multitenancy: duplicate tenant id %q", t.ID)
		}
		ids[t.ID] = true
		for _, h := range t.Hosts {
			if other, ok := hosts[h]; ok && other != t.ID {
				return fmt.Errorf("multitenancy: host %q is mapped to both %q and %q", h, other, t.ID)
			}
			hosts[h] = t.ID
		}
	}

	for _, r := range cfg.Routes {
		if r.TenantID == "" {
			return fmt.Errorf("multitenancy: route %q has no tenant_id", r.Path)
		}
		if !ids[r.TenantID] {
			return fmt.Errorf("multitenancy: route %q references unknown tenant %q", r.Path, r.TenantID)
		}
	}
	return nil
}

func validateAlerting(cfg GatewayConfig) error {
	// Empty values are accepted: Load() fills them with defaults afterwards.
	switch cfg.Alerting.Format {
	case "", "generic", "slack":
	default:
		return fmt.Errorf("alerting.format must be 'generic' or 'slack', got %q", cfg.Alerting.Format)
	}
	switch cfg.Alerting.MinSeverity {
	case "", "info", "warning", "critical":
	default:
		return fmt.Errorf("alerting.min_severity must be 'info', 'warning' or 'critical', got %q", cfg.Alerting.MinSeverity)
	}
	if u := cfg.Alerting.WebhookURL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("alerting.webhook_url must be an http(s) URL")
	}
	return nil
}

func validateAdminSecret(cfg GatewayConfig) error {
	if !cfg.AdminAuth {
		return nil
	}
	if cfg.AdminSecret == "" {
		return errors.New("admin_auth is enabled but AEGIS_ADMIN_SECRET is not set; " +
			"set the environment variable or disable admin_auth for local development")
	}
	if slices.Contains(insecurePlaceholders, cfg.AdminSecret) {
		return errors.New("admin_secret contains an insecure placeholder; " +
			"set AEGIS_ADMIN_SECRET to a strong random secret (e.g. openssl rand -hex 32)")
	}
	if len(cfg.AdminSecret) < 32 {
		return errors.New("admin_secret is too short; minimum 32 characters required")
	}
	return nil
}

func validateRedis(cfg GatewayConfig) error {
	// Sentinel mode: both master name and at least one sentinel address must be set.
	s := cfg.Redis.Sentinel
	if s.MasterName != "" && len(s.Addrs) == 0 {
		return errors.New("redis.sentinel.master_name is set but redis.sentinel.addrs is empty")
	}
	if s.MasterName == "" && len(s.Addrs) > 0 {
		return errors.New("redis.sentinel.addrs is set but redis.sentinel.master_name is empty")
	}
	if cfg.Redis.Password == "" {
		// Not a hard error: Redis may be in an isolated private network.
		// But if the admin API is exposed externally this is critical — flag it.
		return errors.New("redis.password is empty; set AEGIS_REDIS_PASSWORD " +
			"(an attacker with network access can flush all rate-limit and block state)")
	}
	return nil
}

func validateJWT(cfg GatewayConfig) error {
	if !cfg.Security.Auth.Enabled {
		return nil
	}
	// JWKS URL takes priority over shared secret — no secret needed.
	if cfg.Security.Auth.JWKSURL != "" {
		return nil
	}
	if cfg.Security.Auth.Secret == "" {
		return errors.New("auth is enabled without jwks_url; set AEGIS_JWT_SECRET or configure auth.jwks_url")
	}
	if slices.Contains(insecurePlaceholders, cfg.Security.Auth.Secret) {
		return errors.New("auth.secret contains an insecure placeholder; " +
			"set AEGIS_JWT_SECRET to a strong random value (e.g. openssl rand -hex 32)")
	}
	if len(cfg.Security.Auth.Secret) < 32 {
		return errors.New("auth.secret is too short; minimum 32 characters required for HMAC-SHA256")
	}
	return nil
}

func validateTrustedProxies(cfg GatewayConfig) error {
	for _, cidr := range cfg.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if net.ParseIP(cidr) == nil {
				return fmt.Errorf("trusted_proxies: %q is not a valid CIDR or IP address", cidr)
			}
		}
	}
	return nil
}

func validateThreatFeed(cfg GatewayConfig) error {
	if !cfg.Security.ThreatFeed.Enabled || cfg.Security.ThreatFeed.URL == "" {
		return nil
	}
	if !strings.HasPrefix(cfg.Security.ThreatFeed.URL, "https://") {
		return fmt.Errorf("threat_feed.url must use HTTPS to prevent MITM injection (got %q)",
			cfg.Security.ThreatFeed.URL)
	}
	return nil
}

func validateTLS(cfg GatewayConfig) error {
	if cfg.RequireTLS && !cfg.TLS.Enabled {
		return errors.New("require_tls is set but tls.enabled is false; " +
			"terminate TLS at the gateway (tls.enabled + cert_file/key_file) or, " +
			"if TLS terminates at a trusted upstream, set require_tls: false")
	}
	if cfg.TLS.Enabled && (cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "") {
		return errors.New("tls.enabled is true but cert_file/key_file are not both set")
	}
	return nil
}

func validateCORS(cfg GatewayConfig) error {
	if !cfg.Security.CORS.Enabled {
		return nil
	}
	isWildcard := len(cfg.Security.CORS.AllowOrigins) == 1 &&
		cfg.Security.CORS.AllowOrigins[0] == "*"
	if isWildcard && cfg.Security.Auth.Enabled {
		// Wildcard CORS + JWT auth is a dangerous combination: an attacker's
		// site can trigger cross-origin requests that carry the victim's token.
		return errors.New("CORS allow_origins: [\"*\"] is incompatible with JWT auth; " +
			"list explicit origins in security.cors.allow_origins")
	}
	return nil
}
