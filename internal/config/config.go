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
	Listen         string         `yaml:"listen"`
	AdminListen    string         `yaml:"admin_listen"`
	AdminAuth      bool           `yaml:"admin_auth"`
	AdminSecret    string         `yaml:"admin_secret"`
	ForensicDSN    string         `yaml:"forensic_dsn"` // PostgreSQL DSN for persistent forensic logs
	TrustedProxies []string       `yaml:"trusted_proxies"`
	TLS            TLSConfig      `yaml:"tls"`
	Security       SecurityConfig `yaml:"security"`
	Routes         []RouteConfig  `yaml:"routes"`
	Registry       RegistryConfig `yaml:"registry"`
	Redis          RedisConfig    `yaml:"redis"`
	Logging        LoggingConfig  `yaml:"logging"`
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
}

type RateLimitConfig struct {
	Enabled    bool          `yaml:"enabled"`
	Requests   int           `yaml:"requests"`
	Window     time.Duration `yaml:"window"`
	BurstLimit int           `yaml:"burst_limit"`
}

type AuthConfig struct {
	Enabled  bool     `yaml:"enabled"`
	JWKSURL  string   `yaml:"jwks_url"`
	Issuer   string   `yaml:"issuer"`
	Audience string   `yaml:"audience"`
	Secret   string   `yaml:"secret"`
	Exclude  []string `yaml:"exclude"`
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

type RouteConfig struct {
	Path          string   `yaml:"path"`
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
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
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

	return cfg, nil
}

// applyEnvOverrides replaces sensitive config fields with environment variable
// values when set, so secrets never need to live in YAML files.
func applyEnvOverrides(cfg *GatewayConfig) {
	if v := os.Getenv("AEGIS_ADMIN_SECRET"); v != "" {
		cfg.AdminSecret = v
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
