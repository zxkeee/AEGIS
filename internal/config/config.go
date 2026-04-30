package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// GatewayConfig is the root configuration.
type GatewayConfig struct {
	Listen      string         `yaml:"listen"`
	AdminListen string         `yaml:"admin_listen"`
	AdminAuth   bool           `yaml:"admin_auth"`
	AdminSecret string         `yaml:"admin_secret"`
	ForensicDSN string         `yaml:"forensic_dsn"` // PostgreSQL DSN for persistent forensic logs
	TLS         TLSConfig      `yaml:"tls"`
	Security    SecurityConfig `yaml:"security"`
	Routes      []RouteConfig  `yaml:"routes"`
	Registry    RegistryConfig `yaml:"registry"`
	Redis       RedisConfig    `yaml:"redis"`
	Logging     LoggingConfig  `yaml:"logging"`
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

// Load reads gateway configuration from a YAML file.
func Load(path string) (GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GatewayConfig{}, err
	}

	var cfg GatewayConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return GatewayConfig{}, err
	}

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
