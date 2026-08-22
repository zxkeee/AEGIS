package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// tenantIDPattern constrains tenant ids to a safe charset. This is a hard
// isolation requirement, not cosmetics: Redis keys are built as
// "gw:t:<tenant>:<suffix>", so a ':' in a tenant id would let one tenant's
// keyspace overlap another's (e.g. id "a:x" + suffix "y" collides with id "a" +
// suffix "x:y"). Restricting to [A-Za-z0-9._-] makes the keyspaces provably
// disjoint. See the property test in internal/store.
var tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

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
	// AdminBootstrapSecretDisabled turns off the AEGIS_ADMIN_SECRET bearer-token
	// admin auth path once real per-tenant IAM operators have been provisioned.
	// The bearer path is an always-super-admin, un-auditable-per-operator,
	// single-shared-credential bootstrap mechanism; it exists so a fresh
	// install has a way in before any IAM user exists, not as a long-term
	// credential. Set true after provisioning real users to close that path.
	AdminBootstrapSecretDisabled bool `yaml:"admin_bootstrap_secret_disabled"`
	// AdminSessionTTL is how long a console login session stays valid. Default 8h.
	AdminSessionTTL time.Duration `yaml:"admin_session_ttl"`
	// AdminCookieInsecure drops the Secure flag on the session cookie so the
	// console works over plain HTTP in local development. Never enable in
	// production: the session cookie would be sent over unencrypted connections.
	AdminCookieInsecure bool `yaml:"admin_cookie_insecure"`
	// AdminLoginFailClosed denies /api/login when its Redis-backed brute-force
	// counters (per-IP and per-account) are unavailable, instead of the default
	// fail-open behaviour. Unlike rate-limit/IPGuard — where FailClosed already
	// exists — the login gate had no such option at all, so a Redis outage
	// silently left credential stuffing against /api/login completely
	// unthrottled for its duration. Default false preserves availability
	// (login still works during a Redis blip); set true for high-assurance
	// deployments where that gap must not be permitted, mirroring
	// RateLimitConfig.FailClosed / IPGuardConfig.FailClosed.
	AdminLoginFailClosed bool `yaml:"admin_login_fail_closed"`
	// AdminCORS is the CORS policy for the admin plane. The console is normally
	// same-origin (served by the admin server itself), so this stays unset and
	// the admin plane inherits security.cors. Set it when the console origins
	// differ from the data-plane API origins — sharing one list would otherwise
	// let every customer web-app origin make credentialed admin-API requests.
	AdminCORS *CORSConfig `yaml:"admin_cors"`
	// ShutdownDrain is the lame-duck grace period on SIGTERM/SIGINT: the gateway
	// first flips /readyz to 503 (so a load balancer / k8s readiness probe stops
	// routing new traffic), waits this long while still serving established
	// connections, and only then drains in-flight requests and stops. 0 (default)
	// skips the grace and shuts down immediately — set a few seconds in production
	// so rolling updates cause zero connection errors. Must exceed the LB's
	// readiness probe period.
	ShutdownDrain time.Duration `yaml:"shutdown_drain"`
	// RequireTLS makes startup fail unless TLS is terminated at the gateway
	// (tls.enabled). Set it in production. Leave false only when TLS is terminated
	// by a trusted upstream (ingress / load balancer) in front of AEGIS.
	RequireTLS bool `yaml:"require_tls"`
	// Observe puts the gateway into pilot / passive mode: every control still
	// inspects and records (WAF detection, DLP classification, BOLA/BFLA, passive
	// discovery, schema drift), but NOTHING is blocked, NO response body is
	// modified, and NO control fails closed. It is the guaranteed-safe posture for
	// a first pilot on a partner's live traffic: the findings report is produced
	// with zero risk to their production. ApplyObserveMode coerces the whole
	// security config into this shape after load and on every hot-reload.
	Observe        bool               `yaml:"observe"`
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
	Discovery      DiscoveryConfig    `yaml:"discovery"`
	// OIDC enables single sign-on for the admin console via an external identity
	// provider (Okta, Auth0, Keycloak, Google, Azure AD, …). Independent of
	// security.auth, which governs data-plane JWT validation for proxied traffic.
	OIDC OIDCConfig `yaml:"oidc"`
	// Retention bounds the growth of the PostgreSQL tables that would otherwise
	// grow without limit (forensic logs, admin audit log, consumer graph).
	Retention RetentionConfig `yaml:"retention"`
}

// ApplyObserveMode coerces the security configuration into a guaranteed
// non-disruptive posture when Observe is set. It runs after Validate on both
// startup and hot-reload (see loadValidatedConfig), so the coercion cannot be
// bypassed by a per-route override or a later config edit.
//
// The rule is simple and total: keep the controls that produce findings and
// force them to record-only; disable the controls that only enforce (they add
// no discovery value and can only block); never modify a response body; never
// fail closed. After this runs, no request can be blocked, throttled,
// challenged, redacted, or 401'd by AEGIS.
//
// Returns the list of coercions applied, for a startup log the operator can see.
func (c *GatewayConfig) ApplyObserveMode() []string {
	if !c.Observe {
		return nil
	}
	s := &c.Security
	var changed []string
	note := func(cond bool, msg string) {
		if cond {
			changed = append(changed, msg)
		}
	}

	// Detection controls: keep enabled, force to record-only.
	note(s.WAF.BlockMode, "waf.block_mode -> false")
	note(s.Schema.BlockMode, "schema.block_mode -> false")
	note(s.Abuse.BlockMode, "abuse.block_mode -> false")
	note(s.Abuse.ObjectOwnershipBlock, "abuse.object_ownership_block -> false")
	s.WAF.BlockMode = false
	s.WAF.Observe = true // forces Coraza to DetectionOnly (built-in rules ignore block_mode)
	s.Schema.BlockMode = false
	s.Abuse.BlockMode = false
	s.Abuse.ObjectOwnershipBlock = false
	// DLP classifies + flags the observation but never rewrites the body.
	note(s.DLP.Enabled, "dlp -> observe (classify, no redaction)")
	s.DLP.Observe = true
	// Auth extracts identity from a valid token but never rejects.
	note(s.Auth.Enabled || anyRouteRequiresAuthCfg(c.Routes), "auth -> soft (identity only, no 401)")
	s.Auth.Observe = true

	// Enforcement-only controls: no discovery value, only risk blocking. Off.
	note(s.RateLimit.Enabled, "rate_limit -> off")
	note(s.IPGuard.Enabled, "ip_guard -> off")
	note(s.ThreatFeed.Enabled, "threat_feed -> off")
	note(s.Bot.Enabled, "bot -> off")
	note(s.Challenge.Enabled, "challenge -> off")
	note(s.Behavior.Enabled, "behavior -> off (feeds auto-ban)")
	s.RateLimit.Enabled = false
	s.IPGuard.Enabled = false
	s.ThreatFeed.Enabled = false
	s.Bot.Enabled = false
	s.Challenge.Enabled = false
	s.Behavior.Enabled = false

	// Per-route overrides: the only route-level control that blocks without a
	// block_mode flag is rate_limit — clear it so a route cannot re-enable
	// throttling. WAF/DLP/require_auth route overrides only turn the (now
	// non-blocking) control on, which is fine.
	for i := range c.Routes {
		if c.Routes[i].RateLimit != nil {
			c.Routes[i].RateLimit = nil
			note(true, "route "+c.Routes[i].Path+": rate_limit override -> off")
		}
	}

	// Never fail closed in a pilot.
	s.RateLimit.FailClosed = false
	s.IPGuard.FailClosed = false
	s.Auth.RevocationFailClosed = false

	return changed
}

// anyRouteRequiresAuthCfg reports whether any route explicitly enables auth, so
// the observe log mentions soft-auth even when security.auth is globally off.
func anyRouteRequiresAuthCfg(routes []RouteConfig) bool {
	for _, r := range routes {
		if r.RequireAuth != nil && *r.RequireAuth {
			return true
		}
	}
	return false
}

// RetentionConfig configures the background retention sweep that deletes aged
// rows from the durable PostgreSQL tables. It targets the tables that grow
// unbounded with traffic — forensic_logs, admin_audit_log, and the consumer
// graph (api_consumers / api_endpoint_consumers). The endpoint catalog itself
// (api_endpoints) is intentionally NOT pruned: it is bounded by path
// normalisation and is the valuable inventory. A per-table window of 0 keeps
// that table forever (sweep skips it).
type RetentionConfig struct {
	Enabled bool `yaml:"enabled"`
	// Interval is how often the sweep runs. Default 24h when enabled.
	Interval time.Duration `yaml:"interval"`
	// ForensicDays deletes forensic_logs rows older than N days (0 = keep all).
	ForensicDays int `yaml:"forensic_days"`
	// AuditDays deletes admin_audit_log rows older than N days (0 = keep all).
	AuditDays int `yaml:"audit_days"`
	// ConsumerIdleDays deletes api_consumers / api_endpoint_consumers not seen in
	// N days, then prunes orphaned edges (0 = keep all).
	ConsumerIdleDays int `yaml:"consumer_idle_days"`
}

// OIDCConfig configures OpenID Connect single sign-on for the admin console.
// The gateway runs the Authorization Code flow with PKCE against the provider's
// discovery document (<issuer>/.well-known/openid-configuration), validates the
// returned ID token, maps its claims to a tenant + role, and just-in-time
// provisions the operator as a console user. Secrets come from the environment
// (AEGIS_OIDC_CLIENT_ID, AEGIS_OIDC_CLIENT_SECRET), never this file.
type OIDCConfig struct {
	Enabled bool `yaml:"enabled"`
	// Issuer is the provider base URL; its discovery document is fetched at
	// startup. Must be HTTPS.
	Issuer string `yaml:"issuer"`
	// ClientID / ClientSecret identify this gateway to the provider. Set via
	// AEGIS_OIDC_CLIENT_ID / AEGIS_OIDC_CLIENT_SECRET.
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// RedirectURL is this gateway's callback, registered with the provider. It
	// must resolve to GET /api/auth/oidc/callback on the admin plane, e.g.
	// "https://console.example.com/api/auth/oidc/callback".
	RedirectURL string `yaml:"redirect_url"`
	// Scopes requested from the provider. "openid" is always added. Include the
	// scope that carries group/role membership (often "groups").
	Scopes []string `yaml:"scopes"`
	// TenantClaim is the ID-token claim carrying the operator's tenant. Empty =>
	// every SSO user lands in DefaultTenant (single-tenant deployments).
	TenantClaim string `yaml:"tenant_claim"`
	// RolesClaim is the claim carrying role/group membership (string or []string).
	// Default "groups".
	RolesClaim string `yaml:"roles_claim"`
	// AdminRoles / SuperAdminRoles list the claim values that grant the admin and
	// super-admin roles. A user matching neither is provisioned as a read-only
	// viewer — unless RequireMappedRole is set, in which case they are rejected.
	AdminRoles      []string `yaml:"admin_roles"`
	SuperAdminRoles []string `yaml:"super_admin_roles"`
	// RequireMappedRole rejects a successfully-authenticated user who matches no
	// admin/super-admin role instead of granting viewer. Use it when console
	// access must be explicitly granted via an IdP group.
	RequireMappedRole bool `yaml:"require_mapped_role"`
	// AllowedDomains, when non-empty, restricts SSO to these email domains.
	AllowedDomains []string `yaml:"allowed_domains"`
	// AllowedTenants, when non-empty, restricts which tenant_claim values SSO
	// may resolve to. Without it, mapIdentity trusts TenantClaim verbatim: the
	// first login asserting a given value silently CREATES that tenant, and
	// every later login asserting the same value joins it. That is safe only
	// when TenantClaim is an IdP-controlled claim the end user cannot
	// influence (e.g. a directory/org ID) — for a self-service or
	// multi-org-per-directory claim, set this allowlist so an unprivileged IdP
	// user cannot assert membership in an arbitrary existing tenant.
	AllowedTenants []string `yaml:"allowed_tenants"`
}

// DiscoveryConfig tunes passive API discovery. The catalog itself is enabled by
// forensic_dsn (PostgreSQL); these are optional refinements.
type DiscoveryConfig struct {
	// SpecPath points to an OpenAPI 3.x / Swagger 2.0 document (YAML or JSON)
	// used as the fallback for documented-vs-observed drift detection. It applies
	// to every tenant that has not uploaded its own spec via the admin API. Empty
	// disables the config-level fallback.
	SpecPath string `yaml:"spec_path"`
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
	Schema     SchemaConfig       `yaml:"schema"`
}

// SchemaConfig controls positive-security schema enforcement: requests are
// validated against the documented OpenAPI/Swagger contract and non-conforming
// ones are flagged (monitor) or rejected (block). The contract is the
// config-level spec (discovery.spec_path). See docs/design/schema-enforcement.md.
type SchemaConfig struct {
	Enabled bool `yaml:"enabled"`
	// BlockMode rejects a non-conforming request with 422; when false (default)
	// the gateway only records the violations (safe rollout / FP collection).
	BlockMode bool `yaml:"block_mode"`
	// MaxBodyBytes caps how much request body is buffered for validation. A larger
	// body streams through unvalidated rather than being held in memory (bounded
	// inspection gap over OOM risk). Default 1 MiB.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
}

type RateLimitConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Requests int           `yaml:"requests"`
	Window   time.Duration `yaml:"window"`
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
	// IdentityClaim names an additional JWT claim to propagate as the caller's
	// object-ownership identity (header X-Gateway-Identity), for BOLA ownership
	// detection when the resource owner in the response body is NOT the JWT
	// subject. Example: tokens carry sub=<email> but resources are owned by a
	// numeric user id in claim "uid" and field "user_id" — set identity_claim:
	// "uid" and abuse.owner_fields: ["user_id"] so the two compare. When unset,
	// ownership compares against sub.
	IdentityClaim string `yaml:"identity_claim"`
	// Observe is set by ApplyObserveMode (not an operator field): when set, JWT
	// auth still extracts, propagates and signs identity from a VALID token (so
	// discovery and BOLA attribution work), but a missing, malformed, expired or
	// revoked token is passed THROUGH instead of rejected with 401 — the pilot
	// must never block traffic the customer's own backend would have accepted.
	Observe bool `yaml:"-"`
}

type WAFConfig struct {
	Enabled     bool     `yaml:"enabled"`
	RulesetPath string   `yaml:"ruleset_path"`
	BlockMode   bool     `yaml:"block_mode"`
	Exclude     []string `yaml:"exclude_paths"`
	// UseCRS loads the full OWASP Core Rule Set (v4, ~900 rules with anomaly
	// scoring) via Coraza instead of the built-in starter rules — the
	// production-grade ruleset. Tune with ParanoiaLevel and AnomalyThreshold, and
	// start in detection (block_mode: false) to surface false positives on your
	// traffic before enforcing. A RulesetPath, when set, is included after CRS as
	// tenant overrides (e.g. rule exclusions).
	UseCRS bool `yaml:"use_crs"`
	// ParanoiaLevel (1–4) trades coverage for false positives: 1 (default) suits
	// most APIs; higher levels catch more attacks but flag more benign traffic.
	ParanoiaLevel int `yaml:"paranoia_level"`
	// AnomalyThreshold is the inbound anomaly score at which CRS blocks (default
	// 5). Raise to be more permissive, lower to be stricter. Only used with CRS.
	AnomalyThreshold int `yaml:"anomaly_threshold"`
	// Observe is set by ApplyObserveMode (not an operator field): it forces the
	// Coraza engine to DetectionOnly for BOTH the built-in starter rules and CRS,
	// so attacks are still matched and logged but the request is never
	// interrupted. block_mode alone does not achieve this for the built-in rules,
	// which carry inline `deny` actions and run under `SecRuleEngine On`.
	Observe bool `yaml:"-"`
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
	// AutoBanTTL bounds how long a behaviour-triggered auto-ban lasts. Unlike an
	// admin-initiated block (POST /api/blocked-ips, permanent by intent), an
	// auto-ban is a heuristic verdict and can be wrong — a legitimate client with
	// buggy retry logic can trip the same score threshold a scanner would. A
	// self-expiring ban bounds that blast radius without needing an operator to
	// notice and manually unblock. Default 30m.
	AutoBanTTL time.Duration `yaml:"auto_ban_ttl"`
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
	// Observe is set by ApplyObserveMode (not an operator field): DLP still
	// classifies the response and flags the discovery observation with the PII
	// types it found, but passes the body through UNMODIFIED — no redaction. Lets
	// a pilot report "this endpoint leaks cards" without altering the customer's
	// traffic.
	Observe bool `yaml:"-"`
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
	// ObjectOwnership enables single-object BOLA / IDOR detection. Enumeration
	// detection only catches a consumer sweeping MANY object IDs; this catches a
	// consumer that reads ONE object belonging to someone else — the classic IDOR
	// a signature WAF cannot see. It learns which consumers access which objects
	// and flags a consumer that SUCCESSFULLY (2xx) reads an object previously
	// owned by a different, small set of consumers and never accessed by it. It is
	// evaluated AFTER the response (so a 2xx confirms the object was actually
	// returned to the wrong caller) and is therefore detect-only, regardless of
	// BlockMode. Only applies to authenticated subjects (anonymous ip:-identities
	// are too noisy to attribute ownership).
	ObjectOwnership bool `yaml:"object_ownership"`
	// SharedObjectThreshold bounds ownership detection to genuinely owned objects:
	// an object already accessed by MORE than this many distinct consumers is
	// treated as shared/public and never flagged (default 2). Lower is stricter.
	SharedObjectThreshold int `yaml:"shared_object_threshold"`
	// ObjectOwnershipTTL is how long an object's owner set is retained (default
	// 168h / 7 days). Keep it long relative to Window so ownership reflects a
	// durable access pattern, not a single burst.
	ObjectOwnershipTTL time.Duration `yaml:"object_ownership_ttl"`
	// OwnerFields upgrades ownership detection from heuristic (first-accessor) to
	// CONFIRMED: the response body is parsed for one of these JSON fields (checked
	// top-level and under a "data" wrapper), and its value is the object's true
	// owner. The owner is compared to the authenticated subject
	// (X-Gateway-Subject), so configure these to the field(s) that hold the
	// caller's own id (e.g. "user_id", "owner_id", "account_id"). When a value is
	// found, it supersedes the first-accessor heuristic for that request. Empty =
	// heuristic only.
	OwnerFields []string `yaml:"owner_fields"`
	// ObjectOwnershipBlock denies a request BEFORE forwarding when the object's
	// confirmed owner (learned earlier from a response body via OwnerFields) is
	// known and differs from the caller — preventing the leak instead of only
	// recording it. Requires OwnerFields to populate owner bindings first.
	ObjectOwnershipBlock bool `yaml:"object_ownership_block"`
	// OwnershipFailClosed denies a request when ObjectOwnershipBlock's Redis
	// owner lookup errors, instead of the default fail-open behaviour (the
	// lookup is skipped and the request proceeds as if no owner conflict were
	// known). ObjectOwnershipBlock is the one BOLA control that actually blocks
	// traffic (the rest are detect-and-record); a Redis outage silently
	// disabling it during an active IDOR sweep is the same gap class
	// RateLimitConfig.FailClosed / IPGuardConfig.FailClosed / the login gate's
	// AdminLoginFailClosed already close elsewhere. Default false preserves
	// availability, matching those.
	OwnershipFailClosed bool `yaml:"ownership_fail_closed"`
	// OwnershipBypassRoles are roles allowed to access objects they do not own
	// (support/admin views); a consumer holding any of them skips ownership
	// detection and blocking entirely.
	OwnershipBypassRoles []string `yaml:"ownership_bypass_roles"`
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

// RegistryConfig is EXPERIMENTAL / NOT YET WIRED INTO THE REQUEST PATH.
// middleware.ServiceAuth (the HMAC service-to-service auth control this
// config feeds) is never called from internal/gateway.chainSteps, and no
// RegistryProvider implementation exists outside test fakes — there is no
// real registry backend to look services up against. Setting Enabled: true
// is rejected by config.Validate (see validateRegistry) specifically so an
// operator can never believe this control is protecting live traffic when it
// structurally cannot be. Remove that rejection only once ServiceAuth is
// actually wired into the chain AND a real RegistryProvider is implemented.
type RegistryConfig struct {
	Enabled bool `yaml:"enabled"`
	// DSN is currently unwired: nothing in the codebase reads it yet — only
	// SignatureFreshnessSecs below is consulted (by ServiceAuth). Whoever
	// wires up the service registry's own datastore MUST route this DSN
	// through applyEnvOverrides (config.go) with an AEGIS_* env var, the same
	// way ForensicDSN is handled, so it never has to live in a YAML file.
	DSN          string `yaml:"dsn"`
	CacheTTLSecs int    `yaml:"cache_ttl_secs"`
	RotationDays int    `yaml:"rotation_days"`
	// SignatureFreshnessSecs bounds how old an X-Timestamp on a service-to-
	// service HMAC signature (ServiceAuth middleware) may be before it's
	// rejected as stale. Mirrors the freshness window sdk/gatewayverify uses
	// for the analogous gateway-to-backend identity signature. Default 60s.
	SignatureFreshnessSecs int `yaml:"signature_freshness_secs"`
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
	if cfg.Security.Behavior.AutoBanTTL == 0 {
		cfg.Security.Behavior.AutoBanTTL = 30 * time.Minute
	}
	if cfg.Registry.SignatureFreshnessSecs == 0 {
		cfg.Registry.SignatureFreshnessSecs = 60
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
	if cfg.Retention.Enabled && cfg.Retention.Interval == 0 {
		cfg.Retention.Interval = 24 * time.Hour
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
	if v := os.Getenv("AEGIS_REDIS_SENTINEL_PASSWORD"); v != "" {
		cfg.Redis.Sentinel.SentinelPassword = v
	}
	if v := os.Getenv("AEGIS_JWT_SECRET"); v != "" {
		cfg.Security.Auth.Secret = v
	}
	if v := os.Getenv("AEGIS_FORENSIC_DSN"); v != "" {
		cfg.ForensicDSN = v
	}
	if v := os.Getenv("AEGIS_OIDC_CLIENT_ID"); v != "" {
		cfg.OIDC.ClientID = v
	}
	if v := os.Getenv("AEGIS_OIDC_CLIENT_SECRET"); v != "" {
		cfg.OIDC.ClientSecret = v
	}
	if v := os.Getenv("AEGIS_ALERT_WEBHOOK_URL"); v != "" {
		cfg.Alerting.WebhookURL = v
	}
}

// Validate returns an error if the configuration is unsafe to run in production.
// Call this after Load() before starting any servers.
func Validate(cfg GatewayConfig) error {
	if cfg.ShutdownDrain < 0 {
		return errors.New("shutdown_drain must not be negative")
	}
	if cfg.Security.WAF.UseCRS {
		if pl := cfg.Security.WAF.ParanoiaLevel; pl != 0 && (pl < 1 || pl > 4) {
			return fmt.Errorf("waf.paranoia_level must be 1-4 (got %d)", pl)
		}
		if cfg.Security.WAF.AnomalyThreshold < 0 {
			return errors.New("waf.anomaly_threshold must not be negative")
		}
	}
	if cfg.Security.Behavior.Enabled {
		window := time.Duration(cfg.Security.Behavior.WindowSeconds) * time.Second
		if cfg.Security.Behavior.AutoBanTTL < window {
			// The score an auto-ban is based on decays over WindowSeconds (the
			// request/error counters behind it carry that same TTL). A shorter
			// AutoBanTTL just re-arms itself the instant it expires as long as
			// traffic keeps flowing — the ban flag clears but the still-elevated
			// score immediately re-trips it, so it never actually lifts.
			return fmt.Errorf("behavior.auto_ban_ttl (%s) must be >= behavior.window_seconds (%s), or an auto-ban can never actually expire under sustained traffic",
				cfg.Security.Behavior.AutoBanTTL, window)
		}
	}
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
	if err := validatePropagationSecret(cfg); err != nil {
		return err
	}
	if err := validateTrustedProxies(cfg); err != nil {
		return err
	}
	if err := validateIPGuard(cfg); err != nil {
		return err
	}
	if err := validateRegistry(cfg); err != nil {
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
	if err := validateRoutes(cfg); err != nil {
		return err
	}
	if err := validateOIDC(cfg); err != nil {
		return err
	}
	if err := validateRetention(cfg); err != nil {
		return err
	}
	return nil
}

// validateRetention checks the retention sweep configuration. It needs a
// database to act on, and at least one positive window (else the worker would
// run and delete nothing — likely a misconfiguration the operator should see).
func validateRetention(cfg GatewayConfig) error {
	r := cfg.Retention
	if !r.Enabled {
		return nil
	}
	if cfg.ForensicDSN == "" {
		return errors.New("retention.enabled requires forensic_dsn (the tables it prunes live in PostgreSQL)")
	}
	if r.ForensicDays < 0 || r.AuditDays < 0 || r.ConsumerIdleDays < 0 {
		return errors.New("retention windows (forensic_days/audit_days/consumer_idle_days) must be >= 0")
	}
	if r.ForensicDays == 0 && r.AuditDays == 0 && r.ConsumerIdleDays == 0 {
		return errors.New("retention.enabled but every window is 0; set at least one of " +
			"forensic_days/audit_days/consumer_idle_days, or disable retention")
	}
	return nil
}

// validateOIDC checks the console SSO configuration. SSO layers on top of the
// existing session machinery, so it needs admin_auth on (to have sessions at
// all) and forensic_dsn set (the iam store where SSO users are provisioned).
func validateOIDC(cfg GatewayConfig) error {
	o := cfg.OIDC
	if !o.Enabled {
		return nil
	}
	if !cfg.AdminAuth {
		return errors.New("oidc.enabled requires admin_auth: true (SSO establishes a console session)")
	}
	if cfg.ForensicDSN == "" {
		return errors.New("oidc.enabled requires forensic_dsn (SSO just-in-time provisions users in the iam store)")
	}
	// Issuer must be HTTPS in production. Allow http only under the explicit
	// local-dev flag (same affordance as redirect_url below), so a developer can
	// point at a local IdP without weakening the production default.
	issuerHTTPSDev := cfg.AdminCookieInsecure && strings.HasPrefix(o.Issuer, "http://")
	if !strings.HasPrefix(o.Issuer, "https://") && !issuerHTTPSDev {
		return fmt.Errorf("oidc.issuer must be an https URL, got %q", o.Issuer)
	}
	if o.ClientID == "" {
		return errors.New("oidc.enabled but client_id is empty; set AEGIS_OIDC_CLIENT_ID")
	}
	if o.ClientSecret == "" {
		return errors.New("oidc.enabled but client_secret is empty; set AEGIS_OIDC_CLIENT_SECRET")
	}
	// The redirect must be the callback on the admin plane and — since the ID
	// token and session cookie travel over it — HTTPS, unless the operator has
	// explicitly opted into insecure cookies for local development.
	if o.RedirectURL == "" {
		return errors.New("oidc.enabled but redirect_url is empty (e.g. https://console.example.com/api/auth/oidc/callback)")
	}
	if !strings.HasPrefix(o.RedirectURL, "https://") && !cfg.AdminCookieInsecure {
		return fmt.Errorf("oidc.redirect_url must be https (got %q); set admin_cookie_insecure: true only for local dev", o.RedirectURL)
	}
	if !strings.HasSuffix(o.RedirectURL, "/api/auth/oidc/callback") {
		return fmt.Errorf("oidc.redirect_url must end with /api/auth/oidc/callback, got %q", o.RedirectURL)
	}
	// Secure by default: SSO with no access restriction at all grants a console
	// session (viewer) to EVERY user in the identity provider — almost never the
	// intent when AEGIS fronts a broad corporate directory. Force an explicit
	// choice: gate on a group (admin_roles / super_admin_roles), an email domain
	// (allowed_domains), or require_mapped_role.
	if len(o.AdminRoles) == 0 && len(o.SuperAdminRoles) == 0 &&
		len(o.AllowedDomains) == 0 && !o.RequireMappedRole {
		return errors.New("oidc.enabled with no access restriction would grant console access to every " +
			"user in the identity provider; set at least one of admin_roles, super_admin_roles, " +
			"allowed_domains, or require_mapped_role")
	}
	return nil
}

// validateRoutes rejects route options that would otherwise degrade silently.
// In particular an unknown load_balance strategy used to fall back to
// round-robin without any signal — an operator asking for "least_conn" got
// different behaviour than configured.
func validateRoutes(cfg GatewayConfig) error {
	for _, r := range cfg.Routes {
		switch r.LoadBalance {
		case "", "round_robin":
		default:
			return fmt.Errorf("route %q: unsupported load_balance %q (supported: round_robin)",
				r.Path, r.LoadBalance)
		}
		if r.Timeout != "" {
			if _, err := time.ParseDuration(r.Timeout); err != nil {
				return fmt.Errorf("route %q: invalid timeout %q: %w", r.Path, r.Timeout, err)
			}
		}
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
		if !tenantIDPattern.MatchString(t.ID) {
			return fmt.Errorf("multitenancy: tenant id %q is invalid (allowed: letters, digits, '.', '_', '-'; 1-64 chars) — other characters can break key isolation", t.ID)
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

// looksLowEntropy reports whether a secret is unlikely to be a strong random
// value even though it passes the length floor and matches no literal in
// insecurePlaceholders. The literal-list check alone lets a long-but-predictable
// value through — e.g. "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" or
// "abcdefghijklmnopqrstuvwxyzabcdef" (both 32 chars) — because it can only ever
// catch values someone thought to enumerate in advance.
//
// Two independent signals, either of which flags the secret:
//   - Fewer than 8 distinct characters: a real random hex/base64/alphanumeric
//     secret of 32+ characters draws from a wide alphabet; this few distinct
//     characters is a strong repetition signal on its own.
//   - Shannon entropy below 3 bits/character: random hex sits around 4
//     bits/char, base64 around 6; patterned or low-diversity strings (runs,
//     short repeating cycles, mostly-one-character values) sit well below 3.
func looksLowEntropy(s string) bool {
	if s == "" {
		return true
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	if len(counts) < 8 {
		return true
	}
	var entropy float64
	n := float64(len([]rune(s)))
	for _, c := range counts {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy < 3.0
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
	if looksLowEntropy(cfg.AdminSecret) {
		return errors.New("admin_secret does not look random (too few distinct characters or a repeating pattern); " +
			"set AEGIS_ADMIN_SECRET to a strong random secret (e.g. openssl rand -hex 32)")
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
	if looksLowEntropy(cfg.Security.Auth.Secret) {
		return errors.New("auth.secret does not look random (too few distinct characters or a repeating pattern); " +
			"set AEGIS_JWT_SECRET to a strong random value (e.g. openssl rand -hex 32)")
	}
	return nil
}

// validatePropagationSecret checks auth.propagation_secret — the HMAC key that
// signs the X-Gateway-Signature identity header backends trust via
// sdk/gatewayverify — with the same strength rules as admin_secret/auth.secret.
// It falls back to auth.secret when unset (see jwt.go), so it is only
// validated when explicitly configured.
func validatePropagationSecret(cfg GatewayConfig) error {
	secret := cfg.Security.Auth.PropagationSecret
	if secret == "" {
		return nil
	}
	if slices.Contains(insecurePlaceholders, secret) {
		return errors.New("auth.propagation_secret contains an insecure placeholder; " +
			"set AEGIS_PROPAGATION_SECRET to a strong random value (e.g. openssl rand -hex 32)")
	}
	if len(secret) < 32 {
		return errors.New("auth.propagation_secret is too short; minimum 32 characters required for HMAC-SHA256")
	}
	if looksLowEntropy(secret) {
		return errors.New("auth.propagation_secret does not look random (too few distinct characters or a repeating pattern); " +
			"set AEGIS_PROPAGATION_SECRET to a strong random value (e.g. openssl rand -hex 32)")
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

// validateRegistry rejects registry.enabled: true outright: see RegistryConfig's
// doc comment — ServiceAuth is never wired into the request chain and no real
// RegistryProvider exists, so this control would silently do nothing to
// requests while giving an operator false confidence it's enforcing anything.
func validateRegistry(cfg GatewayConfig) error {
	if cfg.Registry.Enabled {
		return errors.New("registry.enabled: true is rejected — the service-registry/ServiceAuth " +
			"feature is not wired into the request path yet (see RegistryConfig's doc comment in " +
			"internal/config/config.go); enabling it would give no actual protection")
	}
	return nil
}

// validateIPGuard rejects malformed whitelist/blacklist entries at startup
// rather than letting IPGuard silently drop them at request time (a
// misconfigured "10.0.0.0/8" entry used to just never match anything).
func validateIPGuard(cfg GatewayConfig) error {
	check := func(field string, entries []string) error {
		for _, s := range entries {
			if net.ParseIP(s) != nil {
				continue
			}
			if _, _, err := net.ParseCIDR(s); err != nil {
				return fmt.Errorf("ip_guard.%s: %q is not a valid IP address or CIDR", field, s)
			}
		}
		return nil
	}
	if err := check("whitelist", cfg.Security.IPGuard.Whitelist); err != nil {
		return err
	}
	return check("blacklist", cfg.Security.IPGuard.Blacklist)
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
	// The admin plane authenticates with cookies, so a wildcard there is unsafe
	// regardless of the JWT setting. Checked before the data-plane early return:
	// admin_cors is independent of security.cors.enabled.
	if ac := cfg.AdminCORS; ac != nil && ac.Enabled && cfg.AdminAuth &&
		len(ac.AllowOrigins) == 1 && ac.AllowOrigins[0] == "*" {
		return errors.New("admin_cors.allow_origins: [\"*\"] is incompatible with admin_auth; " +
			"list explicit console origins in admin_cors.allow_origins")
	}
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
