package store

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"api-gateway/internal/iam"
	"api-gateway/internal/secevent"
	"api-gateway/internal/tenant"

	"github.com/redis/go-redis/v9"
)

// tkey builds a tenant-scoped Redis key "gw:t:<tenant>:<suffix>" (ADR-001), so
// one tenant's rate limits, blocklists, sessions, metrics, etc. never collide
// with another's. The tenant is read from the request context; it falls back to
// the default tenant when multi-tenancy is disabled.
func tkey(ctx context.Context, suffix string) string {
	return "gw:t:" + tenant.From(ctx) + ":" + suffix
}

// ForensicEntry represents a security event for audit trails. It is an alias of
// secevent.Entry: the canonical type lives in the dependency-free secevent leaf
// so the middleware layer can emit events without importing this package (audit
// finding F2). Existing store/forensic/api references keep working unchanged.
type ForensicEntry = secevent.Entry

// ForensicSink is an interface for persistent forensic log backends (PostgreSQL, etc).
type ForensicSink interface {
	Push(entry ForensicEntry)
}

// Store wraps Redis for all gateway state.
type Store struct {
	client       redis.UniversalClient
	forensicSink ForensicSink
}

// SetForensicSink configures a persistent forensic log backend (e.g., PostgreSQL).
func (s *Store) SetForensicSink(sink ForensicSink) {
	s.forensicSink = sink
}

// New creates a Store backed by Redis. Equivalent to NewWithConfig with only
// the single-address fields set; kept for callers that don't need Sentinel.
func New(addr, password string, db int) (*Store, error) {
	return NewWithConfig(SentinelOptions{Addr: addr, Password: password, DB: db})
}

// SentinelOptions captures everything store.New needs from config.RedisConfig
// without importing the config package (avoids an import cycle: config depends
// on no package, but several layers depend on store + config). Mirrors the
// fields of config.RedisConfig.
type SentinelOptions struct {
	Addr             string
	Password         string
	DB               int
	MasterName       string
	SentinelAddrs    []string
	SentinelPassword string
	// Timeouts bound how long a single Redis operation may block. They exist so
	// a Redis outage degrades FAST: the gateway sits in the request hot path, so
	// a multi-second hang per request (the go-redis defaults of 5s dial / 3s
	// read / 3 retries) would pile up goroutines and explode tail latency before
	// the per-control fail-open / fail-closed logic ever runs. Zero values fall
	// back to the fail-fast defaults below.
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxRetries   int // -1 disables retries; 0 applies the default
}

// Fail-fast Redis defaults. Tuned for a hot-path gateway: a healthy op is sub-
// millisecond, so these are generous for normal traffic yet cap the damage of
// an outage to well under a second per request.
const (
	defaultDialTimeout  = 1 * time.Second
	defaultReadTimeout  = 500 * time.Millisecond
	defaultWriteTimeout = 500 * time.Millisecond
	defaultMaxRetries   = 1
)

// NewWithConfig connects to Redis, either via Sentinel (HA) when MasterName is
// set, or directly to a single instance. The returned client implements the
// same UniversalClient interface so the rest of the codebase doesn't care which
// mode is active.
func NewWithConfig(opts SentinelOptions) (*Store, error) {
	dial, read, write := opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout
	if dial <= 0 {
		dial = defaultDialTimeout
	}
	if read <= 0 {
		read = defaultReadTimeout
	}
	if write <= 0 {
		write = defaultWriteTimeout
	}
	retries := opts.MaxRetries
	if retries == 0 {
		retries = defaultMaxRetries
	}

	var client redis.UniversalClient
	if opts.MasterName != "" {
		client = redis.NewUniversalClient(&redis.UniversalOptions{
			MasterName:       opts.MasterName,
			Addrs:            opts.SentinelAddrs,
			Password:         opts.Password,
			SentinelPassword: opts.SentinelPassword,
			DB:               opts.DB,
			DialTimeout:      dial,
			ReadTimeout:      read,
			WriteTimeout:     write,
			MaxRetries:       retries,
		})
	} else {
		client = redis.NewClient(&redis.Options{
			Addr:         opts.Addr,
			Password:     opts.Password,
			DB:           opts.DB,
			DialTimeout:  dial,
			ReadTimeout:  read,
			WriteTimeout: write,
			MaxRetries:   retries,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connect: %w", err)
	}

	return &Store{client: client}, nil
}

// Close shuts down the Redis connection.
func (s *Store) Close() error {
	return s.client.Close()
}

// Ping checks Redis connectivity for health/readiness probes.
func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// ── Rate Limiting ─────────────────────────────────────────────────────────────

const keyRatePrefix = "rate:"

// rateLimitScript atomically increments the counter and sets the window TTL
// ONLY on the first increment (when the key is created). Refreshing the TTL on
// every request — as a naive INCR+EXPIRE pipeline does — keeps the key alive
// forever under sustained traffic, so the counter never resets and the client
// is locked out permanently. Setting EXPIRE only when no TTL exists (-1) gives
// a true fixed window that resets after `window` seconds.
var rateLimitScript = redis.NewScript(`
	local count = redis.call("INCR", KEYS[1])
	if count == 1 or redis.call("TTL", KEYS[1]) == -1 then
		redis.call("EXPIRE", KEYS[1], ARGV[1])
	end
	return count
`)

// IncrRate increments the rate counter for a key and returns the current count.
func (s *Store) IncrRate(ctx context.Context, key string, window time.Duration) (int64, error) {
	rk := tkey(ctx, keyRatePrefix+key)
	secs := int(window.Seconds())
	if secs < 1 {
		secs = 1
	}
	return rateLimitScript.Run(ctx, s.client, []string{rk}, secs).Int64()
}

// GetRate reads the current counter for a rate-limited key without bumping it.
// Returns 0 when the key has expired.
func (s *Store) GetRate(ctx context.Context, key string) (int64, error) {
	v, err := s.client.Get(ctx, tkey(ctx, keyRatePrefix+key)).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return v, err
}

// DecrRate gives back one unit of budget on a rate-limited key. Used by the
// login brute-force gate: IncrRate reserves a slot atomically BEFORE the
// expensive credential check runs (closing the check-then-act race a plain
// GetRate-then-IncrRate split had), and a successful login refunds that slot
// so the documented "only failures spend budget" behaviour still holds. A
// harmless best-effort op — if it races with an expiring key or drifts the
// counter slightly negative, the next GetRate/IncrRate simply sees more
// headroom, never less.
func (s *Store) DecrRate(ctx context.Context, key string) {
	s.client.Decr(ctx, tkey(ctx, keyRatePrefix+key)) //nolint:errcheck
}

// ── IP Blocking ───────────────────────────────────────────────────────────────

const keyBlockedIPs = "blocked_ips"

// autoBanPrefix namespaces the TTL ban-flag key. Deliberately distinct from
// the "autoban:<ip>" strike counter used by IncrAutoBanCounter below — the two
// used to collide on the same key, which made an auto-ban both fire on the
// very first high-risk hit (any write to the shared key satisfied IsIPBlocked)
// and inherit the counter's 10-minute TTL instead of AutoBanTTL.
const autoBanPrefix = "autoban_active:"

// IsIPBlocked checks if an IP is blocked, either permanently (admin-initiated,
// via the "blocked_ips" set) or by a still-live behaviour auto-ban (TTL key —
// see AutoBanIP).
func (s *Store) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	member, err := s.client.SIsMember(ctx, tkey(ctx, keyBlockedIPs), ip).Result()
	if err != nil {
		return false, err
	}
	if member {
		return true, nil
	}
	n, err := s.client.Exists(ctx, tkey(ctx, autoBanPrefix+ip)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// BlockIP adds an IP to the permanent block list. This is the admin-initiated
// path (POST /api/blocked-ips) — it never expires on its own, matching the
// intent of an operator deliberately blocking an IP.
func (s *Store) BlockIP(ctx context.Context, ip string) error {
	return s.client.SAdd(ctx, tkey(ctx, keyBlockedIPs), ip).Err()
}

// AutoBanIP blocks an IP for a bounded duration. Used by behaviour-based
// auto-banning (internal/middleware/behavior.go): unlike BlockIP, the
// verdict here is a heuristic score crossing a threshold, not an operator
// decision, so the ban self-expires instead of requiring a manual unblock.
func (s *Store) AutoBanIP(ctx context.Context, ip string, ttl time.Duration) error {
	return s.client.Set(ctx, tkey(ctx, autoBanPrefix+ip), "1", ttl).Err()
}

// UnblockIP removes an IP from the given source ("manual", "auto", or ""/"both"
// for either). Exposed as a selective op (rather than always clearing
// everything) because an IP can be blocked by BOTH an admin AND a live
// auto-ban at once — an operator investigating an auto-ban and clicking
// "unblock to test" must be able to lift just that, without silently
// discarding a deliberate permanent block they placed earlier.
func (s *Store) UnblockIP(ctx context.Context, ip, source string) error {
	pipe := s.client.Pipeline()
	if source == "" || source == "manual" || source == "both" {
		pipe.SRem(ctx, tkey(ctx, keyBlockedIPs), ip)
	}
	if source == "" || source == "auto" || source == "both" {
		pipe.Del(ctx, tkey(ctx, autoBanPrefix+ip))
	}
	_, err := pipe.Exec(ctx)
	return err
}

// BlockedIPInfo describes one blocked IP with enough detail for an operator
// to tell a deliberate admin block from a still-live, self-expiring
// behaviour auto-ban before deciding whether/how to lift it.
type BlockedIPInfo struct {
	IP string `json:"ip"`
	// Source is "manual" (admin-initiated, permanent), "auto" (behaviour
	// auto-ban, self-expires), or "manual+auto" when both apply at once.
	Source string `json:"source"`
	// TTLSeconds is set only when an auto-ban is live (Source contains "auto")
	// — how long until it self-expires.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// GetBlockedIPs returns every currently-blocked IP as plain strings (the
// permanent admin list plus any IP still under a live auto-ban), for callers
// that only need membership, not source/TTL detail.
func (s *Store) GetBlockedIPs(ctx context.Context) ([]string, error) {
	details, err := s.GetBlockedIPDetails(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(details))
	for i, d := range details {
		out[i] = d.IP
	}
	return out, nil
}

// GetBlockedIPDetails returns every currently-blocked IP with its source and
// (for auto-bans) remaining TTL — see BlockedIPInfo.
func (s *Store) GetBlockedIPDetails(ctx context.Context) ([]BlockedIPInfo, error) {
	manualList, err := s.client.SMembers(ctx, tkey(ctx, keyBlockedIPs)).Result()
	if err != nil {
		return nil, err
	}
	manual := make(map[string]bool, len(manualList))
	for _, ip := range manualList {
		manual[ip] = true
	}

	autoTTL := make(map[string]int64)
	prefix := tkey(ctx, autoBanPrefix)
	var cursor uint64
	for {
		keys, next, err := s.client.Scan(ctx, cursor, prefix+"*", 100).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			ip := strings.TrimPrefix(k, prefix)
			ttl, err := s.client.TTL(ctx, k).Result()
			if err != nil {
				continue
			}
			autoTTL[ip] = int64(ttl.Seconds())
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}

	out := make([]BlockedIPInfo, 0, len(manual)+len(autoTTL))
	for ip := range manual {
		info := BlockedIPInfo{IP: ip, Source: "manual"}
		if ttl, ok := autoTTL[ip]; ok {
			info.Source = "manual+auto"
			info.TTLSeconds = ttl
		}
		out = append(out, info)
	}
	for ip, ttl := range autoTTL {
		if manual[ip] {
			continue // already emitted above as "manual+auto"
		}
		out = append(out, BlockedIPInfo{IP: ip, Source: "auto", TTLSeconds: ttl})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

// ── Metrics ───────────────────────────────────────────────────────────────────

const keyMetricsPrefix = "metrics:"

// IncrMetric increments a named metric counter (scoped to the request's tenant).
func (s *Store) IncrMetric(ctx context.Context, name string) {
	s.client.Incr(ctx, tkey(ctx, keyMetricsPrefix+name)) //nolint:errcheck
}

// GetMetrics returns all metric counters for the request's tenant.
func (s *Store) GetMetrics(ctx context.Context) (map[string]int64, error) {
	prefix := tkey(ctx, keyMetricsPrefix)
	result := make(map[string]int64)
	// SCAN instead of KEYS: KEYS is O(N) over the whole keyspace and blocks the
	// single-threaded Redis server, stalling every other client. SCAN iterates in
	// bounded chunks without blocking.
	var cursor uint64
	for {
		keys, next, err := s.client.Scan(ctx, cursor, prefix+"*", 256).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			val, _ := s.client.Get(ctx, k).Int64()
			result[strings.TrimPrefix(k, prefix)] = val
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return result, nil
}

// ── Behavioral Scoring ────────────────────────────────────────────────────────

// RecordRequest tracks request metadata for behavioral scoring.
func (s *Store) RecordRequest(ctx context.Context, ip, path string, statusCode int) {
	base := tkey(ctx, "behavior:"+ip)

	pipe := s.client.Pipeline()
	pipe.Incr(ctx, base+":reqs")
	pipe.Expire(ctx, base+":reqs", 60*time.Second)

	// Only genuinely abusive statuses feed the ban-signalling error counter.
	// 401/403/404 are NORMAL API responses (not logged in, forbidden/authz denied,
	// resource missing) — counting them would let an active client behind a shared
	// IP/NAT accrue a ban simply by hitting missing or protected endpoints. 5xx is
	// the backend's fault (a backend outage must not mass-ban every client). Path
	// scanning is already captured by the distinct-path entropy score, not here.
	if isAbusiveStatus(statusCode) {
		pipe.Incr(ctx, base+":errs")
		pipe.Expire(ctx, base+":errs", 60*time.Second)
	}

	// Track unique paths via HyperLogLog
	pipe.PFAdd(ctx, base+":paths", path)
	pipe.Expire(ctx, base+":paths", 60*time.Second)

	if _, err := pipe.Exec(ctx); err != nil {
		s.client.Incr(ctx, tkey(ctx, "metrics:behavior_record_redis_error")) //nolint:errcheck
	}
}

// isAbusiveStatus reports whether a response status is a behavioural-abuse
// signal (malformed request, or the client being rate-limited) rather than a
// normal client-facing outcome. Deliberately narrow to avoid false-positive
// auto-bans on ordinary 401/403/404/5xx traffic.
func isAbusiveStatus(code int) bool {
	return code == http.StatusBadRequest || code == http.StatusTooManyRequests
}

// CalcBehaviorScore calculates a risk score (0-100) for an IP.
// On Redis failure it returns 0 and increments a metric so operators can alert.
// We do NOT fail-closed (return threshold) because a Redis disruption would
// then block all traffic — a worse outcome than a temporary scoring gap.
func (s *Store) CalcBehaviorScore(ctx context.Context, ip string, threshold int) int {
	base := tkey(ctx, "behavior:"+ip)

	pipe := s.client.Pipeline()
	reqCmd := pipe.Get(ctx, base+":reqs")
	errCmd := pipe.Get(ctx, base+":errs")
	hllCmd := pipe.PFCount(ctx, base+":paths")
	burstCmd := pipe.Get(ctx, base+":burst")
	penaltyCmd := pipe.Get(ctx, base+":penalty")

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		// Pipeline error: increment observable metric and bail out.
		s.client.Incr(ctx, tkey(ctx, "metrics:behavior_score_redis_error")) //nolint:errcheck
		return 0
	}

	reqs, _ := reqCmd.Int64()
	errs, _ := errCmd.Int64()
	paths := hllCmd.Val()
	burst, _ := burstCmd.Int64()
	penalty, _ := penaltyCmd.Int64()

	// Score components
	reqScore := int(min64(reqs/5, 30))      // High request volume
	errScore := int(min64(errs*3, 30))      // Error ratio
	entropyScore := int(min64(paths/3, 20)) // Path scanning
	burstBonus := int(min64(burst*5, 20))   // Burst activity

	total := min(reqScore+errScore+entropyScore+burstBonus+int(penalty), 100)

	s.client.Set(ctx, base+":score", total, 5*time.Second) //nolint:errcheck
	return total
}

// IncrBehaviorScore adds penalty points to an IP's risk score.
func (s *Store) IncrBehaviorScore(ctx context.Context, ip string, points int) {
	key := tkey(ctx, "behavior:"+ip+":penalty")
	s.client.IncrBy(ctx, key, int64(points))  //nolint:errcheck
	s.client.Expire(ctx, key, 60*time.Second) //nolint:errcheck
}

// ── JA3 Consistency ───────────────────────────────────────────────────────────

// CheckJA3Consistency tracks TLS fingerprints per IP.
// Returns true if the IP has used too many different fingerprints.
func (s *Store) CheckJA3Consistency(ctx context.Context, ip, ja3 string) (bool, error) {
	key := tkey(ctx, "ja3:"+ip)
	s.client.SAdd(ctx, key, ja3)             //nolint:errcheck
	s.client.Expire(ctx, key, 5*time.Minute) //nolint:errcheck
	count, err := s.client.SCard(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return count > 3, nil // More than 3 different fingerprints = suspicious
}

// ── Auto-Ban ──────────────────────────────────────────────────────────────────

// IncrAutoBanCounter increments the auto-ban violation counter for an IP.
func (s *Store) IncrAutoBanCounter(ctx context.Context, ip string) (int64, error) {
	key := tkey(ctx, "autoban:"+ip)
	pipe := s.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 10*time.Minute)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

// ── Challenge Tokens ──────────────────────────────────────────────────────────

// IssueChallenge creates a challenge token for an IP.
func (s *Store) IssueChallenge(ctx context.Context, ip, token string, ttl time.Duration) error {
	return s.client.Set(ctx, tkey(ctx, "challenge:"+ip), token, ttl).Err()
}

// IsValidChallengeToken checks if a challenge token matches. Constant-time
// compare so a network attacker cannot use timing side-channels to recover the
// expected token byte-by-byte. The challenge itself is anti-bot, not auth, but
// the cost of using subtle.ConstantTimeCompare here is zero.
func (s *Store) IsValidChallengeToken(ctx context.Context, ip, token string) (bool, error) {
	stored, err := s.client.Get(ctx, tkey(ctx, "challenge:"+ip)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(token)) == 1, nil
}

// MarkChallengeSolved marks an IP as having solved the challenge.
func (s *Store) MarkChallengeSolved(ctx context.Context, ip string, ttl time.Duration) error {
	return s.client.Set(ctx, tkey(ctx, "challenge_solved:"+ip), "1", ttl).Err()
}

// IsChallengeSolved checks if an IP has already solved the challenge.
func (s *Store) IsChallengeSolved(ctx context.Context, ip string) (bool, error) {
	_, err := s.client.Get(ctx, tkey(ctx, "challenge_solved:"+ip)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ── API Inventory ─────────────────────────────────────────────────────────────

const keyInventory = "api_inventory"

// inventoryMaxEndpoints caps the inventory set so a flood of unique paths cannot
// exhaust Redis memory. Real APIs have far fewer than this many endpoints.
const inventoryMaxEndpoints = 10_000

// inventoryMaxParamsPerEndpoint caps tracked query parameters per endpoint.
const inventoryMaxParamsPerEndpoint = 200

// RecordEndpoint adds an endpoint to the inventory set.
// Returns (true, nil) when the endpoint is seen for the first time.
func (s *Store) RecordEndpoint(ctx context.Context, endpoint string) (bool, error) {
	// Defence-in-depth cardinality cap: stop growing the set once the limit is
	// reached so a path-flooding attacker cannot exhaust memory.
	invKey := tkey(ctx, keyInventory)
	if card, err := s.client.SCard(ctx, invKey).Result(); err == nil && card >= inventoryMaxEndpoints {
		// At capacity: stop adding new entries (treat as "not new").
		return false, nil
	}
	n, err := s.client.SAdd(ctx, invKey, endpoint).Result()
	return n > 0, err
}

// RecordParameters tracks query parameters per endpoint and returns newly discovered ones.
func (s *Store) RecordParameters(ctx context.Context, endpoint string, params []string) ([]string, error) {
	key := tkey(ctx, "api_params:"+endpoint)
	if card, err := s.client.SCard(ctx, key).Result(); err == nil && card >= inventoryMaxParamsPerEndpoint {
		return nil, nil
	}
	var newParams []string
	for _, p := range params {
		n, err := s.client.SAdd(ctx, key, p).Result()
		if err != nil {
			return nil, err
		}
		if n > 0 {
			newParams = append(newParams, p)
		}
	}
	return newParams, nil
}

// GetInventory returns all discovered API endpoints.
func (s *Store) GetInventory(ctx context.Context) ([]string, error) {
	return s.client.SMembers(ctx, tkey(ctx, keyInventory)).Result()
}

// ── Admin Sessions ──────────────────────────────────────────────────────────────
//
// Sessions are stored under a flat "gw:session:<token>" key (no per-tenant
// prefix) because a session is the user→tenant mapping itself — the tenant
// lives INSIDE the JSON payload. Scoping the key by tenant would create a
// chicken-and-egg: validating the cookie would need to know the tenant before
// the cookie itself can tell us which tenant it belongs to.
const prefixSession = "gw:session:"

// CreateSession stores a server-side admin session (CSRF + tenant + role + the
// optional bound user identity). Session tokens are random 64-hex, so they are
// globally unique even without a per-tenant namespace.
func (s *Store) CreateSession(ctx context.Context, token string, sess iam.Session, ttl time.Duration) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, prefixSession+token, string(data), ttl).Err()
}

// ValidateSession returns the stored session and whether it is valid (exists
// and not expired).
func (s *Store) ValidateSession(ctx context.Context, token string) (iam.Session, bool, error) {
	v, err := s.client.Get(ctx, prefixSession+token).Result()
	if err == redis.Nil {
		return iam.Session{}, false, nil
	}
	if err != nil {
		return iam.Session{}, false, err
	}
	var sess iam.Session
	if err := json.Unmarshal([]byte(v), &sess); err != nil {
		return iam.Session{}, false, err
	}
	return sess, true, nil
}

// DeleteSession invalidates an admin session (logout).
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	return s.client.Del(ctx, prefixSession+token).Err()
}

// RevokeSessions deletes every live session matching tenantID, or every
// session matching userID regardless of tenant when tenantID is empty (the
// super-admin cross-tenant delete path, which does not know the user's
// tenant up front). When both are empty this is a no-op — callers must
// always supply at least one filter. Sessions have no
// per-tenant/per-user index (see prefixSession's doc comment — the token is
// the only key, and the tenant lives inside the JSON payload), so this SCANs
// the flat session keyspace and decodes each entry. Called from
// DeleteTenant/DeleteUser so a revoked identity can't keep acting on stale
// state for the rest of the session TTL. Bounded by the admin-session
// keyspace size, not overall traffic, and runs only on the rare
// tenant/user-deletion path — an O(N) SCAN here is an acceptable trade for
// not maintaining a reverse index.
func (s *Store) RevokeSessions(ctx context.Context, tenantID, userID string) (int, error) {
	if tenantID == "" && userID == "" {
		return 0, nil
	}
	var revoked int
	var cursor uint64
	for {
		keys, next, err := s.client.Scan(ctx, cursor, prefixSession+"*", 256).Result()
		if err != nil {
			return revoked, err
		}
		for _, k := range keys {
			v, err := s.client.Get(ctx, k).Result()
			if err != nil {
				continue // expired between SCAN and GET, or transient error — skip
			}
			var sess iam.Session
			if err := json.Unmarshal([]byte(v), &sess); err != nil {
				continue
			}
			if tenantID != "" && sess.TenantID != tenantID {
				continue
			}
			if userID != "" && sess.UserID != userID {
				continue
			}
			if err := s.client.Del(ctx, k).Err(); err == nil {
				revoked++
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return revoked, nil
}

// prefixLoginFlow stores the one-time OIDC login flow (state→nonce+PKCE
// verifier) between the redirect to the IdP and the callback. Like sessions it
// is NOT tenant-scoped: the flow happens pre-authentication, before any tenant
// is known, and the random state token is globally unique.
const prefixLoginFlow = "gw:oidc:flow:"

// PutLoginFlow persists an OIDC login flow keyed by its state token, with a TTL.
func (s *Store) PutLoginFlow(ctx context.Context, state, payload string, ttl time.Duration) error {
	return s.client.Set(ctx, prefixLoginFlow+state, payload, ttl).Err()
}

// TakeLoginFlow atomically fetches AND deletes the flow for a state token
// (GETDEL), so a given state can be redeemed exactly once — a replayed callback
// finds nothing. Returns ("", false, nil) when the state is unknown/expired.
func (s *Store) TakeLoginFlow(ctx context.Context, state string) (string, bool, error) {
	v, err := s.client.GetDel(ctx, prefixLoginFlow+state).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// ── Abuse Detection (BOLA enumeration) ──────────────────────────────────────────

// TrackObjectAccess records that a consumer accessed a specific object ID on an
// endpoint and returns the number of distinct object IDs that consumer has
// touched on that endpoint within the window. A high count is an enumeration /
// IDOR (BOLA) signal. Distinct counting uses a HyperLogLog so memory stays
// bounded regardless of how many IDs are swept.
func (s *Store) TrackObjectAccess(ctx context.Context, consumer, endpoint, objectID string, window time.Duration) (int64, error) {
	key := tkey(ctx, "bola:"+consumer+":"+endpoint)
	pipe := s.client.Pipeline()
	pipe.PFAdd(ctx, key, objectID)
	pipe.Expire(ctx, key, window)
	cnt := pipe.PFCount(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return cnt.Val(), nil
}

// baselineScript reads the current EWMA baseline and, when learning is enabled
// (ARGV[1]=="1"), folds the current observation into it with a small alpha so a
// single spike barely moves the baseline while a sustained shift is tracked. It
// returns the baseline as it was BEFORE the update, so the caller compares the
// current window against the consumer's established norm, not a value already
// nudged by this same observation.
var baselineScript = redis.NewScript(`
	local b = tonumber(redis.call("GET", KEYS[1]) or "0")
	if ARGV[1] == "1" then
		local cur = tonumber(ARGV[2])
		local alpha = 0.05
		local nb = alpha * cur + (1 - alpha) * b
		redis.call("SET", KEYS[1], tostring(nb), "EX", ARGV[3])
	end
	return tostring(b)
`)

// TrackBaseline implements the per-consumer adaptive BOLA baseline (A2). It
// returns the EWMA of the consumer's distinct-object count on the endpoint
// (pre-update) and, when learn is true, updates that EWMA toward `current`.
// Anomalous spikes pass learn=false so the baseline is not poisoned by an attack.
func (s *Store) TrackBaseline(ctx context.Context, consumer, endpoint string, current int64, learn bool, ttl time.Duration) (float64, error) {
	key := tkey(ctx, "blbase:"+consumer+":"+endpoint)
	learnFlag := "0"
	if learn {
		learnFlag = "1"
	}
	secs := int(ttl.Seconds())
	if secs < 1 {
		secs = 1
	}
	v, err := baselineScript.Run(ctx, s.client, []string{key}, learnFlag, current, secs).Text()
	if err != nil {
		return 0, err
	}
	b, perr := strconv.ParseFloat(v, 64)
	if perr != nil {
		return 0, perr
	}
	return b, nil
}

// objectOwnerSetCap bounds the per-object owner set so a broadly shared object
// cannot grow it without limit. An object past the cap is, by definition, not
// "owned" by a small set and never yields an ownership (IDOR) signal.
const objectOwnerSetCap = 64

// TrackObjectOwner records that `consumer` accessed the object identified by
// (endpoint, objectID) and reports the ownership picture BEFORE this access:
// priorOwners is the number of distinct consumers that had already accessed the
// object, and alreadyOwned is whether `consumer` was one of them. A small
// priorOwners with a new consumer is the single-object BOLA / IDOR signal —
// someone reading an object that belongs to a different, small set of users.
// The owner set is capped (objectOwnerSetCap) and TTL'd; callers decide what
// priorOwners count counts as "shared" (and is therefore benign).
func (s *Store) TrackObjectOwner(ctx context.Context, endpoint, objectID, consumer string, ttl time.Duration) (priorOwners int64, alreadyOwned bool, err error) {
	key := tkey(ctx, "objown:"+endpoint+":"+objectID)
	pipe := s.client.Pipeline()
	member := pipe.SIsMember(ctx, key, consumer)
	card := pipe.SCard(ctx, key)
	if _, err = pipe.Exec(ctx); err != nil {
		return 0, false, err
	}
	priorOwners = card.Val()
	alreadyOwned = member.Val()

	// Record this consumer as an owner (bounded) and refresh the TTL so an object
	// under active access stays tracked; a stale object expires and is forgotten.
	if !alreadyOwned && priorOwners < objectOwnerSetCap {
		wpipe := s.client.Pipeline()
		wpipe.SAdd(ctx, key, consumer)
		wpipe.Expire(ctx, key, ttl)
		if _, werr := wpipe.Exec(ctx); werr != nil {
			return priorOwners, alreadyOwned, werr
		}
	} else {
		_ = s.client.Expire(ctx, key, ttl).Err()
	}
	return priorOwners, alreadyOwned, nil
}

// SetObjectOwner records the CONFIRMED owner of an object, learned from the
// response body (an owner field such as user_id). The owner is an intrinsic
// property of the object, so this is a plain last-writer-wins set with a TTL
// refresh — every legitimate read re-affirms the same value. It backs proactive
// cross-owner blocking (GetObjectOwner) and confirmed-IDOR detection.
func (s *Store) SetObjectOwner(ctx context.Context, endpoint, objectID, owner string, ttl time.Duration) error {
	if owner == "" {
		return nil
	}
	return s.client.Set(ctx, tkey(ctx, "objowner:"+endpoint+":"+objectID), owner, ttl).Err()
}

// GetObjectOwner returns the confirmed owner of an object (from a prior response
// body) and whether one is known. A known owner different from the caller's
// identity is a cross-owner access that can be blocked BEFORE forwarding.
func (s *Store) GetObjectOwner(ctx context.Context, endpoint, objectID string) (owner string, known bool, err error) {
	v, err := s.client.Get(ctx, tkey(ctx, "objowner:"+endpoint+":"+objectID)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// ── JWT Revocation ────────────────────────────────────────────────────────────

const prefixJTI = "jwt:revoked:"

// IsJTIRevoked checks if a JWT ID has been revoked.
func (s *Store) IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	_, err := s.client.Get(ctx, tkey(ctx, prefixJTI+jti)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// RevokeJTI blacklists a JWT ID for the given duration.
func (s *Store) RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error {
	return s.client.Set(ctx, tkey(ctx, prefixJTI+jti), "revoked", ttl).Err()
}

// ── Forensics / Block Log ─────────────────────────────────────────────────────

const keyForensic = "forensic_log"

// PushForensic adds a security event to the forensic log.
// Events are stored as JSON so field values containing special characters
// (pipes, spaces, etc.) cannot corrupt the log structure.
func (s *Store) PushForensic(ctx context.Context, e ForensicEntry) {
	// Attribute the event to the request's tenant when the caller didn't set it
	// explicitly. Without this, controls like the WAF (which don't carry tenant
	// themselves) produced unattributed forensic records in multi-tenant mode.
	if e.Tenant == "" {
		e.Tenant = tenant.From(ctx)
	}
	data, err := json.Marshal(e)
	if err != nil {
		s.client.Incr(ctx, tkey(ctx, "metrics:forensic_marshal_error")) //nolint:errcheck
		return
	}
	fk := tkey(ctx, keyForensic)
	s.client.LPush(ctx, fk, string(data)) //nolint:errcheck
	s.client.LTrim(ctx, fk, 0, 999)       //nolint:errcheck

	if s.forensicSink != nil {
		s.forensicSink.Push(e)
	}
}

// GetForensicLog returns recent security events.
func (s *Store) GetForensicLog(ctx context.Context, limit int64) ([]ForensicEntry, error) {
	vals, err := s.client.LRange(ctx, tkey(ctx, keyForensic), 0, limit-1).Result()
	if err != nil {
		return nil, err
	}
	entries := make([]ForensicEntry, 0, len(vals))
	for _, v := range vals {
		var e ForensicEntry
		if err := json.Unmarshal([]byte(v), &e); err != nil {
			// Skip legacy pipe-delimited entries (migration period) without failing.
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
