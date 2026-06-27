package store

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"api-gateway/internal/iam"
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

// ForensicEntry represents a security event for audit trails.
type ForensicEntry struct {
	Tenant    string         `json:"tenant,omitempty"`
	Timestamp time.Time      `json:"ts"`
	IP        string         `json:"ip"`
	Path      string         `json:"path"`
	Method    string         `json:"method"`
	Reason    string         `json:"reason"`
	Code      int            `json:"code"`
	Extra     map[string]any `json:"extra,omitempty"`
}

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
// Returns 0 when the key has expired. Used by handlers that want to check the
// budget BEFORE consuming it (e.g. the login brute-force gate, which only
// charges the counter on failed attempts).
func (s *Store) GetRate(ctx context.Context, key string) (int64, error) {
	v, err := s.client.Get(ctx, tkey(ctx, keyRatePrefix+key)).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return v, err
}

// ── IP Blocking ───────────────────────────────────────────────────────────────

const keyBlockedIPs = "blocked_ips"

// IsIPBlocked checks if an IP is in the block list.
func (s *Store) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	return s.client.SIsMember(ctx, tkey(ctx, keyBlockedIPs), ip).Result()
}

// BlockIP adds an IP to the block list.
func (s *Store) BlockIP(ctx context.Context, ip string) error {
	return s.client.SAdd(ctx, tkey(ctx, keyBlockedIPs), ip).Err()
}

// UnblockIP removes an IP from the block list.
func (s *Store) UnblockIP(ctx context.Context, ip string) error {
	return s.client.SRem(ctx, tkey(ctx, keyBlockedIPs), ip).Err()
}

// GetBlockedIPs returns all blocked IPs.
func (s *Store) GetBlockedIPs(ctx context.Context) ([]string, error) {
	return s.client.SMembers(ctx, tkey(ctx, keyBlockedIPs)).Result()
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

	if statusCode >= 400 {
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
