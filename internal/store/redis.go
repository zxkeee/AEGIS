package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// ForensicEntry represents a security event for audit trails.
type ForensicEntry struct {
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
	client       *redis.Client
	forensicSink ForensicSink
}

// SetForensicSink configures a persistent forensic log backend (e.g., PostgreSQL).
func (s *Store) SetForensicSink(sink ForensicSink) {
	s.forensicSink = sink
}

// New creates a Store backed by Redis.
func New(addr, password string, db int) (*Store, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

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

const keyRatePrefix = "gw:rate:"

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
	rk := keyRatePrefix + key
	secs := int(window.Seconds())
	if secs < 1 {
		secs = 1
	}
	return rateLimitScript.Run(ctx, s.client, []string{rk}, secs).Int64()
}

// ── IP Blocking ───────────────────────────────────────────────────────────────

const keyBlockedIPs = "gw:blocked_ips"

// IsIPBlocked checks if an IP is in the block list.
func (s *Store) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	return s.client.SIsMember(ctx, keyBlockedIPs, ip).Result()
}

// BlockIP adds an IP to the block list.
func (s *Store) BlockIP(ctx context.Context, ip string) error {
	return s.client.SAdd(ctx, keyBlockedIPs, ip).Err()
}

// UnblockIP removes an IP from the block list.
func (s *Store) UnblockIP(ctx context.Context, ip string) error {
	return s.client.SRem(ctx, keyBlockedIPs, ip).Err()
}

// GetBlockedIPs returns all blocked IPs.
func (s *Store) GetBlockedIPs(ctx context.Context) ([]string, error) {
	return s.client.SMembers(ctx, keyBlockedIPs).Result()
}

// ── Metrics ───────────────────────────────────────────────────────────────────

const keyMetricsPrefix = "gw:metrics:"

// IncrMetric increments a named metric counter.
func (s *Store) IncrMetric(ctx context.Context, name string) {
	s.client.Incr(ctx, keyMetricsPrefix+name) //nolint:errcheck
}

// GetMetrics returns all metric counters.
func (s *Store) GetMetrics(ctx context.Context) (map[string]int64, error) {
	keys, err := s.client.Keys(ctx, keyMetricsPrefix+"*").Result()
	if err != nil {
		return nil, err
	}
	result := make(map[string]int64, len(keys))
	for _, k := range keys {
		val, _ := s.client.Get(ctx, k).Int64()
		name := strings.TrimPrefix(k, keyMetricsPrefix)
		result[name] = val
	}
	return result, nil
}

// ── Behavioral Scoring ────────────────────────────────────────────────────────

// RecordRequest tracks request metadata for behavioral scoring.
func (s *Store) RecordRequest(ctx context.Context, ip, path string, statusCode int) {
	base := "gw:behavior:" + ip

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
		s.client.Incr(ctx, "gw:metrics:behavior_record_redis_error") //nolint:errcheck
	}
}

// CalcBehaviorScore calculates a risk score (0-100) for an IP.
// On Redis failure it returns 0 and increments a metric so operators can alert.
// We do NOT fail-closed (return threshold) because a Redis disruption would
// then block all traffic — a worse outcome than a temporary scoring gap.
func (s *Store) CalcBehaviorScore(ctx context.Context, ip string, threshold int) int {
	base := "gw:behavior:" + ip

	pipe := s.client.Pipeline()
	reqCmd := pipe.Get(ctx, base+":reqs")
	errCmd := pipe.Get(ctx, base+":errs")
	hllCmd := pipe.PFCount(ctx, base+":paths")
	burstCmd := pipe.Get(ctx, base+":burst")
	penaltyCmd := pipe.Get(ctx, base+":penalty")

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		// Pipeline error: increment observable metric and bail out.
		s.client.Incr(ctx, "gw:metrics:behavior_score_redis_error") //nolint:errcheck
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
	key := "gw:behavior:" + ip + ":penalty"
	s.client.IncrBy(ctx, key, int64(points))  //nolint:errcheck
	s.client.Expire(ctx, key, 60*time.Second) //nolint:errcheck
}

// ── JA3 Consistency ───────────────────────────────────────────────────────────

// CheckJA3Consistency tracks TLS fingerprints per IP.
// Returns true if the IP has used too many different fingerprints.
func (s *Store) CheckJA3Consistency(ctx context.Context, ip, ja3 string) (bool, error) {
	key := "gw:ja3:" + ip
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
	key := "gw:autoban:" + ip
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
	return s.client.Set(ctx, "gw:challenge:"+ip, token, ttl).Err()
}

// IsValidChallengeToken checks if a challenge token matches.
func (s *Store) IsValidChallengeToken(ctx context.Context, ip, token string) (bool, error) {
	stored, err := s.client.Get(ctx, "gw:challenge:"+ip).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return stored == token, nil
}

// MarkChallengeSolved marks an IP as having solved the challenge.
func (s *Store) MarkChallengeSolved(ctx context.Context, ip string, ttl time.Duration) error {
	return s.client.Set(ctx, "gw:challenge_solved:"+ip, "1", ttl).Err()
}

// IsChallengeSolved checks if an IP has already solved the challenge.
func (s *Store) IsChallengeSolved(ctx context.Context, ip string) (bool, error) {
	_, err := s.client.Get(ctx, "gw:challenge_solved:"+ip).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ── API Inventory ─────────────────────────────────────────────────────────────

const keyInventory = "gw:api_inventory"

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
	if card, err := s.client.SCard(ctx, keyInventory).Result(); err == nil && card >= inventoryMaxEndpoints {
		// At capacity: stop adding new entries (treat as "not new").
		return false, nil
	}
	n, err := s.client.SAdd(ctx, keyInventory, endpoint).Result()
	return n > 0, err
}

// RecordParameters tracks query parameters per endpoint and returns newly discovered ones.
func (s *Store) RecordParameters(ctx context.Context, endpoint string, params []string) ([]string, error) {
	key := "gw:api_params:" + endpoint
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
	return s.client.SMembers(ctx, keyInventory).Result()
}

// ── Admin Sessions ──────────────────────────────────────────────────────────────

const prefixSession = "gw:session:"

// CreateSession stores a server-side admin session and its bound CSRF token.
// The session token is the opaque cookie value; the CSRF token is returned to
// the client and must accompany state-changing requests.
func (s *Store) CreateSession(ctx context.Context, token, csrf string, ttl time.Duration) error {
	return s.client.Set(ctx, prefixSession+token, csrf, ttl).Err()
}

// ValidateSession returns the session's bound CSRF token and whether the session
// is valid (exists and not expired).
func (s *Store) ValidateSession(ctx context.Context, token string) (string, bool, error) {
	csrf, err := s.client.Get(ctx, prefixSession+token).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return csrf, true, nil
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
	key := "gw:bola:" + consumer + ":" + endpoint
	pipe := s.client.Pipeline()
	pipe.PFAdd(ctx, key, objectID)
	pipe.Expire(ctx, key, window)
	cnt := pipe.PFCount(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return cnt.Val(), nil
}

// ── JWT Revocation ────────────────────────────────────────────────────────────

const prefixJTI = "gw:jwt:revoked:"

// IsJTIRevoked checks if a JWT ID has been revoked.
func (s *Store) IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	_, err := s.client.Get(ctx, prefixJTI+jti).Result()
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
	return s.client.Set(ctx, prefixJTI+jti, "revoked", ttl).Err()
}

// ── Forensics / Block Log ─────────────────────────────────────────────────────

const keyForensic = "gw:forensic_log"

// PushForensic adds a security event to the forensic log.
// Events are stored as JSON so field values containing special characters
// (pipes, spaces, etc.) cannot corrupt the log structure.
func (s *Store) PushForensic(ctx context.Context, e ForensicEntry) {
	data, err := json.Marshal(e)
	if err != nil {
		s.client.Incr(ctx, "gw:metrics:forensic_marshal_error") //nolint:errcheck
		return
	}
	s.client.LPush(ctx, keyForensic, string(data)) //nolint:errcheck
	s.client.LTrim(ctx, keyForensic, 0, 999)       //nolint:errcheck

	if s.forensicSink != nil {
		s.forensicSink.Push(e)
	}
}

// GetForensicLog returns recent security events.
func (s *Store) GetForensicLog(ctx context.Context, limit int64) ([]ForensicEntry, error) {
	vals, err := s.client.LRange(ctx, keyForensic, 0, limit-1).Result()
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
