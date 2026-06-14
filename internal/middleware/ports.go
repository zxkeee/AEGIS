package middleware

import (
	"context"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/store"
)

// Logger defines the interface for logging within the middleware layer.
// Dependency Inversion: middleware depends on abstraction, not *logger.Logger.
type Logger interface {
	Info(msg string, fields ...map[string]any)
	Warn(msg string, fields ...map[string]any)
	Error(msg string, fields ...map[string]any)
	Debug(msg string, fields ...map[string]any)
	BlockEvent(reason, ip, path, method string, extra map[string]any)
}

// Store defines the interface for state management within the middleware layer.
// Dependency Inversion: middleware depends on abstraction, not *store.Store.
type Store interface {
	// Rate limiting
	IncrRate(ctx context.Context, key string, window time.Duration) (int64, error)

	// IP blocking
	IsIPBlocked(ctx context.Context, ip string) (bool, error)
	BlockIP(ctx context.Context, ip string) error

	// Metrics
	IncrMetric(ctx context.Context, name string)

	// Auto-ban
	IncrAutoBanCounter(ctx context.Context, ip string) (int64, error)

	// Behavior scoring
	RecordRequest(ctx context.Context, ip, path string, statusCode int)
	CalcBehaviorScore(ctx context.Context, ip string, threshold int) int
	IncrBehaviorScore(ctx context.Context, ip string, points int)

	// JA3 consistency
	CheckJA3Consistency(ctx context.Context, ip, ja3 string) (bool, error)

	// Challenge tokens
	IssueChallenge(ctx context.Context, ip, token string, ttl time.Duration) error
	IsValidChallengeToken(ctx context.Context, ip, token string) (bool, error)
	MarkChallengeSolved(ctx context.Context, ip string, ttl time.Duration) error
	IsChallengeSolved(ctx context.Context, ip string) (bool, error)

	// API inventory
	RecordEndpoint(ctx context.Context, endpoint string) (bool, error)
	RecordParameters(ctx context.Context, endpoint string, params []string) ([]string, error)

	// JWT revocation
	IsJTIRevoked(ctx context.Context, jti string) (bool, error)
	RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error

	// Abuse detection (BOLA enumeration)
	TrackObjectAccess(ctx context.Context, consumer, endpoint, objectID string, window time.Duration) (int64, error)

	// Forensics
	PushForensic(ctx context.Context, e store.ForensicEntry)
	GetForensicLog(ctx context.Context, limit int64) ([]store.ForensicEntry, error)
}

// AlertEngine defines the interface for the alerting subsystem.
type AlertEngine interface {
	Fire(ctx context.Context, level, title, body string)
}

// RegistryProvider defines the interface for service registry lookups.
type RegistryProvider interface {
	LookupService(ctx context.Context, serviceID string) (secret string, ok bool, err error)
	CheckRateLimit(ctx context.Context, serviceID string, cfg config.RateLimitConfig) (bool, error)
}
