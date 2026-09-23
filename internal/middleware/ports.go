package middleware

import (
	"context"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/secevent"
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

// ── Role interfaces (Interface Segregation) ──────────────────────────────────
//
// Each middleware depends only on the slice of state it actually uses, not on a
// monolithic Store. The concrete *store.Store satisfies all of these; the test
// fake implements the full Store composition below, so it stands in for any role.

// RateLimiter increments a fixed-window counter.
type RateLimiter interface {
	IncrRate(ctx context.Context, key string, window time.Duration) (int64, error)
}

// IPBlockChecker reports whether an IP is currently blocked.
type IPBlockChecker interface {
	IsIPBlocked(ctx context.Context, ip string) (bool, error)
}

// IPBlocker blocks an IP, either permanently (admin-initiated) or for a
// bounded duration (behaviour auto-ban — see AutoBanIP).
type IPBlocker interface {
	BlockIP(ctx context.Context, ip string) error
	AutoBanIP(ctx context.Context, ip string, ttl time.Duration) error
}

// MetricsSink increments a named counter.
type MetricsSink interface {
	IncrMetric(ctx context.Context, name string)
}

// ForensicSink appends a security event to the forensic trail.
type ForensicSink interface {
	PushForensic(ctx context.Context, e secevent.Entry)
}

// AutoBanCounter tracks repeated offences per IP.
type AutoBanCounter interface {
	IncrAutoBanCounter(ctx context.Context, ip string) (int64, error)
}

// BehaviorScorer records requests and computes/raises a per-IP behaviour score.
type BehaviorScorer interface {
	RecordRequest(ctx context.Context, ip, path string, statusCode int)
	CalcBehaviorScore(ctx context.Context, ip string, threshold int) int
	IncrBehaviorScore(ctx context.Context, ip string, points int)
}

// JA3Checker verifies JA3 fingerprint consistency for an IP.
type JA3Checker interface {
	CheckJA3Consistency(ctx context.Context, ip, ja3 string) (bool, error)
}

// ChallengeStore manages proof-of-work / challenge tokens.
type ChallengeStore interface {
	IssueChallenge(ctx context.Context, ip, token string, ttl time.Duration) error
	IsValidChallengeToken(ctx context.Context, ip, token string) (bool, error)
	MarkChallengeSolved(ctx context.Context, ip string, ttl time.Duration) error
	IsChallengeSolved(ctx context.Context, ip string) (bool, error)
}

// RevocationChecker reports whether a JWT ID has been revoked.
type RevocationChecker interface {
	IsJTIRevoked(ctx context.Context, jti string) (bool, error)
}

// AbuseStore backs BOLA enumeration detection (distinct-object counts + EWMA
// baseline). TrackBaseline returns the consumer's baseline BEFORE this update,
// folding `current` in only when learn is true (drives the adaptive threshold, A2).
type AbuseStore interface {
	TrackObjectAccess(ctx context.Context, consumer, endpoint, objectID string, window time.Duration) (int64, error)
	TrackBaseline(ctx context.Context, consumer, endpoint string, current int64, learn bool, ttl time.Duration) (float64, error)

	// Per-consumer behavioural profile (P1-2). Same EWMA machinery as
	// TrackBaseline, applied to named dimensions rather than to one endpoint's
	// distinct-object count. See internal/middleware/profile.go for why these
	// dimensions and why no model.
	IncrProfileWindow(ctx context.Context, consumer, metric string, window time.Duration) (int64, error)
	TrackProfileDistinct(ctx context.Context, consumer, metric, value string, window time.Duration) (int64, error)
	TrackProfileBaseline(ctx context.Context, consumer, metric string, current int64, learn bool, ttl time.Duration) (float64, error)
	// TrackObjectOwner backs single-object BOLA/IDOR detection: it records the
	// accessing consumer against an object and returns how many distinct consumers
	// had accessed it before (priorOwners) and whether this consumer already had
	// (alreadyOwned). A small priorOwners with a new consumer is the IDOR signal.
	TrackObjectOwner(ctx context.Context, endpoint, objectID, consumer string, ttl time.Duration) (priorOwners int64, alreadyOwned bool, err error)
	// SetObjectOwner records the CONFIRMED owner of an object (learned from the
	// response body); GetObjectOwner reads it back. A known owner different from
	// the caller lets the gateway block a cross-owner access before forwarding.
	SetObjectOwner(ctx context.Context, endpoint, objectID, owner string, ttl time.Duration) error
	GetObjectOwner(ctx context.Context, endpoint, objectID string) (owner string, known bool, err error)
}

// SessionValidator validates a console session token, returning the tenant +
// role that AdminAuth threads into the request context.
type SessionValidator interface {
	ValidateSession(ctx context.Context, token string) (iam.Session, bool, error)
}

// DenySink is the minimal surface SecurityDeny needs: bump a metric and record a
// forensic entry. Every middleware that can reject a request depends on this.
type DenySink interface {
	MetricsSink
	ForensicSink
}

// Store is the full composition of every role, satisfied by *store.Store. It is
// retained so the test fake can implement a single type and stand in for any
// role interface; production code should depend on the narrowest role it needs.
type Store interface {
	RateLimiter
	IPBlockChecker
	IPBlocker
	MetricsSink
	ForensicSink
	AutoBanCounter
	BehaviorScorer
	JA3Checker
	ChallengeStore
	RevocationChecker
	AbuseStore
	SessionValidator
}

// ── Per-middleware composites ────────────────────────────────────────────────
// Named for the consumer so each constructor's dependency is explicit.

type rateLimitStore interface {
	RateLimiter
	DenySink
}

type ipGuardStore interface {
	IPBlockChecker
	DenySink
}

type behaviorStore interface {
	IPBlocker
	BehaviorScorer
	AutoBanCounter
	DenySink
}

type botStore interface {
	JA3Checker
	BehaviorScorer
	MetricsSink
}

type abuseStore interface {
	AbuseStore
	DenySink
}

type wafStore interface {
	BehaviorScorer
	DenySink
}

type adminStore interface {
	SessionValidator
	DenySink
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
