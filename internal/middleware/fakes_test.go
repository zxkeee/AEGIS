package middleware

import (
	"context"
	"time"

	"api-gateway/internal/iam"
	"api-gateway/internal/store"
	"api-gateway/internal/tenant"
)

// fakeLogger is a no-op Logger for tests.
type fakeLogger struct{}

func (fakeLogger) Info(string, ...map[string]any)                            {}
func (fakeLogger) Warn(string, ...map[string]any)                            {}
func (fakeLogger) Error(string, ...map[string]any)                           {}
func (fakeLogger) Debug(string, ...map[string]any)                           {}
func (fakeLogger) BlockEvent(string, string, string, string, map[string]any) {}

// fakeStore implements the middleware.Store interface for tests. Behaviour for
// the methods under test can be overridden via the func fields; everything else
// returns zero values.
type fakeStore struct {
	incrRate    func(ctx context.Context, key string, window time.Duration) (int64, error)
	trackObject func() (int64, error)
	trackOwner  func() (int64, bool, error)  // (priorOwners, alreadyOwned, err)
	getOwner    func() (string, bool, error) // GetObjectOwner override (confirmed-owner block)
	setOwners   []string                     // captured SetObjectOwner values
	objOwners   map[string]string            // scope+id -> owner, so Set via one method is seen by Get via another
	jtiRevoked  map[string]bool
	jtiErr      error // when set, IsJTIRevoked returns this error (Redis outage)
	blockedIPs  map[string]bool
	ipBlockErr  error                  // when set, IsIPBlocked returns this error (Redis outage)
	sessions    map[string]string      // token -> csrf (legacy form; super-admin/default tenant)
	sessionFull map[string]iam.Session // token -> full session (overrides `sessions`)
	behavior    int
	// Challenge overrides keyed by IP. nil = the original "false" defaults.
	challengeSolved map[string]bool
	challengeValid  map[string]string // ip -> token expected to match
	// Auto-ban counter feedback (BehaviorAnalysis).
	autoban int64
	// Captured forensic events (abuse detection assertions).
	forensic []store.ForensicEntry
	// baseline is the EWMA value TrackBaseline returns (adaptive BOLA tests).
	baseline float64
	// metrics counts IncrMetric calls by name (schema/WAF skip-visibility assertions).
	metrics map[string]int
}

func (f *fakeStore) IncrRate(ctx context.Context, key string, window time.Duration) (int64, error) {
	if f.incrRate != nil {
		return f.incrRate(ctx, key, window)
	}
	return 1, nil
}

func (f *fakeStore) IsIPBlocked(_ context.Context, ip string) (bool, error) {
	if f.ipBlockErr != nil {
		return false, f.ipBlockErr
	}
	return f.blockedIPs[ip], nil
}
func (f *fakeStore) BlockIP(_ context.Context, ip string) error {
	if f.blockedIPs == nil {
		f.blockedIPs = map[string]bool{}
	}
	f.blockedIPs[ip] = true
	return nil
}
func (f *fakeStore) AutoBanIP(_ context.Context, ip string, _ time.Duration) error {
	if f.blockedIPs == nil {
		f.blockedIPs = map[string]bool{}
	}
	f.blockedIPs[ip] = true
	return nil
}
func (f *fakeStore) IncrMetric(_ context.Context, name string) {
	if f.metrics == nil {
		f.metrics = map[string]int{}
	}
	f.metrics[name]++
}

func (f *fakeStore) IncrAutoBanCounter(context.Context, string) (int64, error) {
	if f.autoban > 0 {
		return f.autoban, nil
	}
	return 1, nil
}

func (f *fakeStore) RecordRequest(context.Context, string, string, int) {}
func (f *fakeStore) CalcBehaviorScore(context.Context, string, int) int { return f.behavior }
func (f *fakeStore) IncrBehaviorScore(context.Context, string, int)     {}

func (f *fakeStore) CheckJA3Consistency(context.Context, string, string) (bool, error) {
	return false, nil
}

func (f *fakeStore) IssueChallenge(context.Context, string, string, time.Duration) error { return nil }
func (f *fakeStore) IsValidChallengeToken(_ context.Context, ip, tok string) (bool, error) {
	return f.challengeValid[ip] != "" && f.challengeValid[ip] == tok, nil
}
func (f *fakeStore) MarkChallengeSolved(_ context.Context, ip string, _ time.Duration) error {
	if f.challengeSolved == nil {
		f.challengeSolved = map[string]bool{}
	}
	f.challengeSolved[ip] = true
	return nil
}
func (f *fakeStore) IsChallengeSolved(_ context.Context, ip string) (bool, error) {
	return f.challengeSolved[ip], nil
}

func (f *fakeStore) RecordEndpoint(context.Context, string) (bool, error) { return false, nil }
func (f *fakeStore) RecordParameters(context.Context, string, []string) ([]string, error) {
	return nil, nil
}

func (f *fakeStore) IsJTIRevoked(_ context.Context, jti string) (bool, error) {
	if f.jtiErr != nil {
		return false, f.jtiErr
	}
	return f.jtiRevoked[jti], nil
}
func (f *fakeStore) RevokeJTI(context.Context, string, time.Duration) error { return nil }

func (f *fakeStore) TrackObjectAccess(_ context.Context, _, _, _ string, _ time.Duration) (int64, error) {
	if f.trackObject != nil {
		return f.trackObject()
	}
	return 1, nil
}

func (f *fakeStore) TrackBaseline(_ context.Context, _, _ string, _ int64, _ bool, _ time.Duration) (float64, error) {
	return f.baseline, nil
}
func (f *fakeStore) TrackObjectOwner(_ context.Context, _, _, _ string, _ time.Duration) (int64, bool, error) {
	if f.trackOwner != nil {
		return f.trackOwner()
	}
	return 0, false, nil
}
func (f *fakeStore) SetObjectOwner(_ context.Context, scope, id, owner string, _ time.Duration) error {
	f.setOwners = append(f.setOwners, owner)
	if f.objOwners == nil {
		f.objOwners = map[string]string{}
	}
	f.objOwners[scope+"\x00"+id] = owner
	return nil
}
func (f *fakeStore) GetObjectOwner(_ context.Context, scope, id string) (string, bool, error) {
	if f.getOwner != nil {
		return f.getOwner()
	}
	if o, ok := f.objOwners[scope+"\x00"+id]; ok {
		return o, true, nil
	}
	return "", false, nil
}

func (f *fakeStore) ValidateSession(_ context.Context, token string) (iam.Session, bool, error) {
	if s, ok := f.sessionFull[token]; ok {
		return s, true, nil
	}
	csrf, ok := f.sessions[token]
	if !ok {
		return iam.Session{}, false, nil
	}
	// Default to a super-admin session so existing tests keep their CSRF flow.
	return iam.Session{CSRF: csrf, TenantID: tenant.Default, Role: iam.RoleAdmin}, true, nil
}

func (f *fakeStore) PushForensic(_ context.Context, e store.ForensicEntry) {
	f.forensic = append(f.forensic, e)
}
func (f *fakeStore) GetForensicLog(context.Context, int64) ([]store.ForensicEntry, error) {
	return nil, nil
}
