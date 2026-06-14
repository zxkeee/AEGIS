package middleware

import (
	"context"
	"time"

	"api-gateway/internal/store"
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
	jtiRevoked  map[string]bool
	blockedIPs  map[string]bool
	sessions    map[string]string // token -> csrf
	behavior    int
}

func (f *fakeStore) IncrRate(ctx context.Context, key string, window time.Duration) (int64, error) {
	if f.incrRate != nil {
		return f.incrRate(ctx, key, window)
	}
	return 1, nil
}

func (f *fakeStore) IsIPBlocked(_ context.Context, ip string) (bool, error) {
	return f.blockedIPs[ip], nil
}
func (f *fakeStore) BlockIP(_ context.Context, ip string) error {
	if f.blockedIPs == nil {
		f.blockedIPs = map[string]bool{}
	}
	f.blockedIPs[ip] = true
	return nil
}
func (f *fakeStore) IncrMetric(context.Context, string) {}

func (f *fakeStore) IncrAutoBanCounter(context.Context, string) (int64, error) { return 1, nil }

func (f *fakeStore) RecordRequest(context.Context, string, string, int) {}
func (f *fakeStore) CalcBehaviorScore(context.Context, string, int) int { return f.behavior }
func (f *fakeStore) IncrBehaviorScore(context.Context, string, int)     {}

func (f *fakeStore) CheckJA3Consistency(context.Context, string, string) (bool, error) {
	return false, nil
}

func (f *fakeStore) IssueChallenge(context.Context, string, string, time.Duration) error { return nil }
func (f *fakeStore) IsValidChallengeToken(context.Context, string, string) (bool, error) {
	return false, nil
}
func (f *fakeStore) MarkChallengeSolved(context.Context, string, time.Duration) error { return nil }
func (f *fakeStore) IsChallengeSolved(context.Context, string) (bool, error)          { return false, nil }

func (f *fakeStore) RecordEndpoint(context.Context, string) (bool, error) { return false, nil }
func (f *fakeStore) RecordParameters(context.Context, string, []string) ([]string, error) {
	return nil, nil
}

func (f *fakeStore) IsJTIRevoked(_ context.Context, jti string) (bool, error) {
	return f.jtiRevoked[jti], nil
}
func (f *fakeStore) RevokeJTI(context.Context, string, time.Duration) error { return nil }

func (f *fakeStore) TrackObjectAccess(_ context.Context, _, _, _ string, _ time.Duration) (int64, error) {
	if f.trackObject != nil {
		return f.trackObject()
	}
	return 1, nil
}

func (f *fakeStore) ValidateSession(_ context.Context, token string) (string, bool, error) {
	csrf, ok := f.sessions[token]
	return csrf, ok, nil
}

func (f *fakeStore) PushForensic(context.Context, store.ForensicEntry) {}
func (f *fakeStore) GetForensicLog(context.Context, int64) ([]store.ForensicEntry, error) {
	return nil, nil
}
