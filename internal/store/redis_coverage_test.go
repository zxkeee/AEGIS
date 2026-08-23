package store

import (
	"context"
	"testing"
	"time"

	"api-gateway/internal/iam"

	"github.com/alicebob/miniredis/v2"
)

// newTestStore spins up an in-memory Redis (miniredis) and a Store on it, so the
// full Redis-backed surface is exercised locally without a real server.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	st, err := New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestStore_RateLimit(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	for i := int64(1); i <= 3; i++ {
		got, err := st.IncrRate(ctx, "k", time.Minute)
		if err != nil || got != i {
			t.Fatalf("IncrRate #%d = %d, %v", i, got, err)
		}
	}
	if v, _ := st.GetRate(ctx, "k"); v != 3 {
		t.Errorf("GetRate = %d, want 3", v)
	}
}

func TestStore_IPBlocklist(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if blocked, _ := st.IsIPBlocked(ctx, "1.2.3.4"); blocked {
		t.Fatal("fresh IP should not be blocked")
	}
	if err := st.BlockIP(ctx, "1.2.3.4"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	if blocked, _ := st.IsIPBlocked(ctx, "1.2.3.4"); !blocked {
		t.Error("IP should be blocked after BlockIP")
	}
	if ips, _ := st.GetBlockedIPs(ctx); len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("GetBlockedIPs = %v", ips)
	}
	if err := st.UnblockIP(ctx, "1.2.3.4", ""); err != nil {
		t.Fatalf("UnblockIP: %v", err)
	}
	if blocked, _ := st.IsIPBlocked(ctx, "1.2.3.4"); blocked {
		t.Error("IP should be unblocked")
	}
}

func TestStore_Metrics(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	st.IncrMetric(ctx, "hits")
	st.IncrMetric(ctx, "hits")
	st.IncrMetric(ctx, "misses")
	m, err := st.GetMetrics(ctx)
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	if m["hits"] != 2 || m["misses"] != 1 {
		t.Errorf("metrics = %v", m)
	}
}

func TestStore_AutoBanCounter(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if n, _ := st.IncrAutoBanCounter(ctx, "ip"); n != 1 {
		t.Errorf("first counter = %d, want 1", n)
	}
	if n, _ := st.IncrAutoBanCounter(ctx, "ip"); n != 2 {
		t.Errorf("second counter = %d, want 2", n)
	}
}

func TestStore_Behavior(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	// No history: score is zero.
	if s := st.CalcBehaviorScore(ctx, "ip", 70); s != 0 {
		t.Errorf("fresh score = %d, want 0", s)
	}
	// Penalty raises the score.
	st.IncrBehaviorScore(ctx, "ip", 25)
	if s := st.CalcBehaviorScore(ctx, "ip", 70); s < 25 {
		t.Errorf("score after penalty = %d, want >=25", s)
	}
	// RecordRequest must not panic and should keep the score bounded.
	for i := 0; i < 10; i++ {
		st.RecordRequest(ctx, "ip", "/p", 500)
	}
	if s := st.CalcBehaviorScore(ctx, "ip", 70); s < 0 || s > 100 {
		t.Errorf("score out of range: %d", s)
	}
}

func TestStore_JA3Consistency(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	// Up to 3 distinct fingerprints is acceptable; the 4th is suspicious.
	for i, ja3 := range []string{"a", "b", "c"} {
		sus, err := st.CheckJA3Consistency(ctx, "ip", ja3)
		if err != nil || sus {
			t.Fatalf("fingerprint #%d (%s): sus=%v err=%v", i+1, ja3, sus, err)
		}
	}
	if sus, _ := st.CheckJA3Consistency(ctx, "ip", "d"); !sus {
		t.Error("4th distinct fingerprint should be flagged suspicious")
	}
}

func TestStore_Challenge(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.IssueChallenge(ctx, "ip", "tok", time.Minute); err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if ok, _ := st.IsValidChallengeToken(ctx, "ip", "tok"); !ok {
		t.Error("correct token should validate")
	}
	if ok, _ := st.IsValidChallengeToken(ctx, "ip", "wrong"); ok {
		t.Error("wrong token must not validate")
	}
	if solved, _ := st.IsChallengeSolved(ctx, "ip"); solved {
		t.Error("challenge not solved yet")
	}
	if err := st.MarkChallengeSolved(ctx, "ip", time.Minute); err != nil {
		t.Fatalf("MarkChallengeSolved: %v", err)
	}
	if solved, _ := st.IsChallengeSolved(ctx, "ip"); !solved {
		t.Error("challenge should be solved")
	}
}

func TestStore_Inventory(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if isNew, _ := st.RecordEndpoint(ctx, "GET /a"); !isNew {
		t.Error("first sighting should be new")
	}
	if isNew, _ := st.RecordEndpoint(ctx, "GET /a"); isNew {
		t.Error("second sighting should not be new")
	}
	newParams, _ := st.RecordParameters(ctx, "GET /a", []string{"x", "y"})
	if len(newParams) != 2 {
		t.Errorf("first params = %v, want 2 new", newParams)
	}
	newParams, _ = st.RecordParameters(ctx, "GET /a", []string{"x", "z"})
	if len(newParams) != 1 || newParams[0] != "z" {
		t.Errorf("second params = %v, want [z]", newParams)
	}
	if inv, _ := st.GetInventory(ctx); len(inv) != 1 || inv[0] != "GET /a" {
		t.Errorf("inventory = %v", inv)
	}
}

func TestStore_JTIRevocation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if revoked, _ := st.IsJTIRevoked(ctx, "jti1"); revoked {
		t.Error("fresh JTI should not be revoked")
	}
	if err := st.RevokeJTI(ctx, "jti1", time.Minute); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}
	if revoked, _ := st.IsJTIRevoked(ctx, "jti1"); !revoked {
		t.Error("JTI should be revoked")
	}
}

func TestStore_TrackObjectAccess(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	// Distinct object IDs accumulate; a repeat does not inflate the count.
	if _, err := st.TrackObjectAccess(ctx, "consumer", "GET /u/{id}", "1", time.Minute); err != nil {
		t.Fatalf("TrackObjectAccess: %v", err)
	}
	if _, err := st.TrackObjectAccess(ctx, "consumer", "GET /u/{id}", "2", time.Minute); err != nil {
		t.Fatalf("TrackObjectAccess: %v", err)
	}
	n, err := st.TrackObjectAccess(ctx, "consumer", "GET /u/{id}", "2", time.Minute)
	if err != nil {
		t.Fatalf("TrackObjectAccess: %v", err)
	}
	if n != 2 {
		t.Errorf("distinct count = %d, want 2", n)
	}
}

func TestStore_Sessions(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	sess := iam.Session{TenantID: "default", Role: iam.RoleAdmin, Email: "a@b.c", CSRF: "csrf"}
	if err := st.CreateSession(ctx, "token123", sess, time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, ok, err := st.ValidateSession(ctx, "token123")
	if err != nil || !ok {
		t.Fatalf("ValidateSession ok=%v err=%v", ok, err)
	}
	if got.Email != "a@b.c" || got.Role != iam.RoleAdmin {
		t.Errorf("session = %+v", got)
	}
	if err := st.DeleteSession(ctx, "token123"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, ok, _ := st.ValidateSession(ctx, "token123"); ok {
		t.Error("deleted session must not validate")
	}
}

func TestStore_RevokeSessions(t *testing.T) {
	ctx := context.Background()
	tenantASess1 := iam.Session{TenantID: "tenant-a", UserID: "u1", Role: iam.RoleAdmin, CSRF: "c1"}
	tenantASess2 := iam.Session{TenantID: "tenant-a", UserID: "u2", Role: iam.RoleViewer, CSRF: "c2"}
	tenantBSess := iam.Session{TenantID: "tenant-b", UserID: "u3", Role: iam.RoleAdmin, CSRF: "c3"}

	t.Run("revoke by tenant clears only that tenant", func(t *testing.T) {
		st := newTestStore(t)
		for token, sess := range map[string]iam.Session{
			"tok-a1": tenantASess1, "tok-a2": tenantASess2, "tok-b1": tenantBSess,
		} {
			if err := st.CreateSession(ctx, token, sess, time.Hour); err != nil {
				t.Fatalf("CreateSession(%s): %v", token, err)
			}
		}
		n, err := st.RevokeSessions(ctx, "tenant-a", "")
		if err != nil {
			t.Fatalf("RevokeSessions: %v", err)
		}
		if n != 2 {
			t.Errorf("revoked = %d, want 2", n)
		}
		if _, ok, _ := st.ValidateSession(ctx, "tok-a1"); ok {
			t.Error("tenant-a session tok-a1 should be revoked")
		}
		if _, ok, _ := st.ValidateSession(ctx, "tok-a2"); ok {
			t.Error("tenant-a session tok-a2 should be revoked")
		}
		if _, ok, _ := st.ValidateSession(ctx, "tok-b1"); !ok {
			t.Error("tenant-b session must survive a tenant-a revoke")
		}
	})

	t.Run("revoke by user narrows within tenant", func(t *testing.T) {
		st := newTestStore(t)
		for token, sess := range map[string]iam.Session{
			"tok-a1": tenantASess1, "tok-a2": tenantASess2, "tok-b1": tenantBSess,
		} {
			if err := st.CreateSession(ctx, token, sess, time.Hour); err != nil {
				t.Fatalf("CreateSession(%s): %v", token, err)
			}
		}
		n, err := st.RevokeSessions(ctx, "tenant-a", "u1")
		if err != nil {
			t.Fatalf("RevokeSessions: %v", err)
		}
		if n != 1 {
			t.Errorf("revoked = %d, want 1", n)
		}
		if _, ok, _ := st.ValidateSession(ctx, "tok-a1"); ok {
			t.Error("u1 session should be revoked")
		}
		if _, ok, _ := st.ValidateSession(ctx, "tok-a2"); !ok {
			t.Error("u2 session must survive a u1-scoped revoke")
		}
	})

	t.Run("empty tenant filter narrows by user only (super-admin cross-tenant delete)", func(t *testing.T) {
		st := newTestStore(t)
		for token, sess := range map[string]iam.Session{
			"tok-a1": tenantASess1, "tok-b1": tenantBSess,
		} {
			if err := st.CreateSession(ctx, token, sess, time.Hour); err != nil {
				t.Fatalf("CreateSession(%s): %v", token, err)
			}
		}
		n, err := st.RevokeSessions(ctx, "", "u3")
		if err != nil {
			t.Fatalf("RevokeSessions: %v", err)
		}
		if n != 1 {
			t.Errorf("revoked = %d, want 1", n)
		}
		if _, ok, _ := st.ValidateSession(ctx, "tok-b1"); ok {
			t.Error("u3 session should be revoked regardless of tenant filter")
		}
		if _, ok, _ := st.ValidateSession(ctx, "tok-a1"); !ok {
			t.Error("u1 session must survive a u3-scoped revoke")
		}
	})
}

func TestStore_Forensic(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	st.PushForensic(ctx, ForensicEntry{
		Timestamp: time.Now().UTC(), IP: "1.1.1.1", Path: "/x", Method: "GET",
		Reason: "test", Code: 403,
	})
	log, err := st.GetForensicLog(ctx, 10)
	if err != nil {
		t.Fatalf("GetForensicLog: %v", err)
	}
	if len(log) != 1 || log[0].Reason != "test" {
		t.Errorf("forensic log = %+v", log)
	}
}

// Normal client-facing statuses (401/403/404) and backend 5xx must NOT feed the
// ban-signalling error score — only genuinely abusive ones (400/429) do. This
// guards against auto-banning active clients (esp. behind shared IP/NAT) that
// simply hit missing or protected endpoints.
func TestStore_BehaviorErrorSignalIsNarrow(t *testing.T) {
	ctx := context.Background()

	scoreAfter := func(status int) int {
		st := newTestStore(t)
		// 20 responses of the given status from one IP within the window.
		for i := 0; i < 20; i++ {
			st.RecordRequest(ctx, "ip", "/p", status)
		}
		return st.CalcBehaviorScore(ctx, "ip", 70)
	}

	// errScore contributes up to +30 (errs*3). reqScore for 20 reqs = 20/5 = +4,
	// entropy for 1 path ~ 0. So a "not an error" status yields a small score
	// (~4), while an "abusive" one adds the error component on top.
	for _, normal := range []int{401, 403, 404, 500, 502, 503} {
		if s := scoreAfter(normal); s > 10 {
			t.Fatalf("status %d contributed to the error score (total=%d); it must not", normal, s)
		}
	}
	for _, abusive := range []int{400, 429} {
		if s := scoreAfter(abusive); s < 30 {
			t.Fatalf("abusive status %d should raise the error score, got %d", abusive, s)
		}
	}
}
