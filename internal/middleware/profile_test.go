package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/config"
)

// recordingLogger captures the last warning, because these tests are about what
// the operator is told — a finding nobody can read is the failure mode this
// whole middleware is shaped against. Separate from the shared fakeLogger,
// which is a no-op used by value in many tests.
type recordingLogger struct {
	msg    string
	fields map[string]any
}

func (l *recordingLogger) Info(string, ...map[string]any)  {}
func (l *recordingLogger) Debug(string, ...map[string]any) {}
func (l *recordingLogger) Error(string, ...map[string]any) {}
func (l *recordingLogger) Warn(msg string, f ...map[string]any) {
	l.msg = msg
	if len(f) > 0 {
		l.fields = f[0]
	}
}
func (l *recordingLogger) BlockEvent(string, string, string, string, map[string]any) {}

func (l *recordingLogger) lastWarn() (string, map[string]any) { return l.msg, l.fields }

// errStore stands in for a Redis outage.
var errStore = errors.New("redis unavailable")

// profileCfg is a configuration with the floors low enough to exercise the
// logic and high enough that the defaults are not what is under test.
func profileCfg() config.ProfileConfig {
	return config.ProfileConfig{
		Enabled:         true,
		Window:          time.Minute,
		BaselineTTL:     time.Hour,
		Sensitivity:     4,
		MinObservations: 10,
	}
}

// runProfile drives one request through the middleware with a given consumer
// and upstream status.
func runProfile(t *testing.T, cfg config.ProfileConfig, st *fakeStore, consumer string, status int) *recordingLogger {
	t.Helper()
	log := &recordingLogger{}
	h := BehaviorProfile(cfg, log, st, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	if consumer != "" {
		r.Header.Set("X-Gateway-Consumer-Key", consumer)
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
	return log
}

// The finding has to be actionable. "Anomaly score 0.87" tells an operator
// nothing; this project has measured what unexplained findings are worth — 101
// identical criticals out of 161 requests, worthless not because there were
// many but because none said why.
func TestProfile_FindingExplainsItself(t *testing.T) {
	st := &fakeStore{
		profileWindow:   map[string]int64{"volume": 100},
		profileBaseline: map[string]float64{"volume": 5},
	}
	log := runProfile(t, profileCfg(), st, "jwt:alice", http.StatusOK)

	msg, fields := log.lastWarn()
	if msg == "" {
		t.Fatal("a consumer at 20x its own norm produced no finding")
	}
	why, _ := fields["why"].(string)
	for _, want := range []string{"jwt:alice", "100", "norm"} {
		if !strings.Contains(why, want) {
			t.Errorf("why = %q, want it to mention %q", why, want)
		}
	}
	if fields["metric"] != "volume" {
		t.Errorf("metric = %v, want the dimension named", fields["metric"])
	}
}

// The single most important property: it must not report a consumer behaving
// normally. A profile that cries wolf is switched off, and then the one real
// finding arrives to an audience that stopped looking.
func TestProfile_SilentOnNormalTraffic(t *testing.T) {
	st := &fakeStore{
		profileWindow:   map[string]int64{"volume": 30},
		profileBaseline: map[string]float64{"volume": 25},
	}
	log := runProfile(t, profileCfg(), st, "jwt:alice", http.StatusOK)
	if msg, _ := log.lastWarn(); msg != "" {
		t.Fatalf("a consumer within its norm was reported: %q", msg)
	}
}

// A consumer whose norm is a fraction of a request must not be "anomalous" at
// three. Below the floor there is no norm to depart from, only noise.
func TestProfile_FloorSuppressesTinyBaselines(t *testing.T) {
	st := &fakeStore{
		profileWindow:   map[string]int64{"volume": 3},
		profileBaseline: map[string]float64{"volume": 0.4},
	}
	log := runProfile(t, profileCfg(), st, "jwt:alice", http.StatusOK)
	if msg, _ := log.lastWarn(); msg != "" {
		t.Fatalf("three requests against a norm of 0.4 were reported as an anomaly: %q", msg)
	}
}

// An attack that persists must not become the new normal. The anomalous window
// is re-recorded with learning off, which is the guard the BOLA baseline needed
// for the same reason.
func TestProfile_DoesNotLearnFromAnAnomaly(t *testing.T) {
	st := &fakeStore{
		profileWindow:   map[string]int64{"volume": 100},
		profileBaseline: map[string]float64{"volume": 5},
	}
	runProfile(t, profileCfg(), st, "jwt:alice", http.StatusOK)

	var sawVolume bool
	for _, m := range st.profileNoLearn {
		if m == "volume" {
			sawVolume = true
		}
	}
	if !sawVolume {
		t.Fatal("the anomalous window was folded into the baseline; a sustained attack would become the norm")
	}
}

// 401/403 is the credential-stuffing and privilege-probing shape, and it is
// only counted when the response actually was one.
func TestProfile_AuthFailuresAreCountedOnlyOnAuthFailures(t *testing.T) {
	st := &fakeStore{
		profileWindow:   map[string]int64{"auth_failures": 60},
		profileBaseline: map[string]float64{"auth_failures": 2},
	}
	log := runProfile(t, profileCfg(), st, "jwt:alice", http.StatusForbidden)
	msg, fields := log.lastWarn()
	if msg == "" || fields["metric"] != "auth_failures" {
		t.Fatalf("a burst of 403s was not reported as an auth-failure departure: %q %v", msg, fields)
	}

	clean := &fakeStore{
		profileWindow:   map[string]int64{"auth_failures": 60},
		profileBaseline: map[string]float64{"auth_failures": 2},
	}
	if _, f := runProfile(t, profileCfg(), clean, "jwt:alice", http.StatusOK).lastWarn(); f != nil &&
		f["metric"] == "auth_failures" {
		t.Error("a 200 response was counted as an authorisation failure")
	}
}

// The batch job, the indexer and the monitoring probe look anomalous by nature.
// They are excluded entirely rather than tuned around, which is the main
// false-positive control here.
func TestProfile_AllowlistedConsumerIsNeverReported(t *testing.T) {
	cfg := profileCfg()
	cfg.Allowlist = []string{"jwt:nightly-batch"}
	st := &fakeStore{
		profileWindow:   map[string]int64{"volume": 10000},
		profileBaseline: map[string]float64{"volume": 1},
	}
	log := runProfile(t, cfg, st, "jwt:nightly-batch", http.StatusOK)
	if msg, _ := log.lastWarn(); msg != "" {
		t.Fatalf("an allowlisted consumer was reported: %q", msg)
	}
	if len(st.profileCounts) != 0 {
		t.Errorf("an allowlisted consumer was still measured: %v", st.profileCounts)
	}
}

// With no consumer identity, "unlike itself" has no meaning: every caller is
// the same one. Measuring anyway would attribute one client's behaviour to all
// of them.
func TestProfile_NoConsumerNoProfile(t *testing.T) {
	st := &fakeStore{profileBaseline: map[string]float64{"volume": 1}}
	runProfile(t, profileCfg(), st, "", http.StatusOK)
	if len(st.profileCounts) != 0 {
		t.Errorf("a request with no consumer identity was profiled: %v", st.profileCounts)
	}
}

// A store outage must produce neither a blocked request nor an invented
// finding. Profiling is an observation; it has no business failing anything.
func TestProfile_StoreOutageIsSilentAndHarmless(t *testing.T) {
	// A norm low enough that the value the failing store returns would be
	// reported as an anomaly if the error were ignored. Without this the test
	// passes for the wrong reason — the zero-value branch catches it — which a
	// mutation demonstrated.
	st := &fakeStore{
		profileErr:      errStore,
		profileBaseline: map[string]float64{"volume": 0.1},
	}
	log := &recordingLogger{}
	h := BehaviorProfile(profileCfg(), log, st, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	r.Header.Set("X-Gateway-Consumer-Key", "jwt:alice")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the request served normally during a store outage", rec.Code)
	}
	if msg, _ := log.lastWarn(); msg != "" {
		t.Errorf("a store outage produced a finding: %q", msg)
	}
}

// Disabled means not in the path at all, not "enabled and quiet".
func TestProfile_DisabledIsPassthrough(t *testing.T) {
	cfg := profileCfg()
	cfg.Enabled = false
	st := &fakeStore{
		profileWindow:   map[string]int64{"volume": 10000},
		profileBaseline: map[string]float64{"volume": 1},
	}
	runProfile(t, cfg, st, "jwt:alice", http.StatusOK)
	if len(st.profileCounts) != 0 {
		t.Errorf("a disabled profiler measured traffic: %v", st.profileCounts)
	}
}

// A sensitivity below 1 makes every consumer permanently anomalous against its
// own norm. Coerced rather than obeyed, because an operator who types 0.5 wants
// "more sensitive", not "report everything forever".
func TestProfile_SensitivityBelowOneIsCoerced(t *testing.T) {
	cfg := profileCfg()
	cfg.Sensitivity = 0.5
	st := &fakeStore{
		profileWindow:   map[string]int64{"volume": 30},
		profileBaseline: map[string]float64{"volume": 25},
	}
	log := runProfile(t, cfg, st, "jwt:alice", http.StatusOK)
	if msg, _ := log.lastWarn(); msg != "" {
		t.Fatalf("sensitivity 0.5 reported a consumer within its norm: %q", msg)
	}
}
