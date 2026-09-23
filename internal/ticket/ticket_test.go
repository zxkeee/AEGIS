package ticket

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// tracker is a stand-in Jira or ServiceNow.
type tracker struct {
	mu sync.Mutex
	// existing is what a search will find, keyed by correlation key.
	existing map[string]string
	created  []map[string]any
	searches []string
	// failSearch makes every search fail, which is the condition under which
	// this package knowingly risks a duplicate.
	failSearch bool
	// failCreate makes creation fail.
	failCreate bool
	auth       string
}

func newTracker() *tracker { return &tracker{existing: map[string]string{}} }

func (tr *tracker) jira() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		tr.auth = r.Header.Get("Authorization")

		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/search") {
			if tr.failSearch {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			jql := r.URL.Query().Get("jql")
			tr.searches = append(tr.searches, jql)
			for key, ref := range tr.existing {
				if strings.Contains(jql, key) {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"issues": []map[string]string{{"key": ref}},
					})
					return
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"issues": []any{}})
			return
		}

		if tr.failCreate {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":{"project":"project is required"}}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		tr.created = append(tr.created, body)
		_ = json.NewEncoder(w).Encode(map[string]string{"key": "SEC-1"})
	}
}

func (tr *tracker) servicenow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		tr.auth = r.Header.Get("Authorization")

		if r.Method == http.MethodGet {
			if tr.failSearch {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			key := r.URL.Query().Get("correlation_id")
			tr.searches = append(tr.searches, key)
			if ref, ok := tr.existing[key]; ok {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"result": []map[string]string{{"sys_id": ref}},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{}})
			return
		}

		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		tr.created = append(tr.created, body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]string{"sys_id": "abc123", "number": "INC0010001"},
		})
	}
}

func (tr *tracker) lastCreated() map[string]any {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.created) == 0 {
		return nil
	}
	return tr.created[len(tr.created)-1]
}

func (tr *tracker) createCount() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return len(tr.created)
}

// loopbackClient points a client at a test server.
//
// httptest listens on 127.0.0.1, which both production clients refuse — see
// TestClient_RefusesLoopbackEvenWhenPrivateIsAllowed for the assertion that
// they do. A test exercising delivery has to dial loopback deliberately.
func loopbackClient(t *testing.T, system, base, project string) *Client {
	t.Helper()
	c, err := New(system, base, project, "bot@acme.example", "token-1", Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.http = &http.Client{Timeout: 5 * time.Second}
	return c
}

func sampleIncident() Incident {
	return Incident{
		ID: "bola-jwt-alice-20260923", Title: "BOLA on /orders/{id}",
		Class: "bola", Subject: "jwt:alice", Severity: "major",
		Detected: time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC), Events: 120,
		Tenant: "acme",
	}
}

func TestJira_CreatesWithCorrelationLabel(t *testing.T) {
	tr := newTracker()
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	c := loopbackClient(t, SystemJira, srv.URL, "SEC")
	filed, err := c.File(context.Background(), sampleIncident())
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if filed.Ref != "SEC-1" {
		t.Errorf("ref = %q, want SEC-1", filed.Ref)
	}
	if filed.Adopted {
		t.Error("a freshly created ticket was reported as adopted")
	}

	body := tr.lastCreated()
	fields, _ := body["fields"].(map[string]any)
	labels, _ := fields["labels"].([]any)
	var found bool
	for _, l := range labels {
		if l == CorrelationKey(sampleIncident().ID) {
			found = true
		}
	}
	if !found {
		// Without the label the next run cannot find this ticket, and every
		// restart files it again.
		t.Errorf("the correlation label is missing; labels = %v", labels)
	}
	// Jira Cloud rejects a plain string description outright.
	if _, ok := fields["description"].(map[string]any); !ok {
		t.Errorf("description = %#v, want an Atlassian Document Format object", fields["description"])
	}
}

func TestJira_AdoptsAnExistingTicketInsteadOfDuplicating(t *testing.T) {
	tr := newTracker()
	tr.existing[CorrelationKey(sampleIncident().ID)] = "SEC-99"
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	c := loopbackClient(t, SystemJira, srv.URL, "SEC")
	filed, err := c.File(context.Background(), sampleIncident())
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if !filed.Adopted || filed.Ref != "SEC-99" {
		t.Fatalf("filed = %+v, want the existing SEC-99 adopted", filed)
	}
	if n := tr.createCount(); n != 0 {
		t.Errorf("created %d tickets when one already existed", n)
	}
}

// The single most valuable property: a crashed run left a ticket behind, the
// local record is gone, and the next sweep must not produce a second ticket.
func TestServiceNow_AdoptsByCorrelationID(t *testing.T) {
	tr := newTracker()
	tr.existing[CorrelationKey(sampleIncident().ID)] = "sys-777"
	srv := httptest.NewServer(tr.servicenow())
	defer srv.Close()

	c := loopbackClient(t, SystemServiceNow, srv.URL, "")
	filed, err := c.File(context.Background(), sampleIncident())
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if !filed.Adopted || filed.Ref != "sys-777" {
		t.Fatalf("filed = %+v, want sys-777 adopted", filed)
	}
	if n := tr.createCount(); n != 0 {
		t.Errorf("created %d records when one already existed", n)
	}
}

func TestServiceNow_MapsSeverityToItsInvertedUrgency(t *testing.T) {
	tr := newTracker()
	srv := httptest.NewServer(tr.servicenow())
	defer srv.Close()
	c := loopbackClient(t, SystemServiceNow, srv.URL, "")

	for severity, wantUrgency := range map[string]string{
		"major": "1", "significant": "2", "minor": "3",
	} {
		inc := sampleIncident()
		inc.ID = "inc-" + severity
		inc.Severity = severity
		if _, err := c.File(context.Background(), inc); err != nil {
			t.Fatalf("File(%s): %v", severity, err)
		}
		if got := tr.lastCreated()["urgency"]; got != wantUrgency {
			// ServiceNow counts 1 as most urgent, the opposite of every
			// severity scale here. Passing the value through would file every
			// major incident as the lowest urgency in the queue.
			t.Errorf("severity %s -> urgency %v, want %s", severity, got, wantUrgency)
		}
	}
}

// A search that fails must not stop the incident being filed — silence is the
// wrong way to fail for something whose purpose is that somebody finds out —
// but the caller has to be told the duplicate check did not run.
func TestFile_SearchFailureStillFilesAndSaysSo(t *testing.T) {
	tr := newTracker()
	tr.failSearch = true
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	c := loopbackClient(t, SystemJira, srv.URL, "SEC")
	filed, err := c.File(context.Background(), sampleIncident())
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if filed.Ref == "" {
		t.Fatal("the incident went unfiled because a search failed")
	}
	if !filed.SearchFailed {
		t.Error("the duplicate check did not run and the result does not say so")
	}
}

func TestFile_TrackerErrorCarriesTheReason(t *testing.T) {
	tr := newTracker()
	tr.failCreate = true
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	c := loopbackClient(t, SystemJira, srv.URL, "SEC")
	_, err := c.File(context.Background(), sampleIncident())
	if err == nil {
		t.Fatal("a rejected creation returned no error")
	}
	// "400" alone leaves an operator with no way forward; the tracker says
	// which field it disliked and that is the useful half.
	if !strings.Contains(err.Error(), "project is required") {
		t.Errorf("error = %v, want it to carry the tracker's explanation", err)
	}
}

func TestClient_AuthenticatesWithBasicAuth(t *testing.T) {
	tr := newTracker()
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	c := loopbackClient(t, SystemJira, srv.URL, "SEC")
	if _, err := c.File(context.Background(), sampleIncident()); err != nil {
		t.Fatalf("File: %v", err)
	}

	tr.mu.Lock()
	got := tr.auth
	tr.mu.Unlock()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("bot@acme.example:token-1"))
	if got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestNew_RefusesAnUnknownTracker(t *testing.T) {
	if _, err := New("trello", "https://x.example", "", "", "", Options{}); err == nil {
		t.Error("an unsupported tracker was accepted; it would be configured and file nothing")
	}
	if _, err := New(SystemJira, "", "SEC", "", "", Options{}); err == nil {
		t.Error("a tracker with no base url was accepted")
	}
}

// The relaxation for self-hosted trackers must stop short of loopback and the
// cloud metadata service, exactly as it does for SIEM sinks.
func TestClient_RefusesLoopbackEvenWhenPrivateIsAllowed(t *testing.T) {
	tr := newTracker()
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	c, err := New(SystemJira, srv.URL, "SEC", "u", "t", Options{AllowPrivate: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.File(context.Background(), sampleIncident()); err == nil {
		t.Fatal("a tracker client allowed to reach private addresses connected to loopback")
	}
	if n := tr.createCount(); n != 0 {
		t.Errorf("the request reached the tracker anyway (%d created)", n)
	}
}

// --- worker ---

type fakeRegister struct {
	mu       sync.Mutex
	pending  map[string][]Incident
	recorded map[string]string
	recErr   error
	listErr  error
}

func newFakeRegister() *fakeRegister {
	return &fakeRegister{pending: map[string][]Incident{}, recorded: map[string]string{}}
}

func (f *fakeRegister) Tenants(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.pending))
	for t := range f.pending {
		out = append(out, t)
	}
	return out, nil
}

func (f *fakeRegister) Unticketed(_ context.Context, tenant, _ string, _ int) ([]Incident, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pending[tenant], nil
}

func (f *fakeRegister) RecordTicket(_ context.Context, tenant, incidentID, _, ref, _ string) error {
	if f.recErr != nil {
		return f.recErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k := tenant + "/" + incidentID
	if _, ok := f.recorded[k]; ok {
		return ErrAlreadyRecorded
	}
	f.recorded[k] = ref
	return nil
}

type testLog struct {
	mu     sync.Mutex
	errors []string
}

func (l *testLog) Info(string, ...map[string]any) {}
func (l *testLog) Error(msg string, _ ...map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, msg)
}
func (l *testLog) saw(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.errors {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

func TestWorker_FilesEachIncidentOnce(t *testing.T) {
	tr := newTracker()
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	reg := newFakeRegister()
	reg.pending["acme"] = []Incident{sampleIncident()}
	w := NewWorker(loopbackClient(t, SystemJira, srv.URL, "SEC"), reg, &testLog{}, time.Hour, "major", 10)

	w.Sweep(context.Background())
	if tr.createCount() != 1 {
		t.Fatalf("created %d tickets on the first sweep, want 1", tr.createCount())
	}
	if reg.recorded["acme/"+sampleIncident().ID] != "SEC-1" {
		t.Errorf("the reference was not recorded: %v", reg.recorded)
	}
}

// Losing the race is not an error to swallow: both gateways created a ticket
// and only one reference is stored, so the orphan has to be named or nobody
// can close it.
func TestWorker_ReportsTheDuplicateWhenItLosesTheRace(t *testing.T) {
	tr := newTracker()
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	reg := newFakeRegister()
	reg.pending["acme"] = []Incident{sampleIncident()}
	reg.recorded["acme/"+sampleIncident().ID] = "SEC-42" // another gateway won
	log := &testLog{}
	w := NewWorker(loopbackClient(t, SystemJira, srv.URL, "SEC"), reg, log, time.Hour, "major", 10)

	w.Sweep(context.Background())

	if !log.saw("duplicate") {
		t.Errorf("losing the race was not reported; errors = %v", log.errors)
	}
}

// A tracker outage must delay filing, never drop it. The next sweep is the
// retry, which is the entire reason this is a poller.
func TestWorker_RetriesAfterATrackerOutage(t *testing.T) {
	tr := newTracker()
	tr.failCreate = true
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	reg := newFakeRegister()
	reg.pending["acme"] = []Incident{sampleIncident()}
	w := NewWorker(loopbackClient(t, SystemJira, srv.URL, "SEC"), reg, &testLog{}, time.Hour, "major", 10)

	w.Sweep(context.Background())
	if len(reg.recorded) != 0 {
		t.Fatalf("a failed filing was recorded as done: %v", reg.recorded)
	}

	tr.mu.Lock()
	tr.failCreate = false
	tr.mu.Unlock()

	w.Sweep(context.Background())
	if reg.recorded["acme/"+sampleIncident().ID] == "" {
		t.Error("the incident was not retried after the tracker recovered")
	}
}

func TestWorker_RecordFailureLeavesItForTheNextSweep(t *testing.T) {
	tr := newTracker()
	srv := httptest.NewServer(tr.jira())
	defer srv.Close()

	reg := newFakeRegister()
	reg.pending["acme"] = []Incident{sampleIncident()}
	reg.recErr = errors.New("database down")
	log := &testLog{}
	w := NewWorker(loopbackClient(t, SystemJira, srv.URL, "SEC"), reg, log, time.Hour, "major", 10)

	w.Sweep(context.Background())
	if !log.saw("filed but not recorded") {
		t.Errorf("a ticket that exists remotely and not locally was not reported; errors = %v", log.errors)
	}
}
