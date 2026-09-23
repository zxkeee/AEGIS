// Package ticket files incidents into an external tracker — Jira or
// ServiceNow.
//
// WHY THIS IS ATTACHED TO INCIDENTS AND NOT TO EVENTS. A BOLA campaign is
// thousands of events and one incident. Filing per event would produce
// thousands of tickets, and an integration that does that is switched off on
// its first day and never switched on again. The incident register already does
// the correlation (internal/incident), so a ticket is one per incident by
// construction rather than by a deduplication window somebody has to tune.
//
// # Idempotency, which is the whole problem
//
// "Create a ticket once" is not something a single database write can promise
// across a network. The process can create the remote ticket and then die
// before recording the reference, and the next run would create a second one.
//
// Three things together make that unlikely and detectable rather than pretended
// away:
//
//   - The local record is a UNIQUE row per incident, so two gateways racing can
//     both create and exactly one wins the write. The loser learns it lost, and
//     logs the duplicate it made with both references, instead of discarding
//     the fact.
//   - Before creating, the tracker is SEARCHED for the correlation key. Jira
//     gets a label, ServiceNow has a correlation_id field meant for precisely
//     this. A ticket created by a previous crashed run is adopted rather than
//     duplicated.
//   - The correlation key is the incident id, which is deterministic in the
//     incident's identity and start — so it is stable across restarts, and two
//     gateways derive the same one.
//
// What remains: a crash in the window between "tracker created it" and "search
// would find it" (trackers index asynchronously) can still produce a duplicate.
// That is a real gap, it is documented in docs/ticketing.md, and the honest
// description is "at least once, deduplicated on the tracker side", not
// "exactly once".
package ticket

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"api-gateway/internal/safefetch"
)

// Supported trackers.
const (
	SystemJira       = "jira"
	SystemServiceNow = "servicenow"
)

// Filed is the outcome of filing one incident.
type Filed struct {
	// Ref is the tracker's identifier: "SEC-123" for Jira, the sys_id for
	// ServiceNow.
	Ref string
	// URL is where a human opens it. Empty when the tracker did not say.
	URL string
	// Adopted reports that the ticket already existed and was found by its
	// correlation key rather than created. Worth surfacing: a run that adopts
	// everything is a run whose local records were lost.
	Adopted bool
	// SearchFailed reports that the duplicate check could not run, so this
	// ticket was created without knowing whether one already existed. Reported
	// rather than swallowed: it is the one condition under which this package
	// knowingly risks a duplicate, and an operator seeing two tickets deserves
	// to find the reason in a log rather than in this file.
	SearchFailed bool
}

// Incident is what a tracker needs to know. A narrow struct rather than
// internal/incident.Incident, to keep this package free of the register's
// schema and testable without a database.
type Incident struct {
	ID       string
	Title    string
	Class    string
	Subject  string
	Severity string
	Detected time.Time
	Events   int
	Tenant   string
}

// Client files incidents into one tracker.
type Client struct {
	system string
	// baseURL is the tracker root: https://acme.atlassian.net or
	// https://acme.service-now.com.
	baseURL string
	// project is Jira's project key. ServiceNow files into a fixed table and
	// ignores it.
	project string
	user    string
	token   string
	http    *http.Client
}

// Options carries the parts that are not obvious at a call site.
type Options struct {
	// AllowPrivate permits a tracker on the operator's own network — a
	// self-hosted Jira Data Center is an ordinary deployment. Loopback,
	// link-local (cloud metadata) and multicast stay refused regardless; see
	// safefetch.InternalClient.
	AllowPrivate bool
	// Timeout bounds one tracker call. Zero means 15s.
	Timeout time.Duration
}

// New builds a client. user is the Jira account email (ServiceNow ignores it
// only when an OAuth token is used; basic auth needs it).
func New(system, baseURL, project, user, token string, opts Options) (*Client, error) {
	switch system {
	case SystemJira, SystemServiceNow:
	default:
		return nil, fmt.Errorf("ticket: unknown system %q", system)
	}
	if baseURL == "" {
		return nil, fmt.Errorf("ticket: %s has no base url", system)
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	newClient := safefetch.Client
	if opts.AllowPrivate {
		newClient = safefetch.InternalClient
	}
	return &Client{
		system:  system,
		baseURL: strings.TrimRight(baseURL, "/"),
		project: project,
		user:    user,
		token:   token,
		http:    newClient("ticket_"+system, timeout),
	}, nil
}

// System reports which tracker this client files into.
func (c *Client) System() string { return c.system }

// CorrelationKey is what links an incident to its ticket in the tracker.
//
// Deterministic in the incident id, which is itself deterministic in the
// incident's identity and start. Two gateways derive the same key, and a run
// after a crash derives the key the crashed run used.
func CorrelationKey(incidentID string) string { return "aegis-" + incidentID }

// File creates a ticket for one incident, or adopts the one already there.
func (c *Client) File(ctx context.Context, inc Incident) (Filed, error) {
	key := CorrelationKey(inc.ID)

	// Search first. A ticket left behind by a run that died before recording
	// its reference is adopted rather than duplicated.
	found, findErr := c.find(ctx, key)
	if findErr == nil && found.Ref != "" {
		found.Adopted = true
		return found, nil
	}

	// A failed search is not a reason to skip filing. The incident would then
	// go unreported because a query failed, and for something whose whole
	// purpose is that somebody finds out, silence is the wrong way to fail. So
	// create, and say that the duplicate check did not run.
	var (
		created Filed
		err     error
	)
	switch c.system {
	case SystemJira:
		created, err = c.createJira(ctx, inc, key)
	default:
		created, err = c.createServiceNow(ctx, inc, key)
	}
	if err != nil {
		return Filed{}, err
	}
	created.SearchFailed = findErr != nil
	return created, nil
}

// find looks for an existing ticket by correlation key.
func (c *Client) find(ctx context.Context, key string) (Filed, error) {
	switch c.system {
	case SystemJira:
		// A label is the only field every Jira project has that is both
		// free-form and indexed. A custom field would be cleaner and would
		// require the customer to create it before anything works.
		jql := fmt.Sprintf(`labels = %q ORDER BY created DESC`, key)
		endpoint := c.baseURL + "/rest/api/3/search?maxResults=1&fields=key&jql=" + url.QueryEscape(jql)
		var out struct {
			Issues []struct {
				Key string `json:"key"`
			} `json:"issues"`
		}
		if err := c.call(ctx, http.MethodGet, endpoint, nil, &out); err != nil {
			return Filed{}, err
		}
		if len(out.Issues) == 0 {
			return Filed{}, nil
		}
		return Filed{Ref: out.Issues[0].Key, URL: c.baseURL + "/browse/" + out.Issues[0].Key}, nil

	default:
		endpoint := c.baseURL + "/api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id&correlation_id=" +
			url.QueryEscape(key)
		var out struct {
			Result []struct {
				SysID string `json:"sys_id"`
			} `json:"result"`
		}
		if err := c.call(ctx, http.MethodGet, endpoint, nil, &out); err != nil {
			return Filed{}, err
		}
		if len(out.Result) == 0 {
			return Filed{}, nil
		}
		return Filed{Ref: out.Result[0].SysID, URL: c.incidentURL(out.Result[0].SysID)}, nil
	}
}

func (c *Client) incidentURL(sysID string) string {
	return c.baseURL + "/nav_to.do?uri=incident.do%3Fsys_id%3D" + url.QueryEscape(sysID)
}

func (c *Client) createJira(ctx context.Context, inc Incident, key string) (Filed, error) {
	body := map[string]any{
		"fields": map[string]any{
			"project":   map[string]string{"key": c.project},
			"issuetype": map[string]string{"name": "Bug"},
			"summary":   summary(inc),
			"labels":    []string{key, "aegis"},
			// Atlassian Document Format: Jira Cloud rejects a plain string here.
			"description": map[string]any{
				"type":    "doc",
				"version": 1,
				"content": []any{map[string]any{
					"type":    "paragraph",
					"content": []any{map[string]any{"type": "text", "text": description(inc)}},
				}},
			},
		},
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := c.call(ctx, http.MethodPost, c.baseURL+"/rest/api/3/issue", body, &out); err != nil {
		return Filed{}, err
	}
	if out.Key == "" {
		return Filed{}, fmt.Errorf("ticket: jira accepted the issue but returned no key")
	}
	return Filed{Ref: out.Key, URL: c.baseURL + "/browse/" + out.Key}, nil
}

func (c *Client) createServiceNow(ctx context.Context, inc Incident, key string) (Filed, error) {
	body := map[string]any{
		"short_description": summary(inc),
		"description":       description(inc),
		"correlation_id":    key,
		"category":          "security",
		// ServiceNow's urgency is 1 (high) to 3 (low) — inverted relative to
		// every severity scale here, which is why it is mapped rather than
		// passed through.
		"urgency": map[string]string{"major": "1", "significant": "2", "minor": "3"}[inc.Severity],
	}
	var out struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}
	if err := c.call(ctx, http.MethodPost, c.baseURL+"/api/now/table/incident", body, &out); err != nil {
		return Filed{}, err
	}
	if out.Result.SysID == "" {
		return Filed{}, fmt.Errorf("ticket: servicenow accepted the record but returned no sys_id")
	}
	ref := out.Result.SysID
	if out.Result.Number != "" {
		// The number is what a human quotes; the sys_id is what the API needs.
		// Both are kept, number first, because the local record is read by
		// people more often than by code.
		ref = out.Result.Number + " (" + out.Result.SysID + ")"
	}
	return Filed{Ref: ref, URL: c.incidentURL(out.Result.SysID)}, nil
}

func summary(inc Incident) string {
	return fmt.Sprintf("[AEGIS] %s — %s", strings.ToUpper(inc.Class), inc.Title)
}

func description(inc Incident) string {
	var b strings.Builder
	fmt.Fprintf(&b, "AEGIS detected a security incident.\n\n")
	fmt.Fprintf(&b, "Incident: %s\n", inc.ID)
	fmt.Fprintf(&b, "Class: %s\n", inc.Class)
	fmt.Fprintf(&b, "Subject: %s\n", inc.Subject)
	fmt.Fprintf(&b, "Severity: %s\n", inc.Severity)
	fmt.Fprintf(&b, "First seen: %s\n", inc.Detected.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Events correlated: %d\n", inc.Events)
	if inc.Tenant != "" {
		fmt.Fprintf(&b, "Tenant: %s\n", inc.Tenant)
	}
	b.WriteString("\nSeverity here is AEGIS's own classification of observed " +
		"activity. It is not a regulatory classification: NIS2 Art. 23 and " +
		"DORA Art. 18 thresholds are decided by an operator in the incident " +
		"register, and this ticket does not make that decision.\n")
	return b.String()
}

// call performs one tracker request.
func (c *Client) call(ctx context.Context, method, endpoint string, body any, out any) error {
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Both trackers accept basic auth with a token in the password position:
	// Jira with an API token, ServiceNow with the account password or an
	// integration user's.
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(c.user+":"+c.token)))

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		// The body of a tracker error says which field it disliked, and without
		// it an operator gets "400" and no way forward. Bounded, because a
		// misrouted request can return a whole HTML page.
		snippet := make([]byte, 512)
		n, _ := resp.Body.Read(snippet)
		return fmt.Errorf("%s returned %d: %s", c.system, resp.StatusCode,
			strings.TrimSpace(string(snippet[:n])))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
