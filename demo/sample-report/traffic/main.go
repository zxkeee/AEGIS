// Command traffic drives realistic load through the sample stand.
//
// Written in Go rather than a shell loop because the report needs thousands of
// requests to look like an estate rather than a demo, and a few thousand curl
// processes take minutes. It also lets each consumer keep its own identity and
// behaviour profile, which is what makes the consumer graph in the report worth
// looking at.
//
// The shape of the traffic is deliberately mundane. Almost all of it is
// ordinary business use; the problems are a small minority of requests, which
// is exactly why they are hard to notice without something watching for them.
package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type consumer struct {
	name  string
	token string // empty = anonymous
	uid   int    // resource-owner id carried in the token's uid claim; 0 = anonymous
	// weight is the share of ordinary traffic this consumer generates.
	weight int
}

// ownOrder returns an order id that genuinely belongs to uid, mirroring the
// backend's ownership rule (order i is owned by (i%40)+1). Ordinary users
// reading their OWN orders is what makes the one job that reads other people's
// stand out — if everybody reads everybody's data, "confirmed IDOR" stops
// meaning anything and the report is just noise.
func ownOrder(uid int, k int) int {
	if uid <= 0 || uid > 40 {
		uid = 1
	}
	// backend rule: order i is owned by (i%40)+1, so i must be ≡ uid-1 (mod 40).
	return 1000 + (uid - 1) + 40*k
}

var (
	gw      = flag.String("gw", "http://127.0.0.1:19080", "gateway data plane")
	tokens  = flag.String("tokens", "", "name=jwt pairs, comma separated; a name with no '=' is anonymous")
	total   = flag.Int("n", 2400, "approximate number of ordinary requests")
	workers = flag.Int("workers", 24, "concurrent workers")
)

// endpoint is one weighted entry in the ordinary-traffic mix.
type endpoint struct {
	method, path string
	weight       int
	auth         bool
}

// ordinary endpoints, weighted roughly like a real product: reads dominate.
var ordinary = []endpoint{
	{"GET", "/api/v1/products", 14, false},
	{"GET", "/api/v1/products/%d", 12, false},
	{"GET", "/api/v1/orders/%d", 11, true},
	{"GET", "/api/v1/orders", 7, true},
	{"GET", "/api/v1/invoices/%d", 7, true},
	{"GET", "/api/v1/invoices", 5, true},
	{"POST", "/api/v1/payments", 6, true},
	{"GET", "/api/v1/payments/%d", 4, true},
	{"GET", "/api/v1/shipments/%d", 6, true},
	{"GET", "/api/v1/subscriptions/%d", 4, true},
	{"GET", "/api/v1/refunds/%d", 3, true},
	{"POST", "/api/v1/refunds", 2, true},
	{"GET", "/api/v1/webhooks", 2, true},
	{"GET", "/api/v2/orders/%d", 5, true},
	{"GET", "/api/v2/products", 4, true},
	{"POST", "/api/v2/checkout", 3, true},
	{"GET", "/health", 5, false},
}

func main() {
	flag.Parse()
	cs := parseConsumers(*tokens)
	if len(cs) == 0 {
		fmt.Fprintln(os.Stderr, "no consumers given")
		os.Exit(2)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var sent, failed atomic.Int64

	do := func(method, path, token string) {
		var body io.Reader
		if method == "POST" {
			body = strings.NewReader(`{"amount":"25.00"}`)
		}
		req, err := http.NewRequest(method, *gw+path, body)
		if err != nil {
			failed.Add(1)
			return
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			failed.Add(1)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		sent.Add(1)
	}

	// ── 1. Ordinary business traffic ─────────────────────────────────────────
	jobs := make(chan func(), 256)
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				f()
			}
		}()
	}

	// Fixed seed so the sample report is reproducible: two runs of the generator
	// must produce the same traffic mix, or a change in the numbers cannot be
	// read as a change in the product. Nothing here is a secret or a token —
	// this only decides which fictional consumer calls which fictional endpoint.
	rng := rand.New(rand.NewSource(7)) // #nosec G404 -- deterministic demo traffic, not security-relevant
	pickConsumer := weightedConsumer(cs, rng)
	pickEndpoint := weightedEndpoint(rng)

	for i := 0; i < *total; i++ {
		c := pickConsumer()
		e := pickEndpoint()
		path := e.path
		if strings.Contains(path, "%d") {
			switch {
			case strings.Contains(path, "orders"):
				// Own orders, not random ones: see ownOrder.
				path = fmt.Sprintf(path, ownOrder(c.uid, rng.Intn(9)))
			default:
				path = fmt.Sprintf(path, 1+rng.Intn(300))
			}
		}
		tok := c.token
		if !e.auth {
			// Public endpoints: most callers still hold a session, some don't.
			if rng.Intn(3) == 0 {
				tok = ""
			}
		} else if tok == "" {
			// An anonymous consumer cannot use an authenticated endpoint; send
			// it somewhere it legitimately can.
			path, tok = "/api/v1/products", ""
		}
		m, p, t := e.method, path, tok
		jobs <- func() { do(m, p, t) }
	}

	// ── 2. The problems, a small minority of the traffic ─────────────────────
	// The unlocked customer endpoint, read by a partner integration with no
	// credential at all — the single highest-value finding in the report.
	for i := 0; i < 60; i++ {
		id := 1 + rng.Intn(300)
		jobs <- func() { do("GET", fmt.Sprintf("/api/v1/customers/%d", id), "") }
	}
	for i := 0; i < 18; i++ {
		id := 1 + rng.Intn(300)
		jobs <- func() { do("GET", fmt.Sprintf("/api/v1/customers/%d/cards", id), "") }
	}
	// The nightly "internal" export, also reachable without a credential.
	for i := 0; i < 12; i++ {
		jobs <- func() { do("GET", "/internal/reports/export", "") }
	}
	for i := 0; i < 20; i++ {
		jobs <- func() { do("GET", "/internal/jobs/status", "") }
		jobs <- func() { do("GET", "/internal/metrics", "") }
	}

	// The partner API: PII, no auth enforced by config — but every real caller
	// does present a token. That is a latent exposure, not a confirmed one, and
	// the report should say so rather than overstating it.
	partner := tokenOf(cs, "partner-integration")
	for i := 0; i < 45; i++ {
		id := 1 + rng.Intn(300)
		jobs <- func() { do("GET", fmt.Sprintf("/api/partner/v1/customers/%d", id), partner) }
	}
	for i := 0; i < 10; i++ {
		jobs <- func() { do("GET", "/api/partner/v1/settlements", partner) }
	}

	// A support engineer holding only the "user" role reaching the admin
	// surface. The backend does not check roles, so nothing else would notice.
	support := tokenOf(cs, "support-tools")
	for _, p := range []string{"/api/v1/admin/users", "/api/v1/admin/settings", "/api/v1/admin/refunds/approve"} {
		p := p
		for i := 0; i < 6; i++ {
			jobs <- func() { do("GET", p, support) }
		}
	}

	// One authenticated user walking order ids that are not theirs: first a
	// single wrong object (no volume signature at all), then a sweep.
	// Kept deliberately modest: the point is that a handful of cross-owner reads
	// is enough to be caught, and a larger sweep would push every other security
	// event out of the 100-entry window GET /api/block-log returns.
	analytics := tokenOf(cs, "analytics-batch")
	jobs <- func() { do("GET", "/api/v1/orders/1001", analytics) }
	for i := 0; i < 35; i++ {
		id := 1002 + i
		jobs <- func() { do("GET", fmt.Sprintf("/api/v1/orders/%d", id), analytics) }
	}

	close(jobs)
	wg.Wait()
	fmt.Printf("  %d requests sent, %d failed\n", sent.Load(), failed.Load())
}

func parseConsumers(s string) []consumer {
	var out []consumer
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, rest, found := strings.Cut(part, "=")
		c := consumer{name: name, weight: 1}
		if found {
			// "<name>=<uid>:<jwt>" — the uid lets ordinary traffic address the
			// consumer's own objects.
			uidStr, tok, hasUID := strings.Cut(rest, ":")
			if hasUID {
				c.uid, _ = strconv.Atoi(uidStr)
				c.token = tok
			} else {
				c.token = rest
			}
			c.weight = 3 // signed-in consumers are busier than drive-by anonymous ones
		}
		out = append(out, c)
	}
	return out
}

func tokenOf(cs []consumer, name string) string {
	for _, c := range cs {
		if c.name == name {
			return c.token
		}
	}
	return ""
}

func weightedConsumer(cs []consumer, rng *rand.Rand) func() consumer {
	var pool []consumer
	for _, c := range cs {
		for i := 0; i < c.weight; i++ {
			pool = append(pool, c)
		}
	}
	return func() consumer { return pool[rng.Intn(len(pool))] }
}

func weightedEndpoint(rng *rand.Rand) func() endpoint {
	var pool []endpoint
	for _, e := range ordinary {
		for i := 0; i < e.weight; i++ {
			pool = append(pool, e)
		}
	}
	return func() endpoint { return pool[rng.Intn(len(pool))] }
}
