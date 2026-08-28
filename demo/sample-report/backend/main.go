// Command sample-backend is a deliberately flawed API for "Northwind Payments",
// an entirely fictional company, used to generate the sample findings report in
// docs/assets/. It is NOT a demo of good practice — every weakness below is
// there on purpose, because the report is only worth showing if the findings in
// it are real output from real traffic rather than hand-written prose.
//
// It is deliberately estate-shaped rather than minimal: a v1 that grew, a v2
// migration that is half-done, a partner API, an admin surface and an "internal"
// namespace that is in fact reachable. A five-endpoint toy produces a report a
// CISO reads as a lab demo, not as a picture of their own systems.
//
// The planted flaws, all of them ordinary in real estates:
//
//   - /api/v1/customers/{id} and /internal/reports/export return PII (email,
//     phone, PAN) and the routes in front of them require nothing — the
//     "internal-only" endpoints that were never actually locked down.
//   - /api/v1/orders/{id} requires auth but hands any order to any authenticated
//     caller (IDOR): the object's real owner is in the body as user_id.
//   - /api/partner/v1/customers/{id} returns PII and its route does not enforce
//     auth either, but every real caller happens to send a token — a latent
//     exposure one unauthenticated request away.
//   - /api/v1/admin/* is a privileged surface that does not check roles itself.
//   - Several endpoints exist in production but not in the OpenAPI spec shipped
//     alongside (openapi.yaml) — ordinary spec drift.
//
// Data is synthetic throughout: RFC 2606 example.com addresses and the standard
// test card numbers.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type customer struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
	Card  string `json:"card_number"`
}

// order carries user_id: the field the gateway is told to read as the object's
// true owner (abuse.owner_fields), turning an ownership guess into a confirmed
// finding.
type order struct {
	ID       int    `json:"id"`
	UserID   int    `json:"user_id"`
	Total    string `json:"total"`
	Customer string `json:"customer_email"`
}

var firstNames = []string{"Alice", "Bob", "Clara", "Dan", "Eva", "Felix", "Greta", "Hugo",
	"Ines", "Jonas", "Karin", "Lars", "Maja", "Nils", "Olga", "Piet"}
var lastNames = []string{"Renner", "Kessler", "Voss", "Iversen", "Lindqvist", "Brandt",
	"Haas", "Moritz", "Novak", "Persson", "Roth", "Sandberg"}
var cards = []string{"4111111111111111", "4012888888881881", "5555555555554444", "5105105105105100"}

var customers = map[int]customer{}
var orders = map[int]order{}

func init() {
	// A few hundred records so object ids in traffic resolve rather than 404 —
	// a 404 is skipped by discovery and would quietly shrink the catalog.
	for i := 1; i <= 400; i++ {
		fn := firstNames[i%len(firstNames)]
		ln := lastNames[(i*7)%len(lastNames)]
		customers[i] = customer{
			ID:    i,
			Name:  fn + " " + ln,
			Email: strings.ToLower(fn+"."+ln) + "@example.com",
			Phone: fmt.Sprintf("+31 20 555 %04d", 1000+i),
			Card:  cards[i%len(cards)],
		}
	}
	for i := 1001; i <= 1400; i++ {
		owner := (i % 40) + 1
		c := customers[owner]
		orders[i] = order{ID: i, UserID: owner,
			Total: fmt.Sprintf("%d.%02d", 20+(i%900), i%100), Customer: c.Email}
	}
}

func main() {
	addr := ":19100"
	mux := http.NewServeMux()

	// ── Customer-facing v1 ───────────────────────────────────────────────────
	// PII, and the route in front of this requires no authentication.
	mux.HandleFunc("/api/v1/customers/", func(w http.ResponseWriter, r *http.Request) {
		seg := pathSegments(r.URL.Path)
		// /api/v1/customers/{id}/cards — also PII
		if len(seg) >= 6 && seg[5] == "cards" {
			c, ok := customers[atoi(seg[4])]
			if !ok {
				notFound(w)
				return
			}
			writeJSON(w, map[string]any{"customer_id": c.ID, "cards": []map[string]string{
				{"brand": "visa", "number": c.Card, "exp": "11/29"}}})
			return
		}
		c, ok := customers[atoi(lastSeg(r.URL.Path))]
		if !ok {
			notFound(w)
			return
		}
		writeJSON(w, c)
	})

	// IDOR: authenticated, but never checks that the caller owns the order.
	mux.HandleFunc("/api/v1/orders/", func(w http.ResponseWriter, r *http.Request) {
		o, ok := orders[atoi(lastSeg(r.URL.Path))]
		if !ok {
			notFound(w)
			return
		}
		writeJSON(w, o)
	})
	mux.HandleFunc("/api/v1/orders", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"count": 20, "page": 1})
	})

	mux.HandleFunc("/api/v1/invoices/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": lastSeg(r.URL.Path), "status": "paid", "amount": "120.00"})
	})
	mux.HandleFunc("/api/v1/invoices", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"count": 14})
	})
	mux.HandleFunc("/api/v1/payments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"accepted": true, "reference": "PMT-88213"})
	})
	mux.HandleFunc("/api/v1/payments/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": lastSeg(r.URL.Path), "state": "settled"})
	})
	mux.HandleFunc("/api/v1/refunds", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"accepted": true})
	})
	mux.HandleFunc("/api/v1/refunds/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": lastSeg(r.URL.Path), "state": "pending"})
	})
	mux.HandleFunc("/api/v1/products", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"count": 88})
	})
	mux.HandleFunc("/api/v1/products/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": lastSeg(r.URL.Path), "name": "Widget", "price": "19.00"})
	})
	mux.HandleFunc("/api/v1/shipments/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": lastSeg(r.URL.Path), "carrier": "PostNL", "state": "in_transit"})
	})
	mux.HandleFunc("/api/v1/subscriptions/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": lastSeg(r.URL.Path), "plan": "pro", "renews": "2027-01-01"})
	})
	mux.HandleFunc("/api/v1/webhooks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"registered": 3})
	})

	// ── Half-finished v2 migration ───────────────────────────────────────────
	mux.HandleFunc("/api/v2/orders/", func(w http.ResponseWriter, r *http.Request) {
		o, ok := orders[atoi(lastSeg(r.URL.Path))]
		if !ok {
			notFound(w)
			return
		}
		writeJSON(w, o)
	})
	mux.HandleFunc("/api/v2/products", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"count": 88, "schema": "v2"})
	})
	mux.HandleFunc("/api/v2/checkout", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"session": "chk_8812"})
	})

	// ── Partner API: PII, and its route does not enforce auth ────────────────
	mux.HandleFunc("/api/partner/v1/customers/", func(w http.ResponseWriter, r *http.Request) {
		c, ok := customers[atoi(lastSeg(r.URL.Path))]
		if !ok {
			notFound(w)
			return
		}
		writeJSON(w, c)
	})
	mux.HandleFunc("/api/partner/v1/settlements", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"period": "2026-08", "total": "184220.00"})
	})

	// ── Privileged surface that does not check roles itself ──────────────────
	mux.HandleFunc("/api/v1/admin/users", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"users": 42})
	})
	mux.HandleFunc("/api/v1/admin/settings", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"maintenance": false})
	})
	mux.HandleFunc("/api/v1/admin/refunds/approve", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"approved": true})
	})

	// ── "Internal" namespace that is in fact reachable ───────────────────────
	mux.HandleFunc("/internal/reports/export", func(w http.ResponseWriter, _ *http.Request) {
		all := make([]customer, 0, 25)
		for i := 1; i <= 25; i++ {
			all = append(all, customers[i])
		}
		writeJSON(w, map[string]any{"generated": "nightly", "records": all})
	})
	mux.HandleFunc("/internal/jobs/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"queued": 4, "running": 1})
	})
	mux.HandleFunc("/internal/metrics", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"rps": 137})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})

	log.Printf("sample-backend (fictional Northwind Payments) listening on %s", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5_000_000_000}
	log.Fatal(srv.ListenAndServe())
}

func pathSegments(p string) []string { return strings.Split(p, "/") }
func lastSeg(p string) string {
	s := strings.Split(strings.Trim(p, "/"), "/")
	return s[len(s)-1]
}
func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func notFound(w http.ResponseWriter) {
	http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(v)
	_, _ = w.Write(b) // a broken client connection is not this stand's problem
}
