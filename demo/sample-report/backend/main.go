// Command sample-backend is a deliberately flawed API for "Northwind Payments",
// an entirely fictional company, used to generate the sample findings report in
// docs/assets/. It is NOT a demo of good practice — every weakness below is
// there on purpose, because the report is only worth showing if the findings in
// it are real output from real traffic rather than hand-written prose.
//
// The flaws, all of them common in real estates:
//
//   - /api/v1/customers/{id} returns PII (email, phone, PAN) and the route in
//     front of it does not require auth — the classic "internal-only" endpoint
//     that was never actually locked down.
//   - /api/v1/orders/{id} requires auth but hands any order to any authenticated
//     caller (IDOR): the object's real owner is in the body as user_id.
//   - /internal/reports/export dumps customer records wholesale, unauthenticated,
//     because "it's on an internal path".
//
// The data is synthetic: names from a fiction generator, card numbers are the
// standard 4111… test PAN, emails are @example.com (RFC 2606 reserved).
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// customer is one synthetic record. Card/email/phone are shaped to be picked up
// by the gateway's PII classifiers (Luhn-valid PAN, RFC-2606 email domain).
type customer struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
	Card  string `json:"card_number"`
}

// order deliberately carries user_id: that is the field the gateway is told to
// read as the object's true owner (abuse.owner_fields), which turns an
// ownership guess into a confirmed finding.
type order struct {
	ID       int    `json:"id"`
	UserID   int    `json:"user_id"`
	Total    string `json:"total"`
	Customer string `json:"customer_email"`
}

var customers = map[int]customer{
	7:  {7, "Alice Renner", "alice.renner@example.com", "+31 20 555 0142", "4111111111111111"},
	9:  {9, "Bob Kessler", "bob.kessler@example.com", "+31 20 555 0198", "4012888888881881"},
	11: {11, "Clara Voss", "clara.voss@example.com", "+31 20 555 0177", "5555555555554444"},
	12: {12, "Dan Iversen", "dan.iversen@example.com", "+31 20 555 0121", "4111111111111111"},
	13: {13, "Eva Lindqvist", "eva.lindqvist@example.com", "+31 20 555 0163", "4012888888881881"},
}

var orders = map[int]order{
	1001: {1001, 7, "249.00", "alice.renner@example.com"},
	1002: {1002, 9, "89.50", "bob.kessler@example.com"},
	1003: {1003, 7, "1250.00", "alice.renner@example.com"},
	1004: {1004, 11, "17.25", "clara.voss@example.com"},
	1005: {1005, 12, "430.10", "dan.iversen@example.com"},
}

func main() {
	addr := ":19100"
	mux := http.NewServeMux()

	// PII, and the route in front of this requires no authentication.
	mux.HandleFunc("/api/v1/customers/", func(w http.ResponseWriter, r *http.Request) {
		id := lastIDSegment(r.URL.Path)
		c, ok := customers[id]
		if !ok {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		writeJSON(w, c)
	})

	// IDOR: authenticated, but never checks that the caller owns the order.
	mux.HandleFunc("/api/v1/orders/", func(w http.ResponseWriter, r *http.Request) {
		id := lastIDSegment(r.URL.Path)
		o, ok := orders[id]
		if !ok {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		writeJSON(w, o)
	})

	mux.HandleFunc("/api/v1/invoices/", func(w http.ResponseWriter, r *http.Request) {
		id := lastIDSegment(r.URL.Path)
		writeJSON(w, map[string]any{"id": id, "status": "paid", "amount": "120.00"})
	})

	mux.HandleFunc("/api/v1/payments", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"accepted": true, "reference": "PMT-88213"})
	})

	// Bulk PII dump on an "internal" path that is in fact reachable.
	mux.HandleFunc("/internal/reports/export", func(w http.ResponseWriter, r *http.Request) {
		all := make([]customer, 0, len(customers))
		for _, c := range customers {
			all = append(all, c)
		}
		writeJSON(w, map[string]any{"generated": "nightly", "records": all})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})

	log.Printf("sample-backend (fictional Northwind Payments) listening on %s", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5_000_000_000}
	log.Fatal(srv.ListenAndServe())
}

func lastIDSegment(p string) int {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	n, _ := strconv.Atoi(parts[len(parts)-1])
	return n
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(v)
	fmt.Fprint(w, string(b))
}
