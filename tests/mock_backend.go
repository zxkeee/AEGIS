package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Логгируем, что бекенд получил запрос
		fmt.Printf("[Backend] Received %s %s\n", r.Method, r.URL.Path)

		// A customer path returns personal and card data, so the stand can
		// exercise the controls that only fire on sensitive responses: DLP
		// masking, the PII counters behind the catalog, and the API3
		// "sensitive data without authentication" finding. Without a response
		// that contains any, those paths were unreachable on this stand and a
		// live check of them had to be assembled by hand every time.
		//
		// The values are obviously synthetic (4111… is the standard Visa test
		// number) and this backend is a test fixture, never shipped.
		if strings.Contains(r.URL.Path, "/customers/") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      strings.TrimPrefix(path.Base(r.URL.Path), "customers/"),
				"name":    "Alice Example",
				"email":   "alice@example.com",
				"phone":   "415-555-0142",
				"card":    "4111111111111111",
				"user_id": 7,
				"path":    r.URL.Path,
			})
			return
		}

		// An order carries an owner id, which is what object-ownership
		// (BOLA) detection compares against the verified caller.
		if strings.Contains(r.URL.Path, "/orders/") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"order_id": path.Base(r.URL.Path),
				"user_id":  7,
				"total":    "42.00",
				"path":     r.URL.Path,
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"message": "Hello from AEGIS Protected Backend!",
			"path":    r.URL.Path,
			"method":  r.Method,
		})
	})

	// Port from the environment so more than one stand can run at once, and so
	// this never collides with whatever else is on :3000 on a dev machine.
	// Defaults to :3000, which is what the older scripts and docs expect.
	addr := ":3000"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}

	srv := &http.Server{
		Addr:              addr,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		Handler:           nil, // uses DefaultServeMux
	}

	fmt.Printf("🚀 Mock Backend is listening on %s...\n", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("Backend error: %v\n", err)
	}
}
