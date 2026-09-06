package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Логгируем, что бекенд получил запрос
		fmt.Printf("[Backend] Received %s %s\n", r.Method, r.URL.Path)

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
