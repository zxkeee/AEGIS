package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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

	srv := &http.Server{
		Addr:              ":3000",
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		Handler:           nil, // uses DefaultServeMux
	}

	fmt.Println("🚀 Mock Backend is listening on port :3000...")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("Backend error: %v\n", err)
	}
}
