package middleware

import (
	"net/http"
	"strings"
)

// CleanHeaders is a security middleware that drops any incoming headers
// starting with "X-Gateway-". This prevents clients from spoofing internal
// identity or role headers before they reach the gateway's auth logic.
func CleanHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Iterate over headers and remove any starting with X-Gateway- (case-insensitive)
			for headerName := range r.Header {
				if strings.HasPrefix(strings.ToLower(headerName), "x-gateway-") {
					r.Header.Del(headerName)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
