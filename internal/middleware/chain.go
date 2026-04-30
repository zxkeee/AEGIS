package middleware

import "net/http"

// Middleware is a standard HTTP middleware function.
type Middleware func(http.Handler) http.Handler

// Chain applies a series of middlewares in order.
// The first middleware in the list is the outermost (executed first).
func Chain(handler http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// passthrough is a no-op middleware used when a feature is disabled.
var passthrough Middleware = func(next http.Handler) http.Handler {
	return next
}
