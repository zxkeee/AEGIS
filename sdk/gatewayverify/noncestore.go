package gatewayverify

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// MemoryNonceStore is an in-process NonceStore with time-based expiry. It is
// suitable for a single backend instance. For a horizontally scaled fleet,
// implement NonceStore over a shared store (e.g. Redis SETNX with TTL) so a
// replay cannot be routed to a different instance that has not seen the nonce.
type MemoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time // nonce -> expiry
	last time.Time            // last sweep
}

// NewMemoryNonceStore returns an empty in-memory nonce store.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{seen: make(map[string]time.Time)}
}

// SeenBefore records nonce with the given TTL and reports whether it had
// already been recorded (and not yet expired).
func (m *MemoryNonceStore) SeenBefore(nonce string, ttl time.Duration) bool {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	// Opportunistic sweep at most once per second to bound memory.
	if now.Sub(m.last) > time.Second {
		for k, exp := range m.seen {
			if now.After(exp) {
				delete(m.seen, k)
			}
		}
		m.last = now
	}

	if exp, ok := m.seen[nonce]; ok && now.Before(exp) {
		return true
	}
	m.seen[nonce] = now.Add(ttl)
	return false
}

// contextWithIdentity returns a copy of r's context carrying id.
func contextWithIdentity(r *http.Request, id Identity) context.Context {
	return context.WithValue(r.Context(), identityContextKey{}, id)
}
