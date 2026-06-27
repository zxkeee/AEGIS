package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsRetryable(t *testing.T) {
	get := httptest.NewRequest(http.MethodGet, "/", nil)
	if !isRetryable(get) {
		t.Fatal("GET with no body should be retryable")
	}
	post := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x"))
	if isRetryable(post) {
		t.Fatal("POST must not be retryable")
	}
	getBody := httptest.NewRequest(http.MethodGet, "/", strings.NewReader("payload"))
	if isRetryable(getBody) {
		t.Fatal("GET carrying a body must not be retried (body already consumed)")
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := newCircuitBreaker(3, time.Minute)
	if cb.isOpen() {
		t.Fatal("breaker should start closed")
	}
	cb.recordFailure()
	cb.recordFailure()
	if cb.isOpen() {
		t.Fatal("breaker should remain closed below threshold")
	}
	cb.recordFailure() // third failure reaches threshold
	if !cb.isOpen() {
		t.Fatal("breaker should open at threshold")
	}
}

func TestCircuitBreaker_HalfOpenAfterReset(t *testing.T) {
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.recordFailure()
	if !cb.isOpen() {
		t.Fatal("breaker should be open")
	}
	time.Sleep(20 * time.Millisecond)
	if cb.isOpen() {
		t.Fatal("breaker should be half-open (closed) after reset window")
	}
}

func TestCircuitBreaker_HalfOpenAdmitsOnlyOneProbe(t *testing.T) {
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.recordFailure()
	time.Sleep(20 * time.Millisecond)

	// First call after the reset window is the single probe — admitted.
	if cb.isOpen() {
		t.Fatal("first request after reset must be admitted as the probe")
	}
	// Every other request while the probe is in flight must stay blocked.
	if !cb.isOpen() {
		t.Fatal("concurrent requests during a half-open probe must be blocked")
	}
	// A failed probe re-arms the breaker; after the next window a new probe runs.
	cb.recordFailure()
	if !cb.isOpen() {
		t.Fatal("breaker must stay open immediately after a failed probe")
	}
	time.Sleep(20 * time.Millisecond)
	if cb.isOpen() {
		t.Fatal("a new probe should be admitted after the next reset window")
	}
}

func TestCircuitBreaker_HalfOpenProbeSuccessCloses(t *testing.T) {
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.recordFailure()
	time.Sleep(20 * time.Millisecond)
	_ = cb.isOpen()      // admit the probe
	cb.recordSuccess()   // probe succeeds
	if cb.isOpen() {
		t.Fatal("a successful probe must close the breaker for all callers")
	}
}

func TestCircuitBreaker_SuccessResets(t *testing.T) {
	cb := newCircuitBreaker(2, time.Minute)
	cb.recordFailure()
	cb.recordSuccess()
	cb.recordFailure() // would be the 2nd consecutive without the reset
	if cb.isOpen() {
		t.Fatal("a success must reset the failure count")
	}
}

func TestLoadBalancer_RoundRobin(t *testing.T) {
	ups := []*upstream{{}, {}, {}}
	lb := newLoadBalancer(ups, "round_robin")
	seen := map[*upstream]int{}
	for i := 0; i < 9; i++ {
		seen[lb.next()]++
	}
	if len(seen) != 3 {
		t.Fatalf("round-robin should hit all 3 upstreams, hit %d", len(seen))
	}
	for u, n := range seen {
		if n != 3 {
			t.Fatalf("uneven distribution: upstream %p got %d, want 3", u, n)
		}
	}
}

func TestLoadBalancer_EmptyReturnsNil(t *testing.T) {
	lb := newLoadBalancer(nil, "round_robin")
	if lb.next() != nil {
		t.Fatal("empty load balancer must return nil")
	}
}
