// loadgen — gentle constant-rate load generator with a mid-run Redis outage.
// Runs ON the home-server (localhost), so it needs no firewall changes and its
// own CPU cost at 50 rps is negligible. It orchestrates the outage itself via
// `docker stop/start` so the timing lines up exactly with the latency buckets.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os/exec"
	"sort"
	"sync"
	"time"
)

type sample struct {
	elapsed time.Duration
	latency time.Duration
	ok      bool
}

func main() {
	url := flag.String("url", "http://127.0.0.1:18080/get", "target")
	rate := flag.Int("rate", 50, "requests per second")
	dur := flag.Int("dur", 90, "duration seconds")
	container := flag.String("redis", "aegis-lt-redis", "redis container to stop/start")
	outStart := flag.Int("outage_start", 45, "seconds into run to stop redis")
	outEnd := flag.Int("outage_end", 65, "seconds into run to start redis")
	flag.Parse()

	client := &http.Client{Timeout: 10 * time.Second}
	var mu sync.Mutex
	var samples []sample
	var wg sync.WaitGroup

	start := time.Now()
	// Outage orchestration.
	go func() {
		time.Sleep(time.Duration(*outStart) * time.Second)
		_ = exec.Command("docker", "stop", *container).Run() // #nosec G204 -- load-test tool; container is an operator-supplied flag
		fmt.Printf("[t=%ds] redis STOPPED\n", *outStart)
	}()
	go func() {
		time.Sleep(time.Duration(*outEnd) * time.Second)
		_ = exec.Command("docker", "start", *container).Run() // #nosec G204 -- load-test tool; container is an operator-supplied flag
		fmt.Printf("[t=%ds] redis STARTED\n", *outEnd)
	}()

	ticker := time.NewTicker(time.Second / time.Duration(*rate))
	defer ticker.Stop()
	deadline := start.Add(time.Duration(*dur) * time.Second)
	for now := range ticker.C {
		if now.After(deadline) {
			break
		}
		elapsed := now.Sub(start)
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			resp, err := client.Get(*url)
			lat := time.Since(t0)
			ok := err == nil && resp != nil && resp.StatusCode == 200
			if resp != nil {
				_ = resp.Body.Close()
			}
			mu.Lock()
			samples = append(samples, sample{elapsed, lat, ok})
			mu.Unlock()
		}()
	}
	wg.Wait()

	report("PRE   (0-45s, redis up)", samples, func(e float64) bool { return e < float64(*outStart) })
	report("OUTAGE(45-65s, redis DOWN)", samples, func(e float64) bool { return e >= float64(*outStart) && e < float64(*outEnd) })
	report("RECOV (65-90s, redis up)", samples, func(e float64) bool { return e >= float64(*outEnd) })
}

func report(label string, all []sample, in func(float64) bool) {
	var lats []time.Duration
	ok := 0
	for _, s := range all {
		if !in(s.elapsed.Seconds()) {
			continue
		}
		lats = append(lats, s.latency)
		if s.ok {
			ok++
		}
	}
	n := len(lats)
	if n == 0 {
		fmt.Printf("%-28s no samples\n", label)
		return
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	pct := func(p float64) time.Duration { return lats[int(float64(n-1)*p)] }
	fmt.Printf("%-28s n=%-4d ok=%5.1f%%  p50=%-7v p95=%-7v p99=%-7v max=%-7v\n",
		label, n, 100*float64(ok)/float64(n),
		pct(0.50).Round(time.Millisecond), pct(0.95).Round(time.Millisecond),
		pct(0.99).Round(time.Millisecond), pct(1.0).Round(time.Millisecond))
}
