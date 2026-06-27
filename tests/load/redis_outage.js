import http from 'k6/http';
import { Counter } from 'k6/metrics';

// Steady, gentle arrival rate so the home-server's other services are unharmed.
// We are NOT measuring max capacity — only that latency stays BOUNDED when the
// gateway's Redis dies mid-traffic (fail-open must not turn into multi-second hangs).
export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: 50, timeUnit: '1s',
      duration: '90s',
      preAllocatedVUs: 60, maxVUs: 200,
    },
  },
  thresholds: {
    // The whole point of the fix: even during the outage, p99 must stay sane.
    http_req_duration: ['p(99)<2000'],
  },
};

const errors = new Counter('non200');

export default function () {
  const res = http.get('http://192.168.31.116:18080/get', { timeout: '10s' });
  if (res.status !== 200) errors.add(1);
}
