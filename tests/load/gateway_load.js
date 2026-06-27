// AEGIS gateway load & latency benchmark (k6).
//
// Measures request throughput and the latency overhead AEGIS adds in front of a
// backend. Run it twice — once against the gateway and once directly against the
// backend — to isolate the gateway's overhead. Toggle the WAF in the gateway
// config between runs to publish "WAF on" vs "WAF off" numbers.
//
// Usage:
//   k6 run -e TARGET=http://localhost:8080 tests/load/gateway_load.js
//   k6 run -e TARGET=http://localhost:3000 tests/load/gateway_load.js   # backend baseline
//
// Tunables (env):
//   TARGET   base URL to hit            (default http://localhost:8080)
//   PATH     request path               (default /api/v1/ping)
//   VUS      peak virtual users         (default 50)
//   DURATION steady-state duration      (default 30s)
//   TOKEN    Bearer token, if auth is on (default empty)
import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

const TARGET = __ENV.TARGET || 'http://localhost:8080';
const PATH = __ENV.PATH || '/api/v1/ping';
const VUS = parseInt(__ENV.VUS || '50', 10);
const DURATION = __ENV.DURATION || '30s';
const TOKEN = __ENV.TOKEN || '';

const latency = new Trend('aegis_request_latency_ms', true);

export const options = {
  scenarios: {
    steady: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: VUS },     // ramp up
        { duration: DURATION, target: VUS },   // steady state (the published number)
        { duration: '5s', target: 0 },         // ramp down
      ],
      gracefulRampDown: '5s',
    },
  },
  thresholds: {
    // Fail the run (non-zero exit) if the gateway regresses past these bounds.
    http_req_failed: ['rate<0.01'],            // <1% errors
    http_req_duration: ['p(95)<50', 'p(99)<150'], // p95<50ms, p99<150ms added latency budget
  },
};

const params = TOKEN ? { headers: { Authorization: `Bearer ${TOKEN}` } } : {};

export default function () {
  const res = http.get(`${TARGET}${PATH}`, params);
  latency.add(res.timings.duration);
  check(res, {
    'status is 2xx/3xx': (r) => r.status >= 200 && r.status < 400,
  });
}

export function handleSummary(data) {
  const p = (m) => (data.metrics[m] ? data.metrics[m].values : {});
  const dur = p('http_req_duration');
  const reqs = p('http_reqs');
  const summary =
    `\nAEGIS load summary (${TARGET}${PATH}, ${VUS} VUs)\n` +
    `  requests   : ${(reqs.count || 0).toFixed(0)} (${(reqs.rate || 0).toFixed(1)}/s)\n` +
    `  latency p50: ${(dur.med || 0).toFixed(2)} ms\n` +
    `  latency p95: ${(dur['p(95)'] || 0).toFixed(2)} ms\n` +
    `  latency p99: ${(dur['p(99)'] || 0).toFixed(2)} ms\n` +
    `  error rate : ${(((p('http_req_failed').rate) || 0) * 100).toFixed(2)} %\n`;
  return {
    stdout: summary,
    'tests/load/summary.json': JSON.stringify(data, null, 2),
  };
}
