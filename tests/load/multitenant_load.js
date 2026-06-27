// AEGIS multi-tenant load scenario (k6).
//
// Drives mixed-tenant traffic through the gateway so we can measure the cost
// of MT phase 2–3 isolation (per-tenant Redis prefixes + PG RLS + WHERE filter)
// against the single-tenant baseline. Each virtual user is assigned a tenant
// via the Host header (model A in ADR-001); routes carrying tenant_id (model B)
// will set the same tenant authoritatively.
//
// Usage:
//   k6 run -e TARGET=http://localhost:8080 tests/load/multitenant_load.js
//
// Compare against gateway_load.js (single-tenant) to publish the MT overhead.
// Tunables (env):
//   TARGET    base URL                           (default http://localhost:8080)
//   PATH      request path                       (default /api/v1/ping)
//   VUS       peak virtual users                 (default 50)
//   DURATION  steady-state duration              (default 30s)
//   TENANTS   comma-separated tenant ids         (default acme,globex,initech)
//   HOSTS     comma-separated hosts per tenant   (default <id>.api.example)
//   ATTACK    fraction of requests that are an attack (WAF block) (default 0.0)
//   TOKEN     bearer token (auth.enabled=true)   (default empty)
import http from 'k6/http';
import { check } from 'k6';
import { Trend, Counter, Rate } from 'k6/metrics';

const TARGET = __ENV.TARGET || 'http://localhost:8080';
const PATH = __ENV.PATH || '/api/v1/ping';
const VUS = parseInt(__ENV.VUS || '50', 10);
const DURATION = __ENV.DURATION || '30s';
const TENANTS = (__ENV.TENANTS || 'acme,globex,initech').split(',');
const HOSTS_RAW = __ENV.HOSTS || '';
const HOSTS = HOSTS_RAW
  ? HOSTS_RAW.split(',')
  : TENANTS.map((t) => `${t}.api.example`);
const ATTACK_PCT = parseFloat(__ENV.ATTACK || '0.0');
const TOKEN = __ENV.TOKEN || '';

const latency = new Trend('aegis_mt_request_latency_ms', true);
const blocked = new Counter('aegis_mt_waf_blocked');
// legit_errors is the failure rate we actually want to alarm on — attack
// requests intentionally produce 4xx and would always blow a naive threshold.
const legitErrors = new Rate('aegis_mt_legit_errors');
const perTenantLatency = TENANTS.map((id) => new Trend(`aegis_mt_latency_${id}_ms`, true));

export const options = {
  scenarios: {
    mixed_tenants: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: VUS },
        { duration: DURATION, target: VUS },
        { duration: '5s', target: 0 },
      ],
      gracefulRampDown: '5s',
    },
  },
  thresholds: {
    // Absolute budgets; the MT-vs-single-tenant comparison is a separate
    // analysis step (run both scripts, diff the p95/p99 in the summaries).
    aegis_mt_legit_errors: ['rate<0.01'],     // legit-traffic failures only
    http_req_duration: ['p(95)<60', 'p(99)<200'],
  },
};

// SQL-injection-flavoured payload for the attack channel — WAF should 403 these.
const ATTACK_QS = '?id=1%27%20OR%20%271%27%3D%271';

export default function () {
  // Stable per-VU tenant assignment so each VU exercises its tenant's state
  // (rate-limit window, behaviour score) consistently across iterations.
  const tIdx = (__VU - 1) % TENANTS.length;
  const tenant = TENANTS[tIdx];
  const host = HOSTS[tIdx];

  const isAttack = Math.random() < ATTACK_PCT;
  const url = `${TARGET}${PATH}${isAttack ? ATTACK_QS : ''}`;

  const headers = { Host: host };
  if (TOKEN) headers['Authorization'] = `Bearer ${TOKEN}`;

  const res = http.get(url, { headers });
  latency.add(res.timings.duration);
  perTenantLatency[tIdx].add(res.timings.duration);

  if (isAttack) {
    // Attack path: we expect 403 (WAF) or 429 (rate-limit). Not a real failure.
    blocked.add(1);
    check(res, { 'attack: blocked': (r) => r.status === 403 || r.status === 429 });
    return;
  }
  const ok = res.status >= 200 && res.status < 400;
  legitErrors.add(!ok);
  check(res, { 'legit: status is 2xx/3xx': () => ok });
}

export function handleSummary(data) {
  const p = (m) => (data.metrics[m] ? data.metrics[m].values : {});
  const dur = p('http_req_duration');
  const reqs = p('http_reqs');

  let perT = '';
  TENANTS.forEach((id, i) => {
    const v = p(`aegis_mt_latency_${id}_ms`);
    perT +=
      `    ${id.padEnd(10)} ` +
      `p50=${(v.med || 0).toFixed(2)}ms  ` +
      `p95=${(v['p(95)'] || 0).toFixed(2)}ms  ` +
      `p99=${(v['p(99)'] || 0).toFixed(2)}ms\n`;
  });

  const out =
    `\nAEGIS multi-tenant summary (${TARGET}${PATH}, ${VUS} VUs, ${TENANTS.length} tenants, attack=${(ATTACK_PCT * 100).toFixed(0)}%)\n` +
    `  total requests : ${(reqs.count || 0).toFixed(0)} (${(reqs.rate || 0).toFixed(1)}/s)\n` +
    `  aggregate p50  : ${(dur.med || 0).toFixed(2)} ms\n` +
    `  aggregate p95  : ${(dur['p(95)'] || 0).toFixed(2)} ms\n` +
    `  aggregate p99  : ${(dur['p(99)'] || 0).toFixed(2)} ms\n` +
    `  attack blocked : ${(p('aegis_mt_waf_blocked').count || 0).toFixed(0)}\n` +
    `  per-tenant latency:\n${perT}`;

  return {
    stdout: out,
    'tests/load/multitenant_summary.json': JSON.stringify(data, null, 2),
  };
}
