// What does putting AEGIS in front of an API actually cost, in milliseconds?
//
// Every earlier measurement in this directory answered a different question —
// capacity (how many req/s), behaviour under outage, enforce vs observe — and
// all of them ran k6 over Wi-Fi to a NUC. Wi-Fi jitter is tens of milliseconds;
// the gateway's own cost is expected to be a single digit. The noise was larger
// than the signal, so the one number a sales conversation needs ("plus N ms")
// could not be read off any of them.
//
// This run removes the network instead of averaging it away: client, gateway
// and upstream are all on loopback of one machine. That trades realism for
// resolution deliberately — it does NOT tell you what a user in another
// datacentre sees, and it is not a capacity benchmark. It isolates one term.
//
// TWO SCENARIOS, SEQUENTIAL, IDENTICAL LOAD. Same arrival rate, same payload,
// same process, minutes apart rather than parallel: run side by side they would
// compete for the same cores and each would measure the other's scheduling.
// The direct scenario is the control — it carries the cost of k6, loopback and
// the upstream itself, which is exactly what has to be subtracted.
import http from "k6/http";
import { check } from "k6";
import { Trend } from "k6/metrics";

const DIRECT = __ENV.DIRECT_URL;
const GATEWAY = __ENV.GATEWAY_URL;
const RATE = parseInt(__ENV.RATE || "200", 10);
const DURATION = __ENV.DURATION || "30s";

const directLatency = new Trend("aegis_direct_ms", true);
const gatewayLatency = new Trend("aegis_gateway_ms", true);

export const options = {
  discardResponseBodies: false,
  scenarios: {
    direct: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: "direct",
      // A few seconds of warm-up are discarded by starting the measured
      // scenario after the process has already been through its first
      // allocations; a cold first scenario would charge the control with
      // start-up cost that the second one never pays.
      startTime: "5s",
    },
    gateway: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: "gateway",
      startTime: __ENV.GATEWAY_START || "40s",
    },
  },
  thresholds: {
    // Not a pass/fail gate on the delta — the point of the run is to MEASURE
    // it, and a threshold on the answer would turn a measurement into a test
    // that passes by choosing its own number. These only catch a run that is
    // not measuring what it claims: errors mean the comparison is meaningless.
    "checks{scenario:direct}": ["rate>0.99"],
    "checks{scenario:gateway}": ["rate>0.99"],
  },
};

function warmup() {
  // One request outside the measured window so DNS, connection pool and the
  // upstream's own lazy initialisation are not charged to the first sample.
  http.get(DIRECT);
}

export function setup() {
  warmup();
}

export function direct() {
  const r = http.get(DIRECT);
  directLatency.add(r.timings.duration);
  check(r, { "direct 200": (res) => res.status === 200 });
}

export function gateway() {
  const r = http.get(GATEWAY);
  gatewayLatency.add(r.timings.duration);
  check(r, { "gateway 200": (res) => res.status === 200 });
}
