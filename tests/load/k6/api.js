// L-03 API load leg (docs/phase-1/PHASE_1_LOAD_TEST.md):
//   50 VUs, 5 minutes, mixed reads (collectors list + 24 h metric query),
//   p95 < 300 ms, p99 < 1 s, error rate < 0.1%.
//
// Run (from the repository root):
//   docker run --rm -i --network argus-dev_default \
//     -e BASE_URL=http://server:8080 \
//     -e K6_ORG=dev -e K6_EMAIL=admin@dev.local -e K6_PASSWORD=... \
//     grafana/k6:2.3.0 run - < tests/load/k6/api.js
//
// Authentication is performed ONCE in setup() (the session cookie is shared
// with the VUs), which also keeps the documented login rate limiter intact —
// the measured request path is only reads.
//
// Dev-only default credential: when K6_PASSWORD is unset, the documented
// development password is used. Production-like runs MUST set K6_PASSWORD.
//
// Deviation note: the canonical workload says "24 h @ 10 s step", but the
// normative query contract caps results at 2000 points (24 h @ 10 s = 8641
// points -> 422 query.points_exceeded, recorded in ACCEPTANCE_RUN M4c).
// L-03 therefore issues 24 h @ 1 m — the finest permitted 24 h resolution.
import http from "k6/http";
import { check } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://127.0.0.1:8080";
const ORG = __ENV.K6_ORG || "dev";
const EMAIL = __ENV.K6_EMAIL || "admin@dev.local";
const PASSWORD =
  __ENV.K6_PASSWORD || __ENV.ARGUS_DEV_ADMIN_PASSWORD || "dev-admin-changeme";

export const options = {
  vus: 50,
  duration: "5m",
  thresholds: {
    http_req_duration: ["p(95)<300", "p(99)<1000"],
    http_req_failed: ["rate<0.001"],
  },
};

export function setup() {
  const res = http.post(
    `${BASE_URL}/v1/auth/login`,
    JSON.stringify({ org_slug: ORG, email: EMAIL, password: PASSWORD }),
    {
      headers: { "Content-Type": "application/json" },
      tags: { op: "setup_login" },
    },
  );
  check(res, { "setup login 200": (r) => r.status === 200 });
  const cookies = res.cookies["argus_session"];
  if (!cookies || cookies.length === 0) {
    throw new Error("login did not set the argus_session cookie");
  }
  return { session: cookies[0].value };
}

// The session cookie is sent explicitly on every request: the VU cookie jar
// only carries the cookie set during setup() for the first request of each VU
// (observed in the first L-03 run: one 200 then 401s), so the harness does not
// depend on jar state across iterations.
export default function (data) {
  const params = (op) => ({
    headers: { Cookie: `argus_session=${data.session}` },
    tags: { op },
  });

  const listRes = http.get(
    `${BASE_URL}/v1/collectors?limit=10`,
    params("collectors_list"),
  );
  check(listRes, { "collectors list 200": (r) => r.status === 200 });
  let collectorId = "";
  if (listRes.status === 200) {
    const body = JSON.parse(listRes.body);
    if (body.data && body.data.length > 0) {
      collectorId = body.data[0].id;
    }
  }

  if (collectorId) {
    const to = new Date();
    const from = new Date(to.getTime() - 24 * 3600 * 1000);
    const qs =
      "metric=collector_cpu_percent" +
      `&from=${encodeURIComponent(from.toISOString())}` +
      `&to=${encodeURIComponent(to.toISOString())}` +
      "&step=1m";
    const mRes = http.get(
      `${BASE_URL}/v1/collectors/${collectorId}/metrics?${qs}`,
      params("metrics_query"),
    );
    check(mRes, { "metrics query 200": (r) => r.status === 200 });
  }
}
