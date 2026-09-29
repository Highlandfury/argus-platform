# PHASE-1 LOAD TEST REPORT (measured)

**These are observed Phase-1 test results under the documented test
environment. They are not production capacity guarantees.**

The canonical scenarios and thresholds are defined in `PHASE_1_LOAD_TEST.md`.
This report records the actual executions (M4a smoke, L-01, L-02, L-03) and the
single observed architectural bottleneck. Numbers were captured from the
harness summaries, the server's `/metrics` histograms and the database itself;
nothing below is reconstructed or estimated.

## Test environment

| Property | Value |
|---|---|
| Host | Windows laptop, Intel Core i7-8665U @ 1.90 GHz, 23.8 GiB RAM |
| Container runtime | Docker Desktop (Windows), client/server/engine 29.8.1, Compose v2 |
| Topology | Single node: `server`, `collector`, `web`, PostgreSQL all in one Compose project (`argus-dev`), same host |
| Database | `timescale/timescaledb:2.30.1-pg18` @ `sha256:9dede0e3ccc071cf71935b17f76bf243331df0b1575338c8ac294640fcf12a36` (PostgreSQL 18 + TimescaleDB 2.30.1) |
| Server | one `argus-server` process (`:8080` API, `:9090` ops, `:8443`/`:8444` gRPC) |
| Replication / HA | none (Phase-1 dev topology); no compression, no retention, no continuous aggregates |
| Payload | synthetic `collector_cpu_percent` (unit `percent`, one dimension `{"cpu":"total"}`) |

## M4a smoke baseline (2026-09-29)

Single stream, batch 2,000, 4,000 samples/s offered, 20 s.

| Metric | Value |
|---|---|
| Offered | 4,000 samples/s |
| Achieved | **3,919 samples/s (98%)** |
| Batches OK / samples accepted | 40 / 80,000 ; duplicates 0, rejected 0 |
| Ack latency (send → BatchResult) | p50 284 ms, p95 415 ms |
| Errors / reconnects | 0 / 0 |
| Server CPU | not sampled in this smoke; DB round-trips ~200 ms/batch avg |

## L-01 — single-stream ceiling (2026-09-29)

One collector, batch 2,000, 20,000 samples/s offered, 10 min (604.2 s).

| Metric | Value |
|---|---|
| Offered | 20,000 samples/s |
| Achieved | **4,244 samples/s (21%)** |
| Samples accepted | 2,564,000 (1,282 batches; 0 duplicates, 0 rejected, 0 retry) |
| Transport errors / reconnects | 0 / 0 |
| Ack latency p50 / p95 / p99 | 3.73 s / 4.42 s / 5.29 s (window saturated — the collector stalls rather than drops) |
| Server CPU avg / max | 14.8% / 26.9% |
| Database CPU avg / max | **98.4% / 121%** |
| Avg commit per 2,000-sample batch | **435.5 ms** (server histogram, run window) |
| DB growth | 18 MB → 579 MB; 2.64 M samples |
| L-01 pass criteria (commit p95 ≤ 150 ms, ≥ 20k/s) | **not met — honest failure** |

## L-02 — realistic fleet (2026-09-29)

200 collectors × 100 samples/s (batch 500 every 5 s), 10 min (654.6 s). Fleet
enrollment ran with the documented load override
(`docker-compose.load.yml`, enroll rate 1200/min; the default 10/min/IP limiter
is unchanged and covered by S-01).

| Metric | Value |
|---|---|
| Enrollment | 200 collectors in 29.2 s |
| Streams active | max 201 (sampler; avg 184 including ramp-up) |
| Offered | 20,000 samples/s |
| Achieved | **14,934 samples/s (75%)** |
| Batches OK / samples accepted | 19,554 / 9,775,470 (0 duplicates, 0 rejected, 0 retry) |
| Transport errors / reconnects | 0 / 0 |
| Ack latency p50 / p95 / p99 | 50.1 s / 56.6 s / 58.7 s (deep queueing under sustained overcommit; window backpressure) |
| Server CPU avg / max | 71.1% / 170.5% |
| Database CPU avg / max | **642% / 790%** |
| DB growth | 2.59 GB; 12.42 M total samples |
| L-02 pass criteria (≥ 19k/s, ack p95 ≤ 1 s) | **not met — honest failure**; stream/error/reconnect criteria met |

**Post-load integrity:** all counters consistent; zero drops, zero corruption,
zero dead-letters across both runs.

## L-03 — API leg (k6), executed 2026-09-29 (M6a)

**Harness:** `tests/load/k6/api.js`, k6 `v2.3.0` (commit `e088784614`,
go1.27.1, linux/amd64) from the pinned image `grafana/k6:2.3.0`, run inside the
Compose network against the real API (`http://server:8080`). One login in
`setup()` (session cookie reused; the login rate limiter stays intact);
workload = `GET /v1/collectors?limit=10` + `GET /v1/collectors/{id}/metrics`
for `collector_cpu_percent` over **24 h @ 1 m** (the finest permitted 24 h
resolution under the normative 2000-point cap; 24 h @ 10 s is a documented 422).

**Configuration:** 50 VUs, 5 m duration, no think time, thresholds
`p(95) < 300 ms`, `p(99) < 1 s`, `http_req_failed rate < 0.001`.

| Metric | Value |
|---|---|
| VUs / duration | 50 / 5 m 04 s |
| Requests / throughput | 18,875 HTTP requests, 62.06 req/s; 9,437 iterations |
| Checks | 100% succeeded (`collectors list 200`, `metrics query 200`) |
| HTTP failures | **0.00%** (error threshold PASS) |
| Latency p50 / p95 / p99 / max | **564 ms / 1,860 ms / 3,890 ms / 12,150 ms** |
| Thresholds | **FAIL** — `p(95)<300` ✗, `p(99)<1000` ✗; `http_req_failed` ✓ |
| VU utilisation | k6 `vus` min 6 / max 50 (VUs mostly blocked on slow responses) |

**Execution note (harness bug, fixed):** the first attempt shared the
`setup()` cookie via the k6 VU cookie jar; the jar delivered it only for each
VU's first request, producing 1,533,122 fast `401`s (one 200 per VU). The
script now sends the session cookie explicitly on every request. The 401 run
is recorded here only as a harness lesson — the measured L-03 run is the one
above.

### Analysis of the L-03 failure (evidence-based, no fabrication)

| Observation | Value | Source |
|---|---|---|
| Idle latency, same requests | list 22 ms, metrics 34 ms | host curl |
| Under 50 VUs | list p50 551 ms / p95 1,803 ms; metrics p50 567 ms / p95 1,901 ms | server access-log histogram |
| DB time for the whole metric query | avg 11.2 ms, p95 ≈ 50 ms (9,492 queries) | `argus_db_query_duration_seconds{op="query"}` |
| DB CPU while idle after run | 22.8%; server 0.48% | `docker stats` |
| Degradation factor | ~36× vs idle, **identical on both routes** | access logs |

Conclusion recorded for Phase 2: the L-03 failure is **not a SQL/planner
problem** (DB-side query time is ~11 ms avg / ~50 ms p95 throughout). Both
routes degrade identically only under concurrency, so the bottleneck is in the
server-side per-request concurrency path (session/auth middleware, shared
connection pools, request handling) and/or the Windows Docker Desktop container
networking under 50 concurrent keep-alive connections. Distinguishing these
requires profiling (CPU profile + pool wait metrics); per the M6a rule, no
production code was changed to chase the number. Candidate Phase-2 work:
instrument pool wait time, review session-lookup caching, and re-measure on a
native Linux host.

## Observed bottleneck (Phase-1 summary)

```text
Primary observed bottleneck:
PostgreSQL write path
```

Confirmed by L-01 (DB CPU 98–121% while server CPU stayed < 27%; 435 ms average
commit per 2,000-sample batch) and L-02 (DB CPU 642–790% vs server 71%). The
secondary L-03 finding above (read API under 50-VU concurrency) is separate and
recorded with its evidence.

## Methodology and limitations

- **Method:** harnesses use the real control plane/API (mTLS enrollment,
  streams, HTTP sessions); server-side numbers come from Prometheus histograms
  and SQL; container CPU/RAM from periodic `docker stats` samples; DB sizes
  from `hypertable_size`.
- **Limitations:** single Windows Docker Desktop node, no HA, uncompressed
  hypertable, synthetic single-dimension payload, 10-minute runs (no soak),
  small read dataset for L-03 (fresh stack), one host CPU generation. Percentiles
  not measured by a harness are omitted rather than estimated.
- **Failure conditions:** both ingest runs completed with zero errors,
  duplicates, rejects or reconnects; the acknowledged rates were limited by
  end-to-end backpressure, not by loss.
- **Interpretation:** the architecture direction is viable at the observed
  rates; the write-path ceiling (~4.2k samples/s single stream, ~14.9k/s across
  200 streams) is a Phase-1 implementation limit, and the L-03 read API fails
  the canonical latency targets at 50 VUs under the measured conditions. Both
  feed Phase-2 planning; no claims of 20k samples/s or production read scale
  are made.
