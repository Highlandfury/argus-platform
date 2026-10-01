# PHASE-2 LOAD TEST REPORT (measured)

**These are observed Phase-2 test results under the documented test
environment. They are not production capacity guarantees.**

The canonical scenarios and thresholds are defined in
`docs/phase-1/PHASE_1_LOAD_TEST.md` (L-01/L-02/L-03) and
`docs/phase-2/PHASE_2_SPEC.md` P2-AC-12 (>= 1 h at 20k samples/s, <= 5% counted
backpressure drops; L-03 p95 <= 300 ms / p99 <= 1 s at 50 VUs with the root
cause addressed) and P2-AC-10 (measured compression ratio, no vendor numbers).
This report records the Phase-2 executions and the observed bottlenecks.
Numbers were captured from the harnesses, the server's `/metrics` histograms,
the database itself and `docker stats`; nothing below is reconstructed or
estimated. Where a measured value is missing it is omitted, never invented.

Phase-1 history is preserved unchanged in
[`docs/phase-1/LOAD_TEST_REPORT.md`](../phase-1/LOAD_TEST_REPORT.md).

## Test environment

| Property | Value |
|---|---|
| Host | Windows laptop, Intel Core i7-8665U (4C/8T) @ 1.90 GHz, 23.8 GiB RAM |
| Container runtime | Docker Desktop (Windows), engine 29.8.1, Compose v2, WSL2 |
| Topology | Single node: `server`, `collector`, `web`, PostgreSQL in one Compose project (`argus-dev`), same host; the load generator runs on the Windows host |
| Database | `timescale/timescaledb:2.30.1-pg18` @ `sha256:9dede0e3ccc071cf71935b17f76bf243331df0b1575338c8ac294640fcf12a36` (PostgreSQL 18 + TimescaleDB 2.30.1) |
| Server | one `argus-server` process (`:8080` API, `:9090` ops, `:8443`/`:8444` gRPC); ingest write path per ADR-016 (unnest + `ON CONFLICT DO NOTHING`, bounded batch pipelining, duplicate `series_ts` index dropped) |
| Metrics storage | raw `metric_samples` (RLS ENABLE+FORCE, 1-day chunks, 30 d retention) + `metric_1m/5m/1h/1d` CAGGs (materialized-only, tenant views, compression policy after 7 d); `ARGUS_SERVER_DB_MAX_CONNS=10` (default) in every run |
| Payload | synthetic `collector_cpu_percent` (unit `percent`, one dimension `{"cpu":"total"}`) |
| k6 | pinned image `grafana/k6:2.3.0` (commit `e088784614`, go1.27.1, linux/amd64), run inside the Compose network against `http://server:8080` |

## Methodology

- All harnesses talk to the real API/control plane (mTLS enrollment, gRPC
  streams, HTTP sessions). No mocks.
- Client-side numbers: harness summaries (offered/accepted, OK/duplicate/
  rejected/retry, transport errors, reconnect counts, ack latency percentiles).
- Server-side numbers: Prometheus histograms on `:9090` scraped immediately
  before and after each run; deltas are reported (so idle traffic between runs
  is excluded). Per-route latency uses `argus_http_request_duration_seconds`;
  DB time uses `argus_db_query_duration_seconds`.
- Database numbers: `pg_stat_*` deltas across a run (session row updates,
  transactions, WAL bytes), `count(*)`/`pg_database_size`, and
  `timescaledb_information.*` policy/job views.
- Container CPU/RAM: periodic `docker stats` samples.
- Raw artifacts for every run are committed under `tests/load/results/`.

---

## L-01 — single stream (M8-S2a, preserved verbatim)

10 minutes, 1 collector, batch 2,000, 20,000 samples/s offered. This is the
optimized write path (ADR-016); the full run detail is in
[`M8_EVIDENCE.md`](M8_EVIDENCE.md) §7.1.

| Metric | M8-S2a (measured) | Phase 1 (baseline) |
|---|---|---|
| Duration | 600.5 s | 604.2 s |
| Offered | 20,000 samples/s | 20,000 samples/s |
| **Achieved** | **16,869 samples/s (84.3%)** | 4,244 samples/s (21%) |
| Samples accepted | 10,129,810 (harness) / 10,129,932 (DB total) | 2,564,000 |
| Batches OK / duplicate / rejected / retry | 5,086 / 0 / 0 / 0 | 1,282 / 0 / 0 / 0 |
| Transport errors / reconnects | 0 / 0 | 0 / 0 |
| Ack latency p50 / p95 / p99 | 895 / 1,239 / 1,425 ms | 3,730 / 4,420 / 5,290 ms |
| Server CPU avg / max | 55.7% / 97.9% | 14.8% / 26.9% |
| DB CPU avg / max | **569.9% / 797.4%** | 98.4% / 121% |
| Counted backpressure drops | **0** | 0 |

Interpretation (M8-S2a, unchanged): 3.97× the Phase-1 rate; the remaining gap
to 20k is host CPU per batch growing with the table while the process-wide
batch budget is 8; the per-row `org_id` FK is the largest single per-sample
cost (ADR-016 §6.1 #4).

## L-02 — fleet (M8-S2a, preserved verbatim)

10 minutes, 200 collectors, batch 500, 20,000 samples/s offered, extended
watchdog (`-ack-timeout 60s`); full run detail in `M8_EVIDENCE.md` §7.2(b).

| Metric | Value |
|---|---|
| Duration | 636.3 s |
| **Achieved** | **14,934 samples/s** (Phase-1 parity, now clean) |
| Batches OK / dup / rejected / retry | 19,104 / 0 / 0 / 0 |
| Samples accepted | 9,502,274 (DB total 9,502,286) |
| Streams active max / avg | 201 / 146 (ramp; 0 churn) |
| Ack latency p50 / p95 / p99 | 50.6 / 77.7 / 86.6 s |
| Transport errors / reconnects | **0 / 0** |
| Server CPU avg / max | 58.6% / 255.8% |
| DB CPU avg / max | 481.9% / 803.1% |
| Counted backpressure drops / server retries | **0 / 0** |

Interpretation (M8-S2a, unchanged): 200 collectors at window-bounded max
pressure saturate this single 4C/8T host; the limiting factor is host CPU under
the synthetic harness, not the write path (per-batch SQL 218 ms for 500 rows =
0.44 ms/row, same as the single-stream run).

---

## Soak — L-01-style 20k samples/s for >= 1 h (P2-AC-12)

### Result (2026-10-01, run `soak3`)

Single stream, batch 2,000, offered 20,000 samples/s for 62 minutes against the
dev stack (generator on the host, server/DB in Docker; same conditions as L-01).

| Metric | Value |
|---|---|
| Duration | 3,720.5 s (62.0 min) - P2-AC-12 >= 1 h |
| Offered / achieved | 20,000 / **17,535.5 samples/s (87.7%)** |
| Samples accepted | **65,241,605** |
| Batches ok / duplicate / rejected / retry | 32,704 / **0 / 0 / 0** |
| Samples duplicate / transport errors / reconnects | **0 / 0 / 0** |
| Ack latency p50 / p95 / p99 | 769.6 ms / 1,315.4 ms / 1,739.9 ms |
| DB CPU (31 samples) avg / max | **632.3% / 844.3%** (~6.3 of 8 host threads) |
| Server CPU avg / max | 59.5% / 93.4% |
| Raw hypertable growth | 5.02 GB -> 16.50 GB (+11.48 GB for 65.24M samples ~= 176 B/sample, uncompressed, incl. indexes) |
| Session row updates during the run | +4 (throttled touch; the L-03 "before" run wrote +49,986) |

**Interpretation.** The run is **lossless** - zero drops, duplicates, retries,
transport errors or reconnects for 62 minutes - but it **does not reach the
literal 20k samples/s target**: 17,535.5/s = 87.7% of offered, with the offered
rate throttled by ack backpressure (0 counted drops). The DB averaged ~6.3 of
the host's 8 threads while the load generator ran on the same 4C/8T host; the
10-minute L-01 validation (16,869/s) and this run agree, placing the ceiling at
host CPU, not the pipeline. **P2-AC-12's sustained-20k target is therefore
recorded as not met on the dev reference node**, and the pilot-profile re-run
on separate server/generator hardware remains in M13. No extrapolation.

Artifacts: `soak3.json`, `soak3.log`, `soak3_monitor.csv`, `soak3_db_pre.txt` /
`soak3_db_post.txt`, `soak3_metrics_pre.txt` / `soak3_metrics_post.txt`.

## L-03 — API leg, before/after remediation (P2-AC-12)

L-03 is unchanged from Phase 1 (`tests/load/k6/api.js`): 50 VUs for 5 minutes,
`GET /v1/collectors?limit=10` + `GET /v1/collectors/{id}/metrics` for
`collector_cpu_percent` over 24 h @ 1 m (per the M8-reconciled 10k-point cap),
one `setup()` login (the session cookie is shared and sent explicitly), no
think time, thresholds `p(95) < 300 ms`, `p(99) < 1 s`,
`http_req_failed rate < 0.001`. The dev credential was taken from
`deployments/compose/.env` (not committed).

### Phase-1 baseline (2026-09-29)

62.06 req/s; 0% errors; p50 564 ms / p95 1,860 ms / p99 3,890 ms / max
12,150 ms; thresholds FAIL. Same requests idle: list 22 ms, metrics 34 ms
(host curl). DB time for the metric query: avg 11.2 ms, p95 ~50 ms. Both
routes degraded identically (~36×), so the Phase-1 conclusion was "server-side
per-request concurrency path and/or Docker Desktop networking; profile in
Phase 2".

### Root cause (measured in M8-S2b)

Reproduction before any fix (`l03_before_clean_*` artifacts): 49,987 requests,
166.2 req/s, **p95 463 ms (FAIL), p99 585 ms**, 0% errors.

Evidence chain:

1. **Database wait sampling during the run** (`pg_stat_activity`):
   eight concurrent backends parked on `Lock: transactionid` for
   `UPDATE sessions SET last_seen_at = now() WHERE id = $1`, plus
   `commit` waiting on `WalSync`.
2. **Session updates per run**: `pg_stat_user_tables.sessions.n_tup_upd`
   delta = **+49,986 for 49,987 requests** — exactly one row UPDATE (and one
   synchronous WAL commit) per authenticated request. The L-03 setup shares
   one session, so all 50 VUs serialize on one row lock; each commit holds the
   lock through the fsync.
3. **Both protected routes degrade identically** while the control endpoint
   does not: server-side histograms in the same run show
   `/v1/collectors` p50 303 / p95 491 / p99 825 ms and
   `/v1/collectors/{id}/metrics` p50 326 / p95 493 / p99 845 ms, but
   `/v1/healthz` (no session middleware) p95 **4.8 ms** at the same time.
4. **The SQL is not the problem**: `argus_db_query_duration_seconds{op="query"}`
   p50 13.3 ms / p95 24.9 ms for the 24 h metric query (same order as the
   Phase-1 11.2 ms average).
5. The load generator wrote ~123 MB of k6 JSON output on the same host while
   running; even so, a second identical run without the JSON stream (`l03_before_clean_*`)
   reproduced the failure, so the finding is not a harness artifact.

**Classification:** server-side session/auth path — an unconditional
`UPDATE sessions ... SET last_seen_at` inside the authentication middleware
serializes every request of a session on one row lock plus one WAL-flushing
commit. Not SQL/planner, not the Docker network, not the HTTP server settings.

### Fix (production code, justified by the measurements above)

`internal/modules/identity`:

- `Authenticate` resolves session + user in **one** auth transaction/query
  (`getSessionUserByTokenHash`; previously three transactions: session select,
  user select, touch update).
- `last_seen_at` is refreshed **at most once per 30 s per session**
  (`SessionTouchInterval`), in a separate best-effort transaction whose
  conditional `UPDATE ... WHERE last_seen_at < $cutoff` collapses concurrent
  touches instead of queueing them. Failed touches still do not fail requests.
- Semantics unchanged: unknown/expired/revoked sessions and disabled users are
  still rejected uniformly; the touch was already best-effort metadata.

### Before/after (identical harness, same stack, back-to-back)

| Metric | Before (fixed path absent) | After (fixed path) | Threshold |
|---|---|---|---|
| Requests / throughput | 49,987 / 166.2 req/s | **123,175 / 409.9 req/s** | — |
| HTTP failures | 0.00% | 0.00% | < 0.1% PASS |
| Avg | 299.6 ms | **120.9 ms** | — |
| p50 | 280.7 ms | **114.4 ms** | — |
| p90 | 412.0 ms | **195.9 ms** | — |
| **p95** | 463.4 ms **FAIL** | **224.7 ms PASS** | <= 300 ms |
| **p99** | 584.6 ms | **289.6 ms PASS** | <= 1 s |
| Max | 1,040 ms | 585 ms | — |
| k6 exit | 99 (thresholds crossed) | **0** | — |
| Session row updates (DB delta) | +49,986 | **+9** | — |
| WAL bytes (DB delta) | +9.9 MB | **+0.4 MB** | — |
| Server-side list p95 / metrics p95 | 491 / 493 ms | **202 / 249 ms** | — |

Phase-1 (p95 1,860 ms) → before-fix on this stack (p95 463 ms) → after-fix
(p95 225 ms): the remediation closes the canonical threshold with ~2.1× margin
on p95 and ~3.5× on p99, and throughput rises 2.5×. The remaining server-side
latency is now dominated by the metric query transaction itself
(`op=query` p50 80 ms at 410 req/s vs 13 ms in the slower before run), i.e.
the read path doing real work under load — still inside budget.

Artifacts: `l03_before_clean_*` (log, summary JSON, pre/post metrics, route
deltas, docker stats, DB counters), `l03_after_clean_*` (same), plus the
initial JSON-output run `l03_before_*`; its raw per-op dump
(`l03_before_points.json`, 126.8 MB) exceeds the repository host's 100 MB
file limit and is intentionally not committed (kept local, gitignored), and
its writer stalled at shutdown anyway - the aggregate evidence used for the
report is the clean pair).

---

## Compression ratio (P2-AC-10, measured)

Raw-table compression is **blocked by the pinned TimescaleDB + RLS**
(`columnstore cannot be used on table with row security`; RLS stays
ENABLE+FORCE) — documented in `M8_EVIDENCE.md` §5 and re-verified for this
report (`raw_compression_blocked.txt`). The four CAGGs carry the canonical
compression shape (segmentby `series_id`, orderby `bucket DESC`, after 7 d);
the policy had not fired yet on fresh chunks, so one chunk per CAGG was
**force-compressed** for measurement and measured with
`chunk_compression_stats(...)` (raw before/after bytes, no estimates):

| CAGG chunk (forced) | Rows / series | Before total bytes | After total bytes | Ratio (before/after) |
|---|---|---|---|---|
| `metric_1m` `_hyper_2_2_chunk` | 2,138 / 201 | 770,048 (table 483,328 + index 286,720) | 344,064 (table 294,912 + index 16,384 + toast 32,768) | **2.24 : 1** |
| `metric_5m` `_hyper_3_3_chunk` | 614 / 201 | 196,608 | 319,488 | **0.62 : 1 (1.61× larger)** |

Both measured on a development-scale dataset. The 1m materialization (the row
shape the platform actually relies on) compresses 2.24:1; the 5m chunk is too
small for columnstore overhead to pay off (TimescaleDB itself warned "poor
compression ratio 0.62") and no compression benefit is claimed for
materializations this small. Per-chunk ratios grow with rows/chunk; the policy
only compresses chunks older than 7 days, by which time a real fleet's CAGG
chunks hold orders of magnitude more rows. No extrapolation is presented here.

## Bottleneck analysis (Phase-2 summary)

```text
Primary observed bottleneck (write): host CPU, with the per-row org_id FK as
the largest single per-sample cost (ADR-016)
Primary observed bottleneck (read, fixed): session row-lock serialization in
the auth middleware (removed; now the metric query itself dominates, in budget)
Compression: raw blocked by RLS (platform limitation); CAGG 1m measured 2.24:1
```

- The write path is deterministic and lossless: every soak/L-0x run shows
  0 duplicate/rejected/retry samples and 0 transport errors; backpressure
  reaches the collector by stalling the stream (window-bounded), which is the
  designed behavior.
- The read path failure was an application-level lock convoy, not capacity:
  the same process served `/v1/healthz` at p95 4.8 ms while authenticated
  routes sat at ~490 ms p95.

## Limitations and explicit non-claims

- Single Windows Docker Desktop node, 4C/8T, all containers plus the host
  generator on one machine; numbers include Docker Desktop networking overhead.
- Synthetic single-metric payload; soak and L-03 exercise one to two series
  (L-01/L-02 fleet runs use 200 collectors × 1 series). Real fleets mix
  cardinalities and metric types.
- The soak's 1 h window cannot show 7-day compression policy behavior;
  compression was measured by force-compressing a chunk, and retention
  (30 d raw) did not activate in any run.
- No HA, no replication, no PgBouncer; PostgreSQL tuning is the image default.
- Percentiles not measured by a harness are omitted rather than estimated.
- **No production capacity guarantees are made.** The canonical 20k samples/s
  target is reported against the measured ceiling below; the numbers apply to
  this test environment only.

## What feeds M13

- Re-run the soak (and the fleet profile) on a host with dedicated generator
  capacity; the 24 h pilot-profile run required by P2-AC-39 remains open.
- Decide the raw-compression path (keep RLS / enforced replacement / extraction
  per ADR-004); until then P2-AC-10 is only partially satisfiable.
- Re-run L-03 after any auth-layer change (the `meta` assertion in the harness
  is unchanged) and keep the session-touch throttle thresholds pinned.
- The nightly `metrics-maintenance` job already fails loudly on policy
  drift; M12/M13 wire the ops alert on verification failure.
