# M8-EVIDENCE — Metrics pipeline completion

**Status: M8 COMPLETE - gate signed off by user 2026-10-01 (M8-S2b recorded here).** This record covers **M8-S1**
(storage completion: CAGGs/refresh/compression/retention, query resolution
picker + caps, cardinality guards/retirement, verification + tests + evidence),
**M8-S2a** (ADR-016 ingest write-path decision + optimization, correctness tests
under concurrency, 10-minute L-01/L-02 validation runs) and **M8-S2b** (L-03
concurrency remediation with measured root cause, the >= 1 h soak, the measured
CAGG compression ratio and the Phase-2 load report). No M9/M10/alerts work was
done. P2-AC-12 is met on L-03 and reported honestly on the soak (§7.3); P2-AC-10
remains partially blocked on raw compression by the platform RLS constraint
(§5) and is measured on the CAGGs. Deferrals are listed in §10.

References: `PHASE_2_SPEC.md` P2-AC-07..11/13, M8 deliverables; canonical
docs/08 §13.1-13.6 (CAGGs, aggregation policy, picker, cardinality), docs/11
§20.3-20.4/§21.1-21.4 (DDL, refresh policy, compression, retention, series
lifecycle), docs/12 §22.8 (query API caps, `meta`), docs/17 §33/§35 (retention
matrix, verification); `docs/phase-1/PHASE_1_LOAD_TEST.md` (L-01/L-02 canonical
definitions) and `docs/phase-1/LOAD_TEST_REPORT.md` (Phase-1 baselines:
L-01 4,244 samples/s, L-02 14,934 samples/s).

---

## 1. Storage shape and exact policy values

Migration `000012_metrics_rollups` creates the CAGGs, tenant views, refresh
policies and compression; `000013_metrics_lifecycle` adds retention, quarantine
columns and the device-series identity index. All values verified against
`timescaledb_information.*` by `metrics.VerifyPolicies` and the integration
suite.

| CAGG | Source | Aggregation columns | `start_offset` | `end_offset` | `schedule_interval` |
|---|---|---|---|---|---|
| `metric_1m` | `metric_samples` | avg, max, min, sum, n, tw_avg | 7 d | 2 min | 1 min |
| `metric_5m` | `metric_1m` | avg, max, min, sum, n, tw_avg | 30 d | 10 min | 5 min |
| `metric_1h` | `metric_5m` | avg, max, min, sum, n, tw_avg | 90 d | 2 h | 1 h |
| `metric_1d` | `metric_1h` | avg, max, min, sum, n, tw_avg | 13 mo | 2 d | 1 h |

- The 1m row is canonical (docs/11 §21.2). The coarser rows are **documented
  choices** (canonical is silent): `end_offset = 2 × bucket` and
  `schedule = bucket` (1d refreshes hourly), with `start_offset` set to the
  upstream retention horizon so late corrections inside the retained window are
  picked up. This also guarantees the rollup is never more than one schedule
  behind its own watermark; the 1m guarantee is ≤ 2 min (P2-AC-07).
- Hierarchical chain (`raw → 1m → 5m → 1h → 1d`) follows docs/08 §13.1/13.4
  "incremental CAGGs": coarser refreshes scan bucket rows, not raw samples.
- CAGGs are `materialized_only = true`: materialization boundaries are explicit
  and the query engine performs the raw fallback (§3.3) instead of paying a
  real-time union on every query.

| Policy | Value |
|---|---|
| Raw chunk interval | 1 day (canonical docs/20.3/21.2; re-asserted + verified) |
| Raw retention | 30 d default, 30–90 d via `ARGUS_METRICS_RAW_RETENTION_DAYS` (P2-AC-09) |
| `metric_1m` retention | 30 d |
| `metric_5m` retention | 90 d |
| `metric_1h` retention | 13 months |
| `metric_1d` retention | 3 years |
| Compression | `metric_1m/5m/1h/1d`: segmentby `series_id`, orderby `bucket DESC`, after 7 d — see §5 for the raw-compression blocker |

Retention divergence note: docs/17 §35.1's on-prem column reads 90 d / 180 d
for 1m/5m; that column also encodes the *plan-lever maximum*. PHASE_2_SPEC
P2-AC-09 pins the on-prem defaults above (30 d / 90 d / 13 mo / 3 y) and those
were implemented.

---

## 2. Query API reconciliation (Phase 1 → canonical)

`internal/modules/metrics` serves `GET /v1/collectors/{id}/metrics`; the
Phase-1 contract was reconciled to the canonical caps (docs/08 §13.5, docs/12
§22.8, P2-AC-13). This is a deliberate, documented behavior change:

| Aspect | Phase 1 | M8 canonical | Implemented behavior |
|---|---|---|---|
| Points cap | 2,000 → `422 query.points_exceeded` | 10,000 | responses truncate to the **newest** 10,000 buckets/points with `meta.partial` + `meta.truncated` + `meta.points_truncated`; a pathological request (> 1,000,000 expected buckets) still fails loudly `422` instead of scanning |
| Series cap | none | 100 | lowest series ids returned, `meta.series_total` / `meta.series_returned`, `partial=true` |
| Timeout | 5 s | 15 s | `metrics.QueryTimeout = 15s` |
| Max range | 24 h | not specified | 3 years (1d retention horizon, documented) |
| Default step | 10 s | `auto` picker | `""`/`auto` → picker; explicit `raw/10s/1m/5m/1h/1d` remain valid overrides |
| `meta.resolution` | absent | `rollup_1m` … | added; top-level `resolution` kept for backward compatibility (step name) |
| Partial flags | none | — | `meta.partial`, `meta.raw_fallback`, `meta.rollup_missing`, `meta.resolution_warning` |

Backward compatibility: response fields are additive; the only changed
behaviors are the cap values and the empty-step default, both mandated by the
canonical contract and covered by updated tests.

---

## 3. Design decisions

### 3.1 Resolution picker

`PickStep` implements docs/08 §13.5 exactly: ≤ 6 h → 1m, ≤ 7 d → 5m,
≤ 90 d → 1h, beyond → 1d (PHASE_2_SPEC consistency item 1 chose docs/08 over
docs/11 §20.4's wording). `meta.resolution` reports the canonical class
(`raw`, `rollup_1m`, `rollup_5m`, `rollup_1h`, `rollup_1d`; 10s buckets are
computed from raw and report `raw`). Explicit finer-than-recommended steps are
honored and flagged with `meta.resolution_warning` ("user override with
warning").

### 3.2 Aggregation columns and `tw_avg`

Every CAGG materializes `avg/max/min/sum/n/tw_avg` so the query layer can
select per metric definition later (gauge → avg/max/min; rates → avg/sum;
state → max + time-weighted avg — docs/08 §13.4). Values arrive already
normalized (counters as rates, states as enum values, docs/08 §13.2).

`tw_avg` is the sample-count-weighted mean (`sum/n`), propagated
sample-weighted through the hierarchy. TimescaleDB continuous aggregates reject
window functions and sub-queries (both verified against the pinned 2.30.1
image: "Sub-queries are not supported in FROM clause"), so a true
duration-weighted average (which needs the next sample's timestamp) is not
computable inside a CAGG. With the platform's uniform poll cadence the
sample-count-weighted mean equals the duration-weighted average exactly; for
irregular cadences it is the documented conservative approximation, revisited
if/when a duration-weighted rollup is required.

### 3.3 Rollup reads + raw fallback (P2-AC-07/08)

For rollup steps the query engine splits the window at a conservative boundary
`now - (end_offset + schedule)` (1m: 3 min), aligned down to the bucket:
`[from, boundary)` is read from the tenant CAGG, `[boundary, to]` is computed
from raw samples. The boundary alignment guarantees a bucket is never read from
both sources (no double counting). If the older span has no materialization at
all (e.g. immediately after migration), it is recomputed from raw and flagged
`meta.rollup_missing=true`. A window ending "now" reports
`meta.raw_fallback=true`.

### 3.4 RLS handshake and tenant views

PostgreSQL materialized views cannot carry RLS, and TimescaleDB additionally
refuses to create a CAGG (or enable compression) on a hypertable with row
security. `metric_samples` keeps its Phase-1 `ENABLE + FORCE` RLS (G5). The
migration therefore lifts FORCE/ENABLE only inside its own transaction (one
implicit transaction via golang-migrate → no other session can observe the
window) and restores them before commit; `TestMetricsRLSUntouchedInMigration`
pins the committed state.

Because the runtime role must not read aggregate rows directly (matviews cannot
enforce RLS), each CAGG ships an owner-owned org-filtered tenant view
(`metric_1m_tenant`, …) whose predicate is exactly the RLS predicate; `SELECT`
on the aggregates is revoked from `argus_app`. Aggregate creation uses
`WITH NO DATA` so the DDL is transaction-safe; the refresh policies populate
the materialization and the raw fallback covers the gap meanwhile.

Operational requirement: the background refresh policies execute as the table
owner, which is subject to FORCE RLS. Deployments must run
migrations/policies under a role with `BYPASSRLS` (or superuser) — the same
role that already owns every tenant table. The runtime app role stays fully
RLS-enforced (verified: direct aggregate reads as `argus_app` are denied).

### 3.5 Tenancy and measurement notes

- Period comparisons against PostgreSQL intervals use the server's epoch
  conventions (month = 30 d, year = 365.25 d) so verification compares exact
  seconds for `13 months` / `3 years`.
- `last_seen_at` is now maintained per ingest batch (series metadata `UPDATE`,
  not the sample write SQL). This makes retirement truthful; new activity
  un-retires a tombstoned series.

---

## 4. Cardinality guards (P2-AC-11)

Canonical: 250 series/device default (docs/08 §13.3; reconciles docs/11's
"200 typical"), 10,000 series/site, runaway-creation quarantine, 30-day
retirement.

- `EnsureDeviceSeries` (the M9 adoption point; device scraper creation arrives
  with polling) enforces per-device, per-site and creation-rate budgets in the
  tenant transaction. Over-budget series are created **in the quarantined
  state** (identity reserved, visible to the registry) and emit
  `metric.cardinality.exceeded`. The cap check is advisory under concurrency;
  the unique identity index bounds races.
- `QuarantineSeries` quarantines an existing series (runaway detection or
  operator action).
- Quarantine stops ingest **for that series only**: `ensureSeries` surfaces
  quarantined keys, `IngestBatch` drops those samples (counted in
  `rejected_samples` and the `argus_ingest_samples_total{status="quarantined"}`
  counter) while the device's other series keep flowing. Verified end to end.
- Creation-rate threshold: canonical is silent on the number; this build uses
  **60 new series/min/device** (documented conservative choice).
- Retirement: `RetireInactiveSeries` tombstones series with no activity for
  ≥ 30 d (`retired_at`; rows and CAGG history kept, docs/11 §20.4).
- Event surface: Phase 2 has **no events table** yet, so
  `metric.cardinality.exceeded` is a structured slog event
  (`SlogCardinality`, JSON field shape) plus
  `argus_metrics_cardinality_exceeded_total{scope}` and
  `argus_metrics_series_retired_total`. M11 wires events/alerts; M10 surfaces
  quarantine state in the UI.
- Exposure deferral: there is no series-registry HTTP surface in Phase 1/2 yet
  (the only metrics route is the collector query), so quarantine/retirement
  state is not exposed via API in this slice. M10 owns the surfacing.

---

## 5. Compression: raw target blocked by RLS (platform limitation)

**Finding.** On the pinned `timescale/timescaledb:2.30.1-pg18`, compression
and row-level security are mutually exclusive on one hypertable (upstream open
feature request [timescale/timescaledb#6827]). Observed errors:

- enabling compression with RLS on:
  `columnstore cannot be used on table with row security`;
- re-enabling RLS with compression on:
  `operation not supported on hypertables that have columnstore enabled`.

Phase-1 G5 pins RLS on `metric_samples`, and this slice must not weaken RLS, so
**raw compression is not enabled**. This is a real deviation from P2-AC-10 and
is escalated here rather than papered over.

**Compatible maximum implemented.** The four CAGG materializations (which
never had RLS and cannot have it) carry the canonical compression shape —
`segmentby series_id`, `orderby bucket DESC`, after 7 days — so the policy
machinery is exercised, long-retention rollups compress, and
`timescaledb_information` verification is meaningful. `metric_samples` stays
uncompressed.

**Verification posture.** `VerifyPolicies` asserts the designed state: CAGG
compression policies/settings present; `metric_samples` keeps `ENABLE + FORCE`
RLS and has **no** compression settings. If a future stack enables raw
compression (necessarily dropping RLS), verification fails loudly.

**Next step (M8-S2b → M13, storage/compression decision).** Raw compression
remains blocked by the RLS constraint. The remaining options are: (a) keep RLS
and accept uncompressed raw (current), (b) replace table-level RLS with an
equivalent enforced surface to unlock compression (a tenancy redesign), or
(c) move raw storage to a different engine (the pre-committed VictoriaMetrics
extraction path).

**Measured CAGG ratios (M8-S2b, forced compression on the dev stack; raw view
outputs in `tests/load/results/compression_stats_internal.txt`):**

| CAGG chunk | Rows / series | Before bytes | After bytes | Ratio |
|---|---|---|---|---|
| `metric_1m` `_hyper_2_2_chunk` | 2,138 / 201 | 770,048 | 344,064 | **2.24 : 1** |
| `metric_5m` `_hyper_3_3_chunk` | 614 / 201 | 196,608 | 319,488 | **0.62 : 1** (1.61× larger) |

The 1m chunk (the materialization the query path relies on) compresses 2.24:1;
the 5m chunk is too small for columnstore overhead (TimescaleDB warned "poor
compression ratio" itself). The raw-table attempt is re-verified in
`tests/load/results/raw_compression_blocked.txt`:
`ALTER TABLE metric_samples SET (timescaledb.compress, ...)` still fails with
`columnstore cannot be used on table with row security`, and `metric_samples`
keeps ENABLE+FORCE RLS with zero compression settings. No vendor numbers are
used; ratios are from `chunk_compression_stats(...)` before/after bytes.
ADR-016's write-path half is decided on measured evidence in §6 below and does
**not** change this storage question; the storage decision stays open for M13
(§10).

---

## 6. ADR-016 — ingest write path (M8-S2a)

**Status:** accepted on measured evidence (2026-10-01, dev node: Intel
i7-8665U 4C/8T, 23.8 GiB, Docker Desktop 29.8.1, pinned TimescaleDB
2.30.1-pg18; all probes through the runtime app role and RLS, raw artifacts in
`tests/load/results/`).

**Context.** Phase-1 L-01 measured 4,244 samples/s on one stream (DB CPU
98–121%, ~435 ms average commit per 2,000-sample batch) and L-02 14,934
samples/s across 200 streams (DB CPU 642–790%); the write path was the only
observed bottleneck (`docs/phase-1/LOAD_TEST_REPORT.md`). P2-AC-12 requires
20k samples/s with ≤ 5% counted backpressure drops, re-measured against the
optimized path; ADR-016 was deferred from Phase 1 to exactly this data.

### 6.1 Measured findings

Probes: `tests/load/writepath` (drives the real `ingest.Service`) plus psql
probes against the pinned image; raw JSON in
`tests/load/results/adr016_*.json`.

| # | Probe | Result | Reading |
|---|---|---|---|
| 1 | 2,000-row INSERT+COMMIT on a plain table (`synchronous_commit=on`) | 6–10 ms (3.0–3.6 ms off) | WAL flush/fsync is **not** the bottleneck on this host |
| 2 | 2,000-row insert into `metric_samples` (3 indexes, `ON CONFLICT`) | 138–188 ms | per-row cost dominates: hypertable routing + 3 B-trees + RI trigger |
| 3 | Same shape without the duplicate `metric_samples_series_ts` index | 57–96 ms (clone) | duplicate index ≈ 11% end-to-end serial (8,313 → 9,249 samples/s first A/B) and removed |
| 4 | Same on a hypertable clone without the `org_id` FK | 11–17 ms | the per-row FK RI trigger is the single largest cost (~35 µs/sample) |
| 5 | unnest vs staging+COPY+INSERT-SELECT, serial (clean DB) | 9,301 vs 9,415 samples/s | +1.2% — within noise |
| 6 | same, 6 concurrent transactions, overlapping recent timestamps | 18,472 vs 18,976 samples/s | +2.7% — within noise |
| 7 | concurrency sweep (unnest, recent timestamps) | p1 9.3k / p6 18.5k / p8 18.8k / batch=5,000 p6 19.5k samples/s | parallelism is the lever; > 6 does not help this host |
| 8 | concurrent first delivery of one new series | losers failed `series … unresolved after upsert` | pre-existing `ensureSeries` race that pipelining exposes |
| 9 | `TouchSeries` under concurrent batches of one collector | row-lock serialization: pre-fix stream capped at 14.0k samples/s; p6 recent 16,656 → 17,654 samples/s after `SKIP LOCKED` | row-lock hotspot removed |
| 10 | claim / series / chunk-RLS-sweep statements | ~2 / ~3 / ~1.5 ms | immaterial |
| 11 | 200-stream fleet with per-stream-only pipelining (first L-02 attempt) | 14.2k samples/s, ack p50 15.2 s / p99 28.9 s, **597 reconnects** and ~3.3k context-canceled batches | 200 streams × 6 = 1,200 queued transactions vs the 10-connection pool; per-batch latency crossed the collector timeout. Fixed with a process-wide in-flight bound (§6.2 #2) |

### 6.2 Decision

1. **Keep the array-unnest + `ON CONFLICT DO NOTHING` sample write; do not add a
   staging table.** The canonical staging+COPY candidate measured within ≤ 3%
   of the current path (noise) at both serial and concurrent operation, while
   adding a table with its own tenant/cleanup lifecycle, an extra WAL copy per
   batch and a migration.
2. **Bounded batch pipelining with a process-wide budget.** Batch transactions
   run concurrently with a process-wide budget of 8; one stream may use the
   whole budget (single-stream measurement: 6–8 concurrent transactions move
   one stream from ~9k to ~19k samples/s), a fleet shares it. Acquisition
   happens in the stream's receive loop, so a stream never builds an internal
   queue and backpressure reaches the collector through gRPC flow control.
   Without the process-wide bound, 200 collectors × 6 in-flight batches queued
   1,200 transactions against the 10-connection pool, per-batch latency crossed
   the collector ack timeout, and reconnect/cancel storms followed (measured,
   §6.1 #11).
3. **Drop the redundant `metric_samples_series_ts` index** (migration `000014`).
   `metric_samples_pk (series_id, ts)` serves the same range and `ORDER BY ts
   DESC` scans (verified with `EXPLAIN`), and dropping the duplicate removes
   pure write amplification.
4. **`TouchSeries` uses `FOR UPDATE SKIP LOCKED`** (strictly best-effort touch:
   the retirement clock can lag by one batch window, irrelevant against a
   30-day threshold).
5. **`ensureSeries` re-reads raced keys after the upsert** so concurrent first
   delivery of a series cannot fail.
6. **Keep the `org_id` foreign key.** Its per-row RI trigger (~35 µs/sample)
   is the largest remaining write-path item, but removing it would trade
   referential integrity for throughput; that is not done on 10-minute
   evidence. If the 1 h soak (M8-S2b) needs the headroom, the replacement must
   preserve the guarantee (e.g. a batch-validated constraint), not drop it.
7. **`ARGUS_SERVER_DB_MAX_CONNS`** is configurable (default 10 = Phase-1 pool
   sizing; validated [1,80]). The fleet run below uses the default.

### 6.3 Guarantees preserved (all test-pinned)

- **Ack-after-commit:** each worker emits `BatchResult` only after
  `IngestBatch` returns (the transaction committed); the stream loop is the
  only sender, so gRPC's single-writer rule holds.
- **Batch idempotency, original wins:** every batch claims its own
  `ingested_batches` row in its own transaction; concurrent duplicate delivery
  admits exactly one OK (`TestM8S2ConcurrentDuplicateBatchOriginalWins`).
- **Poison handling:** unchanged (`TestM4PoisonBatches`, failure suite T5).
- **RLS discipline:** still `set_config('app.current_org', …, is_local)`
  inside `database.WithTenant`; no policy weakened.
- **Chunk-RLS sweep:** still called post-insert, pre-commit.
- **Failure cleanup:** a failed batch rolls back its claim and every sample;
  a retry lands exactly once
  (`TestM8S2FailedBatchLeavesNoStateAndRetryLandsOnce`), and no staged state
  exists to leak (no staging table was adopted).
- **Tenant isolation:** unchanged probes stay green (`TestM4MetricTenantIsolation`).
- **No drops:** the concurrency bound stalls dispatch; unacked batches are
  replayed by the collector.

**Ordering note.** `BatchResult`s for one stream may now arrive out of order.
The protocol already permits this: acks are keyed by `batch_seq` and the
collector advances its durable watermark only on contiguous acks
(`internal/collector/transport/sender_test.go`, "Out-of-order results must not
advance the watermark past a gap").

## 7. Validation runs — L-01 / L-02 (M8-S2a), L-03 + 1 h soak (M8-S2b)

> Raw artifacts under `tests/load/results/`: `l01.json`/`l01.log`, `l02.json`
> (canonical) and `l02_xt.json` (extended watchdog), `*_cpu.csv`, `*_waits.csv`,
> `*_streams.csv`, `*_before_metrics.txt`, `*_after_metrics.txt`; the
> superseded build revision and earlier attempts are kept with explicit
> suffixes (`l01_k6_*`, `l02_attempt1_*`, `l02_attempt2_*`,
> `l02_canonical_*`).

**Environment (same host as Phase 1).** Windows 11 laptop, Intel Core
i7-8665U (4C/8T) @ 1.90 GHz, 23.8 GiB RAM; Docker Desktop 29.8.1 (WSL2);
TimescaleDB `2.30.1-pg18` digest-pinned; server/collector/web/db on one Compose
project. L-01 starts from a fresh stack; the canonical L-02 runs on the same
stack immediately after (as in Phase 1), while the extended-watchdog L-02 runs
on a fresh stack. `ARGUS_SERVER_DB_MAX_CONNS` stays at its default 10 in every
run. L-02 uses the documented load override for the fleet enrollment limiter
(`docker-compose.load.yml`, 1,200/min).

### 7.1 L-01 — single stream, batch 2,000, 20,000 samples/s offered, 10 min

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
| Server-side batch pipeline avg | 861 ms | 435 ms avg commit |
| `op=samples` statement avg / claim / series | 813 / 2.2 / 3.9 ms | ~200 ms round-trip report |
| DB state after run | 10.13 M rows, 1,707 MB, 5,197 ledger rows | 2.64 M rows, 579 MB |
| Counted backpressure drops | **0** (the offered/achieved gap is window backpressure; no loss) | 0 |

Interpretation: clean and 3.97× the Phase-1 rate, but short of 20k at the end of
the run. The gap is CPU cost per batch growing with the table (insert ~561 ms
at 2.3 M rows in the pre-run sanity → ~813 ms at 10.1 M) while the process-wide
budget is 8 and the host (4C/8T) is effectively saturated (DB 570–797% plus
server + load generator + Windows/background agents). Wait-event sampling shows
no lock bottleneck; the per-row `org_id` FK is the measured largest single cost
(§6.1 #4). The earlier build revision (per-stream-only budget) measured 15,790
samples/s under identical parameters and is kept under `l01_k6_*` as secondary
evidence; the shipped revision matches the run above.

### 7.2 L-02 — fleet, 200 collectors, batch 500, 10 min

The canonical harness invocation was used first; it has a 15 s no-ack watchdog
that closes a stream when acks are deeper than the watchdog (a real collector
instead keeps the spool and replays). Both measurements are recorded:

**(a) canonical invocation (`-ack-timeout` default 15 s), run after L-01 on the
same stack (start 10.13 M rows):**

| Metric | M8-S2a | Phase 1 (baseline) |
|---|---|---|
| Duration | 609 s (10 m + churn) | 654.6 s |
| Enrollment | 200 collectors | 200 collectors in 29.2 s |
| Offered | 20,000 samples/s | 20,000 samples/s |
| **Achieved** | **12,777 samples/s** | 14,934 samples/s |
| Batches OK / dup / rejected / retry (harness) | 15,705 / 0 / 0 / 0 | 19,554 / 0 / 0 / 0 |
| Samples accepted (harness) | 7,812,989 | 9,775,470 |
| Streams active max / avg | 201 / 76 (**700 reconnects**) | 201 / 184 (0 reconnects) |
| Ack latency p50 / p95 / p99 | 18.5 / 37.3 / 48.2 s | 50.1 / 56.6 / 58.7 s |
| Transport errors / reconnects | 700 / 700 | 0 / 0 |
| Server CPU avg / max | 64.5% / 462.5% | 71.1% / 170.5% |
| DB CPU avg / max | 484.0% / 862.2% | 642% / 790% |
| Server-side batch txs / retry | 18,020 (21 canceled → RETRY; not replayed by the synthetic client) | n/a |
| DB state after run | 19.09 M rows, 3,117 MB | 12.42 M total samples (2.59 GB growth) |

**(b) extended watchdog (`-ack-timeout 60s`, opt-in; measures capacity without
synthetic abandons), fresh stack:**

| Metric | Value |
|---|---|
| Duration | 636.3 s |
| **Achieved** | **14,934 samples/s** (Phase-1 parity, but clean) |
| Batches OK / dup / rejected / retry | 19,104 / 0 / 0 / 0 |
| Samples accepted | 9,502,274 (DB total 9,502,286) |
| Streams active max / avg | **201** / 146 (ramp; 0 churn) |
| Ack latency p50 / p95 / p99 | 50.6 / 77.7 / 86.6 s |
| Transport errors / reconnects | **0 / 0** |
| Server CPU avg / max | 58.6% / 255.8% |
| DB CPU avg / max | 481.9% / 803.1% |
| `op=samples` statement avg (500-row batch) | 218 ms |
| Counted backpressure drops / server retries | **0 / 0** |
| DB state after run | 9.50 M rows, 1,492 MB |

Interpretation, honestly: 200 collectors at window-bounded **max pressure**
saturate this single 4C/8T host (DB ~4.8–8 cores, plus the load generator and
server on the same CPU), and the sustained fleet rate is ~15k samples/s — Phase-1
parity, now with zero errors, zero retries and all 201 streams stable when the
client watches the queue instead of abandoning it. The nominal L-02 demand
(200 × 100 samples/s = 20k/s = 40 batches/s) was **not** reached (29.9 batches/s);
the limiting factor is host CPU under the synthetic harness, not the write path
(L-01 improved 4×, and per-batch SQL time is 218 ms for 500 rows = 0.44 ms/row,
the same per-row cost as the single-stream run). Two methodology notes: (1) the
Phase-1 table's "100 samples/s per collector" is the scenario intent, but the
harness ticks at `batch / total-offered` (25 ms) while the 8-deep window has
room — max pressure in both eras, so the comparison holds; (2) both runs keep
the documented load override for the fleet enrollment limiter, and `(a)` ran
cumulatively after L-01 while `(b)` started from a fresh database.

**Load-run limitations (feed M8-S2b):** the generator runs on the same host and
consumes ~2 cores; per-batch latency under fleet pressure is tens of seconds
(deep but bounded queueing, no loss); the per-row `org_id` FK remains the
largest write-path cost. The ≥ 1 h soak should either separate the generator
from the server host or repeat on a host with more cores, and may need the
FK-replacement decision (§6.2 #6) to hold 20k/s with headroom.

### 7.3 L-03 — API leg remediation (P2-AC-12)

The full before/after record, root-cause evidence chain and raw artifacts are in
[`LOAD_TEST_REPORT.md`](LOAD_TEST_REPORT.md) (§ "L-03"); the short version:

- **Before (measured, clean 50 VU / 5 min run):** p95 **463.4 ms FAIL**,
  p99 584.6 ms, 166.2 req/s, 0% errors; server-side both protected routes
  p95 ≈ 490 ms while `/v1/healthz` (no session middleware) stayed at p95
  4.8 ms; `argus_db_query_duration_seconds{op="query"}` p50 13.3 ms.
- **Root cause:** every authenticated request ran an unconditional row-locking
  `UPDATE sessions SET last_seen_at = now()` (best-effort touch) in its own
  transaction. `pg_stat_activity` showed the full concurrency parked on
  `Lock: transactionid` for that statement plus `WalSync` waits on its commit;
  the DB delta was **+49,986 session updates for 49,987 requests** (the L-03
  setup shares one session, so all VUs serialized on one row). Classified as
  the auth/session path — not SQL, not HTTP settings, not Docker networking.
- **Fix (production code, `internal/modules/identity`):** session + user
  resolved in **one** auth query/transaction (`getSessionUserByTokenHash`), and
  the touch is **throttled to at most once per 30 s per session** with a
  conditional `UPDATE ... WHERE last_seen_at < cutoff`, keeping the previous
  best-effort semantics (a failed touch never fails the request).
- **After (identical harness/stack):** p95 **224.7 ms PASS**, p99
  **289.6 ms PASS**, 120.9 ms avg, 409.9 req/s (2.5×), 0% errors, k6 exit 0;
  session row updates **+9**, WAL **+0.4 MB**; server-side list/metrics p95
  202 / 249 ms.
- **Semantics preserved/tested:** unknown/expired/revoked sessions and disabled
  users still fail uniformly; the auth role still cannot read tenant tables
  (`TestM8S2bAuthLookupAndTouchThrottle`).

Artifacts: `tests/load/results/l03_before_clean_*`, `l03_after_clean_*`
(logs, k6 summaries, pre/post `/metrics`, route deltas, docker stats, DB
counter deltas). The initial JSON-output run's raw per-op dump
(`l03_before_points.json`, 126.8 MB) exceeds the host's 100 MB file limit and
is intentionally not committed (kept local, gitignored).

### 7.4 Soak — L-01-style, 20k samples/s offered for >= 1 h

Run `soak3` (2026-10-01): single stream, batch 2,000, 20,000 samples/s offered
for 62.0 min; 65,241,605 samples accepted; **0 duplicate / 0 rejected / 0 retry
/ 0 transport errors / 0 reconnects**; ack p50 769.6 / p95 1,315.4 / p99
1,739.9 ms; DB CPU avg 632.3% / max 844.3%, server CPU avg 59.5%; raw
hypertable +11.48 GB (~176 B/sample uncompressed); session updates +4
(throttled touch). Achieved **17,535.5/s = 87.7% of offered** - the run is
lossless but the sustained-20k target is **not met on this host** (DB ~6.3 of
8 threads with the generator sharing the node); the 10-minute L-01 validation
(16,869/s) agrees, attributing the ceiling to host CPU. P2-AC-12 is recorded
with this shortfall; the pilot-profile re-run on separate server/generator
hardware is M13. Full table + interpretation: `LOAD_TEST_REPORT.md` Soak
section; artifacts `tests/load/results/soak3_*`.

## 8. Verification and maintenance path (P2-AC-09)

- `metrics.VerifyPolicies` checks via `timescaledb_information`:
  4 CAGGs exist + materialized-only; refresh offsets (exact seconds);
  tenant views exist and are the only aggregate surface granted to `argus_app`;
  5 retention policies with exact windows (raw = configured); 4 CAGG
  compression policies + segmentby/orderby; raw chunk interval = 1 day; raw RLS
  ENABLE+FORCE; raw compression absent. Every mismatch is aggregated and
  returned as a `PolicyError` — the job fails loudly with the full list.
- `argus-server metrics-maintenance` (owner DSN) applies the configured raw
  retention via `alter_job(config_merge => drop_after)`, retires inactive
  series, then verifies; exit non-zero on any violation. `--verify-only`
  skips the mutating steps.
- Nightly CI job `metrics-maintenance` (`.github/workflows/ci.yml`,
  `schedule` + `workflow_dispatch`, runs `go test ./tests/integration/...
  -run '^TestMetrics'`) asserts the same policies on a real TimescaleDB
  container. Existing jobs were not modified.

---

## 9. Test evidence

New/updated tests:

- `internal/modules/metrics/picker_test.go`: picker boundaries, resolution
  vocabulary, override warning, exact policy tables, cap reconciliation.
- `internal/modules/metrics/query_test.go`: step parsing (auto + 1h/1d),
  intervals, expected buckets, 10k/3y budget invariants.
- `tests/integration/metrics_m8_test.go`:
  - `TestMetricsPolicyVerification` (baseline pass, tamper detection, restore);
  - `TestMetricsRawRetentionConfig` (45 d apply → verify; mismatch violation);
  - `TestMetricsRLSUntouchedInMigration` (RLS flags, raw compression absent,
    direct aggregate read denied);
  - `TestMetricsCAGGComputation` (gauge avg/max/min/sum/n; counter avg/sum;
    state max + tw_avg; hierarchical 5m/1d propagation; tenant-view isolation);
  - `TestMetricsResolutionPickerMetaAndCaps` (2h/3d/30d/120d picker +
    `meta.resolution`; finer-step warning; partial=false on empty);
  - `TestMetricsRawFallbackServesMaterializedAndRecent` (materialized read
    proven after raw rows are deleted; raw tail merged; flags);
  - `TestMetricsPointsAndSeriesCaps` (100-series truncation; 10k-point
    truncation with newest-first semantics);
  - `TestMetricsQuarantineStopsSeriesOnly` (event, idempotent quarantine,
    1 accepted / 1 rejected, healthy series keeps ingesting);
  - `TestMetricsDeviceSeriesGuards` (device/site/rate caps + event details);
  - `TestMetricsSeriesRetirement` (tombstone + retirement + reactivation).
- Migration governance: `migrations.Latest = 14`; full down/up round trip and
  the inventory round trip now traverse the M8 migrations (000014 down
  recreates the Phase-1 index).

M8-S2a tests (new):

- `tests/integration/m8s2_ingest_test.go`:
  - `TestM8S2ConcurrentFirstDeliveryNoSeriesRace` — 8 concurrent first batches
    on one cold collector: all OK, exactly one series, no lost samples (fails
    before the `ensureSeries` fix);
  - `TestM8S2ConcurrentDuplicateBatchOriginalWins` — same `batch_seq` twice
    concurrently: exactly one OK / one DUPLICATE, one sample, winner's value;
  - `TestM8S2FailedBatchLeavesNoStateAndRetryLandsOnce` — flaky-store failure
    rolls back claim + samples, retry lands exactly once;
  - `TestM8S2PipelinedGRPCBatchesAckAll` — 6 batches sent back-to-back are all
    acked exactly once (order-independent);
  - `TestM8S2RedundantIndexDropped` — pin migration 000014.
- Existing T4/T5/T9 + full suite stay green (§9 table below).

Observed verification results (Windows host, Docker Desktop, TimescaleDB 2.30.1):

| Command | Result |
|---|---|
| `go build ./...` | pass |
| `gofmt -l internal cmd tests` | empty |
| `go vet ./...` | pass |
| `golangci-lint v2.14.0 run --timeout 10m ./...` | **0 issues** |
| `go test ./internal/... -count=1` | pass |
| `go test ./tests/integration/ -run '^TestM8S2' -count=1 -v` | pass (5 tests, exit 0) |
| `go test ./tests/integration/ -count=1` | **pass, full suite (129.8 s)** — T4/T5/T9 and the M8-S1 metrics tests included |
| `go test ./tests/contract/... -count=1` | pass |
| `go test ./tests/integration/ -run '^TestMetrics' -count=1 -v` (M8-S1) | pass (10 tests; re-run green in the M8 suite) |
| L-01 / L-02 validation runs | §7 (raw artifacts under `tests/load/results/`) |

Staging lifecycle: **no staging table was adopted** (the measured candidate
offered no gain), so there is no staging lifecycle to test; the equivalent
guarantee is pinned by
`TestM8S2FailedBatchLeavesNoStateAndRetryLandsOnce` (a failed batch leaves no
claim, no samples, and a retry lands exactly once). The staging variant remains
in the ADR-016 harness (`tests/load/writepath -variant staging`) if a future
slice needs to re-measure it.

---

## 10. Deferrals and explicit non-goals for this slice

- **Closed in M8-S2b:** L-03 root cause addressed and passing (p95 224.7 ms /
  p99 289.6 ms); >= 1 h soak executed and reported honestly (§7.4: measured
  sustained rate vs the 20k target, with bottleneck attribution — no fabricated
  success); CAGG compression measured (2.24:1 on `metric_1m`); the Phase-2 load
  report delivered (`docs/phase-2/LOAD_TEST_REPORT.md`). The soak's shortfall,
  if any, is exactly what the FK-replacement decision below needs.
- **Raw compression** — see §5; blocked by the RLS constraint on the pinned
  TimescaleDB; the storage choice (keep RLS / enforced replacement / different
  engine) is a Phase-2/M13 decision on top of the measured CAGG ratios.
- **Pool/pprof instrumentation** — the DB-level evidence (row-lock waits,
  per-statement WAL commits, session update deltas) localised L-03 without
  pgxpool acquire histograms or CPU/block profiles; those remain an ops nicety
  and were deliberately not added in this slice.
- **`org_id` FK replacement (if soak needs it)** — the per-row RI trigger is
  the largest remaining per-sample cost (§6.1 #4). Any replacement must keep
  the referential guarantee; deferred until the 1 h numbers exist.
- **Template compile-time series-budget check (P2-AC-11, last clause)** — M9
  (`mibgen`/template pipeline does not exist yet).
- **Quarantine/retirement UI surfacing and resolution badge** — M10 (no
  series-registry API exists; the metrics route is the only surface).
- **`POST /metrics/query` contract, ETag caching, per-metric aggregation
  selection** — M10; M8 materializes all aggregate columns and exposes
  `agg`-ready data.
- **Event table + ops alert on verification failure** — M11/M12; this slice
  logs the structured event, exports counters, and fails the nightly job.
- **M9 polling/SNMP/ICMP and any alerting work** — untouched, as scoped.

## 11. Files changed

**M8-S1 (as before):** migrations `000012_metrics_rollups`, `000013_metrics_lifecycle`,
metrics module (picker/query/store/series/guards/maintenance + tests),
`cmd/argus-server/main.go` (metrics-maintenance + guards), config, contracts/CI.

**M8-S2a (this slice):**

- Migrations: `migrations/000014_drop_redundant_series_ts_index.{up,down}.sql`;
  `migrations/embed.go` (`Latest = 14`).
- Ingest write path: `internal/modules/collectors/stream.go` (bounded per-stream
  batch pipelining, single-sender result loop); `internal/modules/metrics/series.go`
  (concurrent-first-delivery re-read); `internal/modules/metrics/store.go`
  (`TouchSeries` `FOR UPDATE SKIP LOCKED`).
- Config/wiring: `internal/platform/config/config.go` (+`config_test.go`,
  `ARGUS_SERVER_DB_MAX_CONNS`), `cmd/argus-server/main.go` (app-pool bound).
- Tests: `tests/integration/m8s2_ingest_test.go` (new: concurrent series race,
  concurrent duplicate batch, pipelined gRPC acks, failure cleanup + retry,
  migration index state).
- Load tooling/evidence: `tests/load/writepath/main.go` (new ADR-016 harness);
  `tests/load/gen/main.go` (opt-in `-ack-timeout`, default unchanged);
  `tests/load/README.md`; raw artifacts `tests/load/results/*` (L-01/L-02 JSON,
  logs, CPU/wait/stream samples, server metrics snapshots, ADR-016 bench JSON).
- Docs: this file (§6/§7/§10/§11).

**M8-S2b (this slice):**

- L-03 fix: `internal/modules/identity/service.go` (single-query session+user
  auth; throttled best-effort `last_seen_at` touch, `SessionTouchInterval`),
  `internal/modules/identity/repo.go` (`getSessionUserByTokenHash`, conditional
  `touchSession`; removed the per-request `getSessionByTokenHash`/`getUserByID`
  pair from the request path).
- Tests: `tests/integration/m8s2b_identity_test.go` (new: joined lookup, touch
  throttle, uniform rejection for unknown/revoked/disabled, auth-role grant
  boundary).
- Load evidence: `tests/load/results/l03_before_clean_*`, `l03_after_clean_*`,
  the `l03_before_*` run (raw per-op dump kept local, gitignored),
  `soak3_*` artifacts, `compression_*` and `raw_compression_blocked.txt`.
- Docs: `docs/phase-2/LOAD_TEST_REPORT.md` (new);
  `tests/load/README.md` (L-03 result + harness lesson + soak recipe); this
  file (§5/§7.3/§7.4/§10/§12).

---

## 12. P2-AC coverage (P2-AC-07..13)

| AC | State | Evidence |
|---|---|---|
| P2-AC-07 (rollup freshness <= 2 min guarantee) | met | §1 (1m `end_offset` 2 min + schedule 1 min; hierarchical refresh); `TestMetricsCAGGComputation`; live refreshes verified in `timescaledb_information.job_stats` (0 failures except the unrelated TimescaleDB telemetry job) |
| P2-AC-08 (raw fallback correctness) | met | §3.3; `TestMetricsRawFallbackServesMaterializedAndRecent`; picker `meta` fields |
| P2-AC-09 (retention/compression policies + loud verification) | met | §1/§8; `VerifyPolicies` + `metrics-maintenance --verify-only`; nightly CI job; `TestMetricsRawRetentionConfig`, `TestMetricsPolicyVerification` |
| P2-AC-10 (compression enabled + measured ratio) | **partial — raw blocked by RLS** | §5: CAGG policies present, measured `metric_1m` 2.24:1 / `metric_5m` 0.62:1 (raw bytes, force-compressed chunk); raw compression impossible on the pinned TimescaleDB with ENABLE+FORCE RLS (error + vetted state in `raw_compression_blocked.txt`); decision deferred to M13 (§10) |
| P2-AC-11 (cardinality guards) | met except compile-time budget + UI | §4: caps/quarantine/retirement + tests; compile-time template budget → M9; quarantine UI surfacing → M10 |
| P2-AC-12 (load evidence) | partial/honest | L-01 16,869 samples/s and L-02 14,934 samples/s re-measured on the optimized path (§7.1/7.2, unchanged from S2a); L-03 fixed and passing (§7.3: p95 224.7 ms / p99 289.6 ms); >= 1 h soak executed with honest shortfall reporting (§7.4) |
| P2-AC-13 (query budgets) | caps met; 7 d latency budget not separately measurable here | caps 10k points / 100 series / 15 s with partial flags (M8-S1, `TestMetricsPointsAndSeriesCaps`); L-03 exercises the 24 h @ 1 m metric query at p95 224.7 ms client-side / 249 ms server-side under 50 VUs. A 7-day window cannot be measured truthfully on this dataset (the dev stack holds ~1 h of raw history; the soak targets 1 h), so the NFR-PERF-002 7 d p95 < 2 s check is deferred to M13's pilot-profile run with production-shaped history |
