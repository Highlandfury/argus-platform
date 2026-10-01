# M8-EVIDENCE — Metrics pipeline completion

**Status: M8 IN PROGRESS.** This record covers **M8-S1** (storage completion:
CAGGs/refresh/compression/retention, query resolution picker + caps, cardinality
guards/retirement, verification + tests + evidence). **M8-S2** — ADR-016 ingest
write-path decision, load/soak re-runs (L-01/L-02/L-03) and the phase load
report — is not in this slice and remains open. No M9/M10/alerts work was done.

References: `PHASE_2_SPEC.md` P2-AC-07..11/13, M8 deliverables; canonical
docs/08 §13.1-13.6 (CAGGs, aggregation policy, picker, cardinality), docs/11
§20.3-20.4/§21.1-21.4 (DDL, refresh policy, compression, retention, series
lifecycle), docs/12 §22.8 (query API caps, `meta`), docs/17 §33/§35 (retention
matrix, verification).

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

**Next step (M8-S2, ADR-016).** The ADR-016 storage/write-path decision must
pick one: (a) keep RLS and accept uncompressed raw (current), (b) replace
table-level RLS with an equivalent enforced surface to unlock compression (a
tenancy redesign), or (c) move raw storage to a different engine (the
pre-committed VictoriaMetrics extraction path). P2-AC-10's "measured
compression ratio" therefore cannot be produced for raw this slice; CAGG
compression ratios are measurable in the load slice.

---

## 6. Verification and maintenance path (P2-AC-09)

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

## 7. Test evidence

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
- Migration governance: `migrations.Latest = 13`; full down/up round trip and
  the inventory round trip now traverse the M8 migrations.

Observed verification results (this slice, Windows host, Docker Desktop,
TimescaleDB 2.30.1):

| Command | Result |
|---|---|
| `go build ./...` | pass |
| `go test ./internal/... -count=1` | pass |
| `go test ./tests/integration/ -run '^TestMetrics' -count=1 -v` | pass (10 tests) |
| `go test ./tests/integration/ -count=1` | pass (full suite; 143–202 s observed across runs on this host) |
| `go test ./tests/contract/... -count=1` | pass |
| `go vet ./...` | pass |
| `gofmt -l internal cmd tests` | empty |
| `golangci-lint v2.14.0` (docker) `run --timeout 10m ./...` | 0 issues |

---

## 8. Deferrals and explicit non-goals for this slice

- **Ingest write-path optimization + load/soak runs (M8-S2 next slice)**:
  ADR-016 decision, staging/`COPY`/`INSERT…SELECT` path, L-01/L-02/L-03
  re-measurement, `LOAD_TEST_REPORT`-style evidence, measured compression
  ratios. The k6/README deviations were annotated to point at the canonical
  10k cap; the harness re-baseline happens there.
- **Raw compression** — see §5; blocked by the RLS constraint on the pinned
  TimescaleDB, deferred to the ADR-016 storage decision.
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

## 9. Files changed

Migrations: `migrations/000012_metrics_rollups.{up,down}.sql`,
`migrations/000013_metrics_lifecycle.{up,down}.sql`, `migrations/embed.go`.

Metrics module: `picker.go`, `query.go`, `store.go`, `series.go`, `http.go`,
`guards.go`, `guards_metrics.go`, `maintenance.go`, `picker_test.go`,
`query_test.go`.

Ingest/wiring: `internal/modules/ingest/service.go` (quarantine filtering +
series touch; sample write SQL unchanged), `cmd/argus-server/main.go`
(`metrics-maintenance` + guard instruments), `internal/platform/config/config.go`
(+test), `internal/platform/telemetry` unchanged.

Contracts/CI: `openapi/argus.v1.yaml`, `.github/workflows/ci.yml`.

Tests: `tests/integration/metrics_m8_test.go` (new), `m4c_query_test.go`,
`m4_ingest_test.go`, `inventory_schema_test.go` (step-count generalization),
`tests/load/README.md`, `tests/load/k6/api.js` (comment annotations only).
