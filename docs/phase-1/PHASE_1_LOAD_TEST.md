# PHASE-1 LOAD TEST

Purpose: prove the **architectural direction** (collector → spool → mTLS gRPC → ingest → TimescaleDB) is viable at the architecture's first scale target — **5,000 → 20,000 samples/s** — on a single dev node. This does **not** claim production scalability (no HA, no compression, no retention policies, one node, synthetic metrics). Results feed the Phase-2 plan and the ADR-004 extraction trigger discussion; they must be reported honestly, including any failure to reach targets.

## 1. Harness

**Component:** `tests/load/gen` (Go, uses the repo's generated gRPC client — the same code path as a real collector, including mTLS and batch framing).

**Modes:**
| Mode | Description |
|---|---|
| `single-stream` | One enrolled collector, batch size 2,000, target rate configurable (default 20k samples/s), duration 10 min. Measures raw ingest ceiling with maximum batching. |
| `fleet` | N enrolled collectors (default 200), each 100 samples/s (batch 500 every 5 s), 10 min. Measures realistic fan-out: connections, credits, scheduling jitter, DB concurrency. |
| `replay-storm` | Fleet mode + sever/reconnect cycles (toxiproxy) to measure catch-up behavior and duplicate accounting. |

**Enrollment:** the harness automates: `POST /v1/enrollments` (N tokens) → enroll N collectors (parallel, bounded) → connect streams. It is itself an end-to-end test of the control plane under concurrency.

**Measurements (client-side):** offered rate, OK/DUPLICATE/RETRY/REJECTED counts, send-to-ack latency histogram per batch, reconnect counts, backoff time, spool watermark progress, RSS/CPU of collector+server through cgroup stats.
**Measurements (server-side):** `argus_ingest_samples_total`, `argus_ingest_batch_duration_seconds` (validate+commit), `argus_db_query_duration_seconds{op="samples"}`, `argus_grpc_streams_active`, DB: `pg_stat_activity` wait events sampling, `pg_stat_statements` top queries (if enabled), hypertable chunk count (`SELECT show_chunks`), table sizes (`hypertable_size`).
**API leg (L-03):** k6 v2.3.0 script: 50 VUs mixed read (metrics query + collectors list) for 5 min.

## 2. Scenarios and pass criteria

| ID | Scenario | Parameters | Pass criteria |
|---|---|---|---|
| **L-01** | Single-stream ceiling | 1 collector; batch 2,000; 20,000 samples/s; 10 min | 0 errors; ack rate ≥ offered − 1%; ingest commit p95 ≤ 150 ms, p99 ≤ 500 ms; server CPU < 80% of allocated cores sustained; no OOM; `ingested_batches` row count == expected batches; `metric_samples` count == samples sent (minus duplicates == 0) |
| **L-02** | Realistic fleet | 200 collectors; 100 samples/s each; batch 500/5 s; 10 min | All 200 streams established; `argus_grpc_streams_active` ≥ 195 at steady state; total accepted ≥ 19,000 samples/s equivalent; reconnect count ≤ 5 total; per-batch ack p95 ≤ 1 s; no collector spool growth beyond one batch window; DB connection pool wait time < 20% |
| **L-03** | API leg | 50 VUs; metrics query (24 h @ 10 s step) + collectors list; 5 min | p95 < 300 ms, p99 < 1 s; error rate < 0.1%; no increase in ingest latency during the run (isolation of read/write paths) |
| **L-04** | Replay storm | Fleet + 3 × (sever 60 s / restore) | Zero data loss; duplicate ratio reported (expected non-zero, bounded); catch-up completes ≤ 3× outage duration; no unbounded memory growth |
| **L-05** | Soak (stretch, nightly) | L-02 for 2 h | RSS stable (±10% after warm-up); no chunk/commit degradation trend; no lock contention growth |

## 3. Interpretation guide (expected bottlenecks, in order)

1. **`SET LOCAL` + tx-per-batch overhead** — visible if commit p95 climbs with fleet size; mitigation path: larger batches, connection pool sizing, or Phase-2 staging-table + `COPY` + `INSERT … SELECT ON CONFLICT` (documented, not built now).
2. **Array materialization in the samples insert** — `unnest` of 2,000-element arrays per batch; CPU-bound parse/serialize; measure `op="samples"` histogram.
3. **Series resolution overhead** — Phase 1 does a per-batch `SELECT` map (quota-capped at 1,000 series/collector; small working set expected).
4. **gRPC window/backpressure** — if ack latency forces window saturation, collectors stall rather than drop (correct); tune `max_inflight_batches` and batch size between L-01/L-02.
5. **Autovacuum/chunk creation** — 1-day chunks; ensure ingest isn't blocked by chunk creation at boundaries (test crosses no boundary at 10 min, note for soak).

**Explicit non-claims:** results are single-node, uncompressed, no retention/CAGG, synthetic metric payload, Linux dev hardware (record specs). Production claims require Phase-2 configurations + the extraction-path decision per ADR-004 (> 50k samples/s sustained per region → evaluate VictoriaMetrics).

## 4. Report template (`LOAD_TEST_REPORT.md`, filled in M6)

```text
Environment: <CPU/RAM/disk/OS/docker versions> | image digests | commit SHA
L-01: offered=____ accepted=____ dup=____ rejected=____ | commit p50/p95/p99=____ms
      server CPU avg/max=____% RAM peak=____MB | DB rows=____ | notes
L-02: streams max=____ reconnect=____ | ack p95=____ms | accepted/s=____ | notes
L-03: p95=____ms p99=____ms errors=____% | notes
L-04: loss=____ dup ratio=____ catch-up=____s | notes
Bottleneck observed: <stage> evidenced by <metric>
ADR-004 implication: <none yet | watch | trigger reached>
Caveats: single-node, uncompressed, synthetic, no HA
```
