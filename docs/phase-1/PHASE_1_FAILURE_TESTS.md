# PHASE-1 FAILURE TESTS

All tests run against the pinned dev stack (`docker compose`), automated where marked, with evidence artifacts captured (logs, SQL dumps, Prometheus snapshots). A test passes only if **all** assertions hold. Injection primitives: `docker compose stop|pause|start`, `docker kill -9`, `iptables`/`tc` on the host or `toxiproxy` (optional), file-system fault injection for ENOSPC (tmpfs size-capped mount), log/filesystem inspection.

---

## T1 — Normal operation (happy path)

**Setup:** fresh stack, one enrolled collector.
**Steps:** observe 10 minutes.
**Assertions:**
1. `argus_grpc_streams_active == 1` continuously; reconnect count == 0.
2. `collector_cpu_percent` present per 5 s interval; ≥ 110 samples over 10 min; values within [0,100].
3. Batches arrive in order (`ingested_batches.batch_seq` is dense from 1..N).
4. `acked_seq == highest_seq` at the end; spool bytes return to ~0 after ack.
5. No ERROR-level server/collector logs in the window (warnings allowed, investigated).
**Automation:** `tests/e2e/scenarios_test.go::TestHappyPath10m` (CI: shortened 2-min variant; full 10-min in nightly).

## T2 — Server unavailable (collector autonomy)

**Steps:** `docker compose stop server`; wait 10 min; verify; `docker compose start server`; wait 5 min.
**Assertions:**
1. Collector stays alive; production continues at cadence; heartbeat log lines show disconnected state with backoff.
2. `spool_records` grows ≈ 10 min × (5 s cadence) records ± 5%; `dropped_records_total == 0`; spool bytes < configured max.
3. During outage: no batches acked (`acked_seq` frozen); no data loss possible by construction (nothing leaves the spool until acked).
4. After restart: all batches delivered; `acked_seq == highest_seq`; `ingested_batches` count == highest seq; spot-check that the first/last sample timestamps of the outage window exist in `metric_samples`.
5. Reconnect happens automatically (no operator action).
**Automation:** `tests/integration/failure_tests.go::TestServerOutageAutonomy` (compose orchestration).

## T3 — Network interruption (mid-stream drop)

**Steps:** with stream active, `toxiproxy` (or host `iptables`) severs TCP to 8443 for 60 s mid-batch; restores.
**Assertions:**
1. In-flight batch not lost: either delivered after reconnect or still in spool (never both absent) — verify by seq accounting.
2. At most the batches that were fully delivered-and-acked are not re-sent; any re-sent batch returns `STATUS_DUPLICATE` and does not duplicate samples.
3. Reconnect backoff observed (log lines: 1s, 2s, … with jitter); no tight reconnect loop (≤ 8 attempts/min).
4. `metric_samples` has no duplicated `(series_id, ts)` rows (SQL assertion).
**Automation:** `failure_tests.go::TestNetworkInterruption` (toxiproxy).

## T4 — Duplicate batch (idempotency)

**Steps:** capture a legitimate batch payload (from loadgen fixture); after normal run, inject the **same batch_seq with different sample values** via the loadgen replay tool.
**Assertions:**
1. First delivery: `STATUS_OK`. Replay: `STATUS_DUPLICATE`.
2. `ingested_batches` has exactly one row for the (collector, seq).
3. **Original values remain in `metric_samples`** (the duplicate cannot overwrite: `ON CONFLICT DO NOTHING`).
4. Retry storm of 50 duplicates: response time stable; counters `argus_ingest_batches_total{status="duplicate"} == 50`; no DB errors.
**Automation:** `failure_tests.go::TestDuplicateBatchIdempotency`.

## T5 — Malformed / poison metric

**Cases:** (a) value out of range (101 for percent); (b) ts = now+30 d; (c) dimensions with 20 keys; (d) batch with 6,000 samples; (e) unknown metric key not in policy; (f) NaN/Inf value.
**Assertions per case:** `STATUS_REJECTED` with specific machine-readable reason; **not retried**; collector moves batch to `deadletter/`; nothing appears in `metric_samples`; counters increment; service stays healthy for subsequent valid batches.
**Automation:** `failure_tests.go::TestPoisonBatches` (each case subtests).

## T6 — Expired enrollment token

**Steps:** create token with TTL 2 s; wait 5 s; attempt enroll.
**Assertions:**
1. Generic `PERMISSION_DENIED` ("enrollment failed") — no oracle distinguishing expired vs used vs unknown.
2. No `collectors` or `collector_certificates` rows created; token row unchanged (`used_at` null).
3. Server log contains reason `expired` + request id; metric `argus_enroll_attempts_total{result="expired"}` increments.
4. Collector backs off and does not hot-loop (< 6 attempts/min).
**Automation:** `failure_tests.go::TestExpiredToken` (+ used-token and unknown-token variants).

## T7 — Revoked collector

**Steps:** enroll + run; call `POST /v1/collectors/{id}:revoke`; observe.
**Assertions:**
1. Live stream terminated ≤ 5 s with `Disconnect{CODE_REVOKED}` (collector log).
2. Reconnect attempts fail at auth (fingerprint → revoked) — server metric `argus_grpc_streams_active == 0`; attempts counted.
3. Collector does **not** retry after `CODE_REVOKED` (terminal state): attempts stop after ≤ 1 retry; `doctor` reports `identity revoked`.
4. Audit log row exists (actor, collector, timestamp); `collector_certificates.revoked_at` set.
5. Re-enrollment with a fresh token under the same name succeeds only after operator resolves the existing record (documented flow).
**Automation:** `failure_tests.go::TestRevocation`.

## T8 — Tenant isolation

**Setup:** two orgs (A, B), one collector + data each (seed helper).
**Assertions (all must hold):**
1. API: B's session querying A's collector/metrics IDs ⇒ 404 (list endpoints scoped; empty result for A's data).
2. SQL: under B's `app.current_org`, reading A's rows returns 0; inserting a sample for A's series fails RLS `WITH CHECK`.
3. mTLS: A's certificate claiming B's `collector_id` in ClientHello ⇒ stream closed with `CODE_PROTOCOL_ERROR` before DB access; security event logged.
4. Pooled-connection leak test (SPEC §7.2): interleaved A/B transactions on a 1-connection pool never leak scope; setting is empty after commit.
5. Unscoped query path (simulated programming error) hits RLS denial, not data.
**Automation:** `rls_test.go` + `tenant_isolation_test.go`; nightly fuzz: random cross-tenant ID probing.

## T9 — Database restart during ingest

**Steps:** active ingest (loadgen at 5k samples/s); `docker kill -9 db`; wait 5 s; start DB; wait 60 s.
**Assertions:**
1. Server returns `STATUS_RETRY`/stream errors during outage — **never `STATUS_OK` for uncommitted data** (this is the ack-after-commit proof: compare collector `acked_seq` with committed row sets after recovery).
2. `/v1/readyz` == 503 during outage; == 200 ≤ 30 s after DB health returns.
3. No corrupted rows: `metric_samples` count for delivered batches matches `accepted_samples` sums; no constraint violations in logs beyond the outage window.
4. Ingest resumes automatically; final `acked_seq == highest_seq`; duplicates (if any) equal `STATUS_DUPLICATE` and produce no double rows.
**Automation:** `failure_tests.go::TestDbRestartDuringIngest`.

## T10 — Collector restart (spool survival)

**Steps:** run collector 5 min; `docker compose restart collector` (graceful) and separately `docker kill -9` (crash variant); continue 5 min.
**Assertions (both variants):**
1. Spool survives; `highest_seq` continues monotonically (no reuse); `acked_seq` ≥ pre-restart value (never regresses).
2. Replayed-after-ack batches (if any) return `DUPLICATE`; `metric_samples` has zero `(series_id, ts)` duplicates.
3. No data gap beyond the restart window (≤ 15 s).
4. Torn-write simulation (crash variant): truncated tail detected and discarded, `corrupt_records_total` incremented, subsequent records intact.
**Automation:** `failure_tests.go::TestCollectorRestart` (graceful + crash subtests) + spool recovery unit tests.

---

## Additional scheduled robustness checks (Phase-2 hand-off, not phase-gating)

| ID | Scenario | Why deferred |
|---|---|---|
| T11 | Cloud outage during replay (server up/down flapping) | Requires HA/cluster semantics (Phase 2) |
| T12 | Disk-full spool behavior under sustained production rate | ENOSPC unit tests exist (M4b); sustained-rate variant lands with device-scale Phase 5 |
| T13 | Clock skew ±5 min | Mechanism exists (`clock_skew_ms`); full assertion matrix lands with device metrics |
| T14 | Certificate expiry mid-run | 90-day certs; expiry surfaced (acceptance) — automated clock-faked test in Phase 2 |
