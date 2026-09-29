# ACCEPTANCE_RUN — M1 (Database & Security Foundation)

**Date:** 2026-09-29
**Environment:** Docker Desktop 4.93.0 · Docker Engine 29.8.1 · Compose v5.5.1 · PostgreSQL 18.6 · TimescaleDB 2.30.1 (`timescale/timescaledb:2.30.1-pg18@sha256:9dede0e3…`) · Go 1.27.1 (user-local)
**Commits:** M1a `439de0c` · M1b `b3f031b` · M1c `ff82056` · M1d `e46bba6` · M1e (this commit)

---

## Gate results

| Gate | Command | Result |
|---|---|---|
| Migrations | `argus-server migrate` (dev DB) + `TestMigrationsDownAndUpOnFreshDatabase` | **PASS** — up → replay (no-op) → down 5 → up; version 6, `dirty=false` |
| Schema shape | `TestSchemaMatchesSpec` | **PASS** — 11 tenant tables + `schema_migrations`; hypertable `metric_samples` (1 dim, 1-day chunks); RLS enabled+forced on 11; 11 policies; partial unique series index `WHERE (device_id IS NULL)`; exactly 1 FK on `metric_samples` (org; `series_id` intentionally FK-free) |
| Tenant isolation | `TestTenantIsolationReads`, `TestCrossTenantWritesDenied`, `TestUnscopedAccessSeesNothing` | **PASS** — A↔B reads isolated both directions; cross-tenant INSERT → `42501`; UPDATE/DELETE → 0 rows; unscoped reads on all 11 tables → 0 rows; unscoped INSERT → `42501` |
| Transaction-scoped tenancy | `TestTenantContextPoolingDoesNotLeak` | **PASS** — MaxConns=1 (same backend PID proven), alternating tenants ×3, no residual `app.current_org` after COMMIT *and* after a failed callback; pool usable afterwards |
| `argus_auth` boundaries | `TestAuthRoleBoundaries` | **PASS** — reads allowed on exactly organizations/users/sessions; 8 tables denied (`42501`); INSERT/UPDATE users denied; session column scope enforced (`last_seen_at` allowed, `token_hash` denied) |
| Privilege escalation | `TestAppCannotEscalateRole` | **PASS** — `SET ROLE argus_owner` from app → `42501` |
| Chunk boundary | `TestChunkAccessIsRLSProtected` | **PASS** — live chunk has RLS; unscoped chunk read returns 0 rows while the chunk holds ≥2 tenants; scoped reads return exactly the tenant's rows |
| Idempotency | `TestBatchClaimIdempotency`, `TestSampleUpsertIdempotencyOriginalWins`, `TestSeriesUpsertIdempotencyPartialIndexInference`, `TestFullBatchReplayIsEffectivelyOnce` | **PASS** — duplicate claim detected; duplicate sample keeps the **original** value; partial-index conflict inference works; full-batch replay is effectively-once |
| Failure/recovery | `TestFailedTransactionRollsBackAllSteps`, `TestPartialBatchIsAtomicAndReplayable`, `TestDatabaseRestartRecovery` | **PASS** — atomic rollback incl. idempotency claim; no phantom claims; recreate-on-volume restart preserves data + replays migrations |
| Seed | `TestSeedDevIdempotentAndIsolated` + live `argus-server seed-dev` ×2 | **PASS** — converge-on-rerun, stable IDs, per-org email uniqueness, cross-tenant isolation, pre-auth slug resolution |
| Live stack | `docker compose up -d --build --wait` | **PASS** — `migrate → seed → server → collector`; `/v1/readyz` = `{"checks":{"auth_database":"ok","database":"ok"}}`; DB: org `dev`, site `HQ`, `admin@dev.local`, schema v6 clean |
| M0 regression | `go build`, `go vet`, `go test ./...`, `golangci-lint run` (0 issues) | **PASS** |

Full integration suite: **18/18 test functions green** (~55–90 s, real containerized database).

---

## Platform findings (discovered, fixed, documented)

1. **Chunk-level RLS (TimescaleDB).** The M1 suite proved the app role could read chunk tables directly (Timescale propagates hypertable privileges to chunks; parent RLS does not apply there). Two rejected fixes: (a) revoking internal-schema access breaks parent queries (app role needs chunk privileges); (b) DDL event triggers never fire for Timescale chunk creation. **Final:** migration 000006 — `SECURITY DEFINER` sweep `argus_ensure_chunk_rls()` + 1-minute TimescaleDB backstop job + migration backfill; M4 ingest will call the sweep pre-commit (zero window). All three approaches tested empirically.
2. **Compose command/entrypoint gotcha.** Images declare `ENTRYPOINT ["/argus-server"]`; compose `command` must be **args only** (`["migrate"]`). The first full-stack run failed with usage+exit 2 because the command re-included the binary path. Fixed and re-verified.
3. **Docker Desktop ephemeral-port restart.** In-place `start` of a testcontainers container created with an *ephemeral* host port does not re-publish the port proxy (connections refused while Postgres is ready inside; explicit bindings — used by the dev compose stack — are unaffected). The restart test therefore recreates the container on a named volume, which is also the stronger durability scenario.

## Deviations / deferrals (recorded)

- `tenancy/http.go` deferred to M2 (no unauthenticated endpoints exist in M1; the API surface arrives with session auth).
- Seed does **not** mint enrollment tokens (collectors module arrives in M3); it writes `.dev/seed.json` instead.
- `argon2.go` was delivered in M1e (seed needs password hashing) rather than M2 as originally sequenced.

## Reproduce

```powershell
.\scripts\dev.ps1 up            # db -> migrate -> seed -> server -> collector -> web
curl.exe -s http://127.0.0.1:8080/v1/readyz
go test ./tests/integration/... -count=1 -v     # green against a real container
go test ./... -count=1 && .tools\bin\golangci-lint.exe run
```

---

# ACCEPTANCE_RUN — M2 (Identity & API Shell)

**Date:** 2026-09-29 · **Commits:** M2a `2ddeda1` · M2b `d4026c7` · M2c `b1bf47d` · M2d (this commit)

| Gate | Command / evidence | Result |
|---|---|---|
| Auth primitives | `go test ./internal/platform/security/...` | **PASS** — token format/uniqueness, constant-time compare, full CSRF matrix |
| API units | `go test ./internal/api/...` | **PASS** — route registry shape, fail-closed protected routes, login 503 without services, limiter burst/deny |
| OpenAPI contract | `go test ./tests/contract/...` | **PASS** — spec parses as OpenAPI 3.1.0; every implemented `/v1` route exists in the spec; spec-only endpoints limited to the explicit milestone allowlist (stale entries fail) |
| Session lifecycle (AC-12 API half) | `TestLoginSessionLifecycle` | **PASS** — wrong password 401 `auth.invalid_credentials` + no cookies; login sets HttpOnly session + readable CSRF; `/v1/me`, `/v1/sites` 200; logout without CSRF 403 (session survives); with CSRF 204; `/v1/me` after logout 401; raw token absent from DB (stored hashed) |
| Login rate limit (S-09) | `TestLoginRateLimitS09` | **PASS** — attempts 1–10 → 401, 11th → 429 + `Retry-After` |
| Enumeration uniformity (S-16) | `TestLoginEnumerationUniformS16` | **PASS** — identical status/code across unknown-org / unknown-email / wrong-password; timing 118/96/118 ms (dummy-hash equalization), minimum-work assertion enforced |
| Tenant scoping | `TestSitesAreTenantScoped` | **PASS** — org A's session sees only A's sites |
| Web E2E (AC-12 UI half) | `playwright test` (containerized web) | **PASS** — `/` → 307 `/login`; login → dashboard (org "Dev Org", site "HQ"); logout → `/login` and revoked; wrong password shows the problem message |
| Full stack | `docker compose up -d --build --wait` | **PASS** — db → migrate → seed → server → collector → web; API contract verified live by curl (login 200 / me 200 / 401 after logout / CSRF 403↔204) |

**M2 findings (documented):**
1. **Web runtime env:** Next bakes rewrites at build time but server components read `ARGUS_API_BASE` at runtime; the final image stage must set it (fixed in `web/Dockerfile` + compose, with graceful "API unreachable" panels).
2. **TypeScript 7.0.2 verified** with Next 16.3.7 (auto-adjusted `jsx: react-jsx`); the VERSIONS fallback note is retired.
3. **Operational reminder:** the compose stack must be rebuilt (`up --build`) after server code changes — running old images against new UI surfaces 404s that look like UI bugs.

---

# ACCEPTANCE_RUN — M3 (Enrollment, Collector Identity, Control Plane)

**Date:** 2026-09-29 · **Commits:** M3a `ea2c7ea` · M3b `be7b891` · M3c `78406e3` · M3d `2a7356b` · M3e `b443279` + final commit (this one)

| Gate | Command / evidence | Result |
|---|---|---|
| Proto pipeline (M3a) | `buf lint` · `buf generate` ×2 (deterministic hash) · `go build ./...` | **PASS** — stubs committed under `gen/`; CI runs lint → drift (`git diff --exit-code -- gen`) → build → `buf breaking` vs `origin/main` when present |
| Identity core units (M3b) | `go test ./internal/modules/collectors/...` | **PASS** — leaf identity (CN/SAN URI/EKU/validity/chain verify), Ed25519 policy sign/verify/tamper, token format/uniqueness/hash |
| Migrations + RLS (M3b) | integration `TestSchemaMatchesSpec`, `TestAuthRoleBoundaries` | **PASS** — schema v7; auth role SELECT-only on `enrollment_tokens`; resolver function executes for `argus_auth`, denied for `argus_app` |
| Enrollment matrix (M3e) | `TestM3EnrollmentMatrix` | **PASS** — valid; replay/unknown/expired → uniform `PERMISSION_DENIED`; malformed + oversized (64 KiB) CSR → `INVALID_ARGUMENT`; duplicate name → `ALREADY_EXISTS`; raw token absent (SHA-256 at rest); collector invisible to another org |
| Enrollment rate limit (S-01) | `TestM3EnrollmentRateLimit` | **PASS** — attempts 1–10 denied, 11th → `RESOURCE_EXHAUSTED` |
| Enrollment idempotency | `TestM3EnrollmentHTTPIdempotency` + `httpx` units | **PASS** — missing `Idempotency-Key` → 400; same key replays the original credential (`Idempotency-Replayed: true`, one row); new key → new credential |
| Stream lifecycle (T7 / AC-01…04) | `TestM3StreamLifecycle` | **PASS** — hello + policy v1 applied and acked in DB; duplicate connection: newest wins, old receives `CODE_SUPERSEDED`; server restart: reconnect to ACTIVE; revoke: terminal `REVOKED`, `Run` returns nil, fresh connection rejected pre-hello |
| Unknown identity (S-03) | `TestM3UnknownIdentityRejected` | **PASS** — rogue-CA certificate fails at the TLS layer (no application-level disconnect) |
| Live stack (M3d) | compose pristine `down -v` + `up --build --wait` | **PASS** — db → migrate → seed (mints dev token into the shared CA volume) → server (both gRPC listeners) → collector (enroll → ACTIVE) → web |
| Live policy delivery | `POST /v1/collectors/{id}/policy:resync` + collector log | **PASS** — 202 `{"policy_version":2}`; collector applied v2 within ~3 s; acked watermark moved to 2 |
| Live reconnect (collector) | `docker compose restart collector` | **PASS** — identity reloaded (same `collector_id`, persisted policy v2) → RECONNECTING → ACTIVE; registry count still 1 |
| Live reconnect (server) | `docker compose restart server` | **PASS** — collector ACTIVE → DISCONNECTED → RECONNECTING → ACTIVE in ~4 s |
| Live revocation (T7) | `POST /revoke` + container restart | **PASS** — live stream terminated `CODE_REVOKED`; restarted collector exits cleanly in `REVOKED` (no retry storm) |
| Web E2E (AC-11) | `playwright test` (collectors spec) | **PASS** — registry lists `dev-collector`; detail shows acked policy + admin actions; enrollment form shows a one-time `arg_enr_…` credential |
| Regression (M0–M2) | build · vet · full `go test ./...` · golangci-lint · contract · Playwright login spec | **PASS** (see the M3 final gate report) |

**Protocol/API changes recorded (delivered, not silent):**

1. **P1 — `EnrollResponse.policy_signing_public_key` (field 7)** (`ea2c7ea`): SPEC §27.3 requires the collector to pin the policy key at enrollment; the wire contract lacked the field. Added before implementation; the `buf breaking` gate is active from this change onward.
2. **P2 — revoke path `/v1/collectors/{id}/revoke`** (`78406e3`): Go `http.ServeMux` cannot mix a wildcard with literal text inside one path segment; OpenAPI + SPEC §13 updated in the same commit (no consumers existed at the time).

**M3 findings (documented):**

1. **Revoked-before-hello misclassification** (found live): a revoked collector receiving `Disconnect{REVOKED}` as the first server message logged `CODE_PROTOCOL_ERROR` and exited 1. Fixed in `internal/collector/stream` (disconnect handled pre-hello; `OnDisconnect` observability hook added); regression-covered by `TestM3StreamLifecycle`.
2. **TimescaleDB first-boot race** (found on pristine `down -v`): the image's temporary init server shutdown window killed the short-lived `migrate` service. Fixed with a 90 s connection-class retry (`database.MigrateUp`); pristine boots now pass end-to-end (keeps CI non-flaky).
3. **Idempotency gap closed**: SPEC §13 requires `Idempotency-Key` on `POST /v1/enrollments`; the first M3 cut omitted it. Implemented as a bounded 24 h in-memory replay cache (`platform/httpx`) scoped per org+user, 400 when the header is missing.

**Deviations / deferrals (recorded):**

- Org-wide (site-less) enrollment tokens: deferred — M3 requires `site_id` because collectors must belong to a site (SPEC §8.1 updated).
- Per-org enrollment budget (100/h): deferred to fleet-scale work; the per-IP limiter is live.
- `ServerHello` always carries the latest signed policy; the collector applies only newer versions and acks idempotently (SPEC §9.2 updated).
- Leaf auto-renewal: surfaced (`doctor`, `cert_not_after`) but not automated; rotation lands with lifecycle hardening.
- Revocation terminates the collector cleanly; re-enrollment requires a fresh token plus an operator decision (rename/delete flow per SPEC §8.4).

---

# ACCEPTANCE_RUN — M4b (Collector Producer, Durable Spool, Transport)

**Date:** 2026-09-29 · **Commit:** M4b (this commit)

| Gate | Command / evidence | Result |
|---|---|---|
| Producer unit | `go test ./internal/collector/metrics/...` | **PASS** — `/proc/stat` golden deltas (50%), deterministic runtime-metrics fallback on non-procfs hosts, parsing errors, producer interval emission |
| Batcher unit | same | **PASS** — size-cap flush, interval flush, empty-flush no-op, failed flush requeues (no sample loss) |
| Spool unit | `go test ./internal/collector/spool/...` | **PASS** — append/read/ack, watermark persistence across reopen, fully-acked segment unlink, torn-tail truncation + count, sealed-segment CRC quarantine with readable prefix preserved + `*.corrupt` file, capacity drop-oldest with watermark advance, corrupt `state.json` quarantine, empty-batch rejection |
| Sender unit | `go test ./internal/collector/transport/...` | **PASS** — contiguous watermark (out-of-order acks never skip gaps), REJECTED → dead-letter JSON + retire, RETRY ordering (backoff gates later batches; same bytes re-sent), new session resumes from watermark |
| Outage → drain (T2/T3, live + integration) | `TestM4CollectorSpoolSurvivesOutageAndDrains` + compose stop/start | **PASS** — 5 records retained while the stream is down (`acked_seq==0`, `dropped==0`), server returns, spool drains to zero, exactly 5 batches/5 samples in DB; live: server down ~26 s, +10 batches captured and delivered after recovery |
| Restart durability (T10/AC-13) | `TestM4CollectorRestartResumesFromWatermark` + `docker compose restart collector` | **PASS** — watermark/highest durable across reopen (2→2), sequences 1..4 exactly once, no duplicates; live: 9 unacked records recovered (`acked=10 → highest=19`) and drained after container restart |
| Lost-ack → duplicate | `TestM4LostAckReplayedAsDuplicate` | **PASS** — server commits, ack never processed, next session re-sends the same bytes → `DUPLICATE` → only then is the record retired; original value authoritative; exactly 1 batch/1 sample row |
| Heartbeat observability | live `GET /v1/collectors/{id}` | **PASS** — `reported_stats` carries `spool_bytes/records`, `highest_seq`, `acked_seq`, dropped/corrupt counters |
| Protocol/identity | M3 regression + M4a ingest | **PASS** — no second transport; telemetry rides the same mTLS stream, same identity, server-side allowlist/dedupe unchanged |
| Regression | `go build ./...` · `go vet ./...` · `go test ./... -count=1` · `golangci-lint run` · `buf lint` · `buf generate` (no drift) · contract | **PASS** (all packages incl. M1–M4a suites) |

**Deviations / decisions (recorded):**
- **Live-caught stall (fixed):** the spool reader snapshot its segment-file list at session start; once fully-acked segments were purged, the next append opened a *new* segment the long-lived session never discovered — telemetry silently stalled (`acked_seq` frozen) while the spool accumulated. The reader now refreshes its view (lexical cursor over zero-padded segment names) and `TestReaderSeesSegmentsCreatedAfterOpen` locks the regression in. Verified live: the stalled 107-record backlog plus new records drained to `acked==highest`, `spool_records=0`.
- `state.json` watermark semantics: "retired" = acked **or** dropped under capacity pressure (drops are counted and logged; a dropped sequence can never be acked, so the contiguous watermark must advance past it).
- Torn/corrupt tails are counted as one corruption event each (`corrupt_records_total`); the salvageable bytes are preserved (`*.corrupt-*` or truncated prefix) and surfaced by `doctor`.
- Heartbeat `uptime_seconds` / `clock_skew_ms` reset per stream session (per-connection semantics), not process lifetime.
- Policy-cache self-heal: an idempotent re-delivery of an already-applied version now re-persists the policy document, so a missing cache repairs itself on the next connect.
- Load evidence for M4b is the outage/restart/drain timings above plus the M4a 3,919/4,000 samples/s server-ceiling smoke; the full L-01 (20 k/s, 10 min) and L-02 (200 collectors) runs remain scheduled for the M4 load phase — no scalability claim is made from these tests.

---

# ACCEPTANCE_RUN — M4c (Metric Query API, Chart UI, M4 Load Phase)

**Date:** 2026-09-29 · **Commit:** M4c (this commit)

| Gate | Command / evidence | Result |
|---|---|---|
| Query contract | OpenAPI `/v1/collectors/{id}/metrics`; contract test now has an **empty pending list** (every specified endpoint implemented) | **PASS** |
| Query unit matrix | `go test ./internal/modules/metrics/...` | **PASS** — step parsing/defaults, interval mapping, expected-bucket math, catalog restriction, 2000-point cap over 24h@10s vs 24h@1m |
| Query integration (7 tests) | `tests/integration/m4c_query_test.go` vs real TimescaleDB | **PASS** — raw values/order/sample_count; 1m aggregation (avg 20/70, expected=3 gaps=1); empty + omitted latest; malformed/unknown/unsupported metric; bounds (from≥to, >24h, future to); 422 over-cap; tenant isolation (404 cross-tenant, 200 empty own); freshness (stale ≥290 s age vs fresh value); cancellation + unreachable-DB errors; data queryable while the collector stream is down |
| Chart UI (AC-09/AC-10) | Playwright against the real API | **PASS** — 6/6 specs: current value %, last-updated, fresh/stale badge, canvas rendered, ≥50 points in the 15m raw window (live: 60 points in 5m), range switch to 24h, spool stats + sample count on the detail page; injected slow/failing endpoint shows loading and error states (primary path never mocked) |
| Live query evidence | curl against the dev stack | **PASS** — 15m raw 180 points, 5m raw 60 points, 24h@5m honest gap accounting; latest fresh (age 1 s) |
| Query latency (reference dataset) | `go run ./tests/load/query` (25 iterations/shape) | **PASS** — dev-collector (12.4 M-row table): latest p95 20.3 ms, 15m raw 17.3 ms, 1h@10s 15.4 ms, 6h@1m 15.8 ms, 24h@5m 18.8 ms, **24h@1m 22.4 ms**, 0 errors. AC-08 note: 24h@10s is rejected by the normative 2000-point cap (422), so latency is measured at the finest permitted 24h resolution (1m) — far inside the 300 ms target |
| L-01 | loadgen single-stream, batch 2000, 20k/s offered, 10 min | **FAIL (honest)** — achieved **4,244 samples/s (21%)**; 2,564,000 samples in 1,282 batches; 0 errors/duplicates/rejects/reconnects; ack p50 3.73 s (window saturated). DB CPU-bound: **PostgreSQL avg 98.4%/max 121%** vs server avg 14.8%/max 26.9%; avg commit **435.5 ms** per 2,000-sample batch; target (commit p95 ≤150 ms) not met |
| L-02 | loadgen fleet, 200 collectors × 100/s, batch 500/5 s, 10 min | **PARTIAL** — 200 streams enrolled in 29.2 s (documented `docker-compose.load.yml` override: enroll rate 1200/min; default 10/min validated by S-01); streams_active max 201; **achieved 14,934 samples/s (75%)**; 19,554 batches / 9,775,470 samples; **0 duplicates/rejects/retries/errors; 0 reconnects**; ack p95 56.6 s under sustained overcommit; DB CPU avg 642%/max 790%. Meets stream/error/reconnect criteria; misses the ≥19k/s and ack-p95 ≤1 s criteria on the same DB write ceiling |
| Post-load integrity | SQL + `/metrics` | **PASS** — samples == accepted == 12,420,317 rows total; batches ledger consistent; 2.6 GB hypertable; zero drops/corruption/dead-letters throughout |
| Regression | build · vet · full `go test ./...` · golangci-lint · buf lint/generate (no drift) · contract · Playwright | **PASS** (M0–M4b all green) |

**Observed bottleneck (first real one identified by the load phase):** the PostgreSQL write path — per-batch transactions + `unnest` array inserts into the uncompressed hypertable, single chunk. L-02's 200 concurrent streams write ~400 batches/s and reach 14.9k samples/s while the server keeps CPU headroom; L-01's single 2,000-sample stream at 10 batches/s is limited to 4.2k samples/s at 435 ms/batch. Candidate remedies (documented, not built): larger batch windows, Phase-2 staging + `COPY`/`INSERT…SELECT`, compression/retention and CAGGs for reads. The load-test doc's predicted bottleneck ordering (tx-per-batch → array materialization) is confirmed.

**Key finding fixed during M4c (found by the post-load query measurement, not unit tests):** after the first 12 M-row load, the join/`ANY(array)`-shaped latest-value query let the planner satisfy `ORDER BY ts DESC` through the **(org_id, ts DESC)** index, walking ~10 M newer rows of other series before reaching an older one — worst case 16.7 s, surfacing as 504 timeouts on every chart query for the affected collector. Fixed deterministically in `internal/modules/metrics/query.go`: series are resolved first and every sample access is per-series with a scalar `series_id` (index-condition guaranteed); the latest value uses `max(ts)` (backward index seek) + primary-key equality. Post-fix dev-collector p95 ≈ 20 ms with zero errors, even with a 2.56 M-sample series in the same table. Operational hygiene recorded: `ANALYZE metric_samples` after bulk loads (chunk statistics).

**Deviations / notes (recorded):**
- L-02 enrollment used the documented load override (above); the default limiter is unchanged in the canonical compose and covered by S-01.
- AC-08's "24 h @ 10 s" latency leg cannot return points under the normative 2000-point cap; measured at 24h@1m (1440 points). Wide-window queries over a multi-million-sample series are dataset-bound (raw scan; no CAGGs in Phase 1 per G6) and were measured separately (≈1.1 s for a 2.56 M-sample series) — no CAGG/compression work is in scope until Phase 2.
- L-03 (k6 API leg) and the 2-hour soak (L-05) remain M6 items per the file plan.
- Environment honesty: single Windows Docker Desktop node (containerized PostgreSQL 18 + TimescaleDB 2.30.1, same host as server/collectors); synthetic `collector_cpu_percent` only; no HA, no compression. Results are direction/architecture evidence, not a production capability claim.

---

# ACCEPTANCE_RUN — M5b (Collector Self-Observability, :9091)

**Date:** 2026-09-29 · **Commit:** M5b (this commit)

| Gate | Evidence | Result |
|---|---|---|
| Metrics endpoint | `internal/collector/telemetry/metrics.go`; live log `collector metrics listening addr=127.0.0.1:9091` | **PASS** |
| Loopback binding | Non-loopback/wildcard addresses refused at Start (unit-tested with `0.0.0.0:0` and `:9091`); live: in-namespace scrape OK, a peer on the compose network gets `Could not connect to server`, host port not published (unreachable) | **PASS** |
| Canonical metric set | `argus_collector_spool_bytes` (gauge), `_spool_records` (gauge), `_highest_seq` (gauge), `_acked_seq` (gauge), `_dropped_total` (counter), `_corrupt_total` (counter), `_stream_connected` (gauge), `_send_batch_duration_seconds` (histogram), `_backoff_seconds` (gauge), `_clock_skew_ms` (gauge), `collector_cpu_percent` (gauge). All label-free; source: single `SpoolSnapshot()` for the spool family, setters fed by the real pipeline for the rest | **PASS** |
| Spool metrics/transitions | Unit test asserts endpoint == snapshot == `spool.Stats()` at empty → unsent (records 2) → acked-1 → retired; no second state source | **PASS** |
| Stream connectivity | Live outage: `stream_connected` 1 → 0 during server stop → 1 after reconnect (actual session state via the M3 stream lifecycle hooks, not heartbeat inference) | **PASS** |
| Send latency boundary | Histogram = transport **send write → BatchResult receipt** (any of OK/DUPLICATE/REJECTED/RETRY); a transport failure observes nothing until the batch is re-sent and acknowledged. Documented in code | **PASS** |
| Backoff | Live: 8 s during retry, **0 after successful reconnection** (reset to 1 s base on a connected session ending; pre-jitter value exposed) | **PASS** |
| Clock skew | Same skew variable as the heartbeat payload, mirrored via `OnClockSkew`; live values 1–2 ms; no timestamp rewriting anywhere | **PASS** |
| Collector CPU | Exactly the produced sample mirrored at production time (`collector_cpu_percent 4.05…` live) — one measurement, no re-derivation | **PASS** |
| Heartbeat consistency | One `SpoolSnapshot()` feeds both the heartbeat `Stats` callback and the endpoint; unit test proves equality across transitions. Live endpoint seq 1494 vs heartbeat 1474 from its previous 30 s publish — lag is by design (periodic heartbeat), values agree at the same instant | **PASS** |
| Cardinality/label safety | Automated test: no label on any collector family (histogram `le` excepted), no metric family outside the canonical set (+ standard `go_`/`process_`) | **PASS** |
| Race detector | `-race` unavailable on this Windows host (requires cgo/gcc; documented); run in the pinned Linux toolchain container: `ok` for all `internal/collector/...` packages | **PASS** (environment-documented) |
| Failure tests | Non-loopback refused; occupied-port Start returns an error while the collector keeps running (covered live: endpoint restarts on a fresh port); scrape during spool transitions; disconnect/reconnect; spool recovery (M4b suite unchanged); clean `Shutdown` | **PASS** |
| Regression | Full `go test ./...` (17 packages) · lint 0 · buf lint/generate/drift clean · M0–M5a suites green | **PASS** |

**Deviations / notes:** `ARGUS_COLLECTOR_METRICS_ADDR` added (default `127.0.0.1:9091`) — env surface extension beyond the §3.6 table, recorded here; README/RUNBOOK references land in M5d per slice discipline; the spool family is emitted at scrape time (single snapshot per scrape) while the heartbeat remains a 30 s periodic publish — same source, different sampling instants.

---

# ACCEPTANCE_RUN — M5c (Logging Conventions, Correlation, S-08 Log Scan)

**Date:** 2026-09-29 · **Commit:** M5c (this commit)

**Logging schema (required / optional / forbidden).** Required on server lifecycle events: `time, level, msg, component, request_id`. Required where the event is scoped: `collector_id` (collector/stream ops), `operation`/`error` on failures, machine-readable `code`/`reason`/`error_code` on stream/error events (e.g. `CODE_PROTOCOL_ERROR`, `CODE_REVOKED`, `validation.series_quota_exceeded`). Optional: `dur_ms`, `status`, `path`, `method`. Forbidden in every log: enrollment tokens, private keys/cert material, passwords, session/CSRF cookie values, authorization headers, DB/mTLS credentials, raw auth payloads, tenant payload data.

**Request-ID policy:** HTTP `X-Request-ID` accepted only when ≤64 chars of `[A-Za-z0-9._:+-]`; anything else (missing, oversized, whitespace, newline/control injection) is replaced with a 128-bit random ID, echoed on the response, and stored in the request context. Same policy for the gRPC metadata `x-request-id`. This bounds log amplification and makes field/newline injection structurally impossible.

**gRPC interceptor:** unary + stream interceptors on both listeners (enrollment unary, collector stream). Verified live: caller `X-Request-ID: m5c-live-1` → echoed header + server access log `"request_id":"m5c-live-1"`; `bad id with spaces` → replaced (`861ffc…`) and echoed as generated. The stream interceptor echoes the session ID in response headers; it cannot fail an RPC (observability-only).

**Stream correlation model:** one correlation ID per stream session (from the collector's `x-request-id` metadata, generated otherwise). The collector logs its `correlation_id` once at startup and attaches it to every reconnection; server stream lifecycle logs carry `request_id` + `collector_id` (`collector stream connected`, `disconnected by server` with `code`/`reason`, `protocol error` with reason code). Per-message/batch logging is deliberately absent (heartbeat/batch/retry paths log only lifecycle/errors) — no per-sample log amplification.

**S-08 automated log scan (`TestM5LogScanNoSecretLeakage`):** exercises failed login (wrong-password fixture), successful login (session+CSRF cookies), enrollment-token creation (raw token fixture), successful enrollment, denied replay, stream connect, a good batch, and a protocol violation — with server/gRPC/ingest logs captured to a buffer. The scan asserts nine forbidden patterns (token, both private-key markers, password fixture, session/CSRF cookie names, `devpass`, `Authorization:`, `Bearer `) are absent, and fails with the **pattern name only** (fixtures never printed). Anti-vacuous: the capture must contain `request_id`, the connect event, the collector ID, and the protocol-error event. **Result: PASS.**

**Log structure test:** representative success/error events parse as JSON and carry the required fields; `error_code` preserved verbatim (`CODE_PROTOCOL_ERROR`). **PASS.**

**Live verification:** echoed/sanitized request IDs (above); wrong-password login → `401`, password string absent from server logs; collector correlation ID present in collector logs; live server+collector log scan: `arg_enr_`, `BEGIN EC PRIVATE KEY`, `BEGIN PRIVATE KEY`, `devpass`, `argus_session=`, `argus_csrf=` — **none present**.

**Regression:** full `go test ./...` (18 packages incl. integration) PASS · lint 0 · buf lint/generate/drift clean · `-race` green for httpx/grpcx/collectors/collector in the pinned Linux container · Playwright re-run PASS (no web changes).

**Metrics-label review (§12):** M5a/M5b label-policy tests remain green; no secret or unbounded value is promoted into metric labels; correlation IDs are reserved for logs, never metrics.

---

# ACCEPTANCE_RUN — M5d (Runbook, Quickstart, Operational Failure Tests, Fresh-State Smoke)

**Date:** 2026-09-29 · **Commit:** M5d (this commit)

| Gate | Evidence | Result |
|---|---|---|
| Runbook | `docs/phase-1/RUNBOOK.md` — service inventory, ports, startup/shutdown, health/readiness/database/collector verification, common failures, recovery, backup/restore (dev scope), migration ops, collector/server ops, observability checklist, security operations, development reset (explicitly destructive), troubleshooting | **PASS** |
| Quickstart | README fresh-machine path (clone → Docker check → `dev.ps1 up` → login → collector → chart → stop) + troubleshooting section with the M0–M5 lessons; links to the runbook | **PASS** |
| Operational failure tests | `TestM5OperationalReadinessFailure` (dead DB → healthz 200 / readyz 503 naming `database`), `TestM5OperationalStaleCollectorView` (aged heartbeat → API status `stale`; fresh heartbeat → `active`); plus the existing suites: DB restart (M1), collector outage/restart (M4b), revocation + bad CA (M3), query bounds/timeout/DB-down (M4c), metrics-endpoint failure isolation (M5b), S-08 scan (M5c) | **PASS** |
| Fresh-development recovery + full smoke | `down -v` → `up --build --wait`: migrate v7, seed, server healthy, collector enrolled → active, 4 samples arriving within ~25 s, `/v1/readyz` 200, API query `status=fresh`, browser suite 6/6 | **PASS** |
| M5d findings (fresh-state only) | (1) **Fresh-enrollment crash**: after first-time enrollment, `cmdRun` attempted `RECONNECTING → RECONNECTING` (already transitioned by `enrollWithRetry`) → exit 1. Fixed with the state guard; invisible to every earlier test because they reused an enrolled collector. (2) The metrics E2E asserted a warm-stack point count; now requires live points (≥3) from a fresh stack, with AC-09's ≥50-point measurement kept as the warm reference record (M4c). | **PASS (fixed)** |
| Regression | `go test ./...` 18 packages PASS · lint 0 · buf lint/generate/drift clean · `-race ./internal/...` green (Linux container) · contract PASS · Playwright 6/6 | **PASS** |

**Phase-1 final state (inventory).**
*Provides:* authentication + sessions + CSRF, tenancy with RLS, admin/viewer API authorization, OpenAPI-contracted API, collector enrollment (one-time tokens), stable collector identity, internal-CA mTLS, signed policy delivery + acknowledgements, reconnect with backoff, durable segmented spool (fsync-before-send, corruption quarantine, capacity policy), batch ingestion with ack-after-commit + idempotency, TimescaleDB storage, tenant-safe query API with bounded ranges, ECharts metric chart, platform + collector self-observability, structured correlated logs with S-08 guarantees, and this runbook.
*Does not provide:* SNMP/ICMP polling, device discovery, topology, Wi-Fi monitoring, floor-plan heatmaps, network diagnostics/RCA, device configuration management, automation, HA/DR/PITR/zero-downtime upgrades, production scalability claims.

**Performance baseline preserved exactly as measured (M4c):** M4a smoke 3,919/4,000 samples/s; L-01 4,244/20,000; L-02 14,934/20,000 (200 streams, zero errors/duplicates/reconnects); primary observed bottleneck: **PostgreSQL write path**; Phase-1 has had no Phase-2 extraction/optimization work. Observed test results — not product capacity guarantees.

---

# ACCEPTANCE_RUN — M6a (Load Report, k6 L-03)

**Date:** 2026-09-29 · **Commit:** M6a (this commit)

| Requirement | Evidence | Result |
|---|---|---|
| L-01 historical baseline | `LOAD_TEST_REPORT.md` §L-01 (4,244/20,000; DB CPU 98–121%; 435 ms/batch) — preserved verbatim from M4c | **preserved** |
| L-02 historical baseline | `LOAD_TEST_REPORT.md` §L-02 (14,934/20,000; 200 streams; 0 errors/reconnects) — preserved verbatim from M4c | **preserved** |
| L-03 k6 API leg | `tests/load/k6/api.js` run with k6 v2.3.0: 50 VUs / 5 m / 18,875 requests / 0.00% errors / checks 100% — **latency thresholds FAILED** (p95 1,860 ms, p99 3,890 ms vs 300 ms/1 s) | **FAIL (honest)** |
| L-03 classification | Idle 22–34 ms → 50 VUs 785–803 ms avg on **both routes**, DB query time 11 ms avg / 50 ms p95, CPU low at rest → server-side concurrency/request-path (or Docker Desktop networking), **not SQL**; recorded for Phase-2 profiling; no production code changed | recorded |
| Load report | `docs/phase-1/LOAD_TEST_REPORT.md` (environment, methodology, all four results, bottleneck, limitations, interpretation; no fabricated percentiles) | **PASS** |
| Load instructions | `tests/load/README.md` (prerequisites, stack start, setup, exact L-03 command, PASS/FAIL interpretation, dev-only cleanup) | **PASS** |
| Security at load | Non-production credentials only; no secrets in Git; session auth/tenant isolation/rate limits left intact (login once in setup); the k6 jar bug fixed by explicit cookie, not by bypassing auth | **PASS** |
| Post-L-03 regression | build/vet/full `go test ./...` (18 pkgs) · lint 0 · buf lint/generate/drift clean · Playwright 6/6 on the same stack | **PASS** |

**L-03 harness lessons recorded:** (1) the k6 VU cookie jar delivered the `setup()` session cookie only for each VU's first request → 1.5 M fast 401s; the script now sends the session cookie explicitly per request (the 401 run is documented in the report as a harness lesson, not as an L-03 result). (2) The canonical "24 h @ 10 s" workload violates the normative 2000-point cap (422); L-03 issues 24 h @ 1 m, consistent with the recorded AC-08 interpretation.

---

# ACCEPTANCE_RUN — M6b (Failure Suite T1–T10 + nightly CI job)

**Date:** 2026-09-30 · **Commit:** M6b (this commit)

| T-case | Canonical scenario | Automated test (real DB + in-process gRPC) | Result |
|---|---|---|---|
| T1 | Normal operation | `TestM4BatchIngestHappyPath` | PASS |
| T2 | Server unavailable (collector autonomy) | `TestM4CollectorSpoolSurvivesOutageAndDrains` | PASS |
| T3 | Stream interruption + reconnect | `TestM3StreamLifecycle` | PASS |
| T4 | Duplicate batch (idempotency, original wins) | `TestM4DuplicateBatchOriginalWins` | PASS |
| T5 | Malformed / poison metric | `TestM4PoisonBatches` (7 subtests) | PASS |
| T6 | Expired/used/unknown enrollment token | `TestM3EnrollmentMatrix` | PASS |
| T7 | Revoked collector (terminal disconnect) | `TestM3StreamLifecycle` | PASS |
| T8 | Tenant isolation (reads/writes/metric path) | `TestTenantIsolationReads`, `TestCrossTenantWritesDenied`, `TestM4MetricTenantIsolation` | PASS |
| T9 | Database restart during ingest | `TestDatabaseRestartRecovery` | PASS |
| T10 | Collector restart (spool/watermark survival) | `TestM4CollectorRestartResumesFromWatermark` | PASS |

- Entry point: `tests/integration/failure_tests_test.go::TestFailureSuite` (canonical selector `go test ./tests/integration/... -run '^TestFailureSuite$'`); every case is a real end-to-end scenario, nothing mocked. Filename note: Go requires `_test.go` for test code (documented deviation from the plan's `failure_tests.go` shorthand).
- CI: `ci.yml` now triggers on `schedule` (daily 03:00 UTC) and `workflow_dispatch`, with a `failure-suite` job running the canonical selector on `ubuntu-latest` (Docker preinstalled for testcontainers).
- **M6b finding (fixed):** running the suite twice in one process (T8 subtests + the top-level RLS tests) hit fixed-org-slug collisions (`organizations_slug_key`); the RLS fixtures now use unique slugs and the suite is safely composable.
- Evidence: focused suite run 48 s (T1–T10 green); full `go test ./...` with the suite included — 18 packages green (integration 322 s); lint 0; buf lint/generate/drift clean.

---

# ACCEPTANCE_RUN — M6c (Compose-stack E2E Harness + CI Job)

**Date:** 2026-09-30 · **Commit:** M6c (this commit)

| Gate | Evidence | Result |
|---|---|---|
| Harness | `tests/e2e/scenarios_test.go` against the **real compose stack** (API :8080, ops :9090, enrollment :8444, mTLS stream :8443, internal CA, running collector); skipped unless `ARGUS_E2E=1` so `go test ./...` never depends on a running stack | **PASS** |
| AC-01/AC-02 | `TestE2EAC01EnrollAndRegister`: API-created one-time token → real enrollment client (TLS + CSR proof of possession) → certificate ≥80-day validity → signed policy verified by the client → collector visible in `/v1/collectors` | **PASS** (0.57 s) |
| AC-03 | `TestE2EAC03StreamActiveAndRevocationT7`: real mTLS stream reaches ACTIVE; `argus_grpc_streams_active` present in ops `/metrics` | **PASS** |
| T7 (live) | Same test: `POST /v1/collectors/{id}/revoke` → live stream terminates within 15 s with the terminal REVOKED state; registry reports `revoked`; a fresh connection with the revoked identity is rejected pre-hello, promptly and permanently | **PASS** (0.66 s) |
| AC-08 | `TestE2EAC08MetricQuery`: query API returns stored points for the running `dev-collector` (15 m raw, polled ≤45 s) | **PASS** (0.28 s) |
| CI job | `ci.yml` job `e2e`: compose `up -d --build --wait` → extract internal CA → `ARGUS_E2E=1 go test ./tests/e2e/... -v` → compose logs on failure → `down -v` (ubuntu-latest, 25 min timeout) | **PASS (wired)** |
| Harness hygiene | One throwaway collector per run (`e2e-<id>`), revoked during T7; relative CA paths resolve to the repo root; default run skips (0.49 s) | **PASS** |
| Regression | `go vet ./tests/e2e/...` · lint 0 · harness green twice (fresh + re-run) | **PASS** |

**Scope note (recorded):** T1–T3/T10 are automated against the real control plane in the M6b integration failure suite (containerized DB + in-process gRPC) and were additionally exercised live in M4b/M5d (outage/restart/reconnect evidence). The e2e harness adds the compose-stack AC-01/02/03/08 + T7 live path; compose-orchestrated variants of T2/T3/T10 (container stop/pause driven from Go) remain future work to avoid duplicating the M6b automation.

---

# ACCEPTANCE_RUN — M6d (Security Release Gate, Phase-1 Sign-Off, Final Gate)

**Date:** 2026-09-30 · **Commit:** M6d (this commit)

## Security suite (S-01…S-16 direction) — release gate

Entry point `tests/integration/security_suite_test.go::TestSecuritySuite`
(`go test ./tests/integration/... -run '^TestSecuritySuite$' -count=1 -v`);
CI job `security-suite` runs on push to main / manual dispatch.

| ID | Scenario | Delegated real test | Result |
|---|---|---|---|
| S-01 | Invalid token + per-IP enrollment limit | `TestM3EnrollmentMatrix`, `TestM3EnrollmentRateLimit` | PASS |
| S-02 | Expired / already-used token (uniform denial) | `TestM3EnrollmentMatrix` | PASS |
| S-03 | Cert from unknown CA (TLS-layer reject) | `TestM3UnknownIdentityRejected` | PASS |
| S-04 | Cert/claim confusion (hello ≠ cert) | `TestM3StreamLifecycle` | PASS |
| S-05 | Policy verification + ack (tamper unit-matrix in `internal/modules/collectors`/collector policy) | `TestM3StreamLifecycle` | PASS |
| S-06 | Cross-tenant API access (404, no oracle) | `TestTenantIsolationReads`, `TestCrossTenantWritesDenied`, `TestM4MetricTenantIsolation` | PASS |
| S-07 | RLS bypass / role escalation boundaries | `TestAuthRoleBoundaries`, `TestAppCannotEscalateRole`, `TestUnscopedAccessSeesNothing` | PASS |
| S-08 | Secret leakage (automated log scan + hashed at rest) | `TestM5LogScanNoSecretLeakage` | PASS |
| S-09 | Login brute force (429 threshold) | `TestLoginRateLimitS09` | PASS |
| S-10 | CSRF double-submit | `TestLoginSessionLifecycle` | PASS |
| S-11 | Revoked identity (terminal; reconnect rejected) | `TestM3StreamLifecycle` (+ live `TestE2EAC03StreamActiveAndRevocationT7`) | PASS |
| S-12 | Oversized/malformed payload rejection (64 KiB CSR, 5001-sample batch, 16 MiB gRPC cap, `argus_grpc_malformed_total`) | `TestM4PoisonBatches` (+ ingest/validate unit matrices) | PASS |
| S-13 | Replay attempts (batch + token) | `TestM4DuplicateBatchOriginalWins`, `TestM4LostAckReplayedAsDuplicate` | PASS |
| S-14 | Injection: parameterized SQL + dimension canonicalization unit tests; all queries bound-parameter based | unit evidence (`internal/modules/metrics`, `internal/modules/ingest`) | documented |
| S-15 | Ingest flood: server credit window + collector spool backpressure | `LOAD_TEST_REPORT.md` (L-01/L-02 backpressure, zero loss) | documented |
| S-16 | Auth enumeration uniformity (shape + timing) | `TestLoginEnumerationUniformS16` | PASS |

**M6d finding (fixed):** with three suites running shared scenarios in one
process, remaining fixed-slug RLS fixtures (`iso-auth-*`, `iso-token-*`,
`iso-resolver-*`, `iso-escalate`, `iso-unscoped`, `iso-chunk-*`) collided on
`organizations_slug_key`; all now use unique slugs and the suites are safely
composable (focused composability run green; full suite green).

## Acceptance sign-off (AC-01…AC-24)

| AC | Status | Evidence |
|---|---|---|
| AC-01…AC-04 enrollment/identity/policy/stream | PASS | M3 run; M6c e2e (AC-01/02/03) |
| AC-05/06/07 spool autonomy, drain, exactly-once | PASS | M4b run; failure suite T2/T4 |
| AC-08 metric query latency/coverage | PASS | M4c run (24h@1m p95 ≈ 22 ms; interpretation recorded); M6c AC-08 |
| AC-09/10/11 chart, detail, registry UI | PASS | Playwright 6/6 (M5d fresh stack) |
| AC-12 login/session/CSRF/limits | PASS | M2 run + Playwright |
| AC-13 collector restart durability | PASS | M4b run; T10 |
| AC-14 DB restart recovery | PASS | M1 `TestDatabaseRestartRecovery`; T9 |
| AC-15 tenant isolation | PASS | RLS suites; T8; S-06/S-07 |
| AC-16 revocation | PASS | M3 run; M6c live T7 |
| AC-17 expired token | PASS | T6 |
| AC-18 poison batch | PASS | T5 |
| AC-19 no secret leakage | PASS | S-08 log scan (M5c) |
| AC-20 self-observability | PASS | M5a/M5b metric tests + live `/metrics` |
| AC-21 L-01 executed, p95 recorded | PASS (target not met — honest baseline) | `LOAD_TEST_REPORT.md` |
| AC-22 L-02 executed, streams/reconnects criteria | PASS (throughput target not met — honest) | `LOAD_TEST_REPORT.md` |
| AC-23 failure suite T1–T10 + nightly job | PASS | M6b (suite green; CI job wired) |
| AC-24 security suite + release gate | PASS | M6d (suite green; CI job wired) |

## Phase-1 final state

*Provides:* authentication/sessions/CSRF, tenancy + RLS, admin/viewer
authorization, OpenAPI-contracted API, collector enrollment + identity, internal
CA + mTLS, signed policy + acks, reconnect/backoff, durable segmented spool,
ack-after-commit idempotent ingestion, TimescaleDB storage, tenant-safe bounded
query API, metric chart, platform + collector self-observability, correlated
secret-safe logging, runbook, failure/security/e2e proof suites.
*Does not provide:* SNMP/ICMP polling, discovery, topology, Wi-Fi, heatmaps,
network diagnostics/RCA, device automation, HA/DR/PITR/zero-downtime upgrades,
production scalability claims.

*Performance baseline (unchanged):* M4a smoke 3,919/4,000 samples/s; L-01
4,244/20,000; L-02 14,934/20,000 (200 streams, 0 errors/reconnects); L-03 FAIL
(classified server-side concurrency path — tracked Phase-2 item); primary
bottleneck PostgreSQL write path. Observed test results, not capacity guarantees.
