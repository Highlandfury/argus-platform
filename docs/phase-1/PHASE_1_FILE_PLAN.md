# PHASE-1 FILE PLAN

Companion to `PHASE_1_SPEC.md`. Every file below is created in the listed milestone; each slice follows the rule **implement → test → verify → document** before the next slice starts. "Modify" entries modify files created in an earlier milestone. Acceptance IDs reference `PHASE_1_ACCEPTANCE.md`; tests reference `PHASE_1_FAILURE_TESTS.md` (T#), `PHASE_1_SECURITY.md` (S#), `PHASE_1_LOAD_TEST.md` (L#).

---

## M0 — Scaffold & Compatibility Gate

| File | Action | Purpose | Tests / verification |
|---|---|---|---|
| `go.mod`, `go.sum` | create | Module `github.com/argus-platform/argus`, `go 1.27`, all pins from SPEC §5 | `go build ./...` |
| `.gitignore` | create | data/, gen/, .dev/, node_modules, *.pem, coverage | gitleaks clean |
| `.golangci.yml` | create | Lint profile (errcheck, govet, staticcheck, gosec, revive) | `make lint` |
| `Makefile` | create | Targets: `dev up down reset proto build test check e2e load versions doctor` | `make dev` boots stack |
| `buf.yaml`, `buf.gen.yaml` | create | Proto module + pinned plugin versions; gen output `gen/go` | `make proto` reproducible |
| `proto/argus/collector/v1/collector.proto` | create | Wire contract (already authored) | `buf lint` |
| `cmd/argus-server/main.go` | create | Subcommands `serve|migrate|seed-dev|version`; config load; graceful shutdown | `/v1/healthz` 200 |
| `cmd/argus-collector/main.go` | create | Subcommands `run|enroll|doctor|version` | `argus-collector version` |
| `internal/platform/config/config.go` | create | Env parsing + fail-fast validation | unit tests |
| `internal/platform/logging/logging.go` | create | slog JSON + request-id helper | unit tests |
| `internal/platform/telemetry/telemetry.go` | create | Prometheus registry + `go_*`/`process_*` collectors | `/metrics` non-empty |
| `internal/platform/httpx/*.go` | create | problem+json, request-id middleware, pagination, CSRF/session primitives (skeleton) | unit tests |
| `internal/api/router.go` | create | Route registration + middleware order | healthz/readyz tests |
| `deployments/compose/Dockerfile.server`, `Dockerfile.collector` | create | Multi-stage builds, distroless/static base, pinned digests | `docker compose build` |
| `deployments/compose/docker-compose.dev.yml` | create | Stack per SPEC §17; db volume uses the **PG18 image layout** (`/var/lib/postgresql`) | `make dev`; `check-compose` |
| `scripts/check-compose.ps1` + CI assert step | create (M0 fix) | Compose regression checks: db volume must target `/var/lib/postgresql` (never `/var/lib/postgresql/data`); `/docker-entrypoint-initdb.d` must never be directory-mounted (would hide image init scripts, incl. TimescaleDB extension install/tune) | `scripts/dev.ps1 check-compose`; CI `compose-smoke` |
| `.github/workflows/ci.yml` | create | Full pipeline per SPEC §16 (`compat-matrix` job included) | green on PR |
| `docs/phase-1/VERSIONS.md` | create | Generated pin matrix (`make versions`) | reviewed in PR |
| `web/` scaffold (Next 16.3.7, TS 7.0.2, ES-Lint, Playwright config) | create | App shell + API client skeleton + `/login` placeholder | `next build` in compat job |

**Exit criteria:** `make dev` brings up db→migrate(no-op)→server→collector(idle)→web; healthz/readyz semantics correct; compat-matrix green.

---

## M1 — Schema, Migrations, RLS

| File | Action | Purpose | Tests / verification |
|---|---|---|---|
| `migrations/000001_init_core.up.sql/.down.sql` | create | `organizations, sites, users, sessions`; roles `argus_app` (NOLOGIN→login-less grant target) + `argus_owner`; grants | migration up/down/up |
| `migrations/000002_collectors.up.sql/.down.sql` | create | `enrollment_tokens, collectors, collector_certificates, collector_policies` | up/down + constraint tests |
| `migrations/000003_metrics.up.sql/.down.sql` | create | `metric_series` (+partial unique index), `metric_samples` hypertable (`create_hypertable` 1-day chunks), index `(org_id, ts DESC)` | hypertable + ON CONFLICT smoke (in `compat-matrix`) |
| `migrations/000004_ingestion.up.sql/.down.sql` | create | `ingested_batches` PK + indexes | duplicate-claim test |
| `migrations/000005_rls.up.sql/.down.sql` | create | roles `argus_app` + `argus_auth` (pre-auth, BYPASSRLS, 3-table grants), grants + default privileges, enable+force RLS, all policies, `app.current_org` contract comment | RLS suite (T8 core); S-07 variant (auth-role restrictions, chunk access denied) |
| `migrations/000006_chunk_access_guard.up.sql/.down.sql` | create (M1 finding) | Chunk-level RLS: `SECURITY DEFINER` sweep function + 1-minute TimescaleDB backstop job + migration backfill; M4 ingest calls the sweep pre-commit (zero window). Event trigger and schema-revocation approaches were implemented, tested, and rejected (documented in the migration header). | `TestChunkAccessIsRLSProtected` + all isolation tests |
| `migrations/000007_collector_identity.up.sql/.down.sql` | create (M3b) | Pre-auth hooks: `enrollment_tokens` SELECT for `argus_auth` (claim/UPDATE stays tenant-side) + `argus_resolve_collector_certificate(bytea)` SECURITY DEFINER resolver granted only to `argus_auth` | `TestAuthRoleBoundaries` subtests + `TestSchemaMatchesSpec` function check |
| `internal/platform/database/pool.go` | create | pgx pool (app role); health ping | integration test |
| `internal/platform/database/tenant.go` | create | `WithTenant(ctx, orgID, fn)` — BEGIN, `SET LOCAL`, commit/rollback; error if called without tx | unit + leak test |
| `internal/platform/database/migrate.go` | create | golang-migrate runner (owner DSN) invoked by `argus-server migrate` | up/down/up job |
| `internal/modules/tenancy/{service,repo}.go` (+ `devseed.go`) | create | orgs/sites read paths; pre-auth slug resolution; idempotent dev seed. (`http.go` deferred to M2 — no unauthenticated endpoints exist in M1.) | tenant-scoped read tests; `TestSeedDevIdempotentAndIsolated` |
| `internal/platform/security/argon2.go` (+ test) | create (M1e) | Argon2id PHC hash/verify for the seeded admin credential (originally sequenced for M2; seed-dev needed it earlier) | unit tests |
| `tests/integration/seed_test.go` | create (M1e) | Seed idempotence, per-org email uniqueness, cross-tenant isolation, pre-auth slug resolution | M1 acceptance evidence |
| `docs/phase-1/ACCEPTANCE_RUN.md` | create (M1e) | Executed M1 acceptance evidence (commands + results + findings) | sign-off |
| `cmd/argus-server/seed_dev.go` | create | dev seed: org, site, admin user, dev token file | idempotent seed test |
| `tests/integration/migrations_test.go` | create | up→down→up; schema assertions | CI job 9 |
| `tests/integration/rls_test.go` | create | cross-tenant read/write denial; pooled-connection leak test (SPEC §7.2) | T8; S-06, S-07 |

**Exit criteria:** all tables match SPEC §7.1; RLS denial proven; seed works from empty DB.

---

## M2 — Identity & API Shell

| File | Action | Purpose | Tests / verification |
|---|---|---|---|
| `internal/modules/identity/{service,repo,http}.go` | create | Argon2id verify, session create/revoke, `GET /v1/me` | unit + integration |
| `internal/platform/security/argon2.go` | create | Argon2id params (m=64MiB, t=3, p=4), PHC string format — *delivered in M1e; consumed here* | unit + vectors |
| `internal/platform/security/tokens.go` | create | Random token mint, SHA-256 hash, constant-compare helper | unit |
| `internal/platform/security/csrf.go` | create | Double-submit cookie issue/verify | unit + integration |
| `internal/api/auth_routes.go` | create | `/v1/auth/login|logout`, rate limit (x/time/rate, 10/min/IP) | S-09, S-10 |
| `internal/api/middleware_session.go` | create | Session cookie auth → request context (user, org) | integration |
| `openapi/argus.v1.yaml` | create | Phase-1 contract (see SPEC §13) | `openapi lint` + route-spec check |
| `web/src/lib/api.ts` | create | Typed fetch wrapper (cookie + CSRF + problem+json) | unit |
| `web/src/app/(auth)/login/page.tsx` | create | Login form + error surfaces | Playwright AC-12 |
| `web/src/app/(app)/layout.tsx` | create | App shell: header, site selector, logout | Playwright smoke |

**Exit criteria:** login/logout/me; CSRF enforced; every subsequent endpoint requires session; OpenAPI served and lint-clean.

---

## M3 — Enrollment, Collector Identity, Control Plane

| File | Action | Purpose | Tests / verification |
|---|---|---|---|
| `internal/modules/collectors/tokens.go` | create | Token mint/validate/claim (`arg_enr_…`), TTL, one-time atomic claim | T6; S-01, S-02 |
| `internal/modules/collectors/ca.go` | create | Internal CA (generate-on-first-boot, 0600), CSR verify (P-256, signature check), 90-day issuance, chain build | unit + S-11 |
| `internal/modules/collectors/service.go` | create | Collector registry lifecycle (pending→active→stale→revoked), policy issue v1, resync, revoke | integration |
| `internal/modules/collectors/repo.go` | create | SQL for collectors/certs/policies/tokens (tenant-scoped) | integration |
| `internal/modules/collectors/enroll.go` | create | `EnrollmentService.Enroll` + rate limits + no-oracle errors (delivered name; plan said `enroll_grpc.go`) | T6; S-01–S-04 |
| `internal/platform/grpcx/fingerprint.go` | create | mTLS leaf fingerprint extraction (delivered; plan said `auth.go` — resolution runs through migration 000007's `argus_resolve_collector_certificate`, granted only to `argus_auth`) | T7; S-03, S-11 |
| `internal/modules/collectors/stream.go` | create | Stream handler: hello validation, credits, heartbeat intake, stream registry, disconnect-on-revoke | T7; AC-01–AC-04 |
| `internal/modules/collectors/policy.go` | create | Policy document build + Ed25519 sign; version bump | unit + integration |
| `internal/modules/collectors/http.go` | create | `/v1/enrollments`, `/v1/collectors`, detail, `:revoke`, `:resync` | AC-11 (partial) |
| `internal/collector/identity/store.go` (path under `cmd/argus-collector` internals per repo rules → `internal/collector/identity`) | create | Key/cert/collector.json persistence (0600), load/validate | unit |
| `internal/collector/enrollclient/client.go` | create | CSR gen, Enroll RPC, policy verify+persist | integration vs real server |
| `internal/collector/stream/client.go` | create | Connect loop, hello, heartbeat loop, backoff, disconnect handling, terminal REVOKED (delivered name; plan said `internal/collector/transport/stream.go`) + `internal/collector/state.go` explicit lifecycle machine | T3 partial; AC-03 |
| `web/src/app/(app)/collectors/page.tsx` | create | Collector list view (status, last heartbeat, version, site) | AC-11 |
| `web/src/app/(app)/collectors/[id]/page.tsx` | create | Detail view (identity/status/policy/connection/spool stats) | AC-11 |

**Exit criteria:** a real collector enrolls against the dev stack, appears in UI as `pending→active` with live heartbeat; expired/used/revoked paths behave per SPEC §8.4.

**Delivered (2026-09-29; commits M3a `ea2c7ea` · M3b `be7b891` · M3c `78406e3` · M3d `2a7356b` · M3e `b443279` + docs commit):**
- Generated protobuf/gRPC stubs are now **committed** under `gen/` with a CI drift gate (`buf generate` + `git diff --exit-code -- gen`, plus conditional `buf breaking`); protocol change **P1** (`EnrollResponse.policy_signing_public_key`) recorded and delivered.
- Extra delivered files beyond the plan: `internal/modules/collectors/{repo,policy,session,metrics,http}.go`, `internal/platform/ratelimit`, `internal/collector/{identity,enrollclient,policy,stream}`, `web/src/components/{EnrollCollectorForm,CollectorActions}.tsx`, `web/e2e/collectors.spec.ts`, compose `ca-data` volume + seed-minted dev token.
- Policy versioning: `collector_policies` holds every issued version; `collectors.policy_version` is the **acked** watermark; `POST /policy:resync` issues vN+1 and pushes it to a live stream; collectors re-verify, apply newer only, and ack either way (idempotent redelivery).
- Collector lifecycle state machine (`NEW/ENROLLING/ACTIVE/DISCONNECTED/RECONNECTING/REVOKED/FAILED`) is explicit and validated; invalid transitions are rejected (unit-tested).
- Findings fixed during M3: revoked identity returning before `ServerHello` was misclassified as a protocol error by the collector (fixed: `Disconnect` handled pre-hello); TimescaleDB first-boot init race killed the short-lived `migrate` job on fresh volumes (fixed: 90 s connection-class retry in `database.MigrateUp`).

---

## M4a — Server Ingest

| File | Action | Purpose | Tests / verification |
|---|---|---|---|
| `internal/modules/ingest/service.go` | create | Pipeline stages per SPEC §12.1; tx-per-batch; ack-after-commit; calls `public.argus_ensure_chunk_rls()` pre-commit (chunk-RLS zero-window requirement from migration 000006) | T4, T5; S-06 |
| `internal/modules/ingest/validate.go` | create | Bounds: ts ±7d, dims ≤8/64ch, batch ≤5000, value finite, policy allowlist | unit + S-08 |
| `internal/modules/ingest/stream_service.go` | create | Wire stream handler → pipeline; BatchResult emission | integration |
| `internal/modules/metrics/series.go` | create | dim canonicalization + FNV-1a dim_hash; series resolve/create (partial-unique ON CONFLICT + SELECT map); quota 1000/collector | unit + integration |
| `internal/modules/metrics/store.go` | create | `MetricStore` interface + Timescale impl (`unnest` arrays; ON CONFLICT DO NOTHING) | L-01 (headless) |
| `tests/load/gen/main.go` | create | Load generator: enrolls N collectors, streams scripted batches at target rate; histograms + CSV report | L-01, L-02 |

**Exit criteria:** duplicate batch → exactly one sample row set; REJECTED vs RETRY semantics proven; 20k samples/s headless run completes with zero errors and measured p95 commit latency.

---

## M4b — Collector Producer, Spool, Transport

| File | Action | Purpose | Tests / verification |
|---|---|---|---|
| `internal/collector/metrics/source.go` | create | `MetricSource` interface + `collector_cpu_percent` source (procfs/sys info; deterministic fallback) | unit (golden samples) |
| `internal/collector/policy/apply.go` | create | Verify (Ed25519 pinned key), schema-validate, atomic swap, ack | AC-02; S-05 |
| `internal/collector/spool/segment.go` | create | Segment file writer: framing [len][crc32c][payload], seal at 8MiB, group-fsync | unit + property tests (fuzz framing) |
| `internal/collector/spool/spool.go` | create | Public API: `Append`, `NextBatchToSend`, `Ack`, `Stats`; watermark persistence (`state.json` tmp+rename) | AC-05, AC-06, AC-13 |
| `internal/collector/spool/recovery.go` | create | Startup scan, torn-tail truncation, CRC quarantine, counters | T10; corruption unit tests |
| `internal/collector/spool/limits.go` | create | ENOSPC handling: drop-oldest, counters, degraded mode | unit (fault-injected FS) |
| `internal/collector/transport/sender.go` | create | Ordering, in-flight window, per-batch retry/backoff, dead-letter on REJECTED | T3, T4, T5 |
| `cmd/argus-collector/run.go` | modify | Wire producer→spool→transport; startup ordering per SPEC §3.5 | AC-03–AC-06 |
| `cmd/argus-collector/doctor.go` | create | Environment/identity/connectivity/spool report | manual + integration |
| `tests/integration/spool_test.go` | create | Kill/restart, torn write, duplicate replay scenarios | T2, T10 |

**Exit criteria:** collector spools during server outage and replays losslessly; restart preserves watermark; REJECTED batches never retried.

---

## M4c — Query API and Chart UI

| File | Action | Purpose | Tests / verification |
|---|---|---|---|
| `internal/modules/metrics/query.go` | create | `GET /v1/collectors/{id}/metrics`; `time_bucket` + avg; step mapping; ≤2000 points; gaps meta | AC-08; unit tests |
| `internal/modules/metrics/http.go` | create | Handler + authz + pagination-free contract | integration |
| `web/src/features/collectors/MetricChart.tsx` | create | ECharts line chart, range selector (5m/1h/24h), loading/empty/gap states | AC-09 (Playwright) |
| `web/src/app/(app)/collectors/[id]/page.tsx` | modify | Embed chart + "metrics received" summary | AC-09, AC-10 |

**Exit criteria:** end-to-end `collector → spool → server → DB → API → chart` visible in browser.

---

## M5 — Observability & Ops Polish

| File | Action | Purpose | Tests / verification |
|---|---|---|---|
| `internal/platform/telemetry/argus_metrics.go` | create | Names/gauges/histograms per SPEC §15; collector gauge refresh loop | `/metrics` snapshot diff test |
| `internal/collector/telemetry/metrics.go` | create | Collector-side metric server (:9091) + heartbeat payload assembly | integration |
| log conventions pass across modules | modify | `request_id|stream_id|batch_seq|org_id|collector_id` everywhere; secret redaction review | S-08 (log scan test) |
| `docs/phase-1/RUNBOOK.md` | create | dev DB reset, cert rotation (manual dev), spool inspection, common failure procedures | review |
| `README.md` | modify | quickstart (one command), troubleshooting links | review |

---

## M6 — Proof Suites and Acceptance

| File | Action | Purpose | Tests / verification |
|---|---|---|---|
| `tests/e2e/scenarios_test.go` | create | Harness running compose stack scenarios T1–T3, T7, T10, AC-01…AC-09 | CI job 10 |
| `tests/integration/failure_tests.go` | create | T2/T4/T5/T8/T9 automation (compose pause/stop, DB restart, duplicate injection) | CI nightly + release |
| `tests/integration/security_test.go` | create | S-01…S-12 suite (see SECURITY doc) | CI release gate |
| `tests/load/README.md` + `tests/load/k6/api.js` | create | L-03 API leg; how to run L-01/L-02 and interpret | `make load` |
| `docs/phase-1/LOAD_TEST_REPORT.md` | create | Actual measured results template (filled during M6) | reviewed |
| `docs/phase-1/ACCEPTANCE_RUN.md` | create | Executed acceptance checklist with evidence links | sign-off |

---

## Slice discipline (applies to every row above)

1. **Implement** the smallest coherent piece (one file or one vertical behavior, ≤ ~400 LOC net).
2. **Test** it at the lowest useful level + add/extend the integration case that exercises it end-to-end.
3. **Verify** by running `make check` and the milestone's specific command; capture output into the PR.
4. **Document** any decision or deviation inline (code comment + spec addendum if behavior changed).
5. Only then start the next slice. A slice that cannot state its acceptance mapping is not started.

**Definition of Ready for M1:** SPEC consistency review passed (done), file plan accepted, M0 compat-matrix green.
**Definition of Done for Phase 1:** every AC in `PHASE_1_ACCEPTANCE.md` green in CI; T/S/L suites executed; `ACCEPTANCE_RUN.md` signed.
