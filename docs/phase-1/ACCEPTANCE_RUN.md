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
