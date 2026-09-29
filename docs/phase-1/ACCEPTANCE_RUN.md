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
