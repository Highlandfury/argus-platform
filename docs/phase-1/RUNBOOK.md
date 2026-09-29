# ARGUS PHASE-1 RUNBOOK (Development Operations)

Operator document for the Phase-1 walking skeleton. It describes how to run,
verify, and recover the system **as it is actually implemented** in this
repository. Production claims are deliberately absent: Phase 1 is a single-node
development topology (one Docker host, no HA, no PITR, no zero-downtime
upgrades).

Conventions used below:
- `<repo>` is the repository root (e.g. `C:\Users\you\Desktop\argus-platform`).
- `.\scripts\dev.ps1 <action>` = Windows entrypoint; `make <target>` = Linux/WSL.
- Compose file: `deployments/compose/docker-compose.dev.yml` (project `argus-dev`).
- `ARGUS_DEV_ADMIN_PASSWORD` defaults to `dev-admin-changeme` (dev only).

---

## 1. System overview

| Component | Purpose |
|---|---|
| `db` | PostgreSQL 18 + TimescaleDB 2.30.1 (pinned image), RLS-enforced schema |
| `migrate` | one-shot migration job (`argus-server migrate`), retries PostgreSQL first-boot races |
| `seed` | one-shot dev seed (org `dev`, site `HQ`, admin login, dev enrollment token) |
| `server` | API `:8080`, ops `:9090`, enrollment gRPC `:8444`, collector stream mTLS `:8443` |
| `collector` | edge agent: enrollment, signed policy, CPU metric → durable spool → mTLS stream; loopback metrics `127.0.0.1:9091` |
| `web` | Next.js UI `:3000` (login, collectors, detail + metric chart) |

Data lives in Docker volumes: `db-data`, `collector-data` (identity + spool),
`ca-data` (internal CA, policy signing key, dev enrollment token file).

---

## 2. Ports and endpoints

| Endpoint | Where | Notes |
|---|---|---|
| `http://127.0.0.1:3000` | web UI | login `dev` / `admin@dev.local` / env password |
| `http://127.0.0.1:8080/v1/healthz` | API liveness | process alive |
| `http://127.0.0.1:8080/v1/readyz` | API readiness | DB + auth role + schema current; 503 otherwise |
| `http://127.0.0.1:9090/metrics` | ops | §15 platform metrics |
| `8443` / `8444` | published | collector stream (mTLS) / enrollment (token-gated TLS) |
| `5432` | published | PostgreSQL (dev credentials in compose; never production) |
| `127.0.0.1:9091` | **loopback inside the collector container only** | collector self-observability; not published, not reachable from other containers |

Inspect the collector endpoint (debug image attached to the collector's network
namespace):
```powershell
docker run --rm --network container:argus-dev-collector-1 curlimages/curl:latest -s http://127.0.0.1:9091/metrics
```

---

## 3. Startup

**Purpose:** bring the whole Phase-1 stack up.
**Prerequisites:** Docker Desktop running (`docker run --rm hello-world`).
**Commands:**
```powershell
cd <repo>
.\scripts\dev.ps1 up          # = docker compose up -d --build --wait
```
**Expected:** `db`, `server`, `collector`, `web` healthy; `migrate`/`seed` exited 0.
**Failure symptoms:** `migrate` exits non-zero; `--wait` times out.
**Next diagnostic:** `.\scripts\dev.ps1 logs`, then section 8.
**Data-loss implications:** none (builds/boots only).
**Recovery:** re-run `up`; a failed one-shot job is retried by Compose.

## 4. Shutdown / restart

```powershell
.\scripts\dev.ps1 down                 # stop, keep volumes
docker compose -f deployments\compose\docker-compose.dev.yml restart server
docker compose -f deployments\compose\docker-compose.dev.yml restart collector
```
Server shutdown is graceful: HTTP drains, live collector streams receive
`Disconnect{CODE_SERVER_SHUTDOWN}`, DB pools close. The collector flushes the
batcher, fsyncs the spool, then exits; on restart it resumes from the spool
watermark (unacked records are re-sent; the server deduplicates).

## 5. Health / readiness verification

```powershell
curl.exe http://127.0.0.1:8080/v1/healthz     # {"status":"ok",...}
curl.exe http://127.0.0.1:8080/v1/readyz      # DB + auth + schema; 503 when not ready
(Invoke-WebRequest -UseBasicParsing http://127.0.0.1:9090/metrics).Content -split "`n" |
  Select-String '^argus_collectors|^argus_grpc_streams_active|^argus_ingest_batches_total'
```
Readiness answers a different question than liveness: `healthz` = process,
`readyz` = dependencies. **Failure symptoms:** `readyz` 503 → read the body
check names; `database` failing → section 8.

## 6. Database verification

```powershell
docker compose -f deployments\compose\docker-compose.dev.yml exec db psql -U argus_owner -d argus -t -c `
  "SELECT version, dirty FROM schema_migrations;
   SELECT count(*) FROM metric_samples;
   SELECT status, count(*) FROM collectors GROUP BY status;"
```
Expected: `version = 7`, `dirty = f`. Dev credentials: owner `argus_owner`,
app `argus_app_login`, auth `argus_auth_login`, password `devpass` (dev only).

## 7. Collector verification

```powershell
docker compose -f deployments\compose\docker-compose.dev.yml logs collector --tail 30
docker compose -f deployments\compose\docker-compose.dev.yml run --rm collector doctor
```
`doctor` prints: config OK, data dir, pinned CA, identity (collector id, cert
expiry, policy version), spool accounting (records/bytes/acked/highest/
dropped/corrupt), stream reachability. Expected on a healthy dev stack:
identity present, `policy_v1`, `spool` counters consistent, `stream addr : OK`.

## 8. Common failures and recovery

### 8.1 PostgreSQL 18 volume layout (historical M0 defect)
The volume must mount **`/var/lib/postgresql`** (PG18 layout; `PGDATA` is
`/var/lib/postgresql/18/docker`). The pre-18 path `/var/lib/postgresql/data`
makes the PG18 entrypoint refuse the "foreign" data. Enforced by
`.\scripts\check-compose.ps1`. Recovery from an old revision: section 12
(dev-only reset).

### 8.2 Init-script mount masking
`/docker-entrypoint-initdb.d` must be mounted as **files**
(`../../scripts/db-init/01-roles.sql:/docker-entrypoint-initdb.d/01-roles.sql`),
never as a directory — a directory mount hides the image's own init scripts
(TimescaleDB install/tuning). Also enforced by `check-compose`.

### 8.3 TimescaleDB first-boot readiness
On a fresh volume the PostgreSQL image starts a temporary server, tunes, then
restarts; short-lived jobs can hit "the database system is shutting down".
`argus-server migrate` retries connection-class failures for ~90 s, so a normal
fresh boot succeeds. If `migrate` still fails:
```powershell
docker compose -f deployments\compose\docker-compose.dev.yml up -d migrate
```

### 8.4 Docker published-port problems
If `up` reports a port is already allocated, another process/stack owns
`3000/8080/8443/8444/9090/5432`. Find it with `docker ps` / `netstat -ano |
findstr :8080`, stop the other instance, or change the host-side port mapping
locally. Do not disable Docker Desktop networking.

### 8.5 Server/unreachable database
`readyz` returns 503 with the failing check; API routes answer 503 for
unavailable services; ingest returns `STATUS_RETRY` (no ack — the collector
keeps the data). Recovery: restore the `db` container, then `up -d --wait`.

### 8.6 Collector spool troubleshooting
Spool lives in the `collector-data` volume (`/var/lib/argus/spool`):
`state.json` (watermark counters), `seg-*.wal` (framed records),
`deadletter/` (server-rejected batches), `*.corrupt-*` (quarantined segments).
Use `doctor` for the summary. Distinguish states:
- **pending** — `spool_records > 0`, `acked < highest`: normal transport lag;
  drains when the server is reachable.
- **acked** — watermark advances; segments are unlinked when fully acked.
- **dropped** — `dropped_records_total > 0`: capacity pressure dropped the
  oldest segment (loud log line, counted, never silent). Investigate spool
  growth: is the server up? is the query/stream healthy?
- **corrupt** — `corrupt_records_total > 0`: torn tail truncated or a sealed
  segment quarantined (`*.corrupt-*` preserved for inspection). Repeated
  corruption on the same host suggests storage problems.

### 8.7 Certificate / enrollment issues
- **expired enrollment token** — server answers uniform `PERMISSION_DENIED`
  ("enrollment failed"); create a fresh token in the UI (Collectors → Create
  enrollment).
- **already-used token** — same uniform denial; tokens are one-time. Operator
  flow: fresh token; collector name must be free (rename/delete pending record
  if it collides).
- **revoked collector** — the live stream terminates with `CODE_REVOKED`; the
  collector stops permanently (by design) and exits 0. Re-enrollment requires a
  fresh token and removing the collector's data dir (dev: section 12).
- **bad CA / trust mismatch** — collector logs a TLS failure and never streams;
  distribute the server's `root.pem` (compose: `ca-data` volume) and set
  `ARGUS_COLLECTOR_CA_FILE`.
- **certificate mismatch** — the server rejects hello/claim mismatches with
  `CODE_PROTOCOL_ERROR` and logs both IDs.

### 8.8 Query issues
Phase-1 query bounds: `metric` restricted to the catalog
(`collector_cpu_percent`), `step ∈ {raw,10s,1m,5m}`, window ≤ 24 h, ≤ 2000
points (422 `query.points_exceeded`), 5 s server timeout (504 `query.timeout`).
Known lessons: wide-window queries over multi-million-sample series are
raw-scan bound (no continuous aggregates in Phase 1); the planner needs fresh
statistics after bulk loads — run `ANALYZE metric_samples;` (documented M4c
finding). This is not a production-scale database architecture.

## 9. Collector operations

```powershell
# enroll explicitly (token from the UI; not needed for the dev collector)
docker compose -f deployments\compose\docker-compose.dev.yml run --rm collector enroll -token arg_enr_...
# start / stop / restart
... run -d collector        # or: restart collector
... stop collector
# inspect
... run --rm collector doctor
# revoke (UI: collector detail → Revoke; API shown in §11)
```
Identity inspection (no secrets printed): `doctor` shows collector id, cert
expiry, policy version. Re-enroll requires a fresh token and an empty data dir.

## 10. Server operations

```powershell
docker compose -f deployments\compose\docker-compose.dev.yml up -d --build server
docker compose -f deployments\compose\docker-compose.dev.yml logs -f server
... exec server /argus-server version        # optional
```
Migration state: §6. Graceful shutdown: `stop server` (see §4).

## 11. Security operations

- **Dev credentials** (never in production): admin `admin@dev.local` /
  `dev-admin-changeme` (`ARGUS_DEV_ADMIN_PASSWORD`), DB password `devpass`.
- **Enrollment tokens** (`arg_enr_…`): shown exactly once at creation; stored
  server-side only as SHA-256. The dev seed writes one to the shared
  `ca-data` volume for the dev collector — delete the file after use.
- **Certificates / CA**: `ca-data` holds `root.pem`, root key, policy signing
  key, server cert (0600 keys). Distribute only `root.pem` to collectors.
- **Revocation**: UI/API revocation is terminal for the stream and marks the
  certificate revoked. Audit entry = server log line with `CODE_REVOKED`.
- **Log handling**: logs are structured JSON and secret-scanned by tests
  (S-08); never paste raw tokens/keys into tickets. Forbidden content is
  enumerated in `ACCEPTANCE_RUN.md` (M5c section).
- **Tenant isolation**: every API path is tenant-scoped (404 without oracle);
  cross-tenant probes are covered by the RLS suite and metric-query tests.
  Ops endpoints (`/metrics`, `/healthz`, `/readyz` on `:9090`) are for the
  operator; `:9091` is loopback-only inside the collector container.
- **mTLS assumption**: the collector stream trusts only the internal CA; a
  client cert from another CA is rejected at the TLS layer.

## 12. Development reset (DEVELOPMENT ONLY)

`.\scripts\dev.ps1 reset` (`docker compose … down -v --remove-orphans`)
**destroys all dev Docker volumes**: the database (`db-data`), the collector's
identity + spool (`collector-data`), and the internal CA + dev token
(`ca-data`). It is not a production recovery procedure and cannot be used to
recover production data. After reset, `.\scripts\dev.ps1 up` re-bootstraps
everything (migrate → seed → server → collector self-enroll).

## 13. Backup / restore (Phase-1 scope)

Development-only logical backup:
```powershell
docker compose -f deployments\compose\docker-compose.dev.yml exec -T db `
  pg_dump -U argus_owner -d argus --format=custom -f /tmp/argus.dump
docker cp argus-dev-db-1:/tmp/argus.dump .\argus.dump
```
Restore into a **reset** stack (or a new database):
```powershell
docker cp .\argus.dump argus-dev-db-1:/tmp/argus.dump
docker compose -f deployments\compose\docker-compose.dev.yml exec -T db `
  pg_restore -U argus_owner -d argus --clean --if-exists /tmp/argus.dump
```
Expected: row counts match §6. **No PITR, no replication, no HA, no
zero-downtime restore** — those are not implemented in Phase 1. Collectors
re-upload unacked spool data after a restore; server-side idempotency makes
replays safe.

## 14. Migration operations

Apply: `docker compose … up -d migrate` (or `docker compose … run --rm migrate`).
Inspect: `SELECT version, dirty FROM schema_migrations;`. Recovery of a dirty
state is a development procedure: inspect the failing migration output, fix the
cause, then use the pinned `golang-migrate` CLI (v4.20.1) against `migrations/`
with the owner DSN (`force <version>` / `down 1` / `up 1`). Do not hand-edit
schema objects outside the migration files.

## 15. Observability checklist (run before debugging a customer network)

- [ ] `healthz` 200 · `readyz` 200
- [ ] `argus_collectors{status="active"}` counts the expected collectors;
      no unexpected `stale`
- [ ] `argus_grpc_streams_active` matches connected collectors
- [ ] heartbeat age for each active collector ≤ 90 s
      (`argus_collector_last_heartbeat_age_seconds`)
- [ ] `argus_ingest_batches_total{status="ok"}` advancing;
      `samples_total{status="accepted"}` advancing
- [ ] spool stable: collector `argus_collector_spool_records` near zero,
      `dropped_total`/`corrupt_total` flat at 0
- [ ] query API latency nominal (see M4c evidence) and the browser chart
      shows current data
- [ ] no `query.points_exceeded`/`query.timeout` storms in server logs

## 16. Fresh-development smoke (canonical)

```powershell
.\scripts\dev.ps1 reset
.\scripts\dev.ps1 up                # waits for healthy
# login + collect + query + chart: run the browser suite
cd web; npx playwright test
```
Expected: collector `dev-collector` active, samples advancing, 6/6 Playwright
tests green (login, registry, metrics chart, failure states, enrollment token).
