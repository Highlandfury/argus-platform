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
- `ARGUS_DEV_ADMIN_PASSWORD` defaults to `dev-admin-change-me` (dev only).

---

## 1. System overview

| Component | Purpose |
|---|---|
| `db` | PostgreSQL 18 + TimescaleDB 2.30.1 (pinned image), RLS-enforced schema |
| `migrate` | one-shot migration job (`argus-server migrate`), retries PostgreSQL first-boot races |
| `seed` | one-shot dev seed (org `dev`, site `HQ`, admin login, dev enrollment token) |
| `server` | API `:8080`, ops `:9090`, enrollment gRPC `:8444`, collector stream mTLS `:8443` |
| `collector` | edge agent: enrollment, signed policy, CPU metric â†’ durable spool â†’ mTLS stream; loopback metrics `127.0.0.1:9091` |
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
| `http://127.0.0.1:9090/metrics` | ops | Â§15 platform metrics |
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
`readyz` = dependencies. **Failure symptoms:** `readyz` 503 â†’ read the body
check names; `database` failing â†’ section 8.

## 6. Database verification

```powershell
docker compose -f deployments\compose\docker-compose.dev.yml exec db psql -U argus_owner -d argus -t -c `
  "SELECT version, dirty FROM schema_migrations;
   SELECT count(*) FROM metric_samples;
   SELECT status, count(*) FROM collectors GROUP BY status;"
```
Expected: `version = 7`, `dirty = f`. Dev credentials: owner `argus_owner`,
app `argus_app_login`, auth `argus_auth_login`, password `dev-db-change-me` (dev only).

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
never as a directory â€” a directory mount hides the image's own init scripts
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
unavailable services; ingest returns `STATUS_RETRY` (no ack â€” the collector
keeps the data). Recovery: restore the `db` container, then `up -d --wait`.

### 8.6 Collector spool troubleshooting
Spool lives in the `collector-data` volume (`/var/lib/argus/spool`):
`state.json` (watermark counters), `seg-*.wal` (framed records),
`deadletter/` (server-rejected batches), `*.corrupt-*` (quarantined segments).
Use `doctor` for the summary. Distinguish states:
- **pending** â€” `spool_records > 0`, `acked < highest`: normal transport lag;
  drains when the server is reachable.
- **acked** â€” watermark advances; segments are unlinked when fully acked.
- **dropped** â€” `dropped_records_total > 0`: capacity pressure dropped the
  oldest segment (loud log line, counted, never silent). Investigate spool
  growth: is the server up? is the query/stream healthy?
- **corrupt** â€” `corrupt_records_total > 0`: torn tail truncated or a sealed
  segment quarantined (`*.corrupt-*` preserved for inspection). Repeated
  corruption on the same host suggests storage problems.

### 8.7 Certificate / enrollment issues
- **expired enrollment token** â€” server answers uniform `PERMISSION_DENIED`
  ("enrollment failed"); create a fresh token in the UI (Collectors â†’ Create
  enrollment).
- **already-used token** â€” same uniform denial; tokens are one-time. Operator
  flow: fresh token; collector name must be free (rename/delete pending record
  if it collides).
- **revoked collector** â€” the live stream terminates with `CODE_REVOKED`; the
  collector stops permanently (by design) and exits 0. Re-enrollment requires a
  fresh token and removing the collector's data dir (dev: section 12).
- **bad CA / trust mismatch** â€” collector logs a TLS failure and never streams;
  distribute the server's `root.pem` (compose: `ca-data` volume) and set
  `ARGUS_COLLECTOR_CA_FILE`.
- **certificate mismatch** â€” the server rejects hello/claim mismatches with
  `CODE_PROTOCOL_ERROR` and logs both IDs.

### 8.8 Query issues
Phase-1 query bounds: `metric` restricted to the catalog
(`collector_cpu_percent`), `step âˆˆ {raw,10s,1m,5m}`, window â‰¤ 24 h, â‰¤ 2000
points (422 `query.points_exceeded`), 5 s server timeout (504 `query.timeout`).
Known lessons: wide-window queries over multi-million-sample series are
raw-scan bound (no continuous aggregates in Phase 1); the planner needs fresh
statistics after bulk loads â€” run `ANALYZE metric_samples;` (documented M4c
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
# revoke (UI: collector detail â†’ Revoke; API shown in Â§11)
```
Identity inspection (no secrets printed): `doctor` shows collector id, cert
expiry, policy version. Re-enroll requires a fresh token and an empty data dir.

## 10. Server operations

```powershell
docker compose -f deployments\compose\docker-compose.dev.yml up -d --build server
docker compose -f deployments\compose\docker-compose.dev.yml logs -f server
... exec server /argus-server version        # optional
```
Migration state: Â§6. Graceful shutdown: `stop server` (see Â§4).

## 11. Security operations

- **Dev credentials** (never in production): admin `admin@dev.local` /
  `dev-admin-change-me` (`ARGUS_DEV_ADMIN_PASSWORD`), DB password `dev-db-change-me`.
- **Enrollment tokens** (`arg_enr_â€¦`): shown exactly once at creation; stored
  server-side only as SHA-256. The dev seed writes one to the shared
  `ca-data` volume for the dev collector â€” delete the file after use.
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

`.\scripts\dev.ps1 reset` (`docker compose â€¦ down -v --remove-orphans`)
**destroys all dev Docker volumes**: the database (`db-data`), the collector's
identity + spool (`collector-data`), and the internal CA + dev token
(`ca-data`). It is not a production recovery procedure and cannot be used to
recover production data. After reset, `.\scripts\dev.ps1 up` re-bootstraps
everything (migrate â†’ seed â†’ server â†’ collector self-enroll).

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
Expected: row counts match Â§6. **No PITR, no replication, no HA, no
zero-downtime restore** â€” those are not implemented in Phase 1. Collectors
re-upload unacked spool data after a restore; server-side idempotency makes
replays safe.

## 14. Migration operations

Apply: `docker compose â€¦ up -d migrate` (or `docker compose â€¦ run --rm migrate`).
Inspect: `SELECT version, dirty FROM schema_migrations;`. Recovery of a dirty
state is a development procedure: inspect the failing migration output, fix the
cause, then use the pinned `golang-migrate` CLI (v4.20.1) against `migrations/`
with the owner DSN (`force <version>` / `down 1` / `up 1`). Do not hand-edit
schema objects outside the migration files.

## 15. Observability checklist (run before debugging a customer network)

- [ ] `healthz` 200 Â· `readyz` 200
- [ ] `argus_collectors{status="active"}` counts the expected collectors;
      no unexpected `stale`
- [ ] `argus_grpc_streams_active` matches connected collectors
- [ ] heartbeat age for each active collector â‰¤ 90 s
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

---

## 17. CI runner (self-hosted)

**Status note (2026-09-30):** this repository was blocked by a billing lock that made GitHub refuse to start *any* Actions job â€” including on
self-hosted runners â€” until the payment issue is resolved in *Settings â†’
Billing & plans*. This repository is now **public**, which resolved the block:
the complete `ci` sweep runs on the self-hosted runner. First fully green run:
**`36689174067`** (commit `5f7262f`, 2026-09-30): all ten jobs success
(`failure-suite` is skipped on push events; it runs nightly/release via
`workflow_dispatch`). Getting there surfaced three CI-only issues, all fixed in
the commits above: host-port conflicts and shared volumes with the local dev
stack, the db-init bind mount not existing on the Docker host, and AC-08
needing the collector container in the e2e stack.
The identical gates remain runnable locally:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ci-local.ps1
# defaults: fmt, vet, build, test, lint, proto
# add: -Race (Linux/WSL), -WithSuites, -WithStack, -WithWeb
```

(The bypass is needed because this host's PowerShell execution policy blocks
direct `.ps1` invocation; `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
is the persistent alternative.)

**Purpose:** run the repository's GitHub Actions workflows without
GitHub-hosted minutes (the account's hosted-runner billing is locked). All jobs
in `.github/workflows/ci.yml` target the labels **`self-hosted, linux, x64,
argus`**.

**Prerequisites:** Docker Desktop running; the repository exists on GitHub; you
can open *Repo â†’ Settings â†’ Actions â†’ Runners*.

**Why a Linux-in-Docker runner:** the workflows are Bash/Docker-based
(gofmt checks, testcontainers integration suites, `docker compose` smoke/e2e).
A native Windows runner would require rewriting those steps; a Linux runner
container reuses them unchanged.

**Step 1 â€” registration token.** Repo â†’ Settings â†’ Actions â†’ Runners â†’ *New
self-hosted runner* â†’ Linux â†’ copy the `--token` value (valid ~1 hour) **or**
create a classic PAT with `repo` scope (the runner image uses it to fetch fresh
tokens at every start; store it only on your machine).

**Step 2 â€” start the runner (PowerShell):**

```powershell
docker run -d --name argus-runner --restart unless-stopped `
  -e REPO_URL="https://github.com/<owner>/<repo>" `
  -e RUNNER_TOKEN="<registration-token-or-PAT>" `
  -e RUNNER_NAME="argus-runner-1" `
  -e LABELS="self-hosted,linux,x64,argus" `
  -e RUNNER_WORKDIR="/tmp/runner/work" `
  -v //var/run/docker.sock:/var/run/docker.sock `
  -v argus-runner-work:/tmp/runner `
  myoung34/github-runner:ubuntu-noble
```

Base tags: `ubuntu-noble` (24.04, current), `ubuntu-jammy` (22.04); runner-version
pins such as `2.337.0-ubuntu-noble` exist and are preferable when the exact
agent version matters.

`ACCESS_TOKEN=<PAT>` instead of `RUNNER_TOKEN` makes restarts survive token
expiry: the image fetches a fresh registration token at every start. Use it:
a one-time `RUNNER_TOKEN` is consumed on first registration, and the runner
image deregisters and deletes its config on a graceful stop (e.g. Docker
Desktop shutdown), so the next start crash-loops with a 404 until the
container is recreated (observed 2026-09-30). Recommended PAT: fine-grained,
repository access to this repo, permission Administration: Read and write.

If queued jobs do not start while the log says `Listening for Jobs`, first
confirm the runner is genuinely idle (no `Running job:` line in
`docker logs argus-runner` - a later queued run staying queued while an
earlier run executes is normal, not a stall). Only then
`docker restart argus-runner` resyncs a stale session; jobs are picked up
within seconds (observed 2026-09-30). Never restart while a job is running:
it aborts that job with "runner lost communication" (observed 2026-10-01).

**Step 3 â€” verify.** Repo â†’ Settings â†’ Actions â†’ Runners shows
`argus-runner-1` (Idle). Then trigger any workflow (push, or *Actions â†’
security-suite â†’ Run workflow*). Inside the runner, both must work:
`docker version` and `docker compose version`.

**Isolation (added 2026-09-30):** the `compose-smoke` and `e2e` jobs run under
compose project `argus-ci` with `deployments/compose/docker-compose.ci.yml`
(published host ports are reset; the runner container joins the
`argus-ci_default` network and the steps use service DNS, e.g.
`http://server:8080`). CI therefore coexists with a running local dev stack,
and CI teardown can never delete local `argus-dev` volumes. The `compat-matrix`
service publishes on host port `15432` (not 5432) to avoid the local db, and
the job probes `host.docker.internal` before `127.0.0.1` so it works for both
containerized and host-process runners. The db init script (a file bind mount
in the dev file) cannot be bind-mounted in CI, because bind-mount sources are
resolved by the Docker host and a containerized runner's checkout is not
visible there; CI runs the same canonical `scripts/db-init/01-roles.sh` in a
`dbinit` one-shot service (built from a tiny image, executed over TCP after
the db is healthy; the script is idempotent).

**Caution / implications**
- Mounting `/var/run/docker.sock` gives the runner root-equivalent access to
  the host Docker daemon â€” acceptable on a development machine, never on a
  shared host.
- The nightly `failure-suite` (03:00 UTC) only runs when this machine and the
  runner container are up; if the runner is offline the scheduled run waits for
  a matching runner.
- Runner disk usage grows with compose builds and testcontainers images; prune
  with `docker system prune` when idle.
- Secrets: the registration token/PAT stays in the local container env â€” it is
  never committed. Revoke the PAT and delete the runner in Settings when you
  stop using it.
- **Revert:** if hosted minutes are restored, replace every `runs-on:
  [self-hosted, linux, x64, argus]` in `ci.yml` with `ubuntu-latest`.
- Uninstall: `docker rm -f argus-runner` and remove the runner entry in Repo â†’
  Settings â†’ Actions â†’ Runners.

**ICMP capability prerequisite (M9-S1, added 2026-10-01):** the polling engine
pings with a raw ICMP socket when the process holds `CAP_NET_RAW`, and falls
back to the Linux unprivileged ping socket (`net.ipv4.ping_group_range`) when
it does not. Integration/CI hosts therefore need one of the two: grant the
runner container `--cap-add NET_RAW` (or run it with the default Docker
`ping_group_range` that covers the process GID). The internal test
(`internal/collector/poll`, Linux-only) skips with the capability reason when
neither is available; the dev compose collector service is granted `NET_RAW`
explicitly.
