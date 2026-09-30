# Argus â€” Network Observability Platform

Implementation repository for the Argus platform. The canonical architecture and the
Phase-1 engineering specification live alongside this repo:

- Architecture package: `../argus-platform-spec/ARCHITECTURE.md`
- Phase-1 spec: `docs/phase-1/PHASE_1_SPEC.md` (file plan, acceptance, security,
  failure tests, load test, ADR review â€” all in `docs/phase-1/`)

## Status

**Phase 1 â€” Walking Skeleton. M0â€“M5 complete (functional + self-observability + operations).**

| Milestone | State |
|---|---|
| M0 scaffold, health/metrics endpoints, config/logging/telemetry, CI | âœ… |
| M1 schema + RLS + migrations + idempotency + seed | âœ… |
| M2 identity API (login/logout/me, CSRF, rate limits) + OpenAPI contract gate + minimal web UI | âœ… |
| M3 enrollment + collector identity + mTLS control plane + collectors UI + live stack bootstrap | âœ… |
| M4 metric spine (producer â†’ durable spool â†’ ingest â†’ query API â†’ chart) + load baseline | âœ… |
| M5 self-observability (Â§15 metrics, collector :9091), correlation + S-08 log scan, runbook | âœ… |
| M6 formal acceptance-run closure (e2e harness, k6 L-03, nightly failure suite) | pending |

Operational procedures live in **`docs/phase-1/RUNBOOK.md`** (startup, recovery,
backup/restore, collector/spool/certificate troubleshooting, operational checklist).
Phase-1 performance results are **observed test measurements, not product capacity
guarantees** â€” see the load section of `docs/phase-1/ACCEPTANCE_RUN.md`.

## Prerequisites

| Tool | Version | How |
|---|---|---|
| Go | 1.27.1 | user-local copy in `.tools\go` (already installed) â€” or `winget install GoLang.Go` |
| Node.js | 24.21.0 LTS | install from nodejs.org (host already matches) |
| **Docker Desktop** | â‰¥ 27 / Compose v2 | `winget install -e --id Docker.DockerDesktop` (needs WSL2; see below) |
| git | â‰¥ 2.40 | host |

Docker Desktop (Windows): run `wsl --install` once (admin, may need a reboot), then
`winget install -e --id Docker.DockerDesktop`. Verify: `docker run --rm hello-world`.

## Quickstart (fresh machine â†’ running Phase-1 stack)

Prerequisites: Windows 10/11 + WSL2, Docker Desktop running, Git, Node.js 24
(`node --version`), and the bundled Go toolchain in `.tools\go` (already in the
repo). For a completely fresh clone:
```powershell
git clone <repo-url> argus-platform        # or unzip the delivered repo
cd argus-platform
docker run --rm hello-world                # Docker Desktop sanity check
.\scripts\dev.ps1 up                       # db -> migrate -> seed -> server -> collector -> web (waits for healthy)
start http://127.0.0.1:3000                # browser: login dev / admin@dev.local
#   password: dev-admin-change-me (ARGUS_DEV_ADMIN_PASSWORD; development only)
```
In the browser: sign in â†’ **Collectors** â†’ **dev-collector** â†’ the metric chart
shows live `collector_cpu_percent` (current value, freshness, 15m/1h/6h/24h
ranges). API spot-check: `curl.exe http://127.0.0.1:8080/v1/readyz`.
Stop with `.\scripts\dev.ps1 down` (keeps data) or `.\scripts\dev.ps1 reset`
(development-only: destroys all dev volumes).

The dev stack is **self-enrolling**: `seed-dev` mints a one-time enrollment credential into the
shared CA volume (`ca-data`), the server writes its internal CA there, and the collector container
pins that CA and enrolls on first start (`dev-collector` appears as `active` in the UI). A pristine
reset (`dev.ps1 reset` then `up`) re-provisions the whole chain end-to-end.
Detailed procedures: **`docs/phase-1/RUNBOOK.md`**.

## Troubleshooting (lessons from M0â€“M5)

- **PostgreSQL 18 volume layout:** the db volume must mount `/var/lib/postgresql`
  (the pre-18 `/var/lib/postgresql/data` is rejected as "foreign data"). Enforced
  by `.\scripts\dev.ps1 check-compose`.
- **Init-script mount masking:** `/docker-entrypoint-initdb.d` is mounted as
  *files*, never as a directory â€” a directory mount hides the image's own
  TimescaleDB init/tuning scripts.
- **TimescaleDB first boot:** the image's temporary init server restarts after
  tuning; `argus-server migrate` retries connection-class failures (~90 s), so a
  fresh `up` is stable. If `migrate` still fails: `docker compose â€¦ up -d migrate`.
- **Docker published ports:** `3000/8080/8443/8444/9090/5432` are fixed; a
  "port is already allocated" error means another stack/process owns one. Stop
  it (`docker ps`) â€” do not reconfigure Docker networking to "fix" it.
- **Collector spool:** inspect with
  `docker compose â€¦ run --rm collector doctor` and the loopback endpoint
  `127.0.0.1:9091` (see RUNBOOK Â§8.6). `dropped_total`/`corrupt_total` moving is
  always logged and counted, never silent.
- **Enrollment/certificates:** expired/used tokens return one uniform denial
  (create a fresh token in the UI); revoked collectors terminate permanently
  (re-enroll requires a fresh token + empty data dir); trust mismatches fail at
  the TLS layer (distribute `root.pem` from the `ca-data` volume).
- **Query limits/planner:** `collector_cpu_percent` only, step âˆˆ
  {raw,10s,1m,5m}, â‰¤24 h, â‰¤2000 points, 5 s timeout; after bulk loads run
  `ANALYZE metric_samples;` (M4c finding). Phase-1 query performance is a
  measured development baseline, not a scale claim.

## Repository map

```text
cmd/argus-server         control plane: API + ops + enrollment :8444 + collector stream :8443 (mTLS)
cmd/argus-collector      edge agent: identity, policy, enrollment, mTLS control stream
internal/platform/       config, logging, telemetry, httpx (problem+json, request IDs, idempotency)
internal/api/            route wiring
internal/collector/      collector runtime (state machine, identity, policy, enroll/stream clients)
internal/modules/        domain modules (collectors arrive in M3)
proto/                   collector.proto (normative wire contract)
gen/                     committed protobuf/gRPC stubs (regenerate with `make proto`; CI drift-checks)
openapi/                 argus.v1.yaml (normative API contract)
migrations/              schema migrations (000001â€“000007)
deployments/compose/     dev stack + Dockerfiles
scripts/                 dev.ps1, env.sh, install-tools.ps1, db-init
docs/phase-1/            Phase-1 specification set (SPEC, FILE_PLAN, ACCEPTANCE, â€¦) + RUNBOOK.md
```

Linux/WSL: use `make` (`make check`, `make dev`, `make versions`); source
`scripts/env.sh` to put `.tools` on PATH.

## Environment variables (server)

| Variable | Default | Purpose |
|---|---|---|
| `ARGUS_ENV` | `dev` | `dev` or `prod` |
| `ARGUS_SERVER_HTTP_ADDR` | `:8080` | public API listener |
| `ARGUS_SERVER_OPS_ADDR` | `:9090` | ops listener (`/metrics`, health) |
| `ARGUS_SERVER_GRPC_ADDR` / `ARGUS_SERVER_ENROLL_ADDR` | `:8443` / `:8444` | collector stream (mTLS) / enrollment (token-gated TLS) |
| `ARGUS_SERVER_GRPC_SANS` | `localhost,server,127.0.0.1` | DNS/IP SANs for the listener certificate |
| `ARGUS_SERVER_CA_DIR` | `./.dev/ca` | internal CA + server cert + policy signing key |
| `ARGUS_SERVER_DB_DSN` | â€” | runtime role (`argus_app_login`) |
| `ARGUS_SERVER_AUTH_DB_DSN` | â€” | pre-auth lookup role (`argus_auth_login`) |
| `ARGUS_SERVER_MIGRATE_DSN` | â€” | owner role (migrations only) |

Collector variables (subset): `ARGUS_COLLECTOR_SERVER` (enrollment URL),
`ARGUS_COLLECTOR_STREAM` (host:port), `ARGUS_COLLECTOR_CA_FILE` (pinned server CA,
required), `ARGUS_COLLECTOR_NAME`, `ARGUS_ENROLL_TOKEN` / `ARGUS_ENROLL_TOKEN_FILE`,
`ARGUS_COLLECTOR_DATA_DIR`, `ARGUS_COLLECTOR_SPOOL_MAX_BYTES`,
`ARGUS_COLLECTOR_FSYNC_INTERVAL_MS`, `ARGUS_COLLECTOR_METRICS_ADDR`
(loopback-only collector metrics, default `127.0.0.1:9091`).

## Golden rules (from the spec)

1. No floating versions anywhere (`docs/phase-1/VERSIONS.md`).
2. No acknowledgment before durability (ingest ACKs only after COMMIT â€” M4).
3. Every tenant query goes through `SET LOCAL app.current_org` (M1).
4. Slices are implement â†’ test â†’ verify â†’ document; see `docs/phase-1/PHASE_1_FILE_PLAN.md`.
