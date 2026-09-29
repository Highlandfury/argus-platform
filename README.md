# Argus — Network Observability Platform

Implementation repository for the Argus platform. The canonical architecture and the
Phase-1 engineering specification live alongside this repo:

- Architecture package: `../argus-platform-spec/ARCHITECTURE.md`
- Phase-1 spec: `docs/phase-1/PHASE_1_SPEC.md` (file plan, acceptance, security,
  failure tests, load test, ADR review — all in `docs/phase-1/`)

## Status

**Phase 1 — Walking Skeleton. M3 (Enrollment, Collector Identity, Control Plane) complete.**

| Milestone | State |
|---|---|
| M0 scaffold, health/metrics endpoints, config/logging/telemetry, CI | ✅ |
| M1 schema + RLS + migrations + idempotency + seed | ✅ |
| M2 identity API (login/logout/me, CSRF, rate limits) + OpenAPI contract gate + minimal web UI | ✅ |
| M3 enrollment + collector identity + mTLS control plane + collectors UI + live stack bootstrap | ✅ |
| M4 metric spine (producer → spool → ingest → chart) | next |
| M5 observability polish | |
| M6 failure/security/load suites + acceptance run | |

## Prerequisites

| Tool | Version | How |
|---|---|---|
| Go | 1.27.1 | user-local copy in `.tools\go` (already installed) — or `winget install GoLang.Go` |
| Node.js | 24.21.0 LTS | install from nodejs.org (host already matches) |
| **Docker Desktop** | ≥ 27 / Compose v2 | `winget install -e --id Docker.DockerDesktop` (needs WSL2; see below) |
| git | ≥ 2.40 | host |

Docker Desktop (Windows): run `wsl --install` once (admin, may need a reboot), then
`winget install -e --id Docker.DockerDesktop`. Verify: `docker run --rm hello-world`.

## Quickstart (Windows)

```powershell
.\scripts\dev.ps1 build     # compile server + collector into bin\
.\scripts\dev.ps1 test      # go test ./...
.\scripts\dev.ps1 up        # docker compose up (db + server + collector + web)
# UI/API:  http://127.0.0.1:8080/v1/healthz   web: http://127.0.0.1:3000
# ops:     http://127.0.0.1:9090/metrics      agent: collector gRPC :8443 (mTLS) / :8444 (enroll)
.\scripts\dev.ps1 down
```

The dev stack is **self-enrolling**: `seed-dev` mints a one-time enrollment credential into the
shared CA volume (`ca-data`), the server writes its internal CA there, and the collector container
pins that CA and enrolls on first start (`dev-collector` appears as `active` in the UI). A pristine
reset (`dev.ps1 reset` then `up`) re-provisions the whole chain end-to-end.

### Troubleshooting: stale dev database volume (PostgreSQL 18 layout)

The dev database mounts its named volume at **`/var/lib/postgresql`** — the PostgreSQL 18
image layout (the pre-18 path `/var/lib/postgresql/data` is rejected by the PG18
entrypoint as "foreign data"). If you booted an earlier revision of the stack before this
fix, delete the stale dev volume **once** (development data only — this is never a
production migration procedure):

```powershell
.\scripts\dev.ps1 reset     # docker compose down -v (removes dev volumes only)
.\scripts\dev.ps1 up
```

`.\scripts\dev.ps1 check-compose` (also enforced by CI) verifies the PostgreSQL 18
volume layout and safe init-script mounts so this class of mistake cannot return
silently.

Linux/WSL: use `make` (`make check`, `make dev`, `make versions`); source
`scripts/env.sh` to put `.tools` on PATH.

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
migrations/              schema migrations (000001–000007)
deployments/compose/     dev stack + Dockerfiles
scripts/                 dev.ps1, env.sh, install-tools.ps1, db-init
docs/phase-1/            Phase-1 specification set (SPEC, FILE_PLAN, ACCEPTANCE, …)
```

## Environment variables (server)

| Variable | Default | Purpose |
|---|---|---|
| `ARGUS_ENV` | `dev` | `dev` or `prod` |
| `ARGUS_SERVER_HTTP_ADDR` | `:8080` | public API listener |
| `ARGUS_SERVER_OPS_ADDR` | `:9090` | ops listener (`/metrics`, health) |
| `ARGUS_SERVER_GRPC_ADDR` / `ARGUS_SERVER_ENROLL_ADDR` | `:8443` / `:8444` | collector stream (mTLS) / enrollment (token-gated TLS) |
| `ARGUS_SERVER_GRPC_SANS` | `localhost,server,127.0.0.1` | DNS/IP SANs for the listener certificate |
| `ARGUS_SERVER_CA_DIR` | `./.dev/ca` | internal CA + server cert + policy signing key |
| `ARGUS_SERVER_DB_DSN` | — | runtime role (`argus_app_login`) |
| `ARGUS_SERVER_AUTH_DB_DSN` | — | pre-auth lookup role (`argus_auth_login`) |
| `ARGUS_SERVER_MIGRATE_DSN` | — | owner role (migrations only) |

Collector variables (subset): `ARGUS_COLLECTOR_SERVER` (enrollment URL),
`ARGUS_COLLECTOR_STREAM` (host:port), `ARGUS_COLLECTOR_CA_FILE` (pinned server CA,
required), `ARGUS_COLLECTOR_NAME`, `ARGUS_ENROLL_TOKEN` / `ARGUS_ENROLL_TOKEN_FILE`,
`ARGUS_COLLECTOR_DATA_DIR`, `ARGUS_COLLECTOR_SPOOL_MAX_BYTES`,
`ARGUS_COLLECTOR_FSYNC_INTERVAL_MS`.

## Golden rules (from the spec)

1. No floating versions anywhere (`docs/phase-1/VERSIONS.md`).
2. No acknowledgment before durability (ingest ACKs only after COMMIT — M4).
3. Every tenant query goes through `SET LOCAL app.current_org` (M1).
4. Slices are implement → test → verify → document; see `docs/phase-1/PHASE_1_FILE_PLAN.md`.
