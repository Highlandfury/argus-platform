# VERSIONS — pinned toolchain and dependency matrix (Phase 1)

**Rule:** no floating versions. Every pin below was verified against an official source on
**2026-09-29**; transitive Go deps are pinned by `go.sum`. Regenerate with `make versions`
(and update this file in the same PR when a pin changes).

## Language toolchains

| Tool | Pin | Verified via | Notes |
|---|---|---|---|
| Go | **go1.27.1** | `go.dev/dl` JSON (stable) | Local dev copy: `.tools\go` (user-local). `go.mod` uses `go 1.27`, `toolchain go1.27.1`. |
| Node.js | **24.21.0 (LTS)** | endoflife.date API | Node 26 becomes LTS 2026-10-28; deliberately not adopted before then. |
| git | ≥ 2.40 | host | |
| Docker Engine / Compose | ≥ 27 / Compose v2 | requirement | Dev host installed & verified: Engine 29.8.1 / Compose v5.5.1 (2026-09-29). CI uses ubuntu-latest runners (Docker 27+). |

## Go module pins (direct)

| Module | Pin | Verified via |
|---|---|---|
| github.com/prometheus/client_golang | v1.24.1 | GitHub release |
| github.com/prometheus/client_model | v0.6.2 (indirect, resolved by tidy) | Go module proxy |
| github.com/google/uuid | v1.6.0 | GitHub release — added M1b (direct) |
| github.com/jackc/pgx/v5 | v5.11.0 | GitHub release — added M1b (direct pin verified) |
| github.com/golang-migrate/migrate/v4 | v4.20.1 | GitHub release — added M1a |
| github.com/testcontainers/testcontainers-go | v0.44.0 | GitHub release — added M1c (integration suite) |
| github.com/pb33f/libopenapi | v0.41.2 | Go module proxy — added M2b (OpenAPI 3.1 contract test) |
| golang.org/x/crypto | v0.57.0 | repo tags — added M1e (direct, Argon2id) |
| google.golang.org/grpc | v1.84.0 | GitHub release — added M3a (generated stubs; collector + server transports) |
| google.golang.org/protobuf | v1.36.12 (codegen and runtime aligned as of M3a) | GitHub release | Generated code is committed under `gen/`; CI checks drift via regenerate+diff. |
| github.com/stretchr/testify | (indirect via client_golang) | tidy | Direct use begins when needed; add the exact tag then. |
| golang.org/x/crypto | v0.57.0 | repo tags — added M1e (direct, Argon2id) | x/time pinned in M2.
| golang.org/x/time | v0.16.0 | repo tags — added M2b (login rate limiting) |
| golang.org/x/sync | v0.23.0 | repo tags — **added when errgroup first used** |
| github.com/google/go-cmp | v0.7.0 (indirect) | tidy |

> Note (M3a): protobuf codegen and runtime are aligned at **v1.36.12**; the older
> divergence note is retired. Generated stubs are committed under `gen/` and
> drift-checked in CI (`buf generate` + `git diff --exit-code -- gen`).## Protocol / codegen tooling (installed into .tools/bin by scripts/install-tools.ps1)

| Tool | Pin | Verified via |
|---|---|---|
| buf | v1.73.0 | GitHub release |
| protoc-gen-go | v1.36.12 | GitHub release |
| protoc-gen-go-grpc | v1.6.2 | Go module proxy `@latest` (no GitHub releases for this module) |
| golangci-lint | v2.14.0 | GitHub release + module proxy |

## CI actions (pinned by full commit SHA)

| Action | SHA | Tag |
|---|---|---|
| actions/checkout | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 |
| actions/setup-go | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | v7.0.0 |
| actions/setup-node | `2028fbc5c25fe9cf00d9f06a71cc4710d4507903` | v6.0.0 |
| golangci/golangci-lint-action | `ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a` | v9.3.0 |

## Container images

| Image | Pin | Digest | Notes |
|---|---|---|---|
| timescale/timescaledb | **2.30.1-pg18** | `sha256:9dede0e3ccc071cf71935b17f76bf243331df0b1575338c8ac294640fcf12a36` | Chosen because official `*-pg18` tags confirm PostgreSQL 18 compatibility, and 2.30.1 contains `INSERT … ON CONFLICT` conflict-handling fixes relevant to the ingest claim path. **PG18 volume layout:** mount `/var/lib/postgresql` (not the pre-18 `/var/lib/postgresql/data`). |
| golang (build stage) | **1.27.1** | `sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244` | Multi-arch index digest; resolved via `docker buildx imagetools` and BuildKit. |
| gcr.io/distroless/static-debian12 | **:nonroot** | `sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab` | Multi-arch index digest; runtime stage. |

Note: Dockerfiles intentionally omit the `# syntax=docker/dockerfile:1` directive — it pulls a
floating BuildKit frontend image from Docker Hub. The engine's built-in frontend is used instead;
its version is pinned by the documented Docker Engine minimum (≥ 27, dev verified on 29.8.1).
PostgreSQL 18 images declare `/var/lib/postgresql` as their volume target (`PGDATA` lives at
`/var/lib/postgresql/18/docker`); compose and regression checks enforce this layout
(`scripts/check-compose.ps1`).

## Verification status (updated 2026-09-29)

1. **Container digests pinned** (via `docker buildx imagetools inspect` + BuildKit resolution); Dockerfiles deliberately omit the floating `# syntax=` frontend directive.
2. **Compose stack booted and verified locally** (Docker Engine 29.8.1 / Compose v5.5.1): PostgreSQL 18.6 at `/var/lib/postgresql/18/docker`, `shared_preload_libraries=timescaledb`, extension 2.30.1 installed, dev roles bootstrapped, hypertable `ON CONFLICT` idempotency smoke passed, volume persistence across down/up and container recreation; server healthy; collector idle-mode healthy.
3. **TypeScript 7.0.2** pin for `web/` (M2) — compatibility check with Next 16.3.7 runs in the M2 slice; documented fallback to the newest 5.x line if the toolchain objects.
