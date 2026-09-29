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
| Docker Engine / Compose | ≥ 27 / Compose v2 | requirement | **Pending on dev host** (user action: Docker Desktop). CI uses ubuntu-latest runners (Docker 27+). |

## Go module pins (direct)

| Module | Pin | Verified via |
|---|---|---|
| github.com/prometheus/client_golang | v1.24.1 | GitHub release |
| github.com/prometheus/client_model | v0.6.2 (indirect, resolved by tidy) | Go module proxy |
| github.com/google/uuid | v1.6.0 | GitHub release — **added in M1** |
| github.com/jackc/pgx/v5 | v5.11.0 | GitHub release — **added in M1** |
| google.golang.org/grpc | v1.84.0 | GitHub release — **added in M3** |
| google.golang.org/protobuf | v1.36.12 (codegen pin; tidy currently resolves v1.36.11 as indirect runtime lib) | GitHub release / proxy | Codegen and runtime pins may diverge; record both when they change. |
| github.com/stretchr/testify | (indirect via client_golang) | tidy | Direct use begins when needed; add the exact tag then. |
| golang.org/x/crypto | v0.57.0 | repo tags — **added in M2 (Argon2id)** |
| golang.org/x/time | v0.16.0 | repo tags — **added in M2 (rate limiting)** |
| golang.org/x/sync | v0.23.0 | repo tags — **added when errgroup first used** |
| github.com/google/go-cmp | v0.7.0 (indirect) | tidy |

> Note: `go mod tidy` resolved protobuf **v1.36.11** as an indirect runtime dependency
> (pulled by client_model); the *codegen* `protoc-gen-go` pin is **v1.36.12**. This
> divergence is expected and re-checked in the M0 compat gate.

## Protocol / codegen tooling (installed into .tools/bin by scripts/install-tools.ps1)

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

| Image | Pin | Notes |
|---|---|---|
| timescale/timescaledb | **2.30.1-pg18** | Chosen because official `*-pg18` tags confirm PostgreSQL 18 compatibility, and 2.30.1 contains `INSERT … ON CONFLICT` conflict-handling fixes relevant to the ingest claim path. |
| golang (build stage) | **1.27.1** | tag `golang:1.27.1` |
| gcr.io/distroless/static-debian12 | **:nonroot** | **Digest pinning pending** — requires a Docker host (`docker buildx imagetools inspect`); tracked M0/M1 task. |

## Pending verification tasks (tracked, not silently skipped)

1. **Digest pinning** for all container images (needs Docker; CI `compose-smoke` validates tags meanwhile).
2. **`golang:1.27.1` tag existence** confirmed by the CI `compose-smoke` job (first green run).
3. **TypeScript 7.0.2** pin for `web/` (M2) — compatibility check with Next 16.3.7 runs in the M2 slice; documented fallback to the newest 5.x line if the toolchain objects.
