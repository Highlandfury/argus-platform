# Load testing (Phase 1)

Two harnesses exist in this repository, both talking to the **real** API / control
plane (no mocks):

| Harness | Path | Covers |
|---|---|---|
| Ingest load generator | `tests/load/gen` (Go) | M4a smoke, L-01 (single stream), L-02 (fleet), reconnect/dedup behavior |
| Query latency probe | `tests/load/query` (Go) | Per-shape query latency (latest, 15m, 1h, 6h, 24h) |
| ADR-016 write-path bench | `tests/load/writepath` (Go) | unnest vs staging+COPY and per-stream concurrency, against the real ingest.Service (M8-S2a) |
| API load leg | `tests/load/k6/api.js` (k6) | L-03: 50 VUs, 5 min, mixed reads (collectors list + 24 h metric query) |

Full measured results and the observed bottleneck live in
[`docs/phase-1/LOAD_TEST_REPORT.md`](../../docs/phase-1/LOAD_TEST_REPORT.md).
The canonical definitions are in
[`docs/phase-1/PHASE_1_LOAD_TEST.md`](../../docs/phase-1/PHASE_1_LOAD_TEST.md).

## Prerequisites

- Docker Desktop running; the dev stack up and healthy.
- k6 is not required on the host: the pinned image `grafana/k6:2.3.0` is used.
- The loadgen/query tools use the repository's Go toolchain (`.tools\go`).

## Start the stack

```powershell
cd <repo>
.\scripts\dev.ps1 reset     # DEVELOPMENT ONLY: destroys dev volumes
.\scripts\dev.ps1 up        # waits for healthy; collector self-enrolls
curl.exe http://127.0.0.1:8080/v1/readyz   # expect 200
```

## Setup / test data

The dev stack is seeded by `seed` (org `dev`, site `HQ`, admin login) and the
collector produces `collector_cpu_percent` every 5 s â€” **no additional test data
is required** and L-03 creates none (it only reads; the single login is the
only write-like action).

For the ingest harnesses, the loadgen enrolls its own collectors through the
real control plane and names them `l01-*` / `l02-*` (they persist in the dev DB
until a dev reset; that is the documented cleanup).

## Run L-03 (API leg)

```powershell
# from the repository root; K6_PASSWORD must be set for anything beyond the
# documented dev credential. Dev stacks using deployments/compose/.env:
# take K6_PASSWORD from ARGUS_DEV_ADMIN_PASSWORD there (do not commit it).
Get-Content tests\load\k6\api.js -Raw | docker run --rm -i --network argus-dev_default `
  -e BASE_URL=http://server:8080 `
  -e K6_PASSWORD=<dev admin password> `
  grafana/k6:2.3.0 run --summary-trend-stats 'min,avg,p(50),p(95),p(99),max' -
```

Canonical thresholds enforced by the script: `p(95) < 300 ms`,
`p(99) < 1 s`, error rate `< 0.1%`. Phase-1 deviation: the canonical text says
"24 h @ 10 s step", but the Phase-1 query contract capped results at 2000
points (24 h @ 10 s -> 422 `query.points_exceeded`), so L-03 issued
**24 h @ 1 m**. M8 reconciled the cap to the canonical 10k points (24 h @ 10 s
= 8641 points now fits); the load slice re-baselined L-03 against the new
contract.

**M8-S2b result:** before the session-touch fix the same harness measured
p95 463 ms (FAIL); after it p95 224.7 ms / p99 289.6 ms (PASS) with 0% errors.
Root cause, fix and raw artifacts: `docs/phase-2/LOAD_TEST_REPORT.md` § L-03
and `docs/phase-2/M8_EVIDENCE.md` §7.3.

**Harness lesson (measured):** do **not** add `--out json=<file>` to L-03. The
metrics query URL carries per-request `from`/`to` timestamps, so every request
creates unique `url`-tagged series; k6 accumulates >100k series and its JSON
writer stalled for minutes after a 5-minute run (the file kept growing after
the test ended). Use the server's `/metrics` histograms
(`argus_http_request_duration_seconds`) for per-route percentiles instead.

## Interpret results

- **PASS** â€” k6 exits 0: both duration thresholds and the error-rate threshold
  are green.
- **FAIL** â€” k6 exits non-zero and prints `thresholds ... have been crossed`
  with the offending metric. Report the measured values; do **not** immediately
  change production code. Classify first (test environment vs. server request
  path vs. database), then hand optimization to the appropriate milestone.

## Run the ingest harnesses (L-01 / L-02 summary)

```powershell
# extract the server CA once (the loadgen trusts the real CA)
docker compose -f deployments\compose\docker-compose.dev.yml cp server:/var/lib/argus/ca/root.pem .dev\ca-root.pem
# L-01: one stream, batch 2000, 20k samples/s offered, 10 min
go run ./tests/load/gen -mode single-stream -duration 10m -samples-per-sec 20000 -batch 2000 -name-prefix l01
# L-02: 200 collectors x 100 samples/s equivalent, batch 500, 10 min
#   (fleet enrollment uses the documented load override for the per-IP limiter:
#    docker compose -f docker-compose.dev.yml -f docker-compose.load.yml up -d server)
go run ./tests/load/gen -mode fleet -collectors 200 -samples-per-sec 20000 -batch 500 -duration 10m -name-prefix l02
```

Fleet-mode note (M8-S2a): the harness sends one batch per collector per
`batch/samples-per-sec` tick while the 8-batch window has room, so at fleet
scale it runs at window-bounded **max pressure**, not at exactly 100 samples/s
per collector. Under deep queueing its default 15 s no-ack watchdog closes the
stream (a real collector instead keeps the spool and replays); the opt-in
`-ack-timeout` flag (default 15 s, unchanged) raises that watchdog to measure
service capacity without the synthetic abandons. Both measurements are recorded
in `docs/phase-2/M8_EVIDENCE.md` §7.2.

## Run the >= 1 h soak (P2-AC-12)

Single-stream, batch 2,000, 20,000 samples/s offered for 62 minutes, generator
on the host (server/DB stay in Docker), detached with periodic monitoring:

```powershell
cd <repo>
$env:ARGUS_DEV_ADMIN_PASSWORD = "<dev admin password>"   # or pass -password
go build -o .dev\loadgen.exe ./tests\load\gen
docker compose -f deployments\compose\docker-compose.dev.yml cp server:/var/lib/argus/ca/root.pem .dev\ca-root.pem
.\.dev\loadgen.exe -mode single-stream -duration 62m -samples-per-sec 20000 -batch 2000 `
  -name-prefix soak -ca-file .dev\ca-root.pem -json tests\load\results\soak.json `
  *> tests\load\results\soak.log
```

Run it detached and poll; measure with `docker stats` sampling plus
`pg_stat_*`/`timescaledb_information` snapshots (see
`tests/load/results/soak_*`). Honest results (including any shortfall against
20k/s) are in `docs/phase-2/LOAD_TEST_REPORT.md` § Soak.

## Query latency probe

```powershell
go run ./tests/load/query -iterations 25                    # dev-collector
go run ./tests/load/query -collector l01-0000 -iterations 25 # large series
```

## ADR-016 write-path bench (M8-S2a)

The ADR-016 measurement harness drives the real `ingest.Service` (RLS, batch
claim, series resolution, sample write, touch, chunk-RLS sweep) with the
runtime app role. Variants: `unnest` (current path) and `staging` (binary
`COPY` into a per-session temp table + `INSERT ... SELECT ... ON CONFLICT`).

```powershell
go run ./tests/load/writepath `
  -owner-dsn "postgres://argus_owner:<pw>@127.0.0.1:5432/argus?sslmode=disable" `
  -app-dsn   "postgres://argus_app_login:<pw>@127.0.0.1:5432/argus?sslmode=disable" `
  -variant unnest -batch 2000 -batches 60 -parallel 6
```

Results and the resulting decision are recorded in
[`docs/phase-2/M8_EVIDENCE.md`](../../docs/phase-2/M8_EVIDENCE.md) §6. Raw final
L-01/L-02 artifacts live under `tests/load/results/`.

## Cleanup (development only)

```powershell
.\scripts\dev.ps1 reset     # removes all dev volumes (db, collector state, CA)
.\scripts\dev.ps1 up
```

Never run the reset against anything but a development environment.
