# M9-EVIDENCE — Polling engine (ICMP + SNMP)

**Status: M9-S1 COMPLETE (recorded here).** This record covers **M9-S1**, the
polling foundation end-to-end with ICMP: per-device poll targets delivered in
the signed policy bundle, the collector scheduler + ICMP prober, device-scoped
metric samples, poll health flowing back over the existing spool/stream/ingest
path, the `poll_health` table (migration 000015) and a minimal session-read
API. **No SNMP client/templates (S2), no credential materialization (S3), no
full adaptive backoff/jitter/rate caps (S4), no M10 UI and no alerts exist or
are claimed.** P2-AC-14 is satisfied for ICMP; P2-AC-20 is satisfied for the
recorded/exposed poll health. The failure-suite additions named in P2-AC-17/18
(poll outage, credential revoked, restart mid-poll) are S4 work; the scheduler
exposes the hooks they will use.

References: `PHASE_2_SPEC.md` M9 deliverables + P2-AC-14/17/20; canonical
`docs/07 §12.2-12.4/§12.7` (ICMP requirements, tiers, failure modes),
`docs/06 §` collector policy/scheduling + poll health, `docs/11 §21.1/§21.2`
(`poll_health`, 90 d retention, hypertables), `docs/12 §22` (endpoint
conventions), `docs/15` (policy sync "keeps last 3 bundles", ICMP concurrency
budget), `ARCHITECTURE.md` equivalents; `M8_EVIDENCE.md` (style).

---

## 1. Slice boundary and what S2-S4 add

| Slice | Content | State |
|---|---|---|
| **S1 (this)** | Poll targets in the signed bundle; collector scheduler + ICMP prober; `net.icmp.*` samples through the existing spool/stream/ingest path; `poll_health` end-to-end; read API; tests/evidence | **done** |
| S2 | SNMP v2c/v3 client, GETBULK/GETNEXT, core templates, counter state machine, `mibgen` | not started |
| S3 | Credential materialization in signed bundles (per-session ECDH+AEAD, RAM-only, revocation) | not started |
| S4 | Full adaptive backoff/jitter/rate/safety caps (one walk in flight, per-tier sessions, ~100 sessions), failure-suite additions (poll outage, credential revoked, restart mid-poll) | hook present (`BackoffPolicy`); policy fixed-tier in S1 |
| M10/M11 | Device/interface UI, status rollups, alerts | untouched |

---

## 2. Poll targets in the signed policy bundle

`internal/modules/collectors/policy.go` adds an **additive** `targets` array to
the signed JSON document (Phase-1 documents remain valid; old collectors ignore
the field):

```json
{"heartbeat_interval_seconds":30, "report_interval_seconds":5, "batch_max_samples":5000,
 "spool_max_bytes":67108864,
 "metrics":[
   {"key":"collector_cpu_percent","unit":"percent","source":"collector_cpu","interval_seconds":5,"dimensions":{"cpu":"total"}},
   {"key":"net.icmp.reachable","unit":"state","source":"icmp","interval_seconds":30},
   {"key":"net.icmp.rtt_ms","unit":"ms","source":"icmp","interval_seconds":30},
   {"key":"net.icmp.loss_pct","unit":"percent","source":"icmp","interval_seconds":30}],
 "targets":[{"device_id":"…","mgmt_ip":"192.0.2.10","name":"edge-1","tier":"fast"}]}
```

- Selection (server-side, inside the tenant transaction): devices with
  `deleted_at IS NULL AND status <> 'retired' AND mgmt_ip IS NOT NULL`,
  `host(mgmt_ip)` (bare address), ordered by id. Tier = `devices.poll_profile`.
- Bound: `MaxPolicyTargets = 10000` — over-ceiling builds fail loudly instead
  of truncating silently (canonical per-collector budget ~1,500, docs/07 §12.8).
- Signing/versioning is unchanged (same Ed25519 CA key, exact-bytes document,
  monotonic version, per-collector persistence). `BuildSignedPolicy(version)`
  remains as the no-targets wrapper; `BuildSignedPolicyWithTargets` is used by
  enroll and `policy:resync`.
- Collector side (`internal/collector/policy`): targets are validated
  structurally (UUID, IP, name/tier length, duplicates, ceiling) and applied
  **atomically** with the rest of the policy — one `Engine.ApplyTargets` swap
  after the signed document is stored and acked. Unknown tier strings normalize
  to `standard` so one operator typo cannot reject the whole bundle.
- Bundle retention: `Store` now keeps the newest **3** `policy-v*.json` bundles
  (canonical docs/15 "keeps last 3 bundles"), pruning older versions
  best-effort after the atomic rename.

---

## 3. Collector poll engine (`internal/collector/poll/`)

Deterministic tier scheduler + ICMP prober. Given the same targets and clock
inputs the due sequence is identical: no wall-clock reads outside the injected
`Clock`, no randomness (jitter/stagger is S4).

| Tier | Canonical cadence (docs/07 §12.4) | S1 default |
|---|---|---|
| fast | 30 s | `FastInterval = 30s` |
| standard | 60 s | `StandardInterval = 60s` |
| slow | 5-15 min | `SlowInterval = 5m` (lower bound) |
| inventory | 6-24 h | `InventoryInterval = 6h` (lower bound) |

- **Scheduler**: `Engine.Step(ctx, now)` polls every due, non-running target
  (reservation prevents double dispatch when a probe outlives its interval),
  emits samples + health, and reschedules at `finished + BackoffPolicy(base
  cadence, consecutive_failures)`. `Engine.Run` loops `Step` and parks on the
  injected clock until the earliest next run; `ApplyTargets` wakes it, keeps
  state for unchanged targets and drops removed ones (an in-flight probe for a
  removed target is discarded). Concurrency is bounded at 20 ICMP flows
  (`DefaultConcurrency`, canonical docs/15).
- **Backoff hook (S4 seam)**: `BackoffPolicy` is called on every completion
  with the failure count; S1 default `FixedBackoff` preserves the tier cadence.
  Tests prove a doubling hook changes the schedule and that successes reset the
  failure counter.
- **ICMP prober**: `Prober` interface with a `Pinger` socket seam; defaults
  `count=3`, `interval=200 ms` (canonical diagnostic maximum),
  `timeout=2 s`, count ceiling 50. Per poll: `reachable` 1/0, average `rtt_ms`
  (only when a reply arrived — an outage is a gap, not a fake 0), `loss_pct`
  0-100. Outcomes: zero replies → `failure/timeout`; partial loss →
  `success/loss` (reachable but degraded); transport error → `failure/
  unreachable` with **no samples** (an untried probe must not fabricate loss);
  no capability → `failure/unsupported`, no samples. Health carries the
  whole-probe duration as `latency_ms`.
- **Capability requirements (per canonical docs/06/§15)**: raw `ip4:icmp`
  socket when the process holds `CAP_NET_RAW`, falling back to the Linux
  unprivileged ping socket (`net.ipv4.ping_group_range`). The dev compose
  collector is granted `cap_add: NET_RAW`; RUNBOOK §17 now documents the CI
  prerequisite. ICMPv6 is not implemented in this slice (canonical: V2;
  IPv6 targets report `unsupported`).
- **OS split**: all socket code is `//go:build linux`
  (`sockping_linux.go`); `sockping_other.go` keeps `go build ./...` green on
  developer hosts (Windows dev host verified) and reports `unsupported`.

---

## 4. Metric keys and wire path

| Key | Unit | Meaning |
|---|---|---|
| `net.icmp.reachable` | `state` | 1 = at least one echo reply in the window, else 0 |
| `net.icmp.rtt_ms` | `ms` | average echo RTT of received replies (omitted when none) |
| `net.icmp.loss_pct` | `percent` | echo loss over the window (0-100) |

Naming follows the canonical dotted namespace (`docs/08 §5`: `net.if.in_octets`,
`wan.latency.p95_ms`). All three keys are added to the signed policy metric
allowlist, so the existing ingest authorization applies unchanged.

Samples carry the additive `MetricSample.device_id`; ingest resolves them
through the M8 `metrics.EnsureDeviceSeries` guard (per-device 250 / per-site
10k / 60-new-per-minute creation caps, quarantine, structured
`metric.cardinality.exceeded` event). Collector-local metrics keep
`device_id IS NULL` and the Phase-1 path.

---

## 5. Proto changes (additive; `buf lint` clean)

`proto/argus/collector/v1/collector.proto`:

- `MetricSample.device_id` (field 6, string) — optional device scope.
- `PollHealth` (new message): `device_id`, `poll_type`, `latency_ms`,
  `outcome`, `error_class`, `consecutive_failures`, `checked_at`.
- `MetricBatch.health` (field 4, `repeated PollHealth`).

**Durability decision (non-lossy, follows the batch ack/claim pattern).**
Poll health is carried on `MetricBatch` so it rides the collector's existing
durable spool WAL, the `ingested_batches(collector_id, batch_seq)` claim and
the `BatchResult` ack-after-commit path. There is no new transport, no second
spool, no loss window and no new ack channel: a health-only batch (zero
samples) is legal in the spool and ingest, and a replayed batch is
deduplicated by the existing ledger before any `poll_health` row is written.
Migration 000015 widens the Phase-1 `ingested_batches_count_ok` check from
`sample_count > 0` to `>= 0` so health-only batches are claimable (down
migration restores it). Generated stubs under `gen/` are regenerated and
commit-ready; they were intentionally **not committed**.

---

## 6. `poll_health` schema and ingest semantics (migration 000015)

TimescaleDB hypertable, 1-day chunks like `metric_samples`:

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | UUIDv7 row identity; PK `(id, ts)` (hypertable rule) |
| `org_id` | uuid | FK organizations; RLS key |
| `collector_id` | uuid | FK collectors |
| `device_id` | uuid | FK devices |
| `ts` | timestamptz | `checked_at` (collector clock, ±7 d validated) |
| `poll_type` | text | `icmp` (S1) / `snmp` (S2); CHECK constraint |
| `latency_ms` | integer | whole-probe duration, `>= 0` |
| `outcome` | text | `success` / `failure`; CHECK constraint |
| `error_class` | text | `timeout`/`loss`/`unreachable`/`unsupported`/…, `<= 100` chars |
| `consecutive_failures` | integer | `>= 0`; drives S4 backoff |
| `created_at` | timestamptz | server ingest time |

- **Retention**: `add_retention_policy('poll_health', INTERVAL '90 days')`
  (canonical docs/11 §21.1/§21.2 retention matrix). The test drives
  `drop_chunks(..., now() - 90 days)` and proves 100-day-old rows are dropped
  while recent rows survive.
- **RLS**: `ENABLE + FORCE` + `app.current_org` tenant policy, exactly the
  000005/000008 contract; unset context denies all rows. Indexes
  `(org_id, device_id, ts DESC)` (API) and `(org_id, collector_id, ts DESC)`
  (M12 self-observability).
- **Ingest**: validated server-side (UUID, poll type/outcome vocabulary,
  latency/failure bounds, timestamp window, class length) and inserted in the
  **same tenant transaction** as the batch claim, sample writes, chunk-RLS
  sweep and COMMIT; `BatchResult(OK)` is emitted only after commit. A device
  outside the collector's tenant makes the whole batch
  `REJECTED/validation.device_not_found` (RLS + explicit org predicate →
  no cross-tenant write; test-pinned). New counter
  `argus_ingest_poll_health_total{status}`.
- **Down migration**: removes the retention policy, drops the hypertable and
  restores the Phase-1 sample-count check (deleting `sample_count = 0` ledger
  rows first, which only describe the dropped table's payloads).

---

## 7. API surface

`GET /v1/devices/{id}/poll-health` (`internal/modules/pollhealth`):

- Session-protected; route metadata `x-argus-capability: device.read`,
  `x-argus-scope: device` (P2-D5 conventions; viewer allowed, anonymous 401).
- Scope resolved from `user_scope_bindings`; foreign/missing devices and
  out-of-scope devices are indistinguishable 404 `device.not_found`.
- `limit` 1-100 (default 25) + opaque keyset `cursor` (`ts DESC, id DESC`),
  bounded to one page; `next_cursor`/`has_more`; `application/problem+json`
  `validation.failed` for bad limit/cursor.
- Response records: `id, device_id, collector_id, poll_type, checked_at,
  latency_ms, outcome, error_class, consecutive_failures`.
- `openapi/argus.v1.yaml` documents the path + `PollHealthRecord` schema; the
  authz/OpenAPI contract gates were updated from 18 to 19 inventory routes.

---

## 8. Verification and test evidence

Environment: Windows 11 dev host, Docker Desktop 29.8.1 (WSL2), pinned
TimescaleDB 2.30.1-pg18 (testcontainers), Go 1.27.1 local toolchain, buf
v1.73.0, golangci-lint v2.14.0.

| Command | Result |
|---|---|
| `go build ./...` | pass (also `GOOS=linux,GOARCH=amd64/arm64 go build ./...` pass) |
| `go test ./internal/... -count=1` | pass (all packages; new poll/policy/ingest/pollhealth/api tests included) |
| `go test ./tests/integration/ -run '^TestM9' -count=1 -v` | **pass, 6/6** (policy bundle targets; ingest round-trip + duplicate replay; cross-tenant ingest rejected; RLS isolation; read API authz/scope/pagination; schema + 90-day retention) |
| `go test ./tests/integration/ -count=1` | **pass, full suite (153.8 s)** — T4/T5/T9, M8 metrics/ingest, M7 inventory/credentials, M9 all green |
| `go test ./tests/contract/... -count=1` | pass (OpenAPI ↔ route registry, capability/scope metadata) |
| `gofmt -l internal cmd tests` | empty |
| `golangci-lint run --timeout 10m ./...` (v2.14.0) | **0 issues** |
| `buf lint` | exit 0 |
| `buf generate` + `git diff --exit-code -- gen` | lint/generate exit 0; only `gen/go/argus/collector/v1/collector.pb.go` changes (additive); a second `buf generate` reproduces a byte-identical `gen/` tree (drift check clean once the commit includes the regenerated stub) |
| Linux ICMP real-socket test, `golang:1.27.1` container, `--cap-add NET_RAW` | `TestSocketPingerLoopback` + `TestICMPProberLoopback` **PASS** (raw socket path) |
| Linux ICMP real-socket test, same container **without** `--cap-add NET_RAW` | **PASS** (unprivileged ping-socket fallback) — command: `docker run --rm [--cap-add NET_RAW] -v <repo>:/src -w /src -e GOTOOLCHAIN=local -e GOMODCACHE=/src/.tools/gomodcache -e GOCACHE=/tmp/gocache golang:1.27.1@sha256:3680233e… go test ./internal/collector/poll/ -run 'TestSocketPingerLoopback|TestICMPProberLoopback' -count=1 -v` |

New unit tests: `internal/collector/poll/{scheduler_test.go,prober_test.go,
health_test.go,sockping_linux_test.go}` (tiers, deterministic due sequence with
a fake clock, backoff hook honored + failure counter reset, target add/remove
semantics, sample/health emission, injectable-pinger success/partial loss/total
loss/transport error/unsupported/IPv6, health batcher size/tick/requeue,
real-socket loopback Linux-only). `internal/collector/policy/apply_test.go`
(targets verify + bounds, last-3 bundle retention).
`internal/collector/spool/spool_test.go` (health-only batch round trip and
restart recovery). `internal/modules/collectors/policy_targets_test.go`
(targets round trip + signature + ceiling). `internal/modules/pollhealth/
health_test.go` (cursor codec). `internal/modules/ingest/health_validate_test.go`
(health-only payload accepted without allowlist; every health bound rejected;
device_id parsing).

---

## 9. Design decisions and limitations

1. **Health on MetricBatch** is deliberate: it makes "poll health flowing back"
   exactly as durable as samples with zero new transport machinery, satisfying
   the slice's "follow the existing batch ack/claim pattern" option. A separate
   health RPC would need its own spool/journal to avoid a loss window.
2. **Partial loss = success + `error_class=loss`**: reachability is binary;
   loss is carried numerically. Consecutive failures count only total loss.
3. **RTT gaps**: windows without replies emit no `rtt_ms` sample (no invented
   zero); loss/reachability still describe the outage.
4. **Targets are org-wide in S1**: every collector of the org receives all live
   devices with a management IP (stated in the slice brief). Per-site collector
   assignment/least-target delivery is a later refinement (it changes policy
   assembly, not the engine).
5. **Per-device series adoption**: M8's `EnsureDeviceSeries` guards are now on
   the ingest path for `device_id`-scoped samples; collector-local series keep
   the Phase-1 behavior.
6. **`ingested_batches.sample_count` counts samples only**; health-only batches
   claim with 0 (constraint widened). The ledger remains per-batch, not
   per-record.
7. **No jitter/stagger yet**: first run is immediate on policy apply; S4 adds
   jitter, failure-doubling, critical-device ceilings and rate caps through the
   `BackoffPolicy` hook and engine limits.
8. **IPv6/ICMPv6 is V2** (canonical): IPv6 targets report `unsupported` and
   produce no samples.
9. **Scope/limitations recorded**: no on-demand check endpoint (M9 remaining
   deliverable), no `poll_schedules` table (schedules live on the collector;
   the canonical table lands when server-side scheduling/assignment does), no
   events table (`poll.health` event wiring is M11; M12 dashboards consume the
   collector_id index).

## 10. Deferred (explicit)

- SNMP v2c/v3, templates, counter correctness — S2.
- Credential materialization/rotation/revocation in bundles — S3.
- Adaptive doubling/jitter, safety caps (one walk in flight, ≤300 req/min,
  session caps), failure-suite additions — S4.
- Device/interface UI, status rollups — M10; alerts/events — M11; dashboards —
  M12.

## 11. Files changed (M9-S1)

- Proto: `proto/argus/collector/v1/collector.proto` (+ regenerated
  `gen/go/argus/collector/v1/collector.pb.go`, not committed).
- Migrations: `migrations/000015_poll_health.{up,down}.sql`,
  `migrations/embed.go` (`Latest = 15`).
- Server policy/API: `internal/modules/collectors/{policy,repo,service}.go`;
  `internal/modules/pollhealth/{health,http}.go` (new);
  `internal/api/{routes,router}.go`; `cmd/argus-server/main.go`;
  `openapi/argus.v1.yaml`.
- Ingest: `internal/modules/ingest/{validate,service,stream_service,metrics}.go`
  + `pollhealth.go` (new); `internal/modules/metrics/store.go`
  (`EnsureDeviceSeries` on the Store seam).
- Collector: `internal/collector/poll/` (new package);
  `internal/collector/policy/apply.go`; `internal/collector/spool/{spool,segment}.go`;
  `internal/collector/metrics/source.go`; `cmd/argus-collector/run.go`.
- Tests: poll/policy/spool/collectors/pollhealth/ingest unit tests;
  `tests/integration/m9_poll_test.go` (new); `tests/integration/migrations_test.go`
  (RLS counts 19); `tests/integration/m4_ingest_test.go` (store seam);
  `internal/api/routes_test.go`, `tests/contract/authz_contract_test.go`
  (18→19 routes).
- Ops/docs: `deployments/compose/docker-compose.dev.yml` (collector
  `NET_RAW`); `docs/phase-1/RUNBOOK.md` §17 (CI ICMP capability);
  `docs/phase-1/VERSIONS.md` (x/net promoted to direct, pin unchanged); this
  file.
