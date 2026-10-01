# M9-EVIDENCE — Polling engine (ICMP + SNMP)

**Status: M9-S1, M9-S2, M9-S3 and M9-S4 COMPLETE (all recorded here).** This
record covers **M9-S1**, the polling foundation end-to-end with ICMP,
**M9-S2**, SNMP v2c/v3 polling with the declarative core template pack, the
counter state machine, snmpsim fixtures and the scheduler/wire integration,
**M9-S3**, real credential materialization into the signed policy bundles
(per-session ECDH+AEAD, RAM-only, revocation), and **M9-S4**, adaptive
scheduling (failure doubling, critical ceiling, recovery re-check, ±10% jitter,
engine-level 30/60/300 ladder, hrProcessorLoad CPU guard), rate/safety limits
(per-device request budget, tier session caps, ~100 global sessions, one walk
in flight per device), the template compile-time series-budget gate and the
canonical polling failure-suite additions. The final per-acceptance-criterion
coverage table is §15. **No M10 UI and no alert engine exist or are claimed.**
P2-AC-14 is satisfied for scheduled ICMP (on-demand checks remain the M9
deferral), P2-AC-15 (SNMP client/templates/fixtures/no SET), P2-AC-16 (counter
correctness; audited ifIndex rebinding needs the M10 interface model),
P2-AC-17 (adaptive scheduling; criticality has no operator-facing source yet),
P2-AC-18 (safety limits, with the CPU guard scoped to packs that expose
hrProcessorLoad), P2-AC-19 (credential use flow; `credential.use` audit
deferred) and P2-AC-20 (poll health + classification + API; events/UI views are
M11/M10) are satisfied for the recorded scope. The P2-AC-11 compile-time
template budget clause is closed by §14.3.

References: `PHASE_2_SPEC.md` M9 deliverables + P2-AC-14/17/19/20; canonical
`docs/07 §12.2-12.4/§12.7` (ICMP requirements, tiers, failure modes),
`docs/06` collector policy/scheduling + SecretsVault, `docs/11 §21.1/§21.2`
(`poll_health`, 90 d retention, hypertables), `docs/12 §22` (endpoint
conventions), `docs/14 §24.5` (envelope encryption, collector
materialization, mlock best-effort, no persistence), `docs/15` (policy sync
"keeps last 3 bundles", ICMP concurrency budget); `ARCHITECTURE.md`
equivalents; `M7_EVIDENCE.md` (credentials resolver/vault) and `M8_EVIDENCE.md`
(style).

---

## 1. Slice boundary and what S2-S4 add

| Slice | Content | State |
|---|---|---|
| **S1** | Poll targets in the signed bundle; collector scheduler + ICMP prober; `net.icmp.*` samples through the existing spool/stream/ingest path; `poll_health` end-to-end; read API; tests/evidence | **done** |
| **S2** | SNMP v2c/v3 client (GETBULK/GETNEXT, no SET), declarative core template pack, counter state machine, snmpsim fixtures, targets carry poll type + template inputs | **done** (see §12) |
| **S3** | Credential materialization in signed bundles (per-session ECDH+AEAD, RAM-only, revocation) | **done** (see §13) |
| **S4** | Full adaptive backoff/jitter/rate/safety caps (one walk in flight, per-tier sessions, ~100 sessions), CPU-impact guard, template compile-time series budget, failure-suite additions (target removal, credential removal, restart, rate-limit isolation, jitter bounds) | **done** (see §14; final AC table §15) |
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

- SNMP v2c/v3, templates, counter correctness — **closed in S2 (§12)**.
- `mibgen` compilation of vendor MIBs into template skeletons + vendor packs,
  sysObjectID-based template selection, operator-loaded template packs —
  future M9 work (§12.7/§12.8 record the core-pack-only limitation); the
  compile-time series-budget gate they must pass is now live (§14.3).
- Credential materialization in signed bundles — **closed in S3 (§13)**;
  `credential.use` audit events remain deferred (see §13.7).
- Adaptive doubling/jitter, safety caps (one walk in flight, ≤300 req/min,
  session caps), CPU-impact guard, template compile-time budget, failure-suite
  additions — **closed in S4 (§14)**.
- On-demand check endpoints (P2-AC-14 wording), server-pushed schedules/jitter
  seeds (`poll_schedules`), v3 engine-ID caching/session pooling, audited
  ifIndex rebinding — still deferred (§14.7).
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

---

## 12. M9-S2 — SNMP polling, templates, counter correctness

**Status: COMPLETE (this section).** SNMP v2c/v3 polling against pinned
snmpsim fixtures, a declarative core template pack, a collector-side counter
state machine, and the S1 scheduler/spool/stream/poll-health wiring. P2-AC-15
and P2-AC-16 are satisfied for this scope; P2-AC-20's classification now
covers the SNMP classes. Credential materialization (S3) and adaptive
scheduling/safety-cap completion (S4) remain out of scope. No SNMP SET exists
anywhere in the monitoring path.

### 12.1 SNMP client (`internal/collector/poll/snmp.go`)

Library: **`github.com/gosnmp/gosnmp v1.45.0`** (released 2026-09-19, active
community maintenance, pure Go, builds on Windows and Linux — the same library
ADR-006 names). Pin justification: stable API, native GETBULK/GETNEXT, v3 USM
with SHA-2 + AES; the alternative `soniah/gosnmp` is the pre-fork archived
ancestor. The client's plain-message timeout/auth classification is written
against this exact pin (VERSIONS.md).

| Behavior | Implementation |
|---|---|
| v2c | Community; **warning posture**: one `slog.Warn` per device on first use (canonical docs/07 §12.6). |
| v3 authPriv (preferred) | SHA / SHA-224 / SHA-256 / SHA-384 / SHA-512 + AES / AES-192 / AES-256; v1 and v3 authNoPriv/noAuthNoPriv are rejected by credential validation. |
| Per-RPC budget | `Timeout = 2s`, `Retries = 2` (canonical docs/07 §12.3), configurable per profile. |
| GETBULK | `max-repetitions` clamped to the documented **10-25** band, default 25; a `TooBig` response halves it down to 10 and then falls back to **GETNEXT** for the remainder. |
| Walk integrity | Out-of-subtree varbind ends the walk; `endOfMibView`/`noSuch*` end it; a non-increasing OID or a no-progress page raises `walk_truncation`; request/varbind caps bound runaway agents. |
| One walk in flight | The client serializes walks (`sync.Mutex`); the scheduler additionally reserves a target while its probe runs, and one client is built per probe. Session pooling is S4. |
| No SET | The `SNMPClient` surface is exactly `{Get, Walk, Close}` and the session surface `{Get, GetBulk, GetNext, Close}` — pinned by `TestSNMPClientSurfaceHasNoSet` (reflection over the interface method sets and the concrete types). There is no code path that can call `GoSNMP.Set`. |

Error classes fed to `poll_health` (P2-AC-20): `timeout` (per-RPC budget
exhausted / `context.DeadlineExceeded`), `auth_failure` (USM wrong digest /
unknown user / decryption / not-in-time-window / authorization error),
`walk_truncation`, `template_drift`, `unreachable` (other transport errors),
plus `credential_missing` / `credential_invalid` for the S3 seam.

### 12.2 Declarative template engine and CORE pack

Templates are YAML (`internal/collector/poll/templates/core/*.yaml`, embedded
via `go:embed`), parsed with strict `KnownFields(true)` and validated at load:
metric/OID syntax, counter width 32/64, units required for series, roles
(`sys_uptime`, `discontinuity`), duplicate metric keys rejected across the
whole set. Packs select by device `kind` (empty/`*` matches all).

| Pack | Series keys | Source | Type | Unit / rule |
|---|---|---|---|---|
| `core/system` | `sys.uptime_s` | sysUpTime.0 | gauge | `s`, scale 0.01; also the reboot signal |
| | `sys.descr`, `sys.object_id`, `sys.name` | system group | string | collected for identity/drift only (see limitation 12.7) |
| `core/if-mib` | `net.if.in_octets`, `net.if.out_octets` | ifHCInOctets / ifHCOutOctets | **counter 64** | `B/s`, `max_rate` 12.5e9 |
| | `net.if.in_errors`, `net.if.out_errors`, `net.if.in_discards`, `net.if.out_discards` | ifTable | counter 32 | `count/s`, `max_rate` 1e7 |
| | `net.if.oper_status` | ifOperStatus | state | `state` |
| `core/host-resources` | `sys.cpu.util` | hrProcessorLoad | gauge | `percent`, dim `cpu` = hrDeviceIndex |

- Selection: `switch/router/firewall/ap/gateway/load_balancer` also get
  IF-MIB, `host/server` get HOST-RESOURCES; every kind gets system.
- Interface rows are **keyed `device_id` + dimensions**: `if_name` (ifName,
  falling back to ifDescr) plus `if_alias`; **ifIndex is never part of the
  identity** (unit-test-pinned, and no series carries an `if_index`
  dimension). The current series model (`metric_series.dimensions`) has no
  separate interface link, so the server-side `interfaces` row association
  and automatic audited rebinding land with the interface/UI work (M10);
  identity stability across an ifIndex renumbering is preserved because the
  index is not in the dimension set.
- Counter entries are **emitted as rates** (docs/08 §13.2, docs/11 §20.4:
  "collectors convert monotonic counters to deltas at ingestion"). Ingest
  stores normalized values unchanged; there is no double conversion (M8
  evidence: values arrive already normalized).

### 12.3 Counter state machine (`snmp_counter.go`)

Per counter series (device + row dimensions + metric key), with injected clock
and values:

1. First observation seeds the baseline (no sample).
2. `ifCounterDiscontinuityTime` change reseeds that series.
3. `sysUpTime` decrease reseeds **every** counter of the device. A 497-day
   TimeTicks wrap is indistinguishable within one interval and also reseeds
   (one skipped sample per 497 days) — strictly safer than a post-wrap spike.
4. `value >= previous`: delta = value - previous.
5. `value < previous`: if the previous value was in the upper half of the
   counter space the decrease is a **wrap** and the modular delta is used
   (32- and 64-bit); otherwise it is a **reset** and reseeds.
6. Any implied rate above `max_rate` is rejected as a false spike (reseed),
   never emitted.
7. Non-positive elapsed time (duplicate ts / out-of-order replay) is ignored
   without advancing state.

Unit tests cover 32-bit and 64-bit wraps, reset, reboot reseed, discontinuity
change, rate guard, out-of-order, seeding, and the uptime-decrease case
(`snmp_counter_test.go`, `snmp_prober_test.go`). The fixture integration
scenario (`switch -> swrap -> sreset -> sreset`) asserts exact wrap rates,
zero counter samples at reboot, and no value above the guard anywhere.

### 12.4 snmpsim fixtures (pinned) and integration tests

No maintained upstream snmpsim image exists at the required v3 SHA-2/AES
level, so the fixture image is built from a **digest-pinned** `python:3.13-slim`
with pip pins `snmpsim==1.2.2`, `pysmi==2.0.0` (undeclared runtime import),
`pysnmp==7.1.30`, `cryptography==50.0.2` (`tests/fixtures/snmpsim/Dockerfile`;
all pins in VERSIONS.md). `cryptography` is mandatory: without it every SNMPv3
request fails with authentication/decryption errors (verified). The responder
listens on non-privileged `1161/udp` inside the container and drops to
`nobody`.

| Fixture (`tests/fixtures/snmpsim/data/`) | Community / v3 context | Content |
|---|---|---|
| `switch.snmprec` | `switch` | ifTable + ifXTable, 3 interfaces; if1 HC counters at the 64-bit ceiling, if1 ifInErrors at the 32-bit ceiling |
| `swrap.snmprec` | `swrap` | same device after a counter wrap (no reboot) |
| `sreset.snmprec` | `sreset` | same device after reboot (sysUpTime drops) + counter reset |
| `host.snmprec` | `host` | hrProcessorLoad for 2 CPUs |

`.snmprec` data is **column-major** (agents return lexicographic varbind
order; snmpsim replays file order and pads with `endOfMibView`, so a
row-major file is (correctly) classified as walk truncation by the walk
checker). Integration tests build/start the container once per suite via
testcontainers (files copied in, no host bind mount), use community selection
as the deterministic "fixture reset", and poll through the real gosnmp client.
A `snmpsim` compose profile (`docker-compose.dev.yml`) serves the same data
for manual dev/e2e runs.

### 12.5 Wiring into S1 (targets, scheduler, credentials seam)

- Signed policy targets now carry `poll_type` (`icmp`|`snmp`) and `kind`.
  Server assembly emits an ICMP target for every live device with a management
  IP and an additional SNMP target when an applicable SNMP credential binding
  exists (device/site/org scope; group-selector resolution arrives with S3's
  dispatch resolution). Invalid/unknown poll types normalize to ICMP on the
  collector; duplicates are rejected per (device, normalized poll type).
- The engine keys target state by `(device_id, poll_type)`, so one device can
  run an ICMP and an SNMP schedule independently, each with its own failure
  counter and tier interval. `TargetRemoved(deviceID, pollType)` releases the
  SNMP prober's counter state when the last SNMP target goes away.
- `MultiProber` dispatches by poll type; the ICMP prober is unchanged.
- Credentials: `CredentialSource` is the M9-S3 seam; S2 ships
  `StaticCredentialSource` (fixtures) and collector env config
  (`ARGUS_SNMP_FIXTURE_COMMUNITY` / `ARGUS_SNMP_FIXTURE_V3_*`). With none
  configured, SNMP targets report `credential_missing` — no secret is ever
  persisted by the collector.
- The signed policy allowlist gains the nine SNMP metric keys (units as
  above), so existing ingest authorization applies unchanged.

### 12.6 Verification (observed 2026-10-01)

Environment: Windows 11 dev host, Docker Desktop 29.8.1 (WSL2), pinned
TimescaleDB 2.30.1-pg18 (testcontainers), Go 1.27.1 local toolchain,
golangci-lint v2.14.0, buf v1.73.0.

| Command | Result |
|---|---|
| `go build ./...` | pass (also `GOOS=linux GOARCH=amd64 go build ./...` pass) |
| `go test ./internal/... -count=1` | pass (all packages, incl. the new SNMP client/template/counter/prober tests) |
| `go test ./tests/integration/ -run '^TestM9S2' -count=1 -v` | **pass, 4/4** (end-to-end switch wrap/reboot through spool→stream→ingest; timeout + auth failure health; host hrProcessorLoad; signed-policy SNMP target) |
| `go test ./tests/integration/ -count=1` | **pass, full suite (207.3 s)** |
| `go test ./tests/contract/... -count=1` | pass |
| `gofmt -l internal cmd tests` | empty |
| `golangci-lint run --timeout 10m ./...` (v2.14.0) | **0 issues** |
| `buf lint` / `buf generate` + `git diff --exit-code -- gen` | exit 0; no proto/gen changes (SLICE did not touch the proto) |

New unit tests: `snmp_test.go` (bulk pages, TooBig smaller-bulk + GETNEXT
fallback, truncation, timeout mapping, error classification, **no-SET
surface**, credential validation/source, v2c warning once), `snmp_counter_test.go`
(seed/rate, 32- and 64-bit wraps, reset, rate guard, discontinuity, reboot,
out-of-order), `snmp_template_test.go` (core pack load, kind selection, HC
64-bit declarations, identity never ifIndex, strict validation), 
`snmp_prober_test.go` (switch poll + exact wrapped rates, reboot no-spike,
discontinuity reseed, drift, truncation, client error classes, credential
states, host selection, state release, uptime-decrease reseed, multi-prober +
engine dual-poll-type, v2c warning). Integration:
`tests/integration/m9s2_snmp_test.go`.

### 12.7 Design decisions and limitations (recorded)

1. **Rates are derived in the collector**, before the spool: the platform has
   no other normalization point (M8 ingest stores values verbatim;
   docs/11 §20.4 assigns counter→delta conversion to collectors). One
   conversion only.
2. **String system-group values** are fetched and used for identity/drift but
   are not persisted: `metric_samples.value` is numeric-only. A text/identity
   series type (or device-identity ingestion) is not part of Phase 2's M9
   scope; recorded rather than invented.
3. **SNMP-bound devices keep their ICMP target** (two targets per device), so
   liveness/RTT/loss series are not lost when metrics move to SNMP.
4. **Uptime decrease = reboot** (no 2^31 heuristic): a TimeTicks wrap reseeds
   once per 497 days instead of risking a post-reboot spike.
5. **max_rate is the false-spike ceiling** declared per counter in the
   template (100 Gbps for octets, 10M/s for errors/discards). A reset
   misread as a wrap cannot emit a rate above it.
6. **32-bit counters that wrap more than once per interval cannot be
   inverted** (information loss); HC counters are mandatory for bandwidth and
   the rate guard prevents a false spike in that case.
7. **Walk truncation is failure-classified** (`walk_truncation`, outcome
   failure): a partial table is not silently treated as complete. Partial
   samples collected before a failed later walk are still emitted (real data)
   while health records the failure.
8. **Template drift** is outcome success + `error_class=template_drift` (the
   device answered): a required pack that produced no metrics is flagged so
   M11/M12 can alert without backing off like an outage.
9. **No session pooling / no v3 engine-ID cache yet** (one client per probe);
   per-device walk serialization is enforced. S4 owns pooling, rate caps and
   session ceilings.

### 12.8 Deferred (explicit, S2 remainder)

- Credential materialization/rotation/revocation in signed bundles — **closed
  in S3 (§13)** (`CredentialSource` is the swap point; fixture env config
  remains a dev-only fallback behind the materialized source).
- Adaptive backoff/jitter, ≤300 req/min per-device budget, per-tier/global
  session ceilings, v3 engine-ID caching, pooling — S4.
- `mibgen`, vendor packs, sysObjectID-based selection, operator-loaded
  template directory, template signatures/checksums — remaining M9/Phase 3.
- Server-side interface linking/automatic audited ifIndex rebinding — M10
  (series model has no interface FK today).
- `poll.health` events and alerts — M11/M12; on-demand check endpoint — M9
  remaining deliverable.

### 12.9 Files changed (M9-S2)

- Collector: `internal/collector/poll/{snmp,snmp_counter,snmp_template,
  snmp_prober,multi}.go` (new) + `templates/core/{system,ifmib,
  hostresources}.yaml` (new); `poll.go` (target spec, poll types, error
  classes), `prober.go` (SNMP result fields), `scheduler.go` (composite key,
  `TargetRemovedHook`); `internal/collector/policy/apply.go`
  (poll_type/kind validation); `internal/platform/config/config.go` (fixture
  credential env, validation); `cmd/argus-collector/run.go` (multi-prober +
  credential source).
- Server policy: `internal/modules/collectors/{policy,repo}.go` (target
  poll_type/kind, SNMP-binding resolution, metric allowlist).
- Tests: `internal/collector/poll/snmp*_test.go` (new),
  `internal/collector/policy/apply_test.go`,
  `internal/modules/collectors/policy_targets_test.go`,
  `tests/integration/m9s2_snmp_test.go` (new), `tests/integration/harness_test.go`
  (fixture teardown hook).
- Fixtures/ops: `tests/fixtures/snmpsim/{Dockerfile,data/*.snmprec}` (new);
  `deployments/compose/docker-compose.dev.yml` (snmpsim dev profile,
  collector fixture env); `docs/phase-1/VERSIONS.md` (gosnmp, yaml.v3, python
  base digest, snmpsim pip pins); this file.
- Dependencies: `github.com/gosnmp/gosnmp v1.45.0`, `gopkg.in/yaml.v3 v3.0.1`
  (direct; testify bumped v1.11.1→v1.12.1 as a gosnmp test dependency via MVS).

---

## 13. M9-S3 — Credential materialization (signed bundles, per-session ECDH+AEAD, RAM-only, revocation)

**Status: COMPLETE (this section).** Real device credentials flow from the
server to the collector only inside the signed policy bundle, encrypted to the
collector's per-stream ephemeral key; the collector decrypts them into RAM,
serves them through the existing `CredentialSource` seam, and drops them on
revocation/binding removal with fail-closed poll health. P2-AC-19 is satisfied
for this scope (signed-bundle delivery, per-session ECDH+AEAD, RAM-only
verified by disk/log scan, revocation on next sync, server-side bindings, no
secret in logs). Adaptive scheduling/safety caps (S4), M10 UI and alerts remain
out of scope; there is still no SNMP SET anywhere.

### 13.1 End-to-end flow

Server (inside the collector stream):

1. `ClientHello` carries a per-stream ephemeral X25519 public key (new
   additive field `session_public_key = 6`). A collector that does not present
   one receives the base bundle unchanged.
2. `Stream` calls `Service.PolicyForSession`, which loads the newest stored
   base bundle in the tenant transaction and, per `snmp` poll target, calls the
   M7-S4 `credentials.Resolver.Materialize` — precedence
   device > device_group (documented hook) > site > org, RLS-scoped, envelope
   opened through the process `SecretsVault` (P2-D2 local-KMS binding).
3. Resolved plaintext is sealed to the collector's session key inside a new
   `session` block attached to a copy of the document; the exact bytes are
   signed with the same Ed25519 policy key, under the same policy version.
   Nothing materialized is persisted: `collector_policies` keeps only the base
   document, and the per-session bytes exist only for the request lifetime.
4. The `policy:resync` push path materializes for the live session key too
   (`SessionRegistry.SessionPublicKey`); enrollment returns the base bundle
   (no session exists yet; the first stream connect materializes).

Collector:

1. Every stream session generates a fresh X25519 keypair; the public half goes
   in the hello, the seed is installed in the RAM-only credential source
   (mlock best-effort on Linux) and cleared on session end.
2. Every signature-verified bundle is handed to
   `poll.BundleCredentialSource.ApplySession`: records are decrypted with the
   session seed, parsed into `poll.SNMPCredentials`, and the whole set is
   swapped atomically (a bundle without material clears it).
3. The SNMP prober consumes the source through `ChainCredentialSource`
   (materialized credentials first; the S2 fixture/env source is a dev-only
   fallback so fixture runs keep working).
4. Fail closed: undecryptable/absent material → `credential_missing`;
   decrypted but malformed payload → `credential_invalid` (both existing
   poll-health classes).

### 13.2 Crypto design (canonical refs; documented choices)

`docs/14 §24.5` specifies "HPKE-like: ECDH + AEAD over the mTLS channel, fresh
key per session, no persistence" without naming primitives. Per the phase-2
delivery brief, the conservative pairing is fixed and recorded here:

| Element | Choice |
|---|---|
| Key agreement | **X25519** (`crypto/ecdh`), fresh server ephemeral per bundle + one collector ephemeral per stream session |
| KDF | **HKDF-SHA256**; salt = SHA-256(server ephemeral ‖ collector public key), info = `argus-policy-credential/v1`, 32-byte output |
| AEAD | **AES-256-GCM**, fresh random 96-bit nonce per record |
| Context (AAD) | canonical string: domain `argus-policy-credential/v1`, `org_id`, `collector_id`, `device_id`, `credential_id`, `credential_version` (stored envelope `key_version`), `policy_version` |

Consequences pinned by tests: ciphertext cannot be replayed across collectors,
sessions, tenants, devices or credential generations; swapping or flipping any
ciphertext/nonce/context byte fails authentication; two bundles never share an
ephemeral key (`sessioncrypto` unit suite, real crypto, no mocks).

Plaintext discipline: `Seal`/`Open` never place secret bytes in errors;
authentication failures collapse to `sessioncrypto.ErrAuthentication`;
credential payload parse errors collapse to a sanitized sentinel before they
reach logs or poll health. The server never interprets vault plaintext — it
moves opaque bytes and labels them with the credential kind; the collector
parses by kind.

**Payload schema** (documented wire contract between vault plaintext and the
SNMP session): `snmp_v2c` is the community string itself; `snmp_v3` is JSON
`{"username","auth_protocol","auth_key","priv_protocol","priv_key","context"}`.

### 13.3 Protocol delta (additive; `buf lint` clean)

- `proto/argus/collector/v1/collector.proto`: `ClientHello.session_public_key`
  (field 6, `bytes`, 32 raw bytes; absence = no materialization). No other
  message changed; old collectors ignore the field, old servers leave the
  bundle untouched.
- Signed policy document gains the additive `session` block:
  `{"algorithm":"X25519-HKDF-SHA256-AES-256-GCM","ephemeral_public_key":…,
  "org_id":…,"collector_id":…,"policy_version":N,
  "credentials":[{"device_id","credential_id","kind","version","nonce","ciphertext"}]}`.
- The materialized document keeps the base bundle's policy version. The
  collector applies material from any verified bundle with
  `version >= applied_version` (a reconnect gets a new session key, so the
  same version must re-apply) and never from an older version. Persisted policy
  storage, last-3 bundle retention and the ingest allowlist are unchanged.
- Base64 is the JSON encoding for the byte fields (Go defaults on both sides).

### 13.4 Bindings, revocation and rotation semantics

- **Bindings are enforced server-side** by the M7-S4 resolver inside the
  tenant transaction; the API is still write-only and the collector never
  resolves scopes. `device_group` membership remains the documented resolver
  hook (no dynamic selector schema yet), and `listPolicyTargets` only emits an
  SNMP target for device/site/org bindings, so group-only bindings materialize
  nothing — recorded, not silently invented.
- **Binding removal**: the next policy sync (resync push or reconnect) resolves
  nothing for that device, the bundle carries no record, the collector replaces
  its RAM set with the shorter one, and the next poll reports
  `credential_missing` — no stale use. Integration-pinned.
- **Collector revocation**: the server refuses revoked streams before hello and
  disconnects a live session with `CODE_REVOKED`; the collector's session ends,
  which clears the seed and all decrypted material. Integration-pinned.
- **Rotation**: the resolver returns the current envelope each sync, so the
  next bundle carries the rotated plaintext with the new `key_version` bound
  into the AAD; old ciphertext does not authenticate under the new record. The
  rotation wizard UI/test flow is not part of this slice.

### 13.5 RAM-only handling (collector)

`poll.BundleCredentialSource` holds the session seed and the decrypted
`SNMPCredentials` in mutex-guarded memory only:

- no filesystem API exists in the type; nothing about it is written to disk;
- the session seed is copied, zeroed on `Clear`, and mlock-ed best-effort on
  Linux (`memlock_linux.go`, `syscall.Mlock`; a build-tagged no-op elsewhere) —
  canonical "Linux mlock best-effort";
- decrypted plaintext is zeroed immediately after parsing;
- each applied bundle atomically replaces the previous set; `Clear` runs on
  disconnect/error/shutdown and on revocation;
- the only collector-visible bytes at rest are the per-session AEAD ciphertext
  inside the signed bundle cache (`policy-vN.json`, existing last-3 store);
  without the RAM-only session seed they are undecryptable, and a restart
  requires a fresh materialization on reconnect. The scan tests read every
  file under the collector policy dir and assert the sentinel plaintext is
  absent; captured slog output (collector + server) is scanned the same way.

### 13.6 Verification (observed 2026-10-01)

Environment: Windows 11 dev host, Docker Desktop 29.8.1 (WSL2), pinned
TimescaleDB 2.30.1-pg18 + snmpsim fixtures (testcontainers), Go 1.27.1 local
toolchain, golangci-lint v2.14.0, buf v1.73.0.

| Command | Result |
|---|---|
| `go build ./...` | pass (also `GOOS=linux GOARCH=amd64 go build ./...` pass) |
| `go test ./internal/... -count=1` | pass (all packages, incl. new sessioncrypto/bundle-source/materialization tests) |
| `go test ./tests/integration/ -run '^TestM9' -count=1 -v` | **pass, 16/16** (S1 6, S2 4, S3 6; 89.4 s) |
| `go test ./tests/integration/ -run '^TestM9S3' -count=1 -v` | **pass, 6/6** (v2c E2E through real spool→stream→ingest; v3 authPriv E2E; binding removal + revocation + RAM-only disk/log scan; cross-tenant isolation; bundle tamper; org/site tier precedence) |
| `go test ./tests/integration/ -count=1` | **pass, full suite (248.4 s)** — T4/T5/T9, M8 metrics/ingest, M7 inventory/credentials, M9 S1/S2/S3 all green |
| `go test ./tests/contract/... -count=1` | pass |
| `gofmt -l internal cmd tests` | empty |
| `golangci-lint run --timeout 10m ./...` (v2.14.0) | **0 issues** |
| `buf lint` / `buf generate` + `git diff --exit-code -- gen` | exit 0; only the additive `collector.pb.go` change (regenerated, commit-ready) |

New unit tests: `internal/platform/sessioncrypto/sessioncrypto_test.go`
(real-crypto round trip, wrong session key, context binding incl. cross-record
ciphertext, tamper, fresh ephemerals, bounds), 
`internal/modules/collectors/policy_session_test.go` (materialize round trip,
wrong-key, fail-closed paths, multi-device),
`internal/collector/poll/bundle_credentials_test.go` (apply/lookup v2c+v3,
wrong key, malformed→invalid, replacement/clear, no-files/sanitized-logs,
payload parser, chain),
`internal/collector/policy/apply_test.go` (session structural validation,
materialized-document verify round trip). Integration:
`tests/integration/m9s3_credentials_test.go` (v2c and v3 polling with the
materialized credential against the pinned snmpsim fixtures, org/site
precedence, binding removal + revocation, RAM-only disk/log scans,
cross-tenant isolation, tamper rejection).

### 13.7 Design decisions and limitations

1. **The server never parses secrets.** Vault plaintext travels as opaque
   bytes; the collector interprets it by credential kind. This keeps the
   crypto boundary simple and avoids a second secret-schema parser server-side.
2. **Fresh server ephemeral per bundle** (on top of the per-session collector
   key) makes every bundle independently decryptable within its session, so
   out-of-order/repeated deliveries are safe; a bundle cached on disk from a
   previous session is dead on restart (reconnect re-materializes).
3. **Same policy version for materialized re-delivery.** Version churn per
   reconnect is avoided; the collector treats `version >= applied` as
   eligible for material application and `version < applied` as
   non-applicable, preserving the no-stale-use rule.
4. **Per-device resolver transactions.** Materialization calls the existing
   per-device `Resolver.Materialize` (one tenant transaction per SNMP-bound
   device per sync). Batching it is a follow-up; it is bounded by the target
   ceiling (10,000/collector documented hard cap).
5. **mlock is best-effort by design**: Go string copies of key material cannot
   be pinned; the seed buffer is. Recorded as the canonical best-effort
   contract, not a hard guarantee.
6. **`credential_version` = envelope `key_version`** (the stored
   `encryption_context.version`). A re-seal that keeps the same KEK version
   does not change it; replaying an old ciphertext within a live session would
   require the server to sign it (signature is the trust boundary).
7. **No `credential.use` audit event yet**: the M7 resolver has no audit sink
   in this slice; the canonical §24.5 use-audit row (purpose-tagged audit per
   use) is an honest deferred item (M10/M11 or a dedicated follow-up).
8. **Old collectors keep working**: without `session_public_key` they get the
   base bundle and their SNMP targets report `credential_missing` unless the
   S2 fixture env vars are set (dev only).

### 13.8 Files changed (M9-S3)

- Crypto: `internal/platform/sessioncrypto/sessioncrypto.go` (new) + tests.
- Server policy/stream: `internal/modules/collectors/{policy,service,session,
  stream,http}.go`; `internal/modules/credentials/{resolver,models}.go`
  (`EffectiveCredential.Version`); `cmd/argus-server/main.go` (shared vault,
  resolver wiring).
- Proto/gen: `proto/argus/collector/v1/collector.proto` (+ regenerated
  `gen/go/argus/collector/v1/collector.pb.go`).
- Collector: `internal/collector/poll/{credential_payload,bundle_credentials}.go`,
  `memlock_linux.go`, `memlock_other.go` (new); `internal/collector/policy/apply.go`
  (session block + validation); `internal/collector/stream/client.go` (session
  keypair, hello field, material application, clear on session end);
  `cmd/argus-collector/run.go` (RAM-only source + chain wiring).
- Tests: `internal/platform/sessioncrypto/sessioncrypto_test.go`,
  `internal/modules/collectors/policy_session_test.go`,
  `internal/collector/poll/bundle_credentials_test.go`,
  `internal/collector/policy/apply_test.go`,
  `internal/modules/credentials/resolver_test.go`,
  `tests/integration/m9s3_credentials_test.go`,
  `tests/integration/m3_collector_test.go` (resolver option).
- Docs: this file.

---

## 14. M9-S4 — adaptive scheduling, safety limits, failure-suite completion

**Status: COMPLETE (this section).** The collector engine now adapts per-target
cadence on failures (doubling to the canonical 15-minute ceiling, 5 minutes for
critical devices), re-checks quickly after recovery, steps down under
agent-reported CPU pressure, jitters every interval ±10%, enforces per-device
request budgets and tier/global SNMP session ceilings, refuses over-budget
templates at compile time, and ships the canonical polling failure cases. The
final P2-AC-14..20 status table is §15.

### 14.1 Adaptive scheduling (P2-AC-17)

Canonical references: docs/07 §12.3 (failure doubling to 15 min; critical
devices 5 min; recovery resets fast), docs/07 §12.4 (tier cadences; step
cadence down on CPU-stress signals; rapid re-check on recovery), docs/06 §9.8
(all schedules jittered ±10%), docs/06 §10.4 (engine-level 30s→60s→300s),
docs/15 §27 (ceilings e.g. 15 min; critical 5 min; queue overflow = skip +
count).

| Rule | Implementation | Constants |
|---|---|---|
| Failure doubling | `AdaptiveBackoff.NextIntervalFor`: `base × 2^consecutive_failures`, clamped to the ceiling | `BackoffCeiling` 15 min; `CriticalBackoffCeiling` 5 min |
| Recovery | first success after a failure streak schedules `min(base, 30 s)` once, then the tier cadence resumes; failure counter resets | `RecoveryRecheckMax` 30 s |
| CPU-stress step-down | consecutive polls with `sys.cpu.util` (hrProcessorLoad) at/above the guard double the cadence per step, same ceiling, recorded as success + `cpu_pressure`; clearing the streak gets the recovery re-check | `DefaultCPUGuardPercent` 80 (canonical silent; documented choice) |
| Jitter | every computed interval ±10% through the injectable `RandSource` (production math/rand/v2; tests inject fixed/sequence sources) | `JitterPercent` 10 |
| Engine ladder | when **every** probe of a Step cycle fails, the engine failure streak floors the next wait with 30s → 60s → 300s; any success resets; floors never shorten a wait; `ApplyTargets` still wakes the engine immediately | `EngineBackoffFloor/Mid/Cap` |
| S1 hook preserved | `BackoffPolicy` is unchanged; the engine prefers the richer `AdaptiveBackoffPolicy` (`NextIntervalFor(BackoffContext)`) and falls back to `NextInterval`; `Config.Backoff` still defaults to `FixedBackoff` (S1-S3 tests untouched) | — |
| Collector autonomy | schedules stay collector-local: `Engine.Run` steps the last applied signed policy; the spool buffers during server outages (T2/T10) | docs/06 §9.8 |

The `BackoffContext` also carries `Critical` (default false — see limitation
14.6.1) and `Recovered`. Health records keep `consecutive_failures` and gain
the `cpu_pressure` success class (the same pattern as `template_drift`) so
M11/M12 can alert without treating a healthy device as down.

### 14.2 Rate and safety limits (P2-AC-18)

| Limit | Value | Enforcement |
|---|---|---|
| One walk in flight per device | — | `snmpClient` mutex serializes walks; the scheduler also reserves the target; unit-pinned |
| Per-device request budget | standard 300/min (canonical docs/07 §12.3); fast 300; slow 120; inventory 60 (canonical silent on these profiles; conservative documented choices) | sliding 60 s window per device behind `RequestLimiter`; **every** GET and walk RPC consumes one slot before the wire; exhaustion aborts the walk with `ErrSNMPBudgetExceeded` → poll health `rate_limited` (failure, backs off); denied requests are not recorded |
| Per-device session caps by tier | fast 1, standard 2, slow 2 (canonical docs/07 §12.3); inventory 1 (documented) | `SessionLimiter.Acquire` before building the client; over-cap probes are skipped + counted (`rate_limited`), never queued (docs/15 §27) |
| Global concurrent SNMP sessions | ~100 (canonical docs/07 §12.3, docs/15 §27) | same limiter, collector-wide |
| Device-CPU impact guard | hrProcessorLoad ≥ 80 % (documented conservative; canonical silent) | `Result.CPULoadHigh` → cadence step-down + `cpu_pressure` health class (docs/07 §12.7 "auto-step cadence + event"; the event surface today is poll health + logs, M11 wires alerting) |

Budgets, counters and the limiter live in the per-device prober state and are
released when the device's last SNMP target disappears (`TargetRemoved`), so
removed devices leak nothing and returning devices start clean.

### 14.3 Template compile-time series-budget gate (P2-AC-11 clause)

The M8 deferral ("template compile-time budget check → M9") is closed:

- `SNMPTemplate.EstimatedSeries()` implements the canonical estimate
  (docs/07 §12.2 "worst-case series (interfaces × metrics + table rows)";
  docs/08 §13.3 estimation check): every emitting scalar counts once; every
  emitting table column counts the declared `max_rows` of its most specific
  table walk root.
- `series_budget` is per-template configurable and defaults to the canonical
  **250 series/device** (docs/08 §13.3, adopted by PHASE_2_SPEC consistency
  item 2 and enforced at ingest by M8).
- Validation **fails loudly**: a template whose estimate exceeds its budget is
  rejected at load (`LoadSNMPTemplates`), a table with emitting columns but no
  `max_rows` is rejected, and `NewSNMPProber` panics on a broken embedded pack
  rather than silently truncating series at runtime.
- Core pack estimates: `core/system` 1, `core/if-mib` 7 × 25 = 175 (25 =
  canonical site average interfaces, docs/07 §12.8), `core/host-resources`
  64 × 1 = 64 (documented CPU ceiling); every kind's selected total ≤ 250.
- The CI gate test `TestM9S4TemplateSeriesBudgetGate` runs in
  `go test ./internal/...` (the CI `build-test` job), pinning the estimates and
  the per-kind totals; `TestTemplateOverBudgetRejectedLoudly` proves a synthetic
  400-series template is rejected and only compiles with an explicit
  `series_budget` override (which does not raise the M8 ingest cap — that stays
  authoritative and quarantine-based).

### 14.4 Failure-suite additions (M9 verification list)

New integration scenarios in `tests/integration/m9s4_failure_test.go`, all
against the containerized DB, the pinned snmpsim fixture and the real
spool → gRPC → ingest path:

| Test | Scenario | Proves |
|---|---|---|
| `TestM9S4BackoffCadenceAndRecovery` | fast target: 3 timeouts then successes | poll_health shows failures 1/2/3 then 0/0 with observed cadence 60 s → 120 s → 240 s → **30 s rapid re-check**; no early wake |
| `TestM9S4TargetRemovedMidRunAndUnreachable` | unreachable management IP + a target removed mid-run, then re-added | timeout/unreachable classification and backoff; removal stops probes with no stale schedule; counter state reseeds on return (no false rates) |
| `TestM9S4CredentialRemovedMidRunBackoff` | S3 materialized credential removed mid-run (bundle without material), then restored | fail-closed `credential_missing`, cadence doubling, recovery re-check; RAM-only removal path unchanged |
| `TestM9S4RestartResetsPollAndCounterState` | collector restart (new engine + prober, same clock) | fresh schedule due immediately (no stale next-run), counter baselines reseed (first poll emits no rates), rates resume; zero failure health across the restart |
| `TestM9S4RateLimitDoesNotStarveTargets` | saturated table-walk device + light device on one prober | `rate_limited` per-device shedding while the other target keeps succeeding |
| `TestM9S4JitterBoundsObserved` | scripted RNG at 0 and 0.9999 | intervals land exactly at 0.9× and inside 1.1×, and the scheduler wakes exactly at the jittered time |

T1–T10 (`TestFailureSuite`), M8, M7 and all M9 S1/S2/S3 suites stay green
(§14.5).

### 14.5 Verification (observed 2026-10-01)

Environment: Windows 11 dev host, Docker Desktop 29.8.1 (WSL2), pinned
TimescaleDB 2.30.1-pg18 + snmpsim fixtures (testcontainers), Go 1.27.1 local
toolchain, golangci-lint v2.14.0.

| Command | Result |
|---|---|
| `go build ./...` | pass (Windows) |
| `GOOS=linux GOARCH=amd64 go build ./...` / `arm64` | pass |
| `go test ./internal/... -count=1` | pass (all packages; new backoff/rate/limits/budget tests included) |
| `go test ./tests/integration/ -run '^TestM9' -count=1 -v` | **pass, 22/22** (S1 6, S2 4, S3 6, S4 6) |
| `go test ./tests/integration/ -count=1` | **pass, full suite (244.8 s)** — T1–T10 (`TestFailureSuite`), M8, M7, M9 all four slices |
| `go test ./tests/contract/... -count=1` | pass |
| `gofmt -l internal cmd tests` | empty |
| `golangci-lint run --timeout 10m ./...` (v2.14.0, docker) | **0 issues** |
| Proto/gen | untouched by S4 (no `buf` gate needed; `go build ./gen/...` covered by `go build ./...`) |

New unit tests: `internal/collector/poll/backoff_test.go` (jitter bounds and
midpoint, doubling/ceilings, critical ceiling, recovery re-check, CPU-pressure
steps, engine ladder, observed cadence via the engine, ladder floor + reset,
fixed-backoff compatibility), `rate_test.go` (per-profile budgets, sliding
window, tier/global session caps incl. idempotent release, budget-exceeded
classification, one-walk-in-flight), `snmp_limits_test.go` (CPU guard flag and
threshold, session-ceiling skip, per-device budget isolation, window recovery),
`snmp_template_budget_test.go` (core-pack gate + pinned estimates, over-budget
rejection, override, max_rows requirement).

### 14.6 Design decisions and limitations

1. **Criticality has no operator-facing source.** `poll.Target.Critical` is
   honored end to end in the collector (5-minute ceiling unit-tested), but the
   signed bundle carries no criticality field in Phase 2 and the server has no
   critical flag/column, so production targets are non-critical until that
   source is designed (M10+). Recorded rather than inventing a heuristic.
2. **CPU guard scope.** The guard fires when the selected packs produce
   `sys.cpu.util`; the core pack collects hrProcessorLoad for host/server kinds
   (walking HOST-RESOURCES on switches would classify missing tables as drift).
   Network gear therefore gets the failure-doubling and rate limits but not the
   CPU step-down yet; extending template selection is template work, not engine
   work. Threshold 80 % is a documented conservative choice (canonical silent).
3. **`rate_limited` is a new failure class** (additive string in the existing
   poll_health free-text column), so saturated devices show up and back off;
   this is load shedding, not a device fault, and is recorded as such.
4. **Sliding-window budget** (not a token bucket) so "≤ N requests/min" is
   strict over any 60 s window and deterministic under the injected clock.
5. **Budget window is in RAM**; a restart clears it. The first minute after a
   restart could therefore admit a full fresh budget for a device that had just
   been saturated (one-minute window, conservative direction not guaranteed
   across restart). Counters are likewise RAM-only by design.
6. **Engine ladder is for collector-wide outage cycles** (all probes of a
   cycle failed). Mixed cycles rely on per-target backoff; the ladder only
   floors waits and never shortens one.
7. **Jitter seeds are not persisted**: the collector recomputes jitter at each
   reschedule; no `jitter_seed` field is pushed yet (the docs/15 §27 schedule
   entry with jitter_seed belongs to server-side schedule push).
8. **Session pooling / v3 engine-ID caching remain unbuilt** (one client per
   probe). The session ceilings and budgets are enforced regardless, so the
   safety properties hold; pooling is a performance refinement.

### 14.7 Deferred (explicit, S4 remainder)

- On-demand check endpoints with idempotency keys (P2-AC-14 "scheduled and
  on-demand runs") — the remaining M9 deliverable/Step 12.
- Operator-facing device criticality source (5-minute ceiling wiring).
- Server-side schedule push (`poll_schedules`, jitter seeds, per-site target
  assignment) — future server orchestrator work.
- v3 engine-ID caching and SNMP session pooling.
- Audited ifIndex rebinding + the interfaces row association — M10 (the series
  model still has no interface FK; ifIndex is already never the identity).
- `credential.use` audit events — M10/M11 (unchanged from §13.7).
- Alert/event wiring and UI views for `cpu_pressure` / `rate_limited` /
  quarantine — M10/M11/M12.

### 14.8 Files changed (M9-S4)

- Collector engine: `internal/collector/poll/backoff.go` (new:
  `AdaptiveBackoff`, `BackoffContext`, jitter, engine ladder),
  `rate.go` (new: per-profile budgets, `RequestLimiter`, `SessionLimiter`),
  `scheduler.go` (adaptive hook, recovery/pressure state, engine failure
  ladder floor, health `cpu_pressure`), `poll.go` (`Target.Critical`,
  `rate_limited`/`cpu_pressure` classes, `sys.cpu.util` key),
  `prober.go` (`Result.CPULoadHigh`), `snmp.go` (budget gate per RPC,
  `ErrSNMPBudgetExceeded`, classification), `snmp_prober.go` (session caps,
  per-device limiter, CPU guard threshold, config seams),
  `snmp_template.go` (series estimate + budget validation, `max_rows`),
  `templates/core/{ifmib,hostresources}.yaml` (`max_rows`).
- Collector wiring: `cmd/argus-collector/run.go` (`AdaptiveBackoff`).
- Tests: `internal/collector/poll/{backoff_test.go,rate_test.go,
  snmp_limits_test.go,snmp_template_budget_test.go}` (new),
  `snmp_template_test.go` (fixtures declare `max_rows`);
  `tests/integration/m9s4_failure_test.go` (new).
- Docs: this file.

---

## 15. Final P2-AC-14..20 coverage and M9 gate readiness

Honest per-criterion status across all four slices. "Met" means implemented,
tested and evidenced here; every exception is named.

| AC | Status | Notes / evidence |
|---|---|---|
| P2-AC-14 | **Met for scheduled runs; on-demand deferred** | ICMP availability/loss/RTT from policy targets through spool/stream/ingest (§2-§4, §8); raw-socket + unprivileged fallback, RUNBOOK §17; scheduled cadence §14.1. On-demand check endpoints (idempotency-keyed) are explicitly the remaining M9 deliverable (§14.7) |
| P2-AC-15 | **Met** | v2c (warning posture) + v3 authPriv SHA-2/AES (§12.1-12.2); core templates; pinned snmpsim fixtures; GETBULK 10-25 + GETNEXT + TooBig fallback; 2 s / 2 retries; no SET, client-surface pinned (§12.1) |
| P2-AC-16 | **Met except audited ifIndex rebinding** | wrap/reset/reboot/discontinuity reseed, false-spike guard, fixture matrix (§12.3-12.4). ifIndex is never the identity, but the interfaces-row association + automatic audited rebinding need the M10 interface model (no interface FK in the series schema today; §12.7.2) |
| P2-AC-17 | **Met with one documented caveat** | tiers fast 30 s / standard 60 s / slow 5-15 min / inventory 6-24 h; failure doubling to 15 min (5 min critical); engine 30/60/300; ±10% jitter; collector-local autonomy (§14.1). Caveat: no operator-facing criticality source yet, so the 5-min ceiling is mechanism-tested with `Target.Critical` default false (§14.6.1) |
| P2-AC-18 | **Met** | one walk in flight; ≤ 300 req/min standard per-device budget (conservative profile constants); tier session caps (fast 1 / standard 2 / slow 2) and ~100 global sessions; CPU-impact guard via hrProcessorLoad with the documented 80 % threshold (scope: packs exposing the metric, §14.6.2); deterministic unit tests + failure test §14.4 |
| P2-AC-19 | **Met except `credential.use` audit** | signed-bundle delivery, per-session ECDH+AEAD, RAM-only disk/log scans, revocation/binding removal fail-closed, server-side bindings (§13). The canonical use-audit row stays deferred (§13.7.7) |
| P2-AC-20 | **Met except events/UI views** | `latency_ms`/`outcome`/`error_class`/`consecutive_failures` recorded and API-surfaced; classification timeout/auth_failure/walk_truncation/template_drift plus `credential_missing`/`credential_invalid` (§12.1, §13) and now `rate_limited`/`cpu_pressure` (§14.1-14.2); `consecutive_failures` drives backoff (§14.4). Platform events are M11 and the collector health views are M10/M12 |
| P2-AC-11 clause | **Closed** | compile-time template series-budget gate (§14.3); the other P2-AC-11 guards landed in M8 (§4 of M8_EVIDENCE) and quarantine UI surfacing remains M10 |

**M9 gate readiness.** All M9 acceptance criteria are met for the recorded
scope; the only open items are explicitly deferred and outside S4's boundary
(on-demand checks, M10/M11/M12 surfaces, criticality source, engine-ID
caching). T1-T10 plus the full integration, contract and unit suites are green
and lint/gofmt/builds are clean (§14.5), so M9 is ready for the user-signed
gate review. Nothing in this slice touched RLS, ack/idempotency, credential
RAM-only semantics or emitted SNMP SET.

