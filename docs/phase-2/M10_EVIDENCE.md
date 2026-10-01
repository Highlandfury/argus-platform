# M10-EVIDENCE — Visibility & operational surfaces (Phase 2)

**Status: M10-S0 COMPLETE; M10-S1 COMPLETE (§7); M10-S2 COMPLETE (§8).**
M10-S0 closes the two
M9-S4 deferrals recorded in `M9_EVIDENCE.md` §14.7 (see the signed M9 gate note
at the top of that file): the operator-facing device criticality source that
finally wires the M9-S4 5-minute failure-backoff ceiling, and
idempotency-keyed on-demand check endpoints (P2-AC-14 "scheduled and on-demand
runs"). M10-S1 (§7) adds the canonical `POST/GET /v1/metrics/query` contract
and the poll-health device status rollups (P2-AC-21, P2-AC-22 device half).
M10-S2 (§8) links SNMP-polled interface data into the `interfaces` inventory
rows (auto-create, live attributes, audited ifIndex rebinding) and exposes the
interface status rollup, closing the M9 AC-16 deferred clause.
The M10 visibility pages, charts, site dashboard and Step-12 diagnostics
remain future slices; nothing in this file duplicates the M9 record.

---

## 1. Scope and canonical references

| Area | Canonical reference | What M10-S0 does |
|---|---|---|
| Criticality | docs/07 §12.3 ("critical devices 5 min ceiling"), docs/15 §27 (critical ceiling 5 min), docs/04 §6.5/§6.4 (diagnostics capability posture) | `devices.critical` column → inventory API → signed policy targets → collector `Target.Critical` (mechanism already built in M9-S4) |
| On-demand runs | P2-AC-14; docs/12 §22.1 (Idempotency-Key on unsafe POSTs, 202 + `status_url`, cursor conventions), docs/12 §9.6.3-style dispatch on the existing control stream, docs/11 §21 table conventions | `device_checks` ledger, idempotent `POST /v1/devices/{id}/checks` + `GET /v1/checks/{id}`, CheckRequest/CheckResult proto messages, collector immediate execution |
| Poll-health origin | docs/11 §21.1 (poll_health), P2-AC-20 | `poll_health.origin` (`scheduled` \| `on_demand`) so an on-demand probe is distinguishable from the scheduled cadence |

Canonical documents do not define a check table or on-demand endpoint shape;
the design follows the platform conventions cited above and every judgment
call is recorded in §5.

## 2. Device criticality (deferral 1)

**Migration 000016** adds `devices.critical boolean NOT NULL DEFAULT false`
(additive; down drops the column). `migrations.Latest` is 17.

**Inventory API.** `critical` is a first-class device field with the same
capability/scope rules as the other device fields (`device.write` + CSRF on
create/update, `device.read` on read; scope `site`/`device`):
`POST /v1/devices`, `PATCH /v1/devices/{id}`, every device payload (list,
detail, create, update) accept/return it; PATCH is a boolean presence field
(omitted = unchanged; non-boolean = 400 `validation.failed`). No validation
beyond the boolean shape (the flag has no cross-field invariants).

**Policy targets.** `collectors.PolicyTarget` gains `critical,omitempty`;
`listPolicyTargets` selects `d.critical` and stamps it on both the ICMP and the
SNMP target (one row, two targets). The collector-side `policy.Document.Target`
and `poll.TargetFromPolicy` carry it into `poll.Target.Critical`, which
`AdaptiveBackoff` already honors (M9-S4 §14.1). `omitempty` keeps old
collectors/bundles byte-compatible.

**Web.** `AddDeviceForm.tsx` has a "Critical device (faster failure backoff)"
checkbox (`data-testid="device-critical"`) posted as `critical: true`;
`DevicesList` renders a small `critical` badge from the API payload.

**Verification.** `TestM10S0DeviceCriticalAPIAndPolicy` (create/update/payload
round-trip false→true→false plus a non-boolean rejection) and the
mechanism-level `TestM10S0CriticalBackoffCeilingMechanism`: two real engines on
one injected clock with a failing prober — the critical target stops doubling
at the 5-minute ceiling (probes at 0/120/360/660/960 s) while the non-critical
target keeps 15-minute-bounded doubling (0/120/360/840 s). No wall-clock waits.

## 3. On-demand checks (deferral 2)

### 3.1 Migration 000017

`device_checks` (one row per request):

```
id uuid PK, org_id, device_id FK, collector_id FK NULL (site's collector at
request time), poll_type icmp|snmp, status pending|completed|failed,
requested_by FK NULL, request_key, created_at, completed_at, outcome,
error_class, latency_ms, UNIQUE (org_id, request_key),
INDEX (org_id, device_id, created_at DESC), partial INDEX (collector_id) WHERE status='pending'
```

RLS is enabled + forced with the exact 000005/000008 tenant policy. The unique
key is the durable idempotency ledger; a state CHECK keeps terminal rows
consistent (pending has no outcome/completed_at; completed carries an outcome;
failed carries completed_at). The same migration adds
`poll_health.origin text NOT NULL DEFAULT 'scheduled'` with a
`scheduled|on_demand` CHECK (old rows and old collectors normalize to
scheduled at ingest).

### 3.2 Proto (additive; buf lint + generate clean)

- server→collector `CheckRequest{check_id, device_id, poll_type}` as
  `ServerMessage.check_request = 6`;
- collector→server `CheckResult{check_id, outcome, error_class, latency_ms}` as
  `ClientMessage.check_result = 5`;
- `PollHealth.origin = 8`.

`gen/go/.../collector.pb.go` was regenerated with the pinned plugins (regen is
hash-stable).

### 3.3 API surface and idempotency semantics

| | Endpoint | Auth | Behavior |
|---|---|---|---|
| POST | `/v1/devices/{id}/checks` | session + CSRF + `diagnostic.run` (canonical docs/04 §6.5; viewer denied) + device scope | Body `{poll_type: icmp\|snmp}`, `Idempotency-Key` header **required** (≤128 chars). 202 `{check_id, device_id, collector_id, poll_type, status, status_url, created_at}`. Replays return the original check with `Idempotent-Replayed: true`. 400 missing key/CSRF (CSRF is middleware, `auth.csrf`)/bad type/no mgmt_ip; 404 device; 409 `check.no_collector` / `check.pending_limit`. |
| GET | `/v1/checks/{id}` | session + `device.read` + device scope | Status/outcome/error_class/latency/completed_at/status_url. Unknown, foreign and out-of-scope checks are all 404 `check.not_found` (RLS + site scope; no existence oracle). |

Idempotency is DB-durable (`UNIQUE (org_id, request_key)` scoped to the
requested device), not an in-memory cache: concurrent replays race on the
unique index and the loser returns the winner's row. The lookup is
device-scoped so a key can never leak another device's check. The canonical
M3 enrollment endpoint spells the replay header `Idempotency-Replayed`; this
new endpoint uses the canonical `Idempotent-Replayed` from docs/12 §22.1
(recorded as a deliberate divergence from the older endpoint).

### 3.4 Collector execution and result path

- `poll.CheckExecutor` (new, `internal/collector/poll/checks.go`) resolves the
  device/poll-type in the **applied** target set, runs the existing ICMP or
  SNMP prober immediately (schedule bypassed; a 30 s bound), and emits one
  `poll_health` row with `origin=on_demand` and `consecutive_failures=0`.
  It never touches the scheduler's failure/backoff state and **never emits
  metric samples** (an off-cadence point would corrupt scheduled counter-rate
  math; documented in the code).
- No credential path changes: SNMP checks use the same M9-S3 materialized /
  fallback credential sources and obey the M9-S4 per-device budget and session
  ceilings; an over-budget check completes as `rate_limited`.
- `stream.Client` (collector) accepts `Config.Checks`, dispatches orders to a
  bounded worker pool (4 concurrent; overflow completes as `busy` rather than
  hanging), and sends one `CheckResult` per order from its send loop
  (single-concurrent-Send contract). `cmd/argus-collector/run.go` wires the
  real executor and the on-demand health rows into the existing health batcher
  → spool → gRPC path.
- Server `StreamServer` pushes live orders (`SessionRegistry.PushCheck`), and
  on reconnect redelivers up to 64 non-expired pending orders for that
  collector (`checks.PendingCheckRequests`). Results are applied idempotently:
  `UPDATE ... WHERE id=$1 AND collector_id=$2 AND status='pending'` — a replay
  (or a foreign collector id, or an unknown check) affects zero rows, is not an
  error, and can never overwrite the first terminal outcome. There is no batch
  ledger on this path: a result lost with the stream leaves the row pending
  until its TTL (limitation, §5).

### 3.5 Bounded pending semantics (chosen policy)

- Cap: **10 pending checks per device** (`checks.PendingLimit`), excess → 409
  `check.pending_limit` (chosen over 429: it is a per-device state limit, not
  rate limiting).
- TTL: **10 minutes** (`checks.PendingTTL`). Pending rows older than the TTL
  are failed as `error_class=expired` lazily on create (freeing the cap), on
  read, and are excluded from redelivery. No unbounded queue exists anywhere:
  session buffer 64, redelivery batch 64, collector workers 4.
- Offline collector: the request stays `pending` (documented) and is completed
  by reconnect redelivery if still within the TTL, otherwise `failed/expired`.

## 4. Tests and observed results

Environment: Windows 11 dev host, Docker Desktop 29.8.1 (WSL2), pinned
TimescaleDB 2.30.1-pg18 + snmpsim fixtures (testcontainers), Go 1.27.1 local
toolchain, golangci-lint v2.14.0, dev compose stack rebuilt at schema v17.

| Command | Result |
|---|---|
| `go build ./...` (windows/amd64) | pass |
| `GOOS=linux GOARCH=amd64 go build ./...` / `arm64` | pass |
| `buf lint` + `buf generate` + repeat-generate hash | pass, hash-stable (no drift) |
| `go test ./internal/... -count=1` | pass (all packages; new checks/poll/ingest/authz tests included) |
| `go test ./tests/integration/ -run '^TestM10' -count=1 -v` | **pass, 7/7** (93.6 s) |
| `go test ./tests/integration/ -count=1 -timeout 30m` | **pass (377.9 s)**, full suite incl. T1-T10, M3-M9 |
| `go test ./tests/contract/... -count=1` | pass |
| `gofmt -l internal cmd tests` | empty |
| `docker run golangci/golangci-lint:v2.14.0 golangci-lint run --timeout 10m ./...` | **0 issues** |
| `npm run build` (web) | pass |
| `npx playwright test e2e/devices.spec.ts --reporter=list` | **pass 5/5** (rebuilt dev stack; add-device critical checkbox + row badge asserted) |

New unit tests: `internal/collector/poll/checks_test.go` (immediate probe, no
samples, on_demand health, target_missing, scheduled origin),
`internal/modules/checks/checks_test.go` (payload shape, input validation,
result validation), `internal/modules/ingest/health_validate_test.go` (origin
accept/normalize/reject), `internal/api/routes_test.go` +
`tests/contract/authz_contract_test.go` (check-route capability/scope counts
and the `diagnostic.run` vocabulary).

New integration tests (`tests/integration/m10s0_checks_test.go`):

| Test | Proves |
|---|---|
| `TestM10S0DeviceCriticalAPIAndPolicy` | create/update/payload round-trip, boolean validation, signed policy target carries `critical` |
| `TestM10S0CriticalBackoffCeilingMechanism` | injected-clock engine cadence: critical stops at 5 min, non-critical continues toward 15 min |
| `TestM10S0OnDemandCheckICMPEndToEnd` | API 202 → live push → real ICMPProber (fake Pinger) → CheckResult → GET completed success with latency; poll_health `on_demand`; **zero** metric samples; collector routing recorded |
| `TestM10S0OnDemandCheckSNMPEndToEnd` | same path with the real SNMP prober against the pinned snmpsim fixture (`completed`, success) |
| `TestM10S0CheckIdempotencyAuthzAndIsolation` | replay returns the same check + `Idempotent-Replayed`, one row; missing key/CSRF/bad type deny; viewer denied `diagnostic.run` but can read; site-scope 404s; cross-tenant 404s; RLS (org B and unset context see nothing) |
| `TestM10S0CheckOfflinePendingRedeliveryAndLimits` | offline collector → pending; 11th pending → 409; TTL backdating → `failed/expired`; reconnect redelivery completes all live requests |
| `TestM10S0CheckResultReplayDoesNotDoubleApply` | wire-level and service-level replays leave outcome/class/latency/completed_at unchanged; a foreign collector id cannot apply a result |

## 5. Decisions and limitations (M10-S0)

1. **Capability for triggering checks** is the canonical `diagnostic.run`
   (docs/04 §6.5), not `device.read`: the canonical permission matrix denies
   diagnostics to read-only principals, so the viewer role cannot trigger
   checks. Reads of `/v1/checks/{id}` stay on `device.read`.
2. **Result delivery is at-most-once with a pending TTL, not a durable spool
   batch.** The instruction allowed a dedicated stream message; results are
   applied idempotently and a stream loss simply leaves the check pending until
   the TTL. Spooling CheckResults through the batch claim/ack path is a
   possible follow-up if at-least-once delivery becomes a requirement.
3. **On-demand probes emit poll health, never metric samples** (counter-rate
   correctness). The health row carries `origin=on_demand` (new column), the
   real outcome/class, and `consecutive_failures=0` so it cannot perturb the
   adaptive scheduler.
4. **Collector selection** is the device site's non-revoked collector with the
   most recent stream/heartbeat (Phase 2 has no per-device collector
   assignment; server-side schedule push remains deferred per M9 §14.7). No
   collector for the site → 409 `check.no_collector`.
5. **Pending policy** (cap 10/device, TTL 10 min, redelivery ≤64) is a
   documented platform choice; canonical documents do not specify check
   queueing. `busy` is a check-transport class (collector worker saturation),
   distinct from probe failure classes.
6. **Criticality is a plain boolean**; alert severity mapping, UI filtering and
   service criticality (docs/06 §) remain future work. The policy field is
   `omitempty`, so bundles without critical devices are byte-identical to M9.
7. **`poll_health.origin` is additive**; old collectors send nothing and the
   server normalizes to `scheduled`, so mixed fleets keep working.
8. The M10 visibility surfaces (poll-health/collector pages, charts, site
   dashboard), Step-12 diagnostics (traceroute/MTR/HTTP/TLS), `credential.use`
   audits, ifIndex rebinding and SNMP session pooling remain out of scope for
   this slice.

## 6. Files changed (M10-S0)

- Migrations: `migrations/000016_device_critical.{up,down}.sql` (new),
  `migrations/000017_device_checks.{up,down}.sql` (new), `migrations/embed.go`.
- Inventory: `internal/modules/inventory/{models,store,service,http}.go`.
- Policy/collector: `internal/modules/collectors/{policy,repo,metrics,session,stream}.go`;
  `internal/collector/policy/apply.go`; `internal/collector/poll/{poll,scheduler,checks}.go`;
  `internal/collector/spool/spool.go`; `internal/collector/stream/client.go`;
  `cmd/argus-collector/run.go`.
- New module: `internal/modules/checks/{models,service,http,checks_test}.go`.
- Server API/wiring: `internal/api/{routes,router,routes_test}.go`,
  `internal/platform/authz/authz.go`, `cmd/argus-server/main.go`.
- Ingest/read: `internal/modules/ingest/{validate,pollhealth}.go`,
  `internal/modules/pollhealth/{health,http}.go`.
- Proto/gen: `proto/argus/collector/v1/collector.proto`,
  `gen/go/argus/collector/v1/collector.pb.go`.
- Contract/OpenAPI: `openapi/argus.v1.yaml`, `tests/contract/authz_contract_test.go`.
- Tests: `tests/integration/m10s0_checks_test.go` (new),
  `tests/integration/{m3_collector_test,m9s2_snmp_test,migrations_test}.go`.
- Web: `web/src/components/AddDeviceForm.tsx`,
  `web/src/features/inventory/DevicesList.tsx`, `web/e2e/devices.spec.ts`.
- Docs: this file.

---

# 7. M10-S1 — canonical metrics query API + device status rollups

**Status: M10-S1 COMPLETE.** This slice implements the server half of
P2-AC-21 (canonical `POST /metrics/query` contract; `GET` convenience with
ETag) and the device half of P2-AC-22 (status rollups derived from poll
health; the interface half is M10-S2 and maintenance is M11). No M10-S2/S3
work, no alerting, no migrations, no proto changes.

Canonical references: docs/12 §22.8 (query contract, caps, `meta.resolution`,
ETag cache), §22.1 (conventions), docs/08 §13.5 (resolution picker, fill
modes, cap values, 15–60 s cache), docs/04 §6.5 (capability catalog; metrics
reads use `device.read` because the catalog defines no metrics capability),
docs/11 §21.1 (poll_health), M9_EVIDENCE §6/§7 (schema, origin, error
classes), M7_EVIDENCE (scope patterns: list filters vs item 404s).

## 7.1 `POST /v1/metrics/query` — implemented contract

Request (strict JSON; unknown fields rejected):

```json
{
  "series": ["s_3f2a9", {"device_id": "…", "metric_key": "net.icmp.rtt_ms",
                          "dimensions": {"if": "ether1"}}],
  "from": "2026-10-01T10:00:00Z", "to": "2026-10-01T11:00:00Z",
  "step": "auto", "agg": "avg", "fill": "null"
}
```

- `series` (required, 1–500 entries, at most 50 selectors): opaque `s_…`
  series ids, selector objects, or both. Selector dimensions are a subset
  match against the stored canonical dimension JSON (docs/08 §13.5); a series
  matches when its stored dimensions are a superset.
- `from`/`to` RFC3339, `from < to`, range ≤ 3 years (M8 bound), `to` not more
  than 5 min in the future.
- `step`: `auto` (M8 picker) or explicit `raw|10s|30s|1m|5m|1h|1d`. `30s` is
  new and is the canonical docs/12 step; it is computed from raw samples like
  `10s` and reports `meta.resolution: raw`. Explicit steps finer than the
  picker's recommendation are honored and flagged with
  `meta.resolution_warning` (docs/08 §13.5 "user override with warning").
- `agg`: `avg|max|p95|rate|sum` (default `avg`). `rate` is the mean of stored
  values because counters arrive already normalized to per-second rates
  (docs/08 §13.2). `p95` is not materialized in the CAGGs, so it is computed
  from raw samples for the whole window (limitation §7.6).
- `fill`: `null` (default), `zero`, `previous`. Only bucketed steps fill;
  `raw` returns exact samples. `previous` never invents a value before the
  first observed sample (leading gaps stay null). Gaps are reported in
  `meta.quality.gaps` regardless of fill.

Response (canonical matrix shape):

```json
{
  "from": "...", "to": "...", "step": "1m", "agg": "avg", "fill": "null",
  "series": [{
    "id": "s_…", "device_id": "…", "collector_id": null,
    "metric_key": "net.icmp.rtt_ms", "unit": "ms",
    "dimensions": {"if": "ether1"},
    "labels": {"if": "ether1", "metric": "net.icmp.rtt_ms", "unit": "ms",
               "device": "core-1"},
    "points": [[1759136400, 18432000.0], [1759136460, null]],
    "truncated": false
  }],
  "meta": {
    "resolution": "rollup_1m", "partial": false, "points_truncated": false,
    "series_total": 1, "series_returned": 1,
    "raw_fallback": false, "rollup_missing": false,
    "expected_points": 2, "returned_points": 2,
    "quality": {"gaps": 1, "dropped_samples": 0}
  }
}
```

- Points are `[unix_seconds, value]`; `null` is an explicit gap and values are
  never interpolated. Bucketed series are dense over the expected bucket grid
  (aligned start → `to.truncate(step)`), newest-first truncation when caps hit.
- Meta carries the M8 vocabulary (`resolution`, `partial`, `points_truncated`,
  `series_total`/`series_returned`, `raw_fallback`, `rollup_missing`,
  `resolution_warning`) plus canonical `quality.gaps`/`dropped_samples`
  (`dropped_samples` is always 0: the query path never drops samples, it only
  caps responses).
- Series identity (id, device_id, collector_id, metric_key, unit, dimensions,
  labels) is returned per series for chart labels; `labels` flattens dimensions
  and adds `metric`, `unit` and the device name when it exists.

**Caps (canonical: 100 series / 10k points / 15 s).** Series are resolved in
deterministic id order and capped at 100 with `partial=true`; `series_total` is
exact in the common single-selector case and a lower bound (with
`partial=true`) when a selector matches more than 100 series. The 10k point
budget is allocated evenly across the returned series; each series keeps its
newest buckets and carries `truncated=true` when it lost older buckets
(`points_truncated`/`partial` on the meta). A pathological scan
(> 1,000,000 expected buckets, or buckets × series over the same bound) is
rejected loudly with `422 query.points_exceeded` instead of scanning into the
15 s timeout. The timeout surfaces as `504 query.timeout`.

**GET `/v1/metrics/query` convenience.** Same parameters in compact form:
repeated/comma-separated `series`, one optional selector
(`device_id`+`metric`+`dimensions=k=v,k2=v2`), `from`, `to`, `step`, `agg`,
`fill`. The response body is byte-identical to POST. GET responses carry
`ETag` (body SHA-256) and `Cache-Control: private, max-age=15`, and are served
from a 256-entry in-process LRU with a 30 s TTL (canonical 15–60 s) keyed by
compiled query + org + resolved scope, so tenants/scopes never share a cached
body. `If-None-Match` matching (weak or strong) returns `304` with no body and
the same validator. POST is deliberately never cached.

## 7.2 Selector resolution and scope semantics

- Resolution runs inside one `database.WithTenant` transaction; `metric_series`
  and `devices`/`collectors` are RLS-scoped and every join repeats the org
  predicate, so cross-tenant rows are invisible even before Go-side scope
  checks.
- **Selectors are filtered by scope like list results**: the selector query
  joins the device and applies the caller's site bindings; a device outside the
  caller's scope (or soft-deleted) simply contributes no series — identical to
  a device with no series, so no existence oracle. Collector-scoped series are
  visible through their collector's site.
- **Explicit series ids follow item semantics (M7 enumeration resistance)**: a
  requested id that is missing, foreign, soft-deleted or outside the caller's
  scope fails the whole request with one uniform `404 series.not_found`. There
  is no partial success and no way to distinguish the cases.
- The canonical request has **no explicit scope-filter parameter**, so the M7
  "conflicting collection filter → 403" clause has no metrics-query surface;
  the only 403 scope path in this slice is the pre-existing device-list
  `filter[site_id]` that the bulk status convention reuses. This is a recorded
  judgment call, not an omission.
- Capability: both routes declare `device.read` (the canonical metrics-read
  capability; docs/04 §6.5 defines none), scope metadata `site` (a
  scope-filtered collection read). The viewer role holds `device.read`.

## 7.3 Device status rollups

Derivation (canonical docs are silent; all choices documented):

| Rule | Value |
|---|---|
| Source | `poll_health` rows with `origin='scheduled'` only; on-demand checks (M10-S0) never drive status (they carry `consecutive_failures=0` and are operator-triggered) |
| up | newest scheduled outcome `success`, or a failure streak below the threshold (transient failures below the ladder do not flap) |
| down | newest scheduled outcome `failure` with `consecutive_failures >= 3` |
| unknown | no scheduled row within 20 min, or no scheduled rows at all; freshness wins even over a stale failure streak, because a schedule that stopped reporting cannot assert state |
| `since` | down: first failure of the trailing failure streak (outage start); up: first success of the trailing success run (recovery) or the last provable success run start when below-threshold failures are trailing; unknown: when the newest row became stale. Bounded to the newest 1,000 scheduled rows per device (documented lower bound beyond that) |

- **Threshold 3** (canonical silent): one or two failures are common
  transients at 30–60 s cadences; three consecutive scheduled failures means
  the target missed the full retry ladder.
- **Freshness 20 min** (canonical silent): the adaptive scheduler probes at
  least once per backoff ceiling (15 min; 5 min critical, M9-S4/docs/07 §12.3)
  plus ±10 % jitter, batching and transport latency; 20 min covers the worst
  case with margin. The payload exposes `down_threshold` and
  `freshness_seconds` so clients can explain the rollup.
- **Maintenance is not merged in this slice** (M11 owns maintenance windows).
  The inventory `devices.status` lifecycle column is untouched and not
  consulted.

API surface:

| | Endpoint | Behavior |
|---|---|---|
| GET | `/v1/devices/{id}/status` | Session + `device.read` + device scope. Returns `{device_id, status, since, last_outcome, last_error_class, last_latency_ms, consecutive_failures, last_checked_at, down_threshold, freshness_seconds}`; null probe fields when no scheduled health exists. Foreign/missing/out-of-scope/malformed ids are the same `404 device.not_found`. |
| GET | `/v1/devices?include=status` | Bulk convention: the device list is unchanged (cursor, filters, pagination, the existing `status` lifecycle field) and each device gains a `poll_status` object **identical to the single endpoint response**. Nested under `poll_status` (not `status`) because overwriting the existing M7 lifecycle field would be a breaking change. `include` is allowlisted (`status` only); anything else is `400 validation.failed`. |

The bulk lookup resolves all page devices in one tenant transaction with a
per-device lateral top-1,000 (`(org_id, device_id, ts DESC)` index), so a
100-device page does not scan 90 days of history.

## 7.4 Tests and observed results

Environment: Windows 11 dev host, Docker Desktop 29.8.1 (WSL2), pinned
TimescaleDB 2.30.1-pg18 (testcontainers), Go 1.27.1 local toolchain,
golangci-lint v2.14.0, dev compose stack at schema v17.

| Command | Result |
|---|---|
| `go build ./...` (windows/amd64) | pass |
| `GOOS=linux GOARCH=amd64 go build ./...` / `arm64` | pass |
| `go test ./internal/... -count=1` | pass (all packages; new metrics/pollhealth/api tests included) |
| `go test ./tests/integration/ -run '^TestM10\|^TestMetrics\|^TestM4' -count=1 -v` | **pass (43 tests, 128.1 s)**; M10-S1 10/10 |
| `go test ./tests/integration/ -count=1 -timeout 30m` | **pass, full suite** (see §7.5) |
| `go test ./tests/contract/... -count=1` | pass (OpenAPI ↔ route registry, capability/scope metadata) |
| `gofmt -l internal cmd tests` | empty |
| `docker run golangci/golangci-lint:v2.14.0 golangci-lint run --timeout 10m ./...` | **0 issues** |

New unit tests:

- `internal/modules/metrics/matrix_test.go`: opaque series-id codec
  round-trip/rejection, agg/fill parsing, canonical `30s` step + override
  warning, densify fill modes (`null`/`zero`/`previous` leading gap),
  newest-bucket truncation, pre-DB query validation (agg, fill, range, raw+agg,
  hard scan budget), cache scope/org key isolation, ETag matching, LRU
  expiry/eviction.
- `internal/modules/pollhealth/status_test.go`: no-rows unknown, success→up,
  below-threshold failures, threshold→down with outage-start `since`,
  recovery, long-run lower bound, stale rows → unknown (freshness first),
  exact boundary freshness.
- `internal/api/routes_test.go`: metrics query routes are protected
  `device.read`/site reads; the device-status route is covered by the
  inventory route sweep; inventory count re-pinned 19 → 20.
- Contract test inventory route count re-pinned 19 → 20.

New integration tests (`tests/integration/m10s1_metrics_test.go`,
`m10s1_status_test.go`):

| Test | Proves |
|---|---|
| `TestM10S1MetricsQueryPostContract` | selector + explicit id in one request; identity/labels/dimensions; null gap bucket from the materialized 1m CAGG; `meta.resolution=rollup_1m`; series/quality meta; no ETag on POST |
| `TestM10S1MetricsQueryAggregationsAndFill` | avg/max/sum/rate from CAGGs; p95 from raw (2.9 for {1,3}) with `raw_fallback`; zero/previous fill; auto step → `rollup_5m`; explicit finer step warning |
| `TestM10S1MetricsQueryValidation` | 422 `query.agg_unsupported`; 400 for fill/step/series/selector/unknown field/raw+agg/range; uniform 404 for unknown ids |
| `TestM10S1MetricsQueryCaps` | 101 series → 100 returned, exact total, `partial`; 10,050 buckets → newest 10k with per-series `truncated` + `points_truncated` |
| `TestM10S1MetricsQueryGetETag` | GET matrix equals POST values; ETag + Cache-Control; `If-None-Match` → 304 with same validator; non-matching → 200; compact selector form; 401 anonymous; 404 unknown id |
| `TestM10S1MetricsQueryScopeAndTenancy` | cross-tenant explicit id → 404; cross-tenant selector → empty 200; site-bound viewer: explicit id 404, selector empty; admin still sees the series |
| `TestM10S1DeviceStatusClassificationAndAPI` | unknown → up → below-threshold → down (since = outage start) → recovery, with all probe fields |
| `TestM10S1DeviceStatusFreshnessAndOrigin` | stale success/failure → unknown with `since=ts+20m`; on-demand-only and mixed-origin rows never drive status |
| `TestM10S1DeviceStatusBulkConsistency` | `?include=status` rollups equal the single endpoint; inventory `status` untouched; pagination + cursor unchanged; include allowlist |
| `TestM10S1DeviceStatusAuthzAndScope` | 401 anonymous; viewer allowed; site-scoped viewer 404 + bulk filtering; malformed/foreign 404 parity |

## 7.5 Decisions and limitations (M10-S1)

1. **Capability**: metrics reads use `device.read`; docs/04 §6.5 defines no
   metrics capability and docs/12 §22.8 lists `device.read` for both routes.
   Route scope metadata is `site` (scope-filtered collection read).
2. **No 403 in the metrics query contract**: the canonical request has no
   explicit scope filter, so scope conflicts are either silent selector
   filtering or uniform item 404s. The M7 403 clause remains on the device
   list filter reused by the bulk status convention.
3. **`agg=rate` is the mean of stored values** (counters are normalized to
   rates at ingest, docs/08 §13.2); no counter differencing happens at query
   time. Per-metric aggregation policies (gauge vs counter vs state) are not
   yet selected automatically.
4. **`p95` is raw-only**: percentiles are precomputed at the collector as
   separate series (docs/08 §13.2) and are not materialized in the CAGGs, so a
   p95 query bypasses the rollups (`raw_fallback=true`) and is only as complete
   as raw retention (30 d default; configurable 30–90 d). A p95 query whose
   window predates raw retention returns gaps rather than wrong values.
5. **Point budget allocation** is even across returned series with
   newest-bucket retention; `expected_points`/`returned_points` and per-series
   `truncated` expose the effect. `series_total` is exact unless a selector
   matched more than the 100-series resolution bound (then it is a lower bound
   and `partial=true`).
6. **`since` history is bounded** to the newest 1,000 scheduled rows per
   device (lateral top-N on the `(org_id, device_id, ts DESC)` index); older
   runs report the oldest fetched row as a lower bound. This keeps a 100-device
   bulk page index-driven instead of scanning 90 days of history.
7. **Status threshold/freshness are documented platform choices** (3
   consecutive failures; 20 min freshness) because canonical documents are
   silent; both are exposed in the payload for client-side explanation.
   Maintenance state is M11; the interface status half is M10-S2; alerting on
   transitions is M11.
8. **On-demand checks are invisible to rollups** by construction
   (`origin='scheduled'` filter); a device with only on-demand history is
   `unknown`, never `up`/`down`.
9. **GET cache is per-process** (256 entries, 30 s TTL) and keyed by
   org + resolved scope + compiled query; POST is uncached. Multi-instance
   deployments will revalidate per instance (ETag still correct, cache hit
   rate lower) — acceptable for the 15–60 s dashboard window.
10. **The existing `GET /v1/collectors/{id}/metrics` is untouched** except
    that it now also accepts the canonical `30s` step; the multi-series engine
    is additive and lives beside it. The pre-existing single-series CAGG upper
    bound (a bucket aligned exactly at `to` can be missed when the whole span
    is materialized) is left as-is in that legacy path; the new multi-series
    path reads the CAGG inclusively when no raw fallback covers the boundary.
11. **No migrations/proto changes**; dev stack schema stays v17.

## 7.6 Files changed (M10-S1)

- Metrics module: `internal/modules/metrics/{matrix,matrix_http,cache,seriesid}.go`
  (new), `internal/modules/metrics/{picker,http}.go` (30s step; GET/POST
  handler fields).
- Poll health: `internal/modules/pollhealth/{status,status_test}.go` (new),
  `internal/modules/pollhealth/http.go` (device status handler).
- Inventory: `internal/modules/inventory/status.go` (new: shared rollup type +
  provider interface), `internal/modules/inventory/http.go` (`?include=status`).
- API wiring: `internal/api/{routes,router,routes_test}.go`.
- Contract/OpenAPI: `openapi/argus.v1.yaml` (metrics query + device status +
  schemas), `tests/contract/authz_contract_test.go` (inventory count 20).
- Tests: `tests/integration/m10s1_metrics_test.go`,
  `tests/integration/m10s1_status_test.go` (new).
- Docs: this file.

---

# 8. M10-S2 — SNMP interface association, audited ifIndex rebinding, interface status

**Status: M10-S2 COMPLETE.** This slice links SNMP-polled IF-MIB data into the
`interfaces` inventory rows: auto-creation of discovered interfaces, live
attribute updates (oper/admin status, speed, MTU, MAC, ifType, ifIndex),
first/last-seen maintenance, **audited ifIndex rebinding with the interface
identity preserved**, and the interface status rollup in the API payloads.
It closes the M9 AC-16 deferred clause ("automatic audited ifIndex rebinding +
interfaces-row association", see §8.7). VLAN / Q-BRIDGE membership, web pages
and charts (M10-S3), maintenance (M11) and discovery remain out of scope.

Canonical references: docs/07 §12.1/§12.3 (IF-MIB core table, "ifIndex is
stored but never the identity; rebinding on ifIndex change is automatic and
audited"; ifCounterDiscontinuityTime/counter rules unchanged), docs/11 §21
(`interfaces` columns + `UQ (device_id, if_index)`), docs/08 §13.2-§13.5
(counter normalization, series identity/dimension budget), docs/12 §22.1
(batch ack/idempotency conventions), docs/04 §6.5 (capability catalog),
M7_EVIDENCE (interfaces schema rationale + audit sink pattern), M9_EVIDENCE
§12.2-§12.4, §12.7.2, §14.7 and the §15 AC table (the deferred clause).

## 8.1 Where the linker runs (design decision)

The pipeline needed to carry per-row attributes that are not numeric series
(ifIndex itself, MAC, enum statuses) from the poller to the server without
putting ifIndex anywhere near series identity. Two inspected options:

1. **Derive observations server-side only from samples** — rejected: samples
   carry only `if_name`/`if_alias` dimensions and numeric values; ifIndex and
   MAC cannot be reconstructed, and adding ifIndex as a sample dimension would
   violate the "never identity" invariant (an ifIndex change would fork/split
   series).
2. **Additive protocol message (chosen)** — `MetricBatch.interfaces = 5`
   (`repeated InterfaceObservation`, regenerated `collector.pb.go`) carries one
   observation per polled row. It rides the existing durable spool record,
   `batch_seq` claim and `BatchResult` ack exactly like samples and poll
   health: one batch is committed, rejected or retried as a whole. Old
   collectors simply omit the field; old servers ignore it (proto3).

Server-side the association runs **inside the same ingest tenant transaction**
as the batch claim (`inventory.LinkInterfacesTx` called from
`ingest.Service.IngestBatch` after series resolution): the device row is
locked `FOR UPDATE` (per-device serialization; different devices do not
block), interfaces are matched/updated/inserted, and the transaction still
commits or rolls back as one unit. This deliberately reuses the ack path — a
DB failure retries the whole batch, a duplicate batch is rejected at the claim
before any association, and RLS/tenant scope apply to every statement. Audit
events are recorded **after COMMIT only** (the sink is not transactional), so
a rolled-back or replayed batch can never leave audit evidence. Validation
bounds the payload at 1,000 observations per batch (`MaxBatchInterfaces`),
with fail-closed checks for device UUID, name/alias lengths, ifIndex ≥ 1,
canonical IF-MIB status strings, speed/MTU ranges, MAC parseability and
`observed_at` inside the ±7-day window.

The collector renders observations in the SNMP prober from the walked rows
(numeric gauges/integers plus the `if_*` template roles); the on-demand check
path (M10-S0 §3.4) deliberately emits no observations, so off-cadence checks
still cannot perturb inventory first/last-seen.

## 8.2 Identity, upsert and audited rebinding rules

Canonical identity is `(device_id, if_name, if_alias, mac)` with ifIndex
stored, never identity (docs/07 §12.3, M7 interfaces rationale). The linker
resolves each observation against the device's rows (all locked):

| Case | Rule |
|---|---|
| Exactly one row with the same `if_name` | match it (MAC/alias are attributes) |
| Several rows share `if_name` | prefer exact MAC; else null-safe alias; else the row whose current `if_index` equals the reported one; otherwise **ambiguous → nothing is written** (never guess) |
| No matching row | insert (`interface.auto_create` audited): role `unknown`, `monitored=true`, `first_seen_at = last_seen_at = observed_at` |
| Known row, same ifIndex | update attributes: alias (only when reported — an empty alias never clears operator text), ifType, admin/oper status, speed, MTU, MAC; `last_seen_at = max(existing, observed_at)` (out-of-order batches can never make a fresh interface look stale) |
| Known row, different ifIndex | update the row in place (**id/identity preserved**), audit `interface.rebind` with `old_index`/`new_index` |
| Reported ifIndex already held by another row on the device | skip the index change and count `IndexConflicts` (the `UQ(device_id, if_index)` row binding wins; a manual concurrent create can also hit this via 23505) |
| Known interface absent from the poll | **left untouched** (explicit deferral: no disappearance inference in this slice) |

Audit actions (inventory `AuditSink` family, actor type `collector`, actor id
= authenticated collector; recorded after commit):

| Action | When | Data |
|---|---|---|
| `interface.auto_create` | an SNMP poll discovered a new interface | `if_index`, `if_name`, `if_alias`, `source=snmp` |
| `interface.rebind` | a known interface reported a different ifIndex | `if_name`, `if_alias`, `old_index`, `new_index` |

No per-poll `interface.update` events are emitted (25 interfaces × 60 s would
be audit noise); attribute changes are visible on the row and in metric
history.

## 8.3 IF-MIB template additions and series budget

`core/if-mib` (version 1, unchanged budget mechanism) gains:

| Column | OID | Kind | Role / series |
|---|---|---|---|
| ifType | 1.3.6.1.2.1.2.2.1.3 | observation-only | `if_type` |
| ifMtu | 1.3.6.1.2.1.2.2.1.4 | gauge | `if_mtu` + series `net.if.mtu` (`B`) |
| ifSpeed | 1.3.6.1.2.1.2.2.1.5 | observation-only | `if_speed` (bit/s fallback) |
| ifPhysAddress | 1.3.6.1.2.1.2.2.1.6 | string | `if_mac` (raw octets → canonical MAC) |
| ifAdminStatus | 1.3.6.1.2.1.2.2.1.7 | observation-only | `if_admin_status` |
| ifOperStatus | 1.3.6.1.2.1.2.2.1.8 | state | existing `net.if.oper_status` + `if_oper_status` |
| ifHighSpeed | 1.3.6.1.2.1.31.1.1.1.15 | gauge, scale 1e6 | `if_high_speed` + series `net.if.speed_bps` (`bit/s`; preferred over the 32-bit ifSpeed fallback) |

Budget impact: the pack's worst-case estimate moves from 7×25 = 175 to
9×25 = 225 series/device; the switch kind total is 1 + 225 = 226, still under
the canonical 250 cap. The compile-time gate pins were updated
(`snmp_template_budget_test.go`) and the policy allowlist gained the two new
keys (`collectors/policy.go`).

## 8.4 API deltas (interface status)

Every interface payload (`GET /v1/devices/{id}/interfaces`,
`POST /v1/devices/{id}/interfaces`, `GET /v1/interfaces/{id}`,
`PATCH /v1/interfaces/{id}`) now carries:

- `status`: `up` | `down` | `unknown` (same vocabulary as the device rollup),
  derived from the newest SNMP observation and the freshness window;
- `freshness_seconds`: 1200 (20 min), the same documented choice as the
  M10-S1 device rollup (worst-case 15-min backoff ceiling + jitter/latency).

| Rollup | Rule |
|---|---|
| up | `last_seen_at` fresh (≤ 20 min) and `oper_status = up` |
| down | fresh and any other known IF-MIB state (down, testing, dormant, not_present, lower_layer_down) |
| unknown | no SNMP observation (`last_seen_at` null), no `oper_status`, or stale — a stopped observation cannot assert state |

`oper_status`/`admin_status`/`speed_bps`/`mtu`/`mac`/`last_seen_at` were
already in the payload and are now kept live by the association. Capability
and scope are unchanged from the existing endpoints (`interface.read` +
`device` scope for GETs; `interface.write` + admin for writes) and
enumeration resistance is untouched: missing, foreign, soft-deleted,
out-of-scope and malformed ids all return the same `404 interface.not_found`.
No new endpoint, no migration, no web change.

## 8.5 Tests and observed results

Environment: Windows 11 dev host, Docker Desktop 29.8.1 (WSL2), pinned
TimescaleDB 2.30.1-pg18 + snmpsim fixtures (testcontainers), Go 1.27.1 local
toolchain, golangci-lint v2.14.0, dev compose stack at schema v17.

| Command | Result |
|---|---|
| `go build ./...` (windows/amd64 + linux/amd64) | pass |
| `gofmt -l internal cmd tests` | empty |
| `go test ./internal/... -count=1` | pass (all packages) |
| `go test ./tests/integration/ -run '^TestM10\|^TestM9' -count=1 -v` | **pass, 42/42** (234.4 s) |
| `go test ./tests/integration/ -count=1 -timeout 30m` | **pass, full suite** |
| `go test ./tests/contract/... -count=1` | pass |
| `golangci-lint v2.14.0` (docker, `--timeout 10m`) | **0 issues** |

New unit tests:

- `internal/collector/poll/observations_test.go`: one observation per walked
  row with all attributes (ifType/ifMtu/ifSpeed fallback/ifHighSpeed/MAC octet
  rendering/admin/oper), ifIndex never a series dimension, raw-octet and
  EUI-64 MAC canonicalization, RFC 2863 enum mapping, observation-batcher
  flush/requeue.
- `internal/collector/poll/snmp_template_budget_test.go`: pinned estimates
  updated to 9×25 (if-mib) and 1+9×25 (switch).
- `internal/modules/ingest/interface_validate_test.go`: accept/canonicalize,
  every rejection class, over-limit, observation-only batch payload.
- `internal/modules/inventory/iflink_test.go`: identity preference order
  (MAC → alias → ifIndex → ambiguous nil), rebind vs occupied-index conflict,
  operator-field preservation, forward-only last_seen, status rollup
  classification (up/down/unknown/stale).

New integration tests (`tests/integration/m10s2_interfaces_test.go`), all
through the real snmpsim fixture and the real spool → gRPC → ingest path:

| Test | Proves |
|---|---|
| `TestM10S2InterfaceLinkerEndToEnd` | first poll auto-creates 3 interfaces with correct if_name/if_alias/index/oper/admin/speed(1 Gbit/s)/MTU(1500)/MAC/type; `net.if.speed_bps`+`net.if.mtu` series land; creation audited (actor=collector, source=snmp); second poll only advances `last_seen_at`, no duplicate rows, no extra audit; an unknown-device observation batch is rejected (`validation.device_not_found`) |
| `TestM10S2IfIndexRebindingAudited` | `srebind` fixture (Gi1/0/1 renumbered 1→4): same row id and MAC preserved, ifIndex 4, speed/MTU refreshed, exactly one `interface.rebind` event with old/new index, total rows unchanged |
| `TestM10S2InterfaceStatusPayloadAndAuthz` | payload `status` unknown→up→down→unknown with freshness; list payload identical; viewer reads allowed; site-scope and cross-tenant ids 404 `interface.not_found`; malformed/unknown ids 404 parity |

## 8.6 Decisions and limitations (M10-S2)

1. **VLAN / Q-BRIDGE membership is deferred** (explicit): the canonical
   `interface_vlan_membership` / `vlans` tables do not exist in this repo yet
   and the Q-BRIDGE walks are slow-tier work; the interface page shows the
   port attributes only in this slice.
2. **Missing interfaces are left untouched** (no disappearance inference):
   a port removed from the poll keeps its last state and ages to `unknown`
   after the freshness window. Deletion/`retired` lifecycle is future work.
   A soft-deleted device still associates until its target leaves the
   collector policy (the sample path accepts it too), so retirement never
   dead-letters an in-flight batch; a device that does not exist at all
   rejects the batch (`validation.device_not_found`), matching device-scoped
   samples.
3. **Identity is resolved in Go, not by a DB unique index**: canonical
   `UQ(device_id, if_index)` is kept; adding a second unique identity index
   would risk migration failure on existing duplicates and changes manual-API
   conflict semantics. Ingest serializes per device (`FOR UPDATE`), so
   concurrent association cannot double-insert; a concurrent *manual* create
   can still race the reported index and is counted/skipped (documented edge).
4. **Ambiguity is never guessed**: several same-name rows with no MAC/alias/
   index tie-break are skipped (counted, metric instrumented), never merged.
5. **An empty `ifAlias` never clears** an existing alias and absent numeric
   attributes keep their last values: SNMP is authoritative only for what it
   reports; operator edits (role, description, monitored) are never touched
   by the association.
6. **`ifSpeed` (32-bit) is a fallback only**: it caps at ~4.29 Gbit/s, so the
   emitted series uses `ifHighSpeed` (Mbit/s → bit/s); the observation uses
   ifHighSpeed when present, else ifSpeed.
7. **Interface status has no streak/failure ladder**: unlike device poll
   health, one SNMP observation carries the full state, so classification is
   `oper_status` + freshness only (documented canonical silence). `since`
   transitions, flap detection and alerting are M11.
8. **Protocol change is additive**: `MetricBatch.interfaces = 5`; old
   collectors/spool records omit it, old servers ignore it. No migration; dev
   stack schema stays v17.
9. **On-demand checks emit no observations** (M10-S0 §3.4 semantics
   unchanged): inventory freshness tracks the scheduled cadence, not manual
   checks.
10. **MAC is a matching preference, not a fork trigger**: when the agent
    reports a different ifPhysAddress for a known port (transceiver swap) the
    row keeps its id and the MAC attribute is updated; only the canonical
    ifName/ifAlias text distinguishes ports. Description (ifDescr when ifName
    is the primary) is not written by the linker in this slice; operator
    `description`/`role`/`monitored` stay operator-owned.

## 8.7 M9 AC-16 caveat closure (cross-reference)

M9_EVIDENCE §15 records P2-AC-16 as "Met except audited ifIndex rebinding"
with the interfaces-row association deferred to M10 (§12.7.2, §14.7). This
slice implements exactly that clause: identity is ifName+ifAlias+MAC (ifIndex
never identity, pinned by existing and new tests), a changed ifIndex updates
the same row and emits `interface.rebind` with old/new index, and new
interfaces are auto-created with audit evidence. **The signed M9 evidence
table is intentionally not modified**; this section is the closure record.

## 8.8 Files changed (M10-S2)

- Proto/gen: `proto/argus/collector/v1/collector.proto` (InterfaceObservation,
  `MetricBatch.interfaces = 5`), `gen/go/argus/collector/v1/collector.pb.go`.
- Collector: `internal/collector/poll/{snmp_template,snmp_prober,prober,
  scheduler}.go`, `templates/core/ifmib.yaml`, `observations.go` (new);
  `internal/collector/spool/spool.go`; `cmd/argus-collector/run.go`.
- Server ingest: `internal/modules/ingest/{validate,service,metrics}.go`.
- Inventory: `internal/modules/inventory/link.go` (new),
  `{status,http,store,models}.go`.
- Policy: `internal/modules/collectors/policy.go` (two new allowlist keys).
- API/contract: `openapi/argus.v1.yaml` (Interface status fields + if_index
  description), `tests/contract/...` unchanged (routes unchanged).
- Fixtures/tests: `tests/fixtures/snmpsim/data/switch.snmprec` (attribute
  columns), `tests/fixtures/snmpsim/data/srebind.snmprec` (new rebinding
  scenario); `internal/collector/poll/{observations_test.go,
  snmp_template_budget_test.go,snmp_prober_test.go}`,
  `internal/modules/ingest/interface_validate_test.go`,
  `internal/modules/inventory/iflink_test.go`,
  `tests/integration/m10s2_interfaces_test.go` (new),
  `tests/integration/{m3_collector_test.go,inventory_api_test.go}` (audit
  wiring/helper).
- Docs: this file.
