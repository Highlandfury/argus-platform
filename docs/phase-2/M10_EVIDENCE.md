# M10-EVIDENCE — Visibility & operational surfaces (Phase 2)

**Status: M10-S0 COMPLETE; M10-S1 COMPLETE (§7); M10-S2 COMPLETE (§8);
M10-S3 COMPLETE (§9); M10-S3a COMPLETE (§10).**
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
M10-S3 (§9) adds the visibility pages, charts and site dashboard on top of
those APIs; Step-12 diagnostics remain a future slice. Nothing in this file
duplicates the M9 record.

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
| `go test ./tests/integration/ -count=1 -timeout 30m` | **pass (268.5 s)**, full suite with the M10-S1 tests. One earlier attempt hit the pre-existing M9-S3 signed-bundle-cache timing flake (`TestM9S3BindingRemovalDropsCredentialRAMOnly`: the stream client applies session credentials one step before persisting the bundle file); the rerun and the isolated rerun were green. |
| `go test ./tests/contract/... -count=1` | pass (OpenAPI ↔ route registry, capability/scope metadata) |
| `gofmt -l internal cmd tests` | empty |
| `docker run golangci/golangci-lint:v2.14.0 golangci-lint run --timeout 10m ./...` | **0 issues** (verified on the committed M10-S1 slice in a detached worktree: exit 0; a cold-cache attempt hit the 10-minute wall under concurrent host load while the parallel M10-S2 session was building, so the confirming run used a warm container and `--timeout 20m` — the tool itself reported `0 issues`) |

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
| `go test ./tests/integration/ -run '^TestM10\|^TestM9' -count=1 -v` | **pass, 42/42** (136.7 s) |
| `go test ./tests/integration/ -count=1 -timeout 30m` | **pass, full suite** (609.8 s) |
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

---

# 9. M10-S3 — visibility pages, charts and site dashboard

**Status: M10-S3 COMPLETE.** Web-only slice: the device detail page
(`/devices/[id]`), the interface detail page (`/interfaces/[id]`) and the site
dashboard (`/sites/[id]`), all backed by the existing M10-S0/S1/S2 APIs. No
Go, OpenAPI, proto or migration change; schema stays v17. (The dev compose
server and collector images were rebuilt from the existing HEAD before
verification because the running containers predated M10-S0..S2; that is a
rebuild of committed code, not a backend change.) The M11 alerts panel is a
placeholder by design; heat strips/floor plans and Step-12 diagnostics stay
out of scope.

## 9.1 Pages and data sources

| Route | Content | APIs |
|---|---|---|
| `/devices/[id]` | Header (name, kind, site link, mgmt IP, critical badge, live status chip), status detail (last check/outcome/error/latency/consecutive failures/threshold/since/freshness), identity + identity-history table, interfaces table (if_name link, status chip, speed, MAC, last seen, one-query utilization strip), ICMP charts, poll-health table, checks panel, M11 placeholder | `GET /v1/devices/{id}`, `/status`, `/identity-history?limit=50`, `/interfaces?limit=100`, `/poll-health?limit=25`, `POST /v1/metrics/query`, `POST /v1/devices/{id}/checks` + `GET /v1/checks/{id}` |
| `/interfaces/[id]` | Identity (name/alias/ifIndex/speed/MTU/MAC/admin+oper status/ifType/last seen/freshness), live status chip, traffic (in/out octets) and errors/discards charts, device backlink | `GET /v1/interfaces/{id}`, `GET /v1/devices/{id}`, `POST /v1/metrics/query` |
| `/sites/[id]` | Status counts as filter cards, bounded recent issues, URL-driven device table (`?status=up|down|unknown`, `?q=` name/IP/kind) with device links | `GET /v1/devices?filter[site_id]=…&include=status&limit=100`, `GET /v1/devices/{id}/poll-health` (≤5 calls) |

The home dashboard now links sites to `/sites/{id}` and the device list links
each name to `/devices/{id}`, so "how is this site doing → which device →
what's wrong" is at most three clicks. The device page's "recent checks" table
reads `poll-health` rows with `origin=on_demand`; the M10-S0 check ledger has
no list endpoint and no backend change was made.

## 9.2 Chart implementation (query usage, badge, ribbon, gaps, brush)

- **Query.** All charts use the canonical `POST /v1/metrics/query` with
  selector objects, `step: "auto"`, `agg: "avg"`, `fill: "null"`. The device
  page sends three selectors in one request (`net.icmp.reachable`,
  `net.icmp.rtt_ms`, `net.icmp.loss_pct`); the interface page sends
  `{device_id, metric_key, dimensions: {if_name}}` for octets and for
  errors/discards. The real stored dimension is `if_name` (the IF-MIB
  template's identity dimension; the collector never puts ifIndex in
  dimensions), which is what the selector uses.
- **Resolution badge.** `TimeSeriesChart` always renders
  `resolution: <meta.resolution>` (raw|rollup_1m|rollup_5m|rollup_1h|rollup_1d)
  plus a note chip when `meta.partial`, `meta.raw_fallback` or
  `meta.resolution_warning` is set. It is visible during loading (`…`) and in
  the empty state.
- **Availability ribbon.** `net.icmp.reachable` (1/0, or a fractional bucket
  average) is bucketed into ≤120 segments: fully reachable / partially
  reachable / unreachable / no data. The legend, every segment `title`, and
  the container `aria-label` carry the state text; the summary reports
  "% of observed buckets fully reachable (n/m)" plus down/partial/no-data
  counts.
- **Gaps.** `connectNulls: false` on every line; the query API returns
  explicit `null` buckets and the foot reports `meta.quality.gaps`, so gaps
  render as line breaks and are counted, never interpolated.
- **Brush-to-zoom.** A horizontal drag on the plot converts the pixel span
  through `convertFromPixel` into axis values and applies
  `dataZoom{startValue,endValue}`; a zoom readout (percentages or time range)
  and a "Reset zoom" button appear while zoomed. Wheel zoom and the dataZoom
  slider remain available; drag-to-pan is disabled so the drag is always the
  brush. There is no auto-refresh on charts (range buttons re-query; status
  alone polls at 30 s).

## 9.3 Check-run UX

`CheckRunner` posts `{poll_type}` to `POST /v1/devices/{id}/checks` with the
session CSRF header and a client-generated `Idempotency-Key`, then polls
`GET /v1/checks/{id}` once per second until the row is terminal (90 s bound,
then an explicit "still pending — collector may be offline" notice). Both
buttons are disabled while a check is pending, so UI retries cannot consume
the per-device pending ceiling. Terminal results show status + outcome (icon +
word), error class and latency. After settling, poll-health is refreshed
immediately and again at +2 s/+5 s because the `origin=on_demand` health row
is emitted asynchronously through the collector health path; that row then
appears in the recent-checks table. A missing mgmt_ip, no collector
(409 `check.no_collector`) and pending-limit (409 `check.pending_limit`) all
render the server problem detail.

## 9.4 Accessibility choices

- Status is never color-only: every `StatusChip` renders a glyph **and** the
  state word (`▲ up`, `▼ down`, `? unknown`, `✓ success`, …) and carries
  `data-status`; the ribbon repeats its states in the legend text and in each
  segment's accessible name.
- Chart containers are `role="img"` with descriptive `aria-label`s; range and
  filter buttons use `aria-pressed`; tables keep header rows and the device
  links are real `<a>` elements.
- Loading, empty and error states exist for every panel and assertable
  `data-testid`s (used by the Playwright specs).

## 9.5 Tests and observed results

Environment: Windows 11 dev host, Docker Desktop, dev compose stack rebuilt
from HEAD (server + collector + web; schema v17), Playwright against
`http://127.0.0.1:3000` with the real API and the real dev collector.

| Command | Result |
|---|---|
| `npm run build` (web/) | **pass** (Next.js 16.3.7, TypeScript clean; routes `/devices/[id]`, `/interfaces/[id]`, `/sites/[id]` dynamic) |
| `npx playwright test e2e/visibility.spec.ts --reporter=list` | **pass, 5/5** (19.0 s) |
| `npx playwright test --reporter=list` (full suite) | **pass, 18/18** (4 workers, 33.0 s; existing devices/credentials/collectors/metrics/login specs unchanged and green) |

The new spec (`web/e2e/visibility.spec.ts`) uses one login for the whole file
(login rate limiter), creates devices/interfaces through the real API with the
session + CSRF pair, and covers:

1. device detail: header/critical badge, live status chip, identity history
   (serial + mgmt IP), interfaces table link, resolution badge present before
   data, M11 placeholder;
2. device charts: real stored ICMP series (`points >= 1`, resolution badge,
   gap accounting, ribbon segments/summary) and brush-to-zoom + reset;
3. on-demand check: pending → completed result with outcome/latency against a
   polled device, then the on-demand poll-health row in recent checks;
4. interface detail: identity/status/backlink, honest empty chart states on
   the dev stack (no SNMP-polled interfaces), then an intercepted canonical
   matrix to assert the chart renders a `rollup_1m` badge, `2 gaps` and brush
   zoom (UI-state test; the real-API path is asserted first);
5. site dashboard: status counts, URL-driven status filter with all shown
   chips matching the filter, URL-driven search, and the device link.

No Go code was touched, so no Go build/lint run was needed or performed.

## 9.6 Decisions and limitations (M10-S3)

1. **Web-only, no backend change:** no OpenAPI, Go, proto or migration edits.
   The only environment action was rebuilding the dev server/collector images
   from the existing HEAD (the running containers predated M10-S0..S2), which
   is required for the app to reach the APIs this slice consumes.
2. **Alerts panel is a placeholder** ("Alerting arrives with M11"); no alert
   data source exists in M10.
3. **Interface utilization strip** is one bounded query per device page
   (`net.if.in_octets` selector without dimensions, latest value per
   `if_name`, % of `speed_bps`); it renders "—" when no rate samples exist.
   Heat strips/floor plans are deferred.
4. **On-demand checks are invisible to the status rollup by design**
   (M10-S0); the checks panel says so. The ledger itself is not listed (no
   list endpoint); recent checks are the `origin=on_demand` poll-health rows.
5. **Dev-stack interface counters are empty:** the dev collector has no
   SNMP-polled interfaces (interfaces table empty, no `net.if.*` series), so
   the interface charts show the honest empty state locally; the chart path is
   exercised with a canonical matrix fixture in Playwright. In an SNMP-polled
   environment the same selectors resolve real series (proved by M10-S2
   integration tests).
6. **Chart compare mode / threshold bands / heatmaps** from docs/13 §23 are
   not in this slice; only ribbon + lines + dual axis are implemented.
7. **No LCP/perf measurement was performed** (noted per the slice brief);
   charts and pages are server-rendered shells with client data fetches, and
   the existing ECharts dynamic import is reused (no new dependency).
8. **Site device table is capped at the API page** (100 devices; `has_more` is
   surfaced); pagination beyond one page is a follow-up. Recent issues fan out
   to at most five poll-health requests and are capped at ten rows.
9. **URL state** is used for the site filters only; device/interface range
   selection stays component state (shareable-range URLs are a follow-up).
10. **TanStack Query / generated OpenAPI client** (docs/13) are not used: the
    Phase-1 web stack is plain client `fetch` components, and this slice
    follows that existing pattern to avoid new dependencies.

## 9.7 Files changed (M10-S3)

- Pages: `web/src/app/(app)/devices/[id]/page.tsx`,
  `web/src/app/(app)/interfaces/[id]/page.tsx`,
  `web/src/app/(app)/sites/[id]/page.tsx` (new); `web/src/app/(app)/page.tsx`
  (site links + copy).
- Features: `web/src/features/visibility/{DeviceDetail,InterfaceDetail,
  SiteDashboard,TimeSeriesChart,AvailabilityRibbon,CheckRunner,StatusChip,
  format}.tsx|ts` (new).
- Shared: `web/src/lib/api.ts` (`problemDetail`, `fetchJSON`),
  `web/src/features/inventory/DevicesList.tsx` (device links),
  `web/src/app/globals.css` (visibility styles).
- Tests: `web/e2e/visibility.spec.ts` (new).
- Docs: this file.

---

# 10. M10-S3a — device edit/delete + SNMP credential binding UI

**Status: M10-S3a COMPLETE.** Web-only follow-up to §9 closing the two
user-reported gaps: the device detail page offered no way to edit or remove a
device, and no way to attach an SNMP credential (binding was API-only). No Go,
OpenAPI, proto or migration change; schema stays v17. All APIs already existed;
no backend tweak was needed.

## 10.1 What was added

| File | Change |
|---|---|
| `web/src/features/visibility/DeviceAdminPanel.tsx` | New: edit form + delete confirm on `/devices/[id]` |
| `web/src/features/visibility/DeviceCredentialPanel.tsx` | New: bound/effective credentials, bind + unbind controls |
| `web/src/features/visibility/DeviceDetail.tsx` | Hosts both panels; `current` device state updates in place on edit (`role` already passed) |
| `web/src/app/(app)/credentials/page.tsx` | Stale "bindings are API-only until the M10 surface" footer replaced with a pointer to the device page panel |
| `web/e2e/device-admin.spec.ts` | New spec (4 tests, one login) |
| `docs/phase-2/M10_EVIDENCE.md` | This section |

## 10.2 Edit / delete UX

- **Edit** (`device-edit-open` toggles `device-edit-form`; fields name, kind,
  mgmt_ip, serial, sys_object_id, critical): `PATCH /v1/devices/{id}` with
  session + `X-CSRF-Token`. The body always carries the six editable fields;
  blank mgmt_ip/serial/sysObjectID are sent as JSON `null`, which is the
  documented "null clears nullable fields" PATCH semantic (non-null fields are
  changes; there is no "omitted = unchanged" ambiguity in this form because it
  is pre-filled with the current values). `kind` is constrained to the same
  canonical taxonomy as the add form (a non-listed current kind is preserved by
  an extra option).
- Server errors render verbatim: `400 validation.failed` + `errors[]` field
  list (`device-edit-field-errors`), `409 device.name_conflict` /
  `device.identity_conflict` and `403 auth.forbidden` details in
  `device-edit-error`. Submit is disabled while busy.
- On success the PATCH payload updates the header immediately via
  `onUpdated` and `router.refresh()` re-syncs the server props.
- **Delete** (`device-delete-open`): inline confirm step
  (`device-delete-confirm-step`) with cancel, then `DELETE /v1/devices/{id}`
  (session + CSRF). 204 soft-deletes; the UI navigates to `/devices`, whose
  list no longer contains the device. Errors render in `device-delete-error`.
- Non-admin callers see `device-admin-readonly` (API enforces admin role +
  `device.write` + CSRF regardless).

## 10.3 Credential panel

- **Data source**: `GET /v1/credentials?limit=100` (metadata + `bindings[]`
  summaries; secrets never appear). Panel states: loading, `403` forbidden,
  error, empty.
- **Bound to this device**: bindings with `scope_type=device` and
  `scope_id=device.id`, one row each with kind, priority and an Unbind button
  (`POST /v1/credentials/{id}/unbind` `{scope_type:"device", scope_id}`).
- **Effective for this device**: derived client-side from the binding
  summaries with the same ordering as `credentials.selectEffective` — scope
  rank `device > device_group > site > org`, then higher priority, then the
  lowest credential id (UUIDv7 is time-sortable, i.e. the oldest credential).
  Device-group membership is not resolvable in this view (and the current
  server resolver's `groupMembership` hook is nil, so the tier does not win
  today); if any `device_group` binding exists the result is explicitly
  labelled provisional. Labelled by design, per the slice brief.
- **Bind control**: select an existing credential (`GET /v1/credentials`
  list), optional integer priority (default 0), `POST
  /v1/credentials/{id}/bind` `{scope_type:"device", scope_id, priority}` with
  session + CSRF. `409 credential.binding_conflict` ("already bound"), `404
  credential.target_not_found` and every other problem+json detail render in
  `device-credentials-bind-error`. The panel reloads after bind/unbind; the
  bind request carries only a credential id (no secret material), and secrets
  are never returned or rendered by this panel.
- **Hint/link**: `device-credentials-create-link` points to `/credentials`
  where the existing create form lives (and the page's stale API-only footer
  was corrected).
- **Permission semantics**: the whole credential surface is org-wide
  (`requireOrgScope`): a caller with site/device scope bindings gets
  `403 auth.forbidden` "credential management requires org-wide scope" on
  list, bind and unbind; the panel renders that detail in
  `device-credentials-forbidden`/`device-credentials-bind-error`. Edit/delete
  require the admin role + `device.write`; non-admins get the readonly note.

## 10.4 Tests and observed results

Environment: Windows 11 dev host, Docker Desktop (WSL2), dev compose stack
rebuilt (`docker compose -f deployments/compose/docker-compose.dev.yml up -d
--build web`), Playwright against `http://127.0.0.1:3000` with the real API.

| Command | Result |
|---|---|
| `npm run build` (web/) | **pass** (Next.js 16.3.7, TypeScript clean) |
| `npx playwright test e2e/device-admin.spec.ts --reporter=list` | **pass, 4/4** (3.5 s) |
| `npx playwright test --reporter=list` (full suite) | **pass, 22/22** (22.6 s, 4 workers): 18 pre-existing + 4 new, all green |

The new spec covers: (1) mgmt_ip edit → header updated, plus the 400
field-error path; (2) credential created via the API, bound with priority 5 →
device row + effective credential, duplicate bind → `binding_conflict`, unbind
→ gone; (3) delete with cancel then confirm → back on `/devices` and the row
is absent; (4) intercepted `403` on PATCH and bind → server problem detail
rendered (the dev caller is org-wide, so the 403 paths need interception to be
observable).

## 10.5 Decisions and limitations (M10-S3a)

1. **No backend change**: PATCH/DELETE devices, GET credentials with binding
   summaries, and bind/unbind all existed and were used as documented in
   `openapi/argus.v1.yaml` (§§ device + credentials). The device_group tier in
   the effective label is provisional until group membership is resolvable.
2. **`null` means clear** in the edit form: blanking a nullable field clears
   it; this is deliberate and surfaced in the labels. `site_id`, `status`,
   `poll_profile`, `firmware` and `metadata` are not edited here (out of the
   reported gap).
3. **Soft delete, not hard delete**: the API soft-deletes and the list hides
   it; there is no undelete UI in this slice.
4. **Credential panel is admin-gated in the UI** and org-wide-gated by the
   API; a scoped admin sees the 403 detail rather than controls. Non-admin
   users see the readonly note and no bindings.
5. **Effective credential can change after bind/unbind** (site/org fallbacks),
   so the panel always reloads; a bounded `limit=100` list is used (no
   pagination beyond one page).
6. **Not addressed** (still out of scope): credential edit of non-secret
   metadata, device-group binding UI, undoing a device delete, and surfacing
   the effective credential on the devices list.

---

# 11. M10-S3b-1 — identity add/close API, device-list usability, credential binding UI

**Status: M10-S3b-1 COMPLETE.** First UI-completion batch of M10-S3b: (A)
identity attributes at device create **and** after create, (B) device-list
filters/search/cursor pagination, (C) credential binding UI for the
site/device_group/org scopes. Additive: no migration (schema stays v17), the
existing PATCH identity lifecycle and every pre-existing route shape are
unchanged. Interface add/edit UI, the device-groups page, merge/split UI and
the global checks page remain S3b-2/3.

## 11.1 API deltas

| Method + path | Capability / scope | Purpose |
|---|---|---|
| `POST /v1/devices/{id}/identities` | `device.write` / `device` | Open one identity-history window (`source=manual`, `last_seen_at` null) |
| `POST /v1/devices/{id}/identities/{historyId}/close` | `device.write` / `device` | Close one identity-history window (stamp `last_seen_at`) |

- Both routes are session + CSRF protected and admin-gated in the handler
  (`requireAdmin`) plus the router capability check; scope is enforced by
  resolving the parent device and `Scope.AllowsDevice`, so foreign/out-of-scope
  devices are a uniform `404 device.not_found` (enumeration resistance). A
  history row that is missing or belongs to another device is
  `404 device.identity_not_found`, so a foreign row and a random UUID are
  indistinguishable.
- **Lifecycle reuse:** the add path reuses `openIdentity` (the same store
  function device create/PATCH use) so the partial unique index
  `device_identity_history_open_uniq` (migration 000011) produces the
  deterministic `409 device.identity_conflict` when the key is open on another
  live device. `openIdentity` now reports whether it actually inserted; a
  repeat for the same `(device, type, value)` returns the existing open row
  (`201`) and emits **no redundant audit event**. Close is likewise idempotent:
  a repeat close returns the already-closed row (`200`) without a second audit
  event. Closing a window frees the value for historical reuse (proved by the
  integration test).
- **Audit:** new actions `device.identity_add` / `device.identity_close`
  (resource type `device`, resource id = device id, data carries the history
  row id/type/value) go through the existing inventory `AuditSink`; only
  actual window transitions are recorded.
- **Create-path validation addition (small, additive):** `identities[]` values
  are now format-checked for `mac` (`net.ParseMAC`) and `mgmt_ip`
  (`net.ParseIP`), the two types `identity.go` canonicalizes. Field errors stay
  indexed (`identities[i].value`) so the add form renders them per row. Other
  identity types remain free text.
- **OpenAPI:** both operations + the `IdentityCreate` schema are documented with
  exact `x-argus-capability`/`x-argus-scope`; the authz contract test and the
  route-registry unit test pin the new inventory count (22).
- Device detail gets the add/close controls; the device list keeps its existing
  fields and adds a poll-status chip (no response-shape change).

## 11.2 Device list

- **Server filters already existed** (`filter[site_id]`, `filter[status]`,
  `filter[kind]`, `cursor`, `limit`) and are unchanged; the UI uses site and
  kind server-side and always requests `include=status` for the M10-S1
  rollup decoration.
- **Status select is up/down/unknown over `poll_status.status`** and is applied
  client-side: the server's `filter[status]` is the inventory lifecycle
  (`new/up/down/degraded/maintenance/retired`) and has no `unknown`, so the
  S1 rollup has no server filter. This is a documented judgment call; the
  select's values are exactly the S1 poll-status vocabulary.
- **Search filters by name or management IP client-side over the loaded rows**:
  `/v1/devices` has no text-query parameter (inspect: only the four filters,
  `cursor`, `limit`). The URL still carries `q` via `router.replace`.
- **URL-driven params**: `site`, `status`, `kind`, `q` (same
  `window.location.search` pattern as the site dashboard).
- **Load more** follows `next_cursor` and appends pages (first page keeps the
  pre-existing 100-row size so a freshly added device is visible immediately;
  capped at 5 loaded pages / 500 rows) with an explicit note; no unbounded
  loading.
- Existing rendering (name links, critical badge, kind/site/lifecycle status,
  mgmt IP, timestamps) is preserved; the poll-status chip carries
  `data-status` so the filter is assertable.
- **Newest-first ordering (verification follow-up):** the slice's first
  verification failed once the dev database passed 100 live devices, because
  `/v1/devices` ordered ascending and newly created devices fell past the first
  cursor page. Fix: additive `order=asc|desc` on the device list (desc mirrors
  the cursor comparison; default `asc` keeps existing consumers byte-identical)
  and the UI now requests `order=desc`. Pinned by
  `TestInventoryListNewestFirstOrder` (asc default, desc pages, invalid order ->
  400). Final gate after the fix: full local gate green (integration 322 s) and
  the full Playwright suite green (27/27).

## 11.3 Credential binding UI

- New `CredentialBindings` client component on `/credentials` (rendered for
  admins): one section per credential listing its binding summaries (scope,
  resolved target label, priority) with a per-binding **Unbind**, plus a
  **Bind** form (scope type select, target picker, optional priority default 0).
  All mutations carry session + CSRF.
- **Targets**: sites from `GET /v1/sites`, device groups from
  `GET /v1/device-groups`, and org — `GET /v1/me` returns
  `org: {id, slug, name}` (`httpx.MePayload`), so the org id is knowable and
  org is bound directly to the caller's own org id, matching the server's
  `resolveTarget` rule. **No org deferral is needed.**
- Device-scope bindings are listed and can be unbound here, but binding to a
  device stays on the device detail page (M10-S3a panel).
- problem+json details render verbatim: `403 auth.forbidden` ("credential
  management requires org-wide scope"), `409 credential.binding_conflict`
  ("already bound"), `404 credential.target_not_found`. After bind/unbind the
  component reloads its list and `router.refresh()` re-renders the server
  table's binding-summary column.

## 11.4 Tests and observed results

Environment: Windows 11 dev host, Docker Desktop (WSL2); full integration suite
runs against a testcontainers TimescaleDB; Playwright runs against the rebuilt
dev stack (`docker compose -f deployments/compose/docker-compose.dev.yml up -d
--build server web`) at `http://127.0.0.1:3000` with the real API.

| Command | Result |
|---|---|
| `go build ./...` (windows) and `GOOS=linux go build ./...` | **pass** |
| `go test ./internal/... -count=1` | **pass** (all packages; new route-count pin in `internal/api`) |
| `go test ./tests/integration/ -count=1 -timeout 30m` | **pass, 365s** (new `TestInventoryIdentityAddAndClose` + capability/CSRF/scope/cross-tenant additions) |
| `go test ./tests/contract/... -count=1` | **pass** (OpenAPI ↔ route metadata match, inventory count 22) |
| `gofmt -l internal cmd tests` | **empty** |
| `golangci-lint run` (v2.14.0) | **0 issues** |
| `npm run build` (web/) | **pass** (Next.js 16.3.7, TypeScript clean) |
| `npx playwright test --workers=1` | **pass, 27/27** (29.7s): 22 pre-existing + 5 new |

New Playwright coverage:
- `devices.spec.ts`: add form records a MAC identity (invalid MAC renders the
  indexed `identities[0].value` problem, then the detail page shows the open
  window); URL-driven site/kind/status/q filters with a server refetch and a
  poll-status consistency check; "Load more" follows `next_cursor` and appends
  the next page (deterministic two-page interception).
- `device-admin.spec.ts`: add identity on an existing device (bad-MAC field
  error, hostname window, idempotent repeat leaves one row, close stamps the
  window and removes the button).
- `credentials.spec.ts`: bind to a site (priority 3) and a device group,
  duplicate bind renders `credential.binding_conflict`, per-row unbind, and an
  intercepted 403 renders the org-wide scope rule.

Environment notes (acceptance hygiene, not code deltas): the dev stack had
accumulated 111 `e2e-*` fixture devices from earlier suite runs, which pushes
new devices past the first cursor page; those fixtures were soft-deleted with
the API's delete semantics (open identity windows closed, non-fixture devices
preserved) before the full run. The suite was run with `--workers=1` because
the per-IP login limiter (burst 10, 1 token/6s) is marginal for the 10
first-logins the seven spec files issue when four workers start together; the
single-worker run is fully green and all assertions are unchanged.

## 11.5 Decisions and limitations

1. **Poll-status and text search are client-side over loaded rows.** The
   status filter only sees rows already loaded (use Load more for deeper
   pages); `filter[status]` is deliberately not reused because it is the
   inventory lifecycle and lacks `unknown`.
2. **Load more is capped at 5 pages (500 rows)** with an explicit note rather
   than unbounded accumulation; the first page stays at 100 rows (the
   pre-existing page size) because the ascending id cursor would otherwise hide
   a freshly added device behind the loaded pages.
3. **Identity add/close only touch identity history.** Adding `serial`,
   `sys_object_id` or `mgmt_ip` via the new endpoint does not rewrite the
   corresponding device column; those columns still transition through PATCH
   (existing lifecycle untouched), which the UI copy states.
4. **Org binding is included, not deferred**, because `/v1/me` exposes the org
   id; the org target is fixed to the caller's organization (the API rejects
   any other id as a uniform 404).
5. **Device-group membership remains unresolvable** in the effective-credential
   previews (pre-existing server resolver limitation); the bindings UI simply
   manages the binding, it does not claim resolution.
6. **Device-scope bindings are not addable on `/credentials`** (only listed and
   unbindable); adding them stays on the device page, per the slice brief.
7. **Create-path identity format validation is a small behavior addition**:
   invalid MAC/mgmt_ip values in `identities[]` now yield indexed 400 field
   errors instead of being stored verbatim.

## 11.6 Files changed

- Backend: `internal/modules/inventory/{audit,http,service,store}.go`,
  `internal/api/{routes,router}.go`, `internal/api/routes_test.go`,
  `openapi/argus.v1.yaml`, `tests/contract/authz_contract_test.go`.
- Integration tests: `tests/integration/m10s3b1_identity_test.go` (new) plus
  capability/CSRF/scope/cross-tenant additions in
  `tests/integration/inventory_api_test.go`.
- Web: `web/src/components/{AddDeviceForm,CredentialBindings}.tsx`,
  `web/src/features/visibility/DeviceDetail.tsx`,
  `web/src/features/inventory/DevicesList.tsx`,
  `web/src/app/(app)/credentials/page.tsx`.
- Playwright: `web/e2e/{devices,device-admin,credentials}.spec.ts`.
- Docs: this section.


## 12. M10-S3b-2 (device-management UIs)

Scope: the remaining device-management surfaces after S3b-1. **No backend or
OpenAPI change was needed**: every operation already existed with the exact
shapes and error codes the UI consumes (verified against
`openapi/argus.v1.yaml` and `internal/modules/inventory/http.go`). The slice is
web-only.

### 12.1 UI surfaces

| Surface | Where | API |
|---|---|---|
| Interface add/edit/delete | device detail, `DeviceInterfacePanel` | `POST /v1/devices/{id}/interfaces`, `PATCH /v1/interfaces/{id}`, `DELETE /v1/interfaces/{id}` |
| Device groups CRUD | `/device-groups`, `DeviceGroupsManager` | `GET/POST /v1/device-groups`, `PATCH/DELETE /v1/device-groups/{id}` |
| Merge | device detail, `DeviceMergePanel` | `GET /v1/devices` (picker) + `POST /v1/devices/{id}/merge` |
| Split | device detail identity section | `POST /v1/devices/{id}/split` |

Nav: the app header now carries Devices / Device groups / Credentials /
Collectors links (always visible in the shell) and the dashboard links the
new page too; the device-groups test walks the nav link.

### 12.2 Interface management

- **Fields** are exactly the accepted create schema: `if_index` (required,
  integer >= 1), `if_name` (required), `if_alias`, `if_type`, `admin_status`,
  `oper_status`, `speed_bps` (>= 0), `mtu` (>= 0), `mac` (must parse),
  `description`, `role` (`uplink|access|trunk|unused|unknown`), `monitored`.
  The form exposes `if_index`, `if_name`, `if_alias`, `role`, `monitored`,
  `speed_bps`, `mtu`, `mac` (the task's named set); edit hides `if_index`
  because `decodeInterfacePatch` treats it as immutable, and poll-derived
  columns (`if_type`, admin/oper status, `description`) stay server-owned.
- **PATCH semantics:** `if_alias`/`mac` are sent as `null` when blank (the
  decoder's `patchNullable` clears them); `speed_bps`/`mtu` are sent only when
  non-blank because the raw PATCH decoder coerces JSON `null` to `0` for both,
  so "blank leaves unchanged" is the honest behaviour.
- Loading/empty/error states, per-field and detail problem+json rendering,
  an add-form ifIndex prefill (`max+1`), a confirm step for delete, and a
  refresh after every mutation. Non-admins see the table plus a read-only note
  (`interface.write`); all mutations carry session + CSRF. Enumeration
  resistance is unchanged: the panel reads through the scope-checked device
  route, so foreign/out-of-scope ids remain a uniform 404.

### 12.3 Device groups page

- Full CRUD with a JSON selector textarea. Client-side validation mirrors the
  one server rule (`validJSONObject`: selector must be a JSON object; arrays,
  scalars and `null` are 400 field errors); blank means `{}`. The hint text
  states the API rule, and server problems render verbatim (`409
  device_group.name_conflict`, `403 auth.forbidden`, 400 field errors).
- **Membership resolution is a documented deferral** (docs/11 §21, M7/M9
  evidence): no engine evaluates the selector, so the page shows the stored
  rule and says so explicitly (`device-groups-membership-note`). The page does
  not pretend to list members and no membership engine was built.
- Delete is a confirm step; create/edit/delete refresh the table. Non-admins
  get a read-only view (the API additionally enforces org-wide scope for
  create and admin + `device_group.write` for mutations).

### 12.4 Merge / split

- **Merge** excludes the target from the picker, searches the loaded first page
  (100 devices, `order=desc`, name/mgmt-IP client-side because the list API has
  no text query), and shows a confirmation that counts each source's identity
  windows and interfaces (fetched from the real per-device list endpoints)
  before posting `{source_device_ids}`. `device.merge_conflict` (ifIndex
  collision), the defensive `device.identity_conflict`, 403 and the uniform
  404 render from problem+json. On success the panel reloads, identity and
  interfaces refetch, and `router.refresh()` re-syncs the shell.
- **Split** renders checkboxes only on **open** identity rows, posts
  `{identity_history_ids, name}` (kind/site/reason omitted so the server
  inherits source kind + site), and renders 400 field errors and the 409
  `device.identity_conflict` / `device.name_conflict` details. Success shows
  the new device name with a link to it, reloads the identity table and
  refreshes the route. No interfaces move on split (server contract).

### 12.5 Tests and observed results

Environment: Windows 11 dev host, Docker Desktop; Playwright against the
rebuilt dev stack (`docker compose -f
deployments/compose/docker-compose.dev.yml up -d --build web`) at
`http://127.0.0.1:3000` with the real API. No Go files were touched, so the
Go gates were not applicable (the previous green backend state is unchanged).

| Command | Result |
|---|---|
| `npm run build` (web/) | **pass** (Next.js 16.3.7, TypeScript clean; `/device-groups` in the route table) |
| `npx playwright test --workers=1` | **pass, 33/33** (46.2s): 27 pre-existing + 6 new |

New Playwright coverage:
- `device-admin.spec.ts` (4): interface add (invalid MAC -> indexed 400 field
  error, then created with alias/speed), duplicate ifIndex -> 409, edit
  (field error then save, ifIndex immutable), delete confirm/cancel/confirm;
  merge moves identity + interfaces onto the target while the source becomes a
  uniform 404 and disappears from inventory (target present, sources absent);
  merge ifIndex collision -> 409 `device.merge_conflict` and the source stays
  live (atomicity); split moves an open identity window onto a new device via
  the result link, with a real `device.name_conflict` 409 first.
- `device-groups.spec.ts` (2): nav link + create/edit/delete with the
  duplicate-name 409 and confirm-step cancel; client selector validation
  (malformed JSON, array) plus the intercepted 403 problem rendering.

Fixture hygiene note: the dev DB now holds >100 live `e2e-*` devices from
repeated suite runs, which surfaced a latent M10-S3 issue: the site dashboard
loaded the site's devices with the inventory cursor default (ascending), so a
device created after the site passed 100 rows was never rendered and the
pre-existing site-dashboard spec failed. The minimal adjacent web fix (one
line) makes `SiteDashboard` request the existing `order=desc` parameter, the
same newest-first choice `DevicesList` already documents. No API shape change.

### 12.6 Decisions and limitations

1. **Web-only slice.** All three surfaces consume existing endpoints; no
   backend, OpenAPI, migration or capability change.
2. **Membership resolution stays deferred.** The groups page stores/validates
   the selector and explicitly documents that nothing evaluates it yet; no
   membership engine or member preview was built (brief + M7 deferral).
3. **Merge identity_conflict is defensive.** Open-window uniqueness makes a
   live duplicate unstageable from the UI, so end-to-end coverage exercises
   the practical 409 (`device.merge_conflict`, ifIndex collision); the
   identity_conflict branch renders the same problem path.
4. **Merge picker is bounded to the newest 100 devices** with client-side
   search, matching the inventory first-page convention; deeper pages are a
   future enhancement, not a membership engine.
5. **Interface form omits poll-derived fields** (`if_type`, `admin_status`,
   `oper_status`, `description`) so operator edits cannot masquerade as SNMP
   observations; `if_index` is immutable by contract.
6. **Speed/MTU cannot be cleared to NULL through PATCH** (the raw decoder maps
   JSON `null` to `0`), so the form leaves them unchanged when blank rather
   than silently writing `0`.
7. **Split exposes open rows only.** Closed windows are history; the server
   requires rows to belong to the source device, which the UI enforces by
   construction (it only offers rows from the loaded identity table).

### 12.7 Files changed

- Web components: `web/src/features/visibility/DeviceInterfacePanel.tsx`
  (new), `web/src/features/visibility/DeviceMergePanel.tsx` (new),
  `web/src/features/inventory/DeviceGroupsManager.tsx` (new),
  `web/src/features/visibility/DeviceDetail.tsx` (panels + split UI),
  `web/src/features/visibility/SiteDashboard.tsx` (order=desc hygiene fix).
- Pages/shell: `web/src/app/(app)/device-groups/page.tsx` (new),
  `web/src/app/(app)/layout.tsx` (nav), `web/src/app/(app)/page.tsx` (home
  link), `web/src/app/globals.css` (`textarea`, `.shell-nav`).
- Playwright: `web/e2e/device-admin.spec.ts` (4 new tests + helper),
  `web/e2e/device-groups.spec.ts` (new, 2 tests).
- Docs: this section.

## 13. M10-S3b-3 (checks / poll-health operator page)

Scope: the final UI-completion slice — an operator-facing `/checks` page
showing (a) the org-wide on-demand check ledger and (b) the bounded recent
poll-failure feed, plus the two minimal additive read endpoints they need
(`GET /v1/checks`, `GET /v1/poll-health`). M11 alerting, Step-12 diagnostics
and global configuration stay out of scope.

### 13.1 Backend endpoints

**`GET /v1/checks`** — org-wide on-demand check ledger.

- **Authz**: session + `device.read` (the capability `GET /v1/checks/{id}`
  already uses). Scope is the same site-filtered collection read as
  `GET /v1/devices`: the query joins `devices` and a caller bound to sites sees
  only checks whose device site is in the bindings. An explicit
  `filter[device_id]` outside the caller's scope is a deterministic
  `403 auth.forbidden` (the M7 list-filter rule, mirroring `filter[site_id]`
  on `/v1/devices`); for restricted callers an unknown id folds into the same
  403, and for unrestricted callers it is a valid filter over an empty set
  (no existence oracle). The join deliberately does not filter soft-deleted
  devices: item/list parity — any row readable through `GET /v1/checks/{id}`
  stays in the ledger (checks are operator history).
- **Pagination**: keyset cursor = check id (UUIDv7). Response
  `{data, next_cursor, has_more}`; `limit` 1..100 (default 25).
- **Ordering**: newest first by default (`order=desc`, the operator feed
  reading); `order=asc` mirrors the devices-list additive `order` parameter
  and is reachable for symmetry. The default flips (desc instead of the
  devices-list asc) because this collection has no pre-existing consumers whose
  cursor contract would change.
- **Filters**: `filter[status]` ∈ `pending|completed|failed`,
  `filter[poll_type]` ∈ `icmp|snmp`, `filter[device_id]` (UUID); anything else
  is a `400 validation.failed` problem+json with a field error.
- **Lazy expiry**: pending rows past `PendingTTL` (10 min) are failed as
  `expired` org-wide before the page is read, the same honest rule
  `GET /v1/checks/{id}` applies per item.

**`GET /v1/poll-health`** — bounded recent poll-health feed.

- **Authz/scope**: session + `device.read`, scope-filtered exactly like the
  checks ledger (join devices on site); the same deterministic 403 applies to
  an explicit out-of-scope `device_id`.
- **Window**: `since` (RFC3339) defaults to now-1h and must be within the last
  24 h; a 60-second grace absorbs client/server clock and request-latency skew
  at the exact 24 h boundary (a request for exactly 24 h must not be rejected
  milliseconds later), while a 25 h bound is still a deterministic 400.
- **Filters/limit**: `outcome` ∈ `success|failure`, `poll_type` ∈
  `icmp|snmp`, `device_id` (UUID); `limit` 1..200 (default 50). Ordered
  `ts DESC` (`id DESC` tie-break). **No cursor**: documented as a bounded feed
  (the window and limit are the only continuation knobs), not a
  deep-pagination collection; the response echoes the effective `since`.

**Route metadata / contracts**: both are `Protected` `GET`s with capability
`device.read` and scope `site` (collection reads, exactly like
`GET /v1/devices`; no CSRF). Route counts re-pinned: inventory 22,
credentials 6, check surface 3 (the 2 M10-S0 routes + `GET /v1/checks`),
poll-health feed 1. `openapi/argus.v1.yaml` gained both paths with
`x-argus-capability`/`x-argus-scope` and full parameter/response docs; the
authz contract test now scans the poll-health surface in both directions
(registry → spec, spec → registry).

### 13.2 Decisions

1. **Newest-first default plus `order`** (documented above): the feed is the
   operator's primary reading order, and the additive `order=asc` keeps the
   devices-list pattern available without changing the new default.
2. **Cursor = raw check id**: UUIDv7 is time-ordered, so the id is the keyset
   and the comparison direction flips with `order`; no opaque encoding is
   needed for a UUIDv7 key (the M9 per-device health route's opaque
   `(ts,id)` cursor stays as-is).
3. **Bounded feed, not pagination**: poll-health volume is probe-cadence
   driven and the operator question is "what failed recently"; a cursor would
   encourage walking the 90-day hypertable through the API. The per-device
   `GET /v1/devices/{id}/poll-health` route remains the deep-pagination path.
4. **24 h max + 60 s grace** (documented above); future `since` values are a
   400 rather than a silent empty page.
5. **Scope and 403 rules mirror M7 exactly**, including the soft-deleted
   device treatment on explicit filters (`includeDeleted=true`) so an in-scope
   deleted device's ledger rows remain filterable.
6. **Lazy expiry is duplicated on the list read** because the checks module has
   no background expiry worker; the same statement shape as the item read uses
   the database clock so create/read/list agree.

### 13.3 Web page

- Shell: a `Checks` nav link (`nav-checks`, between Device groups and
  Credentials) and a dashboard link; the page is `/checks`
  (`web/src/app/(app)/checks/page.tsx` → `ChecksView`). Reads only, so no role
  resolution is needed client-side (the API enforces scope/capability).
- **On-demand checks panel**: real `GET /v1/checks` table (device link, poll
  type, status chip, outcome + error class, latency, created, completed),
  newest first, with URL-driven `status` and `poll_type` filters and a
  cursor-driven **Load more** (append; 25-row pages). Loading/empty/error
  states are explicit (`checks-loading`, `checks-empty`, `checks-error`).
- **Recent poll failures panel**: real `GET /v1/poll-health?outcome=failure`
  table (time, device link, poll type, error class, latency, consecutive
  failures) with a URL-driven window selector (1 h default / 6 h / 24 h). The
  page sends a computed RFC3339 `since`, documents the 24-hour bound in
  `poll-health-note`, and shows `poll-health-loading`/`-empty`/`-error`.
- Device names come from the newest 100 `GET /v1/devices?order=desc` page (the
  bounded convention the rest of the UI uses); unknown ids render a short id
  prefix, and every row still links to `/devices/{id}`.

### 13.4 Tests and observed results

Environment: Windows 11 dev host, Docker Desktop; Go from `.tools/go`, pinned
`golangci-lint` from `.tools/bin`; Playwright against the rebuilt dev stack
(`docker compose -f deployments/compose/docker-compose.dev.yml up -d --build
server web`) at `http://127.0.0.1:3000` with the real API and collector.

| Command | Result |
|---|---|
| `go build ./...` (GOOS=linux GOARCH=amd64 and native windows) | **pass, both** |
| `gofmt -l cmd internal tests` | **clean** (no files) |
| `.tools/bin/golangci-lint run` | **0 issues** |
| `go test ./tests/integration/ -run 'TestM10S3b3' -count=1 -v` | **pass, 2/2** (first targeted iteration; 105 s including testcontainer first-boot) |
| `go test ./tests/integration/ -count=1 -timeout 30m` | **pass** — `ok ... 1253.867s` (exit 0; 139 top-level test functions listed) |
| `go test ./tests/contract/... -count=1` | **pass** (`ok ... 0.272s`) |
| `npm run build` (web/) | **pass** (Next.js 16.3.7, TypeScript clean; `/checks` in the route table) |
| `npx playwright test --workers=1` | **pass, 36/36** (3.1 m) on the rerun; the first attempt was 35/36 with the documented login flake |

New backend coverage (`tests/integration/m10s3b3_checks_health_test.go`):
- checks ledger: newest-first page + cursor continuation, `order=asc`,
  status/poll_type/device filters, 400 validations (status, poll_type,
  device_id shape, order, cursor, limit), unknown-device filter for an
  unrestricted caller (200 empty), a real API-created check becoming the
  newest row, viewer read access, unauthenticated 401, site-scope narrowing,
  deterministic 403 on out-of-scope and unknown device filters, cross-tenant
  invisibility (list and explicit filter).
- poll-health feed: default 1 h window and ts-desc ordering, `since=now-7h`
  including the 6 h row, 25 h / future / malformed `since`, outcome/poll_type/
  device filters, limit bounds, viewer/anon authz, site scope + 403 device
  filters, cross-tenant emptiness.

New Playwright coverage (`web/e2e/checks.spec.ts`, 2 tests): seeds a device +
real on-demand check through the API in `beforeAll`, walks the `nav-checks`
link, asserts the seeded terminal row (status, icmp, real device href),
exercises the URL-driven poll-type/status filters (row disappears then comes
back), and asserts the poll-failure panel against the API's own truth
(table with a device link and error-class cell when failures exist, the
honest empty state otherwise) across the 1 h → 24 h window selector.

**Login flake note (documented):** on the first full Playwright attempt
`collectors.spec.ts` failed only at its `toHaveURL(/\/$/)` after login: the
server's login took 4.4 s under load and exceeded the 5 s assertion window;
the rerun was fully green. This is the known serial-suite login flake (each
spec logs in once; the login route is rate-limited per IP and password
hashing is deliberately slow), not a checks-page regression.

### 13.5 Limitations

- The poll-health feed has **no cursor by design**; deeper history stays on
  the per-device `GET /v1/devices/{id}/poll-health` route (M9-S1).
- The ledger's device-name map is the newest 100 devices (the UI-wide bounded
  convention); devices outside it render a short id prefix with a working
  link. The id is always visible in the href.
- `filter[device_id]` under a device-group-only binding is not expanded:
  group bindings do not resolve to devices yet (unchanged M7/M10-S3b-2
  deferral), so a group-only caller sees an empty ledger exactly like the
  devices list.
- No alerting or diagnostics work (M11/Step-12), no global configuration
  changes — the slice is the two read endpoints plus the page.
- The bounded feed counts on-demand probe failures too (`origin=on_demand`),
  matching the panel title "Recent poll failures"; filtering by origin is not
  exposed (M11 can add it).

### 13.6 Files changed

- Backend: `internal/modules/checks/models.go`,
  `internal/modules/checks/service.go`, `internal/modules/checks/http.go`
  (`ListChecks` + filter/cursor/expiry helpers);
  `internal/modules/pollhealth/health.go`,
  `internal/modules/pollhealth/http.go` (`ListRecent` + `ListPollHealth`);
  `internal/api/routes.go`, `internal/api/router.go` (routes + handlers),
  `internal/api/routes_test.go` (pinned counts/metadata).
- Contract/API: `openapi/argus.v1.yaml` (two paths),
  `tests/contract/authz_contract_test.go` (poll-health surface + counts).
- Integration tests: `tests/integration/m10s3b3_checks_health_test.go` (new).
- Web: `web/src/features/checks/ChecksView.tsx` (new),
  `web/src/app/(app)/checks/page.tsx` (new),
  `web/src/app/(app)/layout.tsx` (nav), `web/src/app/(app)/page.tsx` (home
  link).
- Playwright: `web/e2e/checks.spec.ts` (new, 2 tests).
- Docs: this section.
