# M11-EVIDENCE — Alert engine (Phase 2)

**Status: M11-S1 (alert persistence + evaluator + rules/alerts lifecycle API)
COMPLETE.** This record covers the first slice of M11 only. Notifications and
channels are M11-S2; maintenance windows, silences, SSE and the alert UI are
M11-S3; composite/baseline rules and incidents are V2 (PHASE_2_SPEC §2 and
P2-D3/P2-D6). Nothing else in M11 is claimed here.

References: PHASE_2_SPEC M11 (P2-AC-27..30, P2-D3 in-process evaluator, P2-D6
device-down gating is V2/topology), `../argus-platform-spec/docs/10-alerts-
diagnostics-rca.md` §17.2-17.5 (rule model, evaluation architecture, dedup and
storms, recovery), docs/11 §21.1/§21.2 (`alert_rules`/`alerts`/`alert_events`
catalog), docs/12 §22.9 (rule lifecycle and alert surfaces), docs/04 §6.4/§6.5
(permission matrix and capability catalog), docs/08 §13.5 (resolution picker,
adopted by M8), docs/17 §34.1 (consistency model: at-least-once evaluation
with dedup, state serialized per fingerprint), M8_EVIDENCE §3 (rollup boundary
and raw fallback).

---

## §S1. Alert persistence, evaluator, and lifecycle API

### S1.1 Scope and shape

Delivered in this slice (backend only):

- **Migration 000018** (`alert_rules`, `alerts`, `alert_events`; RLS
  ENABLE+FORCE with the exact 000005 predicate; unique partial
  `(org_id, fingerprint) WHERE state <> 'resolved'`; list/fingerprint/storm
  indexes; full down migration). `migrations.Latest = 18`.
- **In-process evaluator** (`internal/modules/alerts`, new): scheduler +
  evaluator with the canonical cadence, query path, continuity, state machine,
  dedup, recovery, storm control and snooze semantics.
- **Rules/alerts API**: `/v1/alert-rules` CRUD with immutable versioning,
  `:validate` dry-run, `/v1/alerts` list/detail, and
  `ack|snooze|resolve|comment` lifecycle ops. Session+CSRF, capability and
  scope enforcement consistent with M7/M10; OpenAPI + authz contract updated.
- **Tests**: pure semantics unit matrix; integration suites for evaluator
  behaviour against real ingested samples, API/versioning/validation,
  lifecycle ops with snooze reactivation, authz/scope/cross-tenant isolation
  and RLS probes.

Explicitly NOT in this slice: any notification/channel code (S2); maintenance
windows, silences, SSE and UI (S3); composite/baseline rules and incidents
(V2); topology-based parent suppression (P2-D6: only the device-down ->
child-device gating is deferred to Step 11, and nothing topology-dependent is
implemented here).

### S1.2 Migration 000018

```
alert_rules (org_id, rule_id, version PK, name, type threshold|absence|rate_of_change,
             severity info|warning|critical, condition jsonb, scope_selector jsonb,
             enabled bool, created_by, created_at)
  PK (org_id, rule_id, version)  -- every edit is a new immutable row
alerts (id uuid PK, org_id, rule_id, rule_version FK -> alert_rules,
        fingerprint char(64), resource_type, resource_id, dimension_subset jsonb,
        state pending|active|acknowledged|snoozed|suppressed|resolved, severity,
        value jsonb, started_at, last_evaluated_at, resolved_at, ack_by/ack_at,
        snooze_until, suppression_reason, created_at)
  UNIQUE (org_id, fingerprint) WHERE state <> 'resolved'
alert_events (id uuid PK, org_id, alert_id FK ON DELETE CASCADE, kind, actor_id,
              data jsonb, ts)
  INDEX (org_id, alert_id, ts DESC, id DESC)
```

Design notes:

- **Immutable versions.** `condition`/`scope_selector`/name/type/severity are
  never updated in place: PATCH writes version N+1, GET resolves the highest
  version, and pins exist via `?version=N`. Alerts store the
  `rule_version` that fired them (canonical auditability: "which rule text
  fired this?"); later versions evaluate the fingerprint but never rewrite the
  pinned version.
- **DELETE = disable.** The canonical `alert_rules.enabled` flag is preserved
  per version; DELETE writes a new version with `enabled=false`, so the
  definition history stays complete and the evaluator simply stops selecting
  the rule.
- **Inactive** is the absence of an alert row (the canonical state diagram's
  `[*] -> Inactive`); a Pending alert whose condition clears is deleted
  (reset), never surfaced as an operator alert.
- `started_at` records when the condition first became true (the Pending
  onset); activation/resolution timestamps live in the timeline (and
  `resolved_at`). This keeps the deliverable's fixed column set while making
  the `for_duration` history auditable.
- RLS is enabled + forced on all three tables with the 000005 predicate
  (`nullif(current_setting('app.current_org', true), '')::uuid`), unset context
  denies all rows; direct-DB probes are in the integration suite.

### S1.3 Evaluator

**Placement (P2-D3).** In-process scheduler in `argus-server`; no NATS, no
external queue. Every 15 s the scheduler lists organizations through the auth
role (the same pattern as the collector gauges) and evaluates each enabled
rule whose cadence is due. The due map is in-memory, so a restarted process
evaluates every rule immediately; the durable per-rule heartbeat/evaluator-lag
SLI is M12 scope.

**Cadence (docs/10 §17.3).** `max(30 s, window/2)`, capped at 5 min for
threshold/rate rules; absence rules evaluate at `2 × check_interval`
(`check_interval` optional, default 60 s → 120 s), clamped to the same
30 s/5 min bounds. Unit-tested at the boundaries.

**Query path (docs/10 §17.3, docs/08 §13.5, M8 raw-fallback rule).**

- `window < 5 min` → raw samples (`avg|max|min|sum` over
  `(t-window, t]`); the M8 authoritative choice.
- `window >= 5 min` → the continuous aggregate selected by the M8 picker
  (`window <= 6 h → metric_1m`; coarser spans use 5m/1h/1d because the
  canonical picker maps the span). The newest incomplete bucket is excluded by
  the conservative materialization boundary `t - (end_offset + schedule)`
  aligned down to the bucket — the same boundary rule as the M8 query engine.
  `allow_partial: true` adds the raw tail from the boundary to `t`
  (evidence carries `"partial": true`).
- If the CAGG has no rows for the older span (fresh install/backfill), the
  span is recomputed from raw and evidence carries `"rollup_missing": true`,
  exactly the M8 query-engine behaviour. Tests pin both paths.

**Continuity (docs/10 §17.2/§17.3, "no two lucky samples").** A transition
never trusts the current evaluation alone: the trigger must be true at every
instant of a deterministic evaluation grid over the relevant span
(`Continuous`/`GridPoints` in `condition.go`). Pending -> Active requires
`now - started_at >= for_duration` **and** all grid instants true; a single
false instant — including a mid-span dip discovered retroactively — resets or
holds the state. Missing data is false (a gap never fabricates continuity),
which also implements the canonical missed-cycle rule ("no condition is
assumed true/false across gaps"). The grid is capped at 240 points per
transition; a wider span widens the step deterministically while keeping both
endpoints (documented judgement call).

**Recovery (docs/10 §17.5).** The default recovery is the logical inverse
operator with the same threshold and `for_duration = max(2 × trigger
for_duration, window)`; a zero trigger duration means immediate recovery (no
persistence invented). Recovery requires the inverse continuously over
`recovery.for_duration` on the same grid. Absence recovery is presence-based
(samples: a sample within `recovery.window`, default the condition window;
poll health: `recovery_successes` consecutive scheduled successes, default 2 —
the canonical device-down resolution).

**Absence rules (docs/10 §17.2).** Two sources:

- `samples`: no sample for the series for longer than `window`. A series that
  was never seen does not fire (absence cannot be established from nothing).
- `poll_health`: the newest scheduled polls show `consecutive_failures` >= N
  (default 2). Only `origin='scheduled'` rows count, so an on-demand check can
  never flip a device-down state (M10-S0/M10-S1 rule). Recovery is 2
  consecutive scheduled successes (P2-AC-28).

**rate_of_change.** `(agg(current window) - agg(previous window)) / Δ` in
units/second, compared with the operator; both windows use the same
raw/CAGG resolution rules.

**State machine (docs/10 §17.3, P2-AC-28).**

```
(no row) -[condition true]-> Pending -[for_duration continuously true]-> Active
Pending -[condition false]-> (row deleted; Inactive/reset)
Active/Acknowledged/Snoozed/Suppressed -[recovery continuously true]-> Resolved
Active -> Acknowledged (operator ack) -> Resolved (recovery)
Active -> Snoozed (operator, bounded expiry) -> Active (reactivated if still
          true) / Unsnoozed (condition no longer true; recovery still applies)
-> Suppressed (storm) stays suppressed while true; resolves via recovery
```

Every transition appends an `alert_events` row inside the same tenant
transaction as the state update. Repeat firings on an open alert update
`value`/`last_evaluated_at` and append `updated` (docs/10 §17.4); they never
create a second row.

**Dedup (docs/10 §17.4).** `fingerprint = sha256(rule_id, resource_type,
resource_id, canonical dimension JSON)` (64 hex chars, DB length CHECK). The
dimension subset is the **matched series' canonical dimensions**, so two
interfaces of one device monitored by one rule are two alerts, never one. The
unique partial index `(org_id, fingerprint) WHERE state <> 'resolved'` is the
database-level guarantee behind the single-process evaluator.

**Storm control (docs/10 §17.4, P2-AC-29).** When a new alert would be
created for a device that already produced **>= 20 alerts in the last 5
minutes**, the new alert is created `suppressed` with
`suppression_reason='storm'` and retained (alert #21 onward). Suppressed
alerts still evaluate and resolve; automatic promotion once the storm window
passes is incident/V2 scope. `argus_alerts_storm_suppressed_total` counts them.

**Manual resolve + reopen (docs/10 §17.5).** Manual resolve requires the
`alert.ack` capability and a reason; it records actor + `manual_resolved`. A
re-fire of the same fingerprint within the documented 10-minute reopen
cooldown reopens the *same* row (state active/pending, fresh onset) with a
`reopened` event — no duplicate, exactly as canonical.

**Snooze (P2-AC-30).** `snooze_until` is mandatory and bounded to 30 days
(the canonical silence bound; the docs do not specify a snooze bound).
Evaluation continues while snoozed; when the expiry passes the alert
reactivates if the condition is still true (`reactivated`), otherwise it stays
an open alert on the recovery path (`unsnoozed`) until recovery completes; a
snooze never pauses the state machine.

**Timeouts and bounds.** Per-rule evaluation is wrapped in a 5 s query
timeout (canonical); one rule = one tenant transaction, so a timeout rolls the
rule back atomically. At most 1000 resolved targets per rule evaluation
(deterministic `(device_id, series_id)` order). Metrics:
`argus_alerts_evaluations_total{result}`, `argus_alerts_transitions_total{to}`,
`argus_alerts_storm_suppressed_total`.

**Determinism.** `Evaluator.Now` is injectable, and the exported
`EvaluateOnce(ctx, orgID, now)` / `EvaluateRule(ctx, orgID, rule, now)` take
the evaluation instant explicitly. Tests never sleep; a time jump is
evaluated against stored data, not against a timer.

### S1.4 API surface and capabilities

| Endpoint | Capability | Scope | Notes |
|---|---|---|---|
| `POST /v1/alert-rules` | `alertrule.write` | org | Creates version 1; 201; strict JSON (unknown fields rejected) |
| `GET /v1/alert-rules` | `alertrule.read` | org | Latest version per rule, cursor (`rule_id`) |
| `GET /v1/alert-rules/{id}` | `alertrule.read` | org | Latest, or `?version=N` pinned |
| `PATCH /v1/alert-rules/{id}` | `alertrule.write` | org | Writes version N+1 (omitted fields copied); 409 on a concurrent edit |
| `DELETE /v1/alert-rules/{id}` | `alertrule.write` | org | Writes a disabled version (`enabled=false`) |
| `POST /v1/alert-rules:validate` | `alertrule.write` | org | Dry-run: 200 `{valid, errors[]}`, no persistence |
| `GET /v1/alerts` | `alert.read` | site | Filters state/severity/rule_id/device_id + cursor |
| `GET /v1/alerts/{id}` | `alert.read` | device | Detail + recent timeline (max 50) |
| `POST /v1/alerts/{id}/ack` | `alert.ack` | device | Audited timeline event |
| `POST /v1/alerts/{id}/snooze` | `alert.snooze` | device | `until` or `duration_seconds`; <= 30 d |
| `POST /v1/alerts/{id}/resolve` | `alert.ack` | device | Reason required (canonical); reopen cooldown |
| `POST /v1/alerts/{id}/comment` | `alert.ack` | device | Canonical catalog has no `alert.comment`; documented mapping |

Capability vocabulary (canonical docs/04 §6.5, added to
`internal/platform/authz`): `alert.read`, `alert.ack`, `alert.snooze`,
`alert.silence` (declared; the silences surface is M11-S3),
`alertrule.read`, `alertrule.write`. Role derivation follows docs/04 §6.4:
admin holds all six; **viewer holds `alert.read` only** (read-only is granted
alert view, but ack/snooze/silence and rule management are denied). Alert
items/lifecycle resolve the alert's resource device scope; the list is a
site-scoped read exactly like the devices list, and an explicit out-of-scope
`filter[device_id]` is the deterministic 403 used across M7/M10.

Rules are org-scoped objects whose `scope_selector` narrows targets: a caller
with site bindings may only reference in-scope sites/devices (all must exist),
and an org-wide or kind-only selector requires org-wide scope.
`{"metric": "..."}` is accepted as an alias for `{"metric_key": "..."}` and
normalized on output. Unknown selector/condition keys are rejected so a typo
can never silently widen a rule.

### S1.5 Decisions and judgement calls (canonical-silent points)

1. **Metric/dimensions live in `scope_selector`** (`metric_key`,
   `dimensions`), keeping `condition` the pure
   `{agg, op, value, window, for_duration, allow_partial?, recovery?}` shape
   the slice deliverable fixes. The canonical rule example carries `metric`
   separately; the alias accepts that spelling.
2. **Recovery default** `for_duration = max(2 × trigger for_duration,
   window)`; zero stays zero. The canonical example (3 m trigger → 5 m
   recovery) is illustrative; the invariant implemented is "strictly longer
   when the trigger has any persistence".
3. **Absence cadence default check interval 60 s** (→ 120 s) when the rule
   does not declare `check_interval` — the platform's standard poll tier.
4. **Storm threshold** exactly the canonical `> 20 new alerts/5 min/device`:
   the 21st alert inside the window is suppressed.
5. **Reopen cooldown 10 minutes** for manually resolved fingerprints; the
   canonical docs require the behavior but give no number.
6. **Snooze bound 30 days**, aligned with the canonical silence expiry bound.
7. **`composite`/`baseline`/`event_match` are rejected at validation** (V2);
   `recurrence` is accepted syntactically but a non-empty value is rejected as
   unimplemented v1 (it belongs to maintenance windows, S3).
8. **Dimension subset = matched series dimensions** (per-series alerts); the
   canonical "dimension subset" wording is implemented at series granularity
   because that is the only resource identity the Phase-2 metric store can
   produce per fingerprint.
9. **Disabling a rule stops evaluation; open alerts remain** until recovery
   by another version or a manual resolve. Auto-resolve-on-disable is not
   specified canonically and is not invented here.
10. **`alert_events` is a regular RLS table**; the canonical monthly
    partitioning/13-month retention is a storage-lifecycle concern that lands
    with M13's retention pass (documented deferral).
11. **A revealed mid-span false instant resets Pending.** When the
    `for_duration` span has elapsed and the continuity grid finds a false
    instant, the pending row is removed (Pending -> Inactive, canonical) and a
    later true evaluation starts a fresh Pending onset; the evaluator never
    parks a pending alert that the stored data disproves.

### S1.6 Test evidence

Unit tests (`internal/modules/alerts`):

- `condition_test.go`: cadence boundaries (window 1 m/2 m/20 m; absence
  60 s/10 s/10 m check intervals), grid point boundary/cap, continuity with a
  mid-span false instant and error propagation, operator/inverse matrix,
  recovery-duration defaults, rule parsing/validation matrix (missing op,
  bad op, missing value, unknown keys, bad window, recurrence rejection,
  recovery validation, absence defaults, metric-key requirement), canonical
  selector JSON key-order stability.
- `fingerprint_test.go`: key-order stability, all identity components
  distinct, 64-hex length, nil == `{}`.
- `internal/platform/authz/authz_test.go`: admin holds every alert
  capability; viewer holds `alert.read` only; vocabularies do not cross.

Integration (`tests/integration`, real TimescaleDB container + real router):

- `m11s1_evaluator_test.go`: threshold continuity (pending → active at the
  `for_duration` boundary; a mid-span dip resets the pending alert — the
  canonical Pending → Inactive reset — while the clean series activates; dedup
  updates one row and appends events), recovery + auto-resolve
  + re-fire + manual resolve/reopen-in-cooldown (same row), metric absence +
  never-seen no-fire + presence recovery, poll-health device-down (2
  failures) and 2-success recovery with `origin='scheduled'`, rate_of_change
  rising-only, CAGG path with strict vs `allow_partial` evidence and
  `rollup_missing` raw fallback, storm control (21 alerts: exactly 1
  suppressed with reason storm, all retained).
- `m11s1_alerts_api_test.go`: rule CRUD/versioning/validation/CSRF/404s,
  dry-run validate, alert list filters/detail/timeline, ack/comment/snooze
  (keeps evaluating)/reactivation/resolve (reason required)/state conflicts,
  viewer capability denials, site-bound scope filtering + deterministic
  403/404 + rule-target scope enforcement, cross-tenant 404s, and RLS probes
  on all three tables (foreign rows invisible, unscoped default-deny,
  cross-tenant INSERT refused with 42501).

Observed verification results (Windows host, Docker Desktop, pinned
TimescaleDB 2.30.1):

| Command | Result |
|---|---|
| `go build ./...` (windows) | pass |
| `GOOS=linux GOARCH=amd64 go build ./...` | pass |
| `gofmt -l internal cmd tests` | empty |
| `go vet ./...` | pass |
| `golangci-lint v2.14.0 run --timeout 10m ./...` | **0 issues** |
| `go test ./internal/... -count=1` | pass (all packages) |
| `go test ./tests/integration/ -run '^TestM11S1' -count=1 -timeout 20m` | pass (8 tests: 5 evaluator + 3 API/authz) |
| `go test ./tests/integration/ -count=1 -timeout 30m` (full) | **pass, 958 s** (all T1-T10 + S-suites + M11-S1) |
| `go test ./tests/contract/... -count=1` | pass (OpenAPI + authz contract, alert surfaces included) |

Test-robustness fix found during this verification (test-only, no
production/security change): `TestLoginRateLimitS09` issued its 10-token burst
sequentially; on this host each failed login pays an Argon2 verification, so
the burst could exceed the limiter's 6 s refill interval and turn the 11th
attempt into a 401. The test now issues all 11 rapid attempts concurrently and
asserts exactly 10 x 401 + 1 x 429 (with `Retry-After`), which is the same
security property without the wall-clock dependency (verified `-count=3`).

### S1.7 Limitations and deferrals

- **Notifications/channels (S2)**: no SMTP/webhook/Slack/Teams, no delivery
  logs, retry/breaker or notify budgets. `suppressed` alerts are recorded but
  never dispatched.
- **Maintenance windows, silences, SSE, alert UI (S3)**: `alert.silence` is
  declared in the vocabulary but has no route; suppression reasons cover
  `storm` only; no `/streams/events`.
- **Composite/baseline/event_match rules and incidents (V2)**: validation
  rejects them; storm excess is not attached to an incident.
- **Notification-budget/coalescing and topology parent suppression
  (P2-D6)**: not implemented; only same-device storms are suppressed.
- **Evaluator heartbeat/eval-lag SLI and the missed-cycle recovery sweep**
  (docs/10 §17.3) are M12: the evaluator always recomputes continuity from
  stored data (so gaps never fabricate truth), but there is no durable
  heartbeat row or lag surface yet.
- **`alert_events` partitioning/retention** and **pre-aggregated alert
  history rollups** are M13 retention work.
- **Multi-worker evaluation**: the evaluator is one in-process loop (P2-D3);
  the unique partial index plus per-fingerprint `FOR UPDATE` locking keep it
  safe if a second worker ever appears, but no leader election exists (Phase
  2 HA is Step 16).
- **`device_groups` in `scope_selector`**: not implemented (membership
  resolution is a documented M7 limitation); selectors use sites/device
  ids/kinds.
- **P2-AC-28's "metric→alert state change <= 60 s p95"** is bounded by
  design (cadence min 30 s + 15 s scheduler tick + evaluation), but no load
  measurement is claimed in this slice (no alert load harness exists yet).

### S1.8 Files changed

- `migrations/000018_alert_engine.{up,down}.sql`; `migrations/embed.go`
  (`Latest = 18`).
- `internal/modules/alerts/`: `models.go`, `condition.go`, `fingerprint.go`,
  `service.go`, `evaluator.go`, `scheduler.go`, `http.go`, `metrics.go`,
  `condition_test.go`, `fingerprint_test.go`.
- `internal/platform/authz/authz.go` (+alert vocabulary and role mapping) and
  `authz_test.go`.
- `internal/api/routes.go`, `internal/api/router.go`; `cmd/argus-server/main.go`
  (service, evaluator, scheduler wiring + metrics registration).
- `openapi/argus.v1.yaml` (12 operations + alert schemas);
  `tests/contract/authz_contract_test.go` (alert surfaces, counts,
  vocabulary).
- `tests/integration/m11s1_helpers_test.go`,
  `m11s1_evaluator_test.go`, `m11s1_alerts_api_test.go`;
  `tests/integration/migrations_test.go` (RLS/policy counts 20 → 23).
- This file.

## S2. Notification engine (channels, routes, deliveries, default pack)

### S2.1 Scope and shape

Implements the docs/10 §17.7 pipeline end to end for committed alert
transitions: route match -> render -> adapter -> delivery log -> retries and
breaker. Canonical references: docs/10 §17.7 (pipeline, channels, backoff,
breaker, budgets, message fields), docs/12 §22.9/§22.14/§22.17 (channel/route/
deliveries APIs, webhook signing), docs/04 §6.4-6.5 (capabilities), docs/17
§35.1 (delivery-log retention).

Delivered in this slice: channel adapters (SMTP, generic webhook, Slack,
Teams); the transition consumer; severity+scope routing; channel templates
with a plain-text fallback; at-least-once delivery with dedup identity,
retry schedule and dead-letter; per-channel circuit breaker; severity token
buckets and per-recipient caps; duplicate-content suppression; delivery logs
with response code/excerpt; channel test endpoint; P2-AC-32 curated default
rule pack with new-org seeding. Out of scope by plan: maintenance windows,
silences, SSE and the alert UI (S3); incidents, grouping/digest and
escalation policies (V2).

### S2.2 Pipeline as built

- **Consumption**: `alerts.TransitionSink` (interface in the alerts module)
  is implemented by `notify.Engine.Transitioned`. Only the canonical notify
  kinds dispatch: `activated`, `reactivated`, `resolved`, `manual_resolved`.
  Pending/updated/suppression/ack/snooze/comment transitions are
  timeline-only.
- **Enqueue** runs in one tenant transaction: enabled routes are matched on
  severity (empty = all) and scope (sites / device ids / device kinds; empty
  scope = org-wide). For each (transition, route, channel) the engine mints
  the delivery id, consumes the per-route severity token bucket once per
  matched route (never per channel), applies the per-recipient cap (SMTP `to`
  addresses; webhook uses the single channel recipient), and writes either a
  `pending` row (next attempt = now, rendered subject/body/payload snapshot)
  or a `dead_letter` audit row for suppression (`suppressed: duplicate
  content within 5m window`) or throttling (`throttled: ... severity bucket
  exhausted`, `per-recipient cap exhausted`). Suppressed/throttled
  transitions never send and never spend a bucket token for other channels.
- **Delivery identity**: `DedupKey = sha256("v1|channel_id|alert_id|
  event_kind")`, stable across retries and identical transitions; the
  webhook adapter exposes it and the delivery id as `X-Argus-Dedup-Key` /
  `X-Argus-Delivery`.
- **Worker**: `ProcessDue(org, now, limit)` claims due `pending`/`failed`
  rows with a row lock plus lease (`LeaseDuration`) so a second Phase-2
  worker cannot double-claim; open per-channel breakers keep the message
  queued with the provider's last excerpt; otherwise one attempt with a 10 s
  timeout. Success -> `delivered` (delivered_at, response code/excerpt) and
  the channel failure watch. Failure -> `attempts+1`, next attempt =
  failure instant + schedule (1m, 5m, 30m, 2h, 6h; the last delay repeats,
  capped at created+24 h) until 12 attempts -> `dead_letter`. An unreadable
  vault secret or a missing transport dead-letters immediately (no retry
  storm).
- **Circuit breaker**: 5 consecutive failures open the channel; a half-open
  probe is admitted every 5 min; a success resets. Covered by unit tests.
- **Channel failure watch**: >5% failed/dead-letter attempts over 15 min
  (with at least 20 observations) increments
  `argus_notify_channel_failure_watch_total` and logs a warning; wiring that
  to an ops alert is M12.
- **Best-effort boundary**: the alert transition commit and the enqueue are
  separate transactions (crash window documented). Receivers dedup via the
  stable dedup key/header, so at-least-once delivery is safe.

### S2.3 Migration 000019

`notification_channels` (kind/config non-secret + SecretsVault envelope
columns; per-kind config and secret shapes documented in the migration),
`notification_routes` (canonical `match` jsonb + ordered `channel_ids`),
`notification_deliveries` (status/attempts/delivered-shape/dedup-length
constraints; indexes for the due scan, the delivery log, per-channel and
per-alert views, and the 5 min dedup lookup). All three tables are RLS
ENABLE + FORCE with the standard `app.current_org` predicate. Bodies are
90-day and metadata 13-month retention (docs/17 §35.1); enforcement is the
M13 retention job.

### S2.4 Adapters and wire format

- **SMTP** (`{host, port, username?, from, to[], starttls?}` + write-only
  `{password?}`): plain-text body with the canonical required fields
  (severity, scope, summary, start, evidence and ack links, delivery id),
  subject-header injection guard, tested against a local SMTP sink.
- **Generic webhook** (`{url, payload: ids|summary, timeout_ms?}` +
  write-only `{signing_secret}`): canonical signature
  `X-Argus-Signature: v1=hex(hmac-sha256(secret, timestamp + "." + body))`
  with `X-Argus-Timestamp` (Unix seconds) and the 5 min replay window;
  `notify.VerifySignature` is exported for receivers and proved against a
  local httptest receiver in the integration suite. `ids` payloads drop the
  summary fields. Default timeout 10 s.
- **Slack** (incoming webhook `{webhook_url}`): `{"text": subject + "\n" +
  body}`. **Teams** (incoming webhook `{webhook_url}`): MessageCard with
  severity theme color.
- **Envelope**: versioned `spec_version: "1"` payload with `event`
  (`alert.fired` / `alert.resolved`), `occurred_at`, `org_id` and `data`
  (alert id, fingerprint, severity, summary, resource, state, started_at,
  `site_id`, `resolved_at`, `evidence_ref`, `ack_url`).

### S2.5 API surface and authorization

- `/v1/notification/channels` CRUD + `POST /{id}/test`: capability
  `integration.write`; secrets are write-only (`has_secret` only, never
  echoed); name conflicts are deterministic 409s; channel DELETE is a
  soft-disable so the delivery log keeps its FK.
- `/v1/notification/routes` CRUD: capability `alertrule.write`; matches are
  canonicalized and fail closed; channel ids must exist in the same tenant.
- `/v1/notification/deliveries` list: capability `alert.read`; filters
  `filter[channel_id]`, `filter[alert_id]`, `filter[status]` plus cursor.
- **Scope enforcement (found missing and fixed during S2 verification)**:
  every notification route declares `x-argus-scope: org`. The HTTP edge now
  resolves server-side bindings and denies scope-bound callers with 403
  `auth.forbidden` ("notification management requires org-wide scope"),
  mirroring the credentials `requireOrgScope` rule from M7; the authorizer is
  wired in `cmd/argus-server` and the integration harness.

### S2.6 Curated default pack (P2-AC-32)

`internal/modules/alerts/defaults/default_rules.yaml` (embedded) ships five
v1-vocabulary rules: `device-unreachable-icmp`, `poll-failures`,
`interface-down`, `cpu-high`, `interface-utilization-high`. Selectors are
org-wide per device kind; `net.if.util` stays dormant until the collector
emits that canonical series (documented, no fake data). Installation is
idempotent per `default_key`; patching an installed rule writes a normal
immutable version N+1. `POST /v1/alert-rules:install-defaults` exposes it to
`alertrule.write` admins, and the scheduler seeds a brand-new org through
`EnsureDefaults` (any-rule guard: operator deletions never resurrect).

### S2.7 Test evidence

| Command | Result |
|---|---|
| `go build ./...` (windows) | pass |
| `gofmt -l internal cmd tests` | empty |
| `go vet ./tests/integration/ ./internal/modules/notify/ ./internal/modules/alerts/ ./cmd/argus-server/` | pass |
| `go test ./internal/... -count=1` | pass (all packages, incl. `notify` adapter/engine/render/validate suites and `alerts` defaults) |
| `go test ./tests/integration/ -run '^TestM11S2' -count=1 -timeout 20m` | pass (7 tests): migration RLS invariants; channel/route API + secret hygiene (no plaintext in responses, logs or non-vault columns); signed-webhook end to end with resolve; retry/duplicate/throttle rows; authz/scope/cross-tenant; install-defaults idempotence; EnsureDefaults seeding |
| `scripts/ci-local.ps1 -WithIntegration` (authoritative gate) | **PASS**: fmt/vet/build/test/lint/proto + full integration (545 s) |

Test-robustness fix found during this verification (test-only, no
production/security change): `TestM3EnrollmentRateLimit` (security suite
S01 `rate_limit`) issued its 11 attempts sequentially; on a loaded host the
enrollment token bucket refilled between attempts, so the 11th was admitted
and failed with `PermissionDenied` instead of `ResourceExhausted`. The burst
is now issued concurrently (`sync.WaitGroup`) and asserts exactly
10 x PermissionDenied + 1 x ResourceExhausted - the same security property
without the wall-clock dependency. Verified `-count=2` in isolation plus the
full gate.

### S2.8 Defects found and fixed during S2 verification

- `CreateChannel`/`CreateRoute` used the aliased `channelMetaColumns` /
  `routeColumns` lists in `RETURNING` without a table alias, so every create
  failed with SQLSTATE 42P01 (`missing FROM-clause entry for table "c"`) and
  returned a 500. The INSERTs now alias the table (`AS c` / `AS r`).
- The notification HTTP surface had no scope checks at all: a site-bound
  admin could manage org-level channels/routes (found by the authz
  integration suite). Fixed as described in S2.5.

### S2.9 Limitations and deferrals

- Grouping/collapse (one message per group with N items) and quiet-hours
  digests are V2; this slice renders one message per (transition, route,
  channel).
- Escalation policies are V2; route channel order is stored and honored as
  priority only.
- Retention enforcement (90 d bodies / 13 mo metadata) is the M13 maintenance
  job; the shapes are already constrained by the migration.
- The channel failure-rate watch emits a metric/log only (ops alert wiring is
  M12).
- Slack/Teams support incoming-webhook formats only; SMTP supports PLAIN
  auth with optional STARTTLS (no OAuth).
- Maintenance windows, silences, SSE and the alert UI remain S3.

### S2.10 Files changed

- `migrations/000019_notification_engine.{up,down}.sql`;
  `migrations/embed.go` (`Latest = 19`).
- `internal/modules/notify/`: `adapters.go`, `engine.go`, `http.go`,
  `metrics.go`, `models.go`, `render.go`, `service.go`, `validate.go` plus
  `adapters_test.go`, `engine_test.go`, `render_test.go`, `validate_test.go`.
- `internal/modules/alerts/`: transition-sink hooks in `evaluator.go`,
  `http.go`, `models.go`, `scheduler.go`, `service.go`; `defaults.go`,
  `defaults/default_rules.yaml`, `defaults_test.go`.
- `internal/api/{router,routes}.go`; `internal/platform/authz/authz.go`
  (+notification capability use); `cmd/argus-server/main.go` (notify
  service/engine/worker, scope authorizer, metrics, scheduler seeding).
- `openapi/argus.v1.yaml` (channels/routes/deliveries/test +
  install-defaults); `tests/contract/authz_contract_test.go`.
- `tests/integration/`: `m11s2_helpers_test.go`, `m11s2_notify_test.go`;
  `migrations_test.go` (policy counts).
- This file.

## S3a. Maintenance windows, silences, and the SSE alert stream (backend)

### S3a.1 Scope and shape

Implements the canonical suppression ownership surface and the realtime alert
event feed, backend only:

- **Maintenance windows** (docs/10 §17.6, P2-AC-30): scoped single
  `[starts_at, ends_at)` intervals. While active, matching alerts are
  `Suppressed (maintenance)` — still recorded, still evaluated, never
  notified; health/UI can mark resources "in maintenance" from the API's
  computed `active` flag.
- **Operator silences** (docs/10 §17.6): ad-hoc exact matchers
  (`alert_id` and/or `fingerprint` and/or resource scope), mandatory reason,
  mandatory expiry bounded to 30 days, visible in API; they expire cleanly.
- **Suppression semantics** in the M11-S1 engine: the effective suppression at
  each evaluation instant is projected onto the alert
  (`suppression_reason` + `suppression_ref`) and gates the M11-S2 notify
  engine — suppressed transitions never create delivery rows.
- **SSE `GET /v1/streams/events`** (docs/12 §22.16, P2-AC-33): session-cookie
  auth, site-scope filtered, canonical `alert.fired`/`alert.resolved`/
  `alert.updated` event names, `id:` = the `alert_events` UUID, 20 s
  heartbeats, Last-Event-ID resume from a retained 10-minute buffer with a
  PostgreSQL keyset fallback, bounded per-connection buffers with a documented
  drop policy. In-process pub/sub only (P2-D3: no NATS).

Out of scope by plan: the alert UI (M11-S3b), incidents/composite rules,
digests/quiet hours, notification grouping and escalation (V2).

### S3a.2 Migration 000020

`maintenance_windows` (`name`, `scope` jsonb `{sites, device_ids,
device_kinds}`, `enabled`, `starts_at`/`ends_at` with `ends_at > starts_at`,
`created_by`, timestamps) and `silences` (`match` jsonb
`{alert_id|fingerprint|scope}`, `reason`, `starts_at`/`ends_at` with the
30-day bound as a DB CHECK, `created_by`, timestamps). `alerts` gains
`suppression_ref uuid` (no FK: it points at either suppression table; the
alert timeline remains the durable audit). Indexes: `maintenance_windows`
list + partial active scan (`WHERE enabled`), `silences` list + active scan.
Both tables are RLS ENABLE + FORCE with the standard `app.current_org`
predicate; `migrations.Latest = 20` and the policy/RLS counts move 26 → 28.

### S3a.3 Suppression semantics as built

- **Effective suppression** (`suppressionPlan`) is computed at every
  evaluation inside the rule transaction: active silences first (the more
  specific operator action), then enabled maintenance windows. A silence
  matches when **all present matchers match** (AND: alert id, fingerprint,
  scope); a window matches by site/device id/kind (OR across present lists;
  empty scope = org-wide). Windows use `starts_at <= now < ends_at`.
- **Alert lifecycle**: a firing alert with an active suppression is held in
  `suppressed` with `suppression_reason` ∈ {maintenance, silence} and
  `suppression_ref` = the window/silence id:
  - new alerts open directly as Suppressed (or Pending — then Suppressed at
    the Pending → Active instant for `for_duration > 0` rules);
  - `active` alerts entering a window/silence move to suppressed (an
    acknowledged alert keeps its state but projects the reason);
  - a snooze expiring into an active suppression enters suppressed;
  - repeat firings update value/time and append `updated` events;
  - **recovery during suppression** resolves the alert normally
    (`resolved_at`, `resolved` event) with the reason retained as the audit
    answer, and the resolution transition is marked suppressed;
  - **when the suppression ends while still firing**, the alert reactivates
    (`suppressed → active`, `reactivated` event) and is re-notified
    (canonical Suppressed → Active). If the condition was not continuously
    true for `for_duration`, the onset restarts as Pending (new
    `unsuppressed` timeline event) instead of fabricating a firing.
- **Notify gate**: `alerts.Transition` gains `Suppressed bool`; the evaluator
  and service set it for every transition produced under a suppression, and
  `notify.Engine.Transitioned` drops such transitions before any route work
  (incrementing `argus_notify_suppressed_total{reason}`). Resolutions of
  alerts that never activated outside a suppression (storm-born or
  window-born) are also not notified.
- **Storm precedence**: a planned window/silence wins over the storm limiter
  when both apply (documented judgement call; both mute).
- The alert API payload exposes `suppression_reason` (M11-S1 field, now
  maintenance|silence|storm) and `suppression_ref`.

### S3a.4 API surface and authorization

- `POST/GET /v1/maintenance-windows`, `GET/PATCH/DELETE
  /v1/maintenance-windows/{id}` and `POST/GET /v1/silences`, `DELETE
  /v1/silences/{id}`: capability `alert.silence` (canonical docs/12 §22.9),
  org-scoped like alert rules. Restricted callers may only target in-scope
  resources (same P2-D5 rule as `scope_selector`): out-of-scope targets are a
  deterministic 403, org-wide windows and fingerprint-only silences require
  org-wide scope, out-of-scope item access is a 404, and lists are
  scope-filtered.
- `GET /v1/streams/events`: capability `alert.read`, scope `site` (the same
  metadata as the alert collection read); the session cookie authenticates,
  and the caller's server-side bindings filter the feed (stronger than the
  canonical client-supplied `?filter[site]=`).
- Validation: `recurrence` is not part of the window schema (V2), unknown
  fields are rejected, windows are bounded to 365 days (judgement call),
  silences require `reason` and exactly one of `ends_at`/`duration_seconds`
  within 30 days.

### S3a.5 SSE design

- `alerts.StreamHub` implements `TransitionSink`; both the alerts service and
  evaluator fan out to installed sinks (`AddSink`), so the notify engine and
  the hub consume the same committed transitions without touching the state
  machine.
- **Event mapping**: `activated`/`reactivated`/`reopened` → `alert.fired`;
  `resolved`/`manual_resolved` → `alert.resolved`; every other kind (pending,
  updated, acknowledged, snoozed, unsnoozed, suppressed, unsuppressed,
  comment) → `alert.updated`.
- **Envelope**: `id: <alert_events uuid>` (UUIDv7, time-ordered),
  `event: <canonical name>`, `data: {alert_id, event_id, event_kind, state,
  severity, rule_id, fingerprint, resource_type, resource_id, site_id,
  device_id, suppressed, suppression_reason, suppression_ref?, incident_id:
  null, occurred_at, event_data?}`. `incident_id` is forward-compat null
  (incidents are V2); no `summary` field is fabricated.
- **Replay**: an in-memory retained buffer (10 min, 4096 events, TTL+count
  bounded) serves Last-Event-ID resume; when the id is not retained (restart
  or older gap) the handler falls back to a PostgreSQL keyset replay over
  `alert_events JOIN alerts` (`id > last`, ordered, bounded to 1000), with
  the same scope filter.
- **Flow control**: 128-event per-connection buffer; on overflow the event is
  dropped (`argus_alerts_stream_dropped_total{reason="buffer_full"}`) and
  remains recoverable via Last-Event-ID. Metrics:
  `argus_alerts_stream_clients`, `argus_alerts_stream_dropped_total`,
  `argus_alerts_stream_events_total`.
- `httpx.statusRecorder` gained `Unwrap()` so `http.ResponseController` can
  flush through the access-log wrapper.

### S3a.6 Decisions and judgement calls (canonical-silent points)

1. Silence matchers combine with **AND**; matching is recomputed per
   evaluation (silences take effect at the next evaluation, not
   retroactively).
2. Silence precedence over maintenance; plan precedence over storm.
3. An acknowledged alert is **not** forced into `suppressed` (the canonical
   state diagram has no Acknowledged → Suppressed edge); it carries the
   suppression projection while the window applies, and resolutions are still
   notification-gated.
4. Window end with broken `for_duration` continuity restarts the onset as
   Pending instead of notifying a firing that was never continuously true.
5. DELETE hard-deletes a window/silence; suppression history stays on
   alerts/alert_events (docs/10 §17.6 audit).
6. Per-connection buffer bound 128, retained buffer 4096 events / 10 min,
   PG replay page 1000, window duration bound 365 days: documented where the
   canonical docs are silent.
7. The canonical `?filter[site]=` stream query is replaced by server-side
   bindings (a client filter cannot widen scope).

### S3a.7 Test evidence

| Command | Result |
|---|---|
| `go build ./...` (windows) | pass |
| `GOOS=linux GOARCH=amd64 go build ./...` | pass |
| `gofmt -l internal cmd tests` | empty |
| `go test ./internal/... -count=1` | pass (incl. new `alerts` suppression matching + stream buffer/replay unit tests) |
| `go test ./tests/integration/ -run '^TestM11' -count=1 -v` | pass (22 tests: 8 S1 + 7 S2 + 7 S3a) |
| `go test ./tests/integration/ -count=1 -timeout 30m` | pass (full suite, 778 s) |
| `go test ./tests/contract/... -count=1` | pass (silences 3 / windows 5 / stream 1 routes pinned) |
| `golangci-lint run --timeout 10m ./...` | 0 issues |
| `scripts/ci-local.ps1 -WithIntegration` (authoritative gate) | **PASS**: fmt/vet/build/test/lint/proto + full integration (799 s) |

S3a integration tests (7): maintenance-window lifecycle (trigger during,
enter from active, resolve during, reactivate + re-notify on window end,
recovery after); silence by alert id (suppressed, resolve-while-silent,
reason retained); silence by scope (clean time expiry → reactivate); 
suppression API + capability/scope/cross-tenant/RLS invariants; SSE lifecycle
envelope + Last-Event-ID buffer resume + PostgreSQL replay; SSE site-scope
filtering; migration RLS counts.

### S3a.8 Limitations and deferrals

- The web UI (M11-S3b) is the next slice; this backend exposes everything it
  needs (payload fields, CRUD, SSE).
- Window recurrence (RFC 5545 subset), building/floor/device-group targets,
  digests/quiet hours and notification grouping remain V2; windows are single
  intervals over the site/device/kind vocabulary.
- The SSE stream carries alert events only; incident.*/device.*/config.*
  events arrive with their owning slices (incidents are V2).
- Stream buffer and per-connection state are process-local: a restart drops
  the retained buffer, and Last-Event-ID then replays from PostgreSQL (the
  documented fallback). Multi-process fan-out is out of Phase-2 scope (P2-D3).
- The suppression audit is on the alert rows/events; there is no separate
  audit-log surface yet (M13 provides retention enforcement: past suppression
  objects 13 months per docs/17 §35.1).
- `?filter[site]=` is intentionally not implemented; scoping is server-side.

### S3a.9 Files changed

- `migrations/000020_suppression_stream.{up,down}.sql`;
  `migrations/embed.go` (`Latest = 20`).
- `internal/modules/alerts/`: `suppression.go`, `suppression_http.go`,
  `stream.go`, `metrics.go`, `models.go`, `evaluator.go`, `service.go`,
  `http.go`; unit tests `suppression_test.go`, `stream_test.go`.
- `internal/modules/notify/engine.go` (+`metrics.go`): suppressed-transition
  gate and reason labels.
- `internal/api/{router,routes}.go` (`AlertsStream` option, 9 routes);
  `internal/platform/httpx/middleware.go` (`Unwrap`);
  `cmd/argus-server/main.go` (hub wired into both sinks and the router).
- `openapi/argus.v1.yaml` (windows/silences/stream paths, schemas,
  `Last-Event-ID` parameter, alert suppression fields);
  `tests/contract/authz_contract_test.go` (new surfaces + counts).
- `tests/integration/`: `m11s3a_helpers_test.go`,
  `m11s3a_suppression_test.go`, `m11s3a_api_test.go`,
  `m11s3a_stream_test.go`; `migrations_test.go` (28 policies).
- This file.

## S3b. Alerts + suppression web UI (queue, detail, maintenance windows, silences)

### S3b.1 Scope and shape

M11-S3b is the web-only operator surface for the M11 backend (S1 lifecycle API,
S2 deliveries, S3a suppression objects + SSE stream). Delivered:

- **`/alerts` queue** (`?tab=queue`, the default): real rows from
  `GET /v1/alerts` with server-side filters (`filter[state]`,
  `filter[severity]`, `filter[rule_id]`, `filter[device_id]` — the exact
  OpenAPI parameters), cursor "Load more", state/severity/suppression chips,
  resource (device + site) and rule links, evidence summary, started/age, ack
  state, and explicit loading/empty/error states.
- **`/alerts/{id}` detail**: state/severity/rule/resource/site context,
  suppression reason and ref rendered human-readably and linked to the owning
  tab, full evidence object, `alert_events` timeline (max 50 per the API),
  notification deliveries for the alert (`filter[alert_id]`, with a clear
  empty state), and capability-gated actions: Acknowledge, Snooze (duration
  picker), Resolve (mandatory reason), Comment, Silence this alert.
- **`/alerts?tab=maintenance`**: maintenance-window list (Active/Scheduled/
  Expired/Disabled badge, scope summary, interval, enabled) + create dialog
  (name, sites/device-kinds/devices scope pickers, start/end, enabled) +
  delete with a confirm dialog.
- **`/alerts?tab=silences`**: silence list (Active/Expired, mandatory reason,
  target summary, interval) + delete with a confirm dialog.
- **Live updates**: every queue/detail view subscribes to
  `GET /v1/streams/events` via `EventSource` (session cookie, same-origin
  rewrite). `alert.fired`/`alert.resolved`/`alert.updated` patch visible rows
  in place; rows that leave the active state filter are removed; a new
  matching alert refreshes the first page (debounced) or offers an explicit
  "N new updates — Refresh" chip when extra pages are loaded. The connection
  state is always visible ("Live" / "Connecting…" / "Live updates
  unavailable") and the unavailable state keeps manual Refresh working.

No fake data: empty/error/unavailable states are explicit, capped pages are
labeled, and features the API does not expose (text search, time-range filter,
site filter, rule management UI) are stated in the surface rather than
invented.

### S3b.2 Routes and files

| Route | Surface | Test ids (highlights) |
|---|---|---|
| `/alerts` | `AlertsView` queue | `alerts-view`, `alerts-table`, `alerts-row-{id}`, `alerts-filter-{state,severity,rule,device}`, `alerts-sse-status`, `alerts-refresh` |
| `/alerts/{id}` | `AlertDetailView` | `alert-detail`, `alert-detail-state`, `alert-timeline`, `alert-deliveries`, `alert-action-{ack,snooze,resolve,comment,silence}`, `alert-{snooze,resolve,comment,silence}-dialog` |
| `/alerts?tab=maintenance` | `MaintenanceWindowsView` | `maintenance-table`, `maintenance-create-dialog`, `maintenance-delete-confirm` |
| `/alerts?tab=silences` | `SilencesView` | `silences-table`, `silences-row-{id}`, `silence-delete-confirm` |

Web files:

- `web/src/features/alerts/`: `types.ts`, `format.ts`, `stream.ts`,
  `LiveIndicator.tsx`, `AlertsView.tsx` (queue + `AlertStateBadge` /
  `SeverityBadge`), `AlertDetailView.tsx`, `MaintenanceWindowsView.tsx`,
  `SilencesView.tsx`.
- `web/src/app/(app)/alerts/page.tsx` (replaces the Phase-1 `ComingSoon`
  placeholder), `web/src/app/(app)/alerts/[id]/page.tsx`.
- `web/src/components/shell/nav.ts` (Alerts is real, no planned marker),
  `web/src/app/globals.css` (alert-surface classes on the design tokens).
- `web/next.config.ts` (`compress: false`, see S3b.6).
- `web/e2e/alerts.spec.ts` (new); `web/e2e/shell.spec.ts` (the one
  alerts-placeholder assertion replaced with the real queue, see S3b.7).

### S3b.3 UX behaviors as built

- **URL-driven filters.** State/severity/rule/device live in the query string
  (`state`, `severity`, `rule`, `device`) and map 1:1 to the API filters; the
  intent-ref pattern from `ChecksView` prevents stale-parameter races. The
  rule picker loads `/v1/alert-rules`; the device picker loads
  `/v1/devices` + `/v1/sites` and groups options by site (`<optgroup>`). If a
  picker fetch is forbidden/unavailable, it degrades to a UUID text input
  (Enter/blur) instead of a dead end; while loading it is a disabled select.
- **Standard vocabulary.** Alert lifecycle words (Pending/Active/Acknowledged/
  Snoozed/Suppressed/Resolved) are text-first `Badge`s; severity uses
  Info/Warning/Critical with the canonical degraded/down tones; suppression
  adds a Maintenance/Silence/Storm qualifier. The resource-health
  `StatusIndicator` mapping is deliberately not reused for the alert state
  (an active alert must not render as "Healthy").
- **Actions.** Ack is one click; Snooze/Resolve/Comment/Silence use the
  `Dialog` primitive with bounded durations (≤ 30 d), mandatory reason on
  resolve/silence, server `problem+json` details on failure, and a visible
  result line. Actions are hidden for read-only roles (viewer) while the API
  still enforces every capability.
- **Silence semantics.** Creating a silence does not retroactively rewrite an
  open alert; the UI says suppression takes effect at the next rule
  evaluation, and the e2e proves it end to end (S3b.7).

### S3b.4 IA placement decision

The shell's established IA has no planned maintenance/suppression route. The
alerts workspace is therefore one surface with URL-driven tabs (`Queue`,
`Maintenance Windows`, `Silences`) under the existing Observability → Alerts
nav item (test id `nav-alerts` kept, `planned` marker removed). Rationale:
alert suppression objects are owned by the alerting domain (canonical
docs/10 §17.6), the detail dialog must be discoverable from the queue
workspace, and inventing a parallel Admin nav entry would split one domain
across two groups. No `nav.ts` entry was added; the tab is deep-linkable
(`/alerts?tab=silences`) and linked from the detail suppression line.

### S3b.5 Decisions and judgement calls

1. **Site filtering.** The alerts API has no `filter[site]` (site scope is
   enforced server-side by the caller's bindings). The queue renders the
   device picker grouped by site instead of faking a site filter; the UI note
   states which filters the API exposes.
2. **No text search / time range.** `GET /v1/alerts` supports neither; both
   are explicitly listed as not exposed rather than simulated client-side
   (a client-side filter over a cursor-paged list would lie about the result
   set).
3. **Live patching.** SSE events only carry transition metadata, so the queue
   patches the fields it can trust (state/severity/suppression/last-evaluated)
   and refreshes the head for new alerts; the detail view schedules a bounded
   refetch (it needs evidence/timeline/deliveries).
4. **Multi-page live refresh.** When more than one page is loaded, a new
   matching event shows a "Refresh" chip instead of silently collapsing the
   paged list.
5. **E2E fixtures.** Devices/rules/silences/windows are created through the
   real APIs. The evaluator has no HTTP sample-ingest path, so deterministic
   alert rows/events (and the one poll-health failure for the evaluator-driven
   suppression test) are seeded through the dev database with the same shape
   as the Go integration helpers (`docker exec psql`, RLS context set,
   container overridable via `ARGUS_E2E_DB_CONTAINER`).
6. **Role gate = admin/viewer.** The current authz vocabulary has exactly two
   roles; write actions gate on `admin` for the UI and remain
   capability-enforced server-side.

### S3b.6 Defects found and fixed during verification (minimal, documented)

1. **SSE closed immediately in the real server.** `GET /v1/streams/events`
   returned the `retry:` line and closed in ~4 ms on the running stack
   (browser never received events). Root cause: `telemetry.statusWriter` (the
   innermost `http.ResponseWriter` wrapper, applied by `Argus.HTTPMiddleware`)
   had no `Unwrap()`, so `http.ResponseController.Flush()` was unsupported and
   the handler returned. The S3a fix added `Unwrap()` to
   `httpx.statusRecorder` only; the telemetry wrapper was missed, and the
   integration harness does not wire telemetry, which is why S3a tests were
   green. Fix: `statusWriter.Unwrap()` plus
   `TestStatusWriterSupportsFlush` (one method + one regression test; no
   contract change).
2. **Next same-origin rewrite buffered the SSE stream.** Even with Flush
   working, the browser EventSource opened but received no frames through
   `/api/v1/streams/events`: Next's compression layer added
   `content-encoding: gzip` and buffered `text/event-stream`. Fix:
   `compress: false` in `web/next.config.ts` (web-only; payloads are small and
   same-LAN in this deployment). Verified with a browser frame probe
   (`alert.updated` received ~50 ms after the API transition).

### S3b.7 Verification

| Check | Command | Result |
|---|---|---|
| Web build | `npm.cmd run build` (web/) | pass — 27 routes compiled, strict TypeScript clean |
| Web lint | `npm run lint` | not configured (no eslint config/script in `web/package.json`) |
| Go gofmt | `gofmt -l internal/platform/telemetry` | empty |
| Go build | `go build ./...` | pass |
| Go telemetry tests | `go test ./internal/platform/telemetry/... -count=1` | pass (incl. new flush regression test) |
| Go vet | `go vet ./internal/platform/telemetry/` | pass |
| Alerts e2e (focused) | `npx playwright test e2e/alerts.spec.ts --workers=1` | **7 passed** (1.3 m) |
| Full web e2e | `npx playwright test --workers=1` | **45 passed (3.9 m)** — 38 pre-existing + 7 new; the 3 dev-stack flakes recorded in the Phase-1 evidence (checks/metrics/visibility) did not reproduce on this run |
| Final artifact re-check (after the last source cleanup + web image rebuild) | `npx playwright test e2e/alerts.spec.ts e2e/shell.spec.ts --workers=1` | **9 passed** (1.8 m) |
| API smoke | login → `POST /v1/silences` → list → `DELETE` against the running stack | pass (200 / 201 `active:true` / listed / 204 / absent) |

The Go tree is touched only by the one-method telemetry fix and its test. The
authoritative `scripts/ci-local.ps1 -WithIntegration` gate was run on the final
snapshot and reports **PASS** (fmt/vet/build/test/lint/proto + full integration,
500 s), covering all M11-S1/S2/S3a suites plus the new P2-AC-34 lifecycle test
(`tests/integration/m11_gate_lifecycle_test.go`: unreachable device -> exactly
one fired notification -> 2-poll recovery -> resolved, exactly one delivery per
transition with distinct dedup identities).

`shell.spec.ts` keeps its structure and every test id; only the assertion that
`/alerts` renders the ComingSoon placeholder changed to assert the real queue
(`alerts-view`, `alerts-tabs`, no `data-planned` marker) — the planned-page
test still covers `/topology`.

### S3b.8 Limitations and deferrals

- **Redesign Phase 8** owns visual polish and investigation views; this slice
  uses the Phase-1 tokens/primitives and the shell but is intentionally
  utilitarian (dense table, plain panels).
- **No alert-rule management UI.** The rule cell links to the queue filtered
  by that rule (`/alerts?rule=...`); rule CRUD remains API-only.
- **SSE patch scope.** Queue rows patch transition fields only; evidence/
  timeline/deliveries reload on navigation or event-triggered refetch.
- **Deliveries are read-only**; retry/dead-letter operations are not exposed
  by the API.
- **Window recurrence** (RFC 5545 subset), building/device-group targets and
  digests remain V2 per FEATURE_HORIZONS; the dialog creates single intervals.
- **Fingerprint-only silences** require org-wide scope server-side; the UI
  creates alert-id silences from the detail dialog and lists the rest.
- `compress: false` applies to the whole web app; this dev/standalone
  deployment serves small same-LAN payloads and accepts the trade-off, which
  can be revisited with a dedicated streaming route if bandwidth matters.
- The e2e DB-seeding helper depends on the dev compose container name
  (`argus-dev-db-1`, overridable) — the same environment every existing spec
  already requires.

### S3b.9 Files changed

- `web/src/features/alerts/` (new): `types.ts`, `format.ts`, `stream.ts`,
  `LiveIndicator.tsx`, `AlertsView.tsx`, `AlertDetailView.tsx`,
  `MaintenanceWindowsView.tsx`, `SilencesView.tsx`.
- `web/src/app/(app)/alerts/page.tsx` (placeholder → real workspace),
  `web/src/app/(app)/alerts/[id]/page.tsx` (new).
- `web/src/components/shell/nav.ts`, `web/src/app/globals.css`,
  `web/next.config.ts`.
- `web/e2e/alerts.spec.ts` (new, 7 tests), `web/e2e/shell.spec.ts`.
- `internal/platform/telemetry/argus_metrics.go` +
  `argus_metrics_test.go` (SSE flush regression fix).
- `tests/integration/m11_gate_lifecycle_test.go` (P2-AC-34 lifecycle).
- This file.

## S3c. `no_data` max lifetime (24 h -> resolved as unknown state)

### S3c.1 Scope and canonical shape

Closes the last explicit P2-AC-28 clause: `no_data` alerts have "a
max-lifetime policy: if no data for 24 h, auto-resolve with reason
`unknown state` (prevents stale alarms)" (docs/10 §17.5; the optional
follow-up "monitoring gap" task is deferred, see S3c.4).

As built:

- `alerts.NoDataMaxLifetime = 24h` and
  `alerts.ReasonUnknownState = "unknown state"`.
- `Evaluator.SweepNoDataAlerts(org, now)` selects open (`state <> 'resolved'`)
  alerts of **samples-absence** rules that are at least 24 h old and whose
  series has produced no samples in the last 24 h (`metric_series.dimensions
  @> alert.dimension_subset`, so an empty dimension subset stays alive while
  any sibling series of that device+metric reports). Poll-health absence rules
  are excluded: their failures are data, and a device that keeps failing polls
  is still a valid alarm.
- A stale alarm resolves with `resolved_at = now`, state `resolved`, and an
  `alert_events` row `resolved` carrying
  `{reason: "unknown state", auto: true, no_data_for: "24h0m0s", suppressed}`.
  The resolution takes the normal transition path (sinks -> SSE and the
  notification engine), gated by any active maintenance/silence on the
  resource. The sweep is idempotent.
- **Monitoring-gap guard**: the absence trigger path returns false once the
  stream has been silent for the full max lifetime, so a resolved alarm cannot
  re-fire from the gap alone (no resolve/re-fire loop); data resumption puts
  the target back under the normal rule semantics. This mirrors the canonical
  intent that the alarm, not the gap, is stale.
- Wiring: `EvaluateOnce` runs the sweep for the organization and the scheduler
  runs it once per org tick.
- Metric: `argus_alerts_no_data_auto_resolved_total`.

### S3c.2 Decisions and judgement calls

1. Both conditions must hold: the alert is at least 24 h old **and** no data
   exists in the trailing 24 h window; ageing an alert without an aged stream
   (or vice versa) changes nothing.
2. Dimension-subset matching is superset-based (`series.dimensions @> alert
   subset`): with an empty subset any live series of the device+metric keeps
   the alarm alive; with a specific subset only that series does.
3. The auto-resolve is notification-worthy like any recovery (canonical
   requires suppression to gate it; it does not exempt resolves).
4. The optional follow-up "monitoring gap" task is deferred: the platform has
   no task object yet (M13 self-observability owns platform-visible gap
   tracking).

### S3c.3 Test evidence

`TestM11S3cNoDataMaxLifetimeAutoResolve` (tests/integration/m11s3c_nodata_test
.go): a 2 h-stale series fires normally and its activation is dispatched; 25 h
of silence auto-resolves it with reason `unknown state` and dispatches exactly
one resolved message (2 deliveries total, each delivered on attempt 1); a
second sweep is a no-op; a stream silent for the full lifetime does not
re-fire; a fresh sample inside the window keeps an aged alarm active.

| Command | Result |
|---|---|
| `go build ./...` (windows) | pass |
| `go test ./internal/... -count=1` | pass |
| `go test ./tests/integration/ -run '^TestM11S3c' -count=1` | pass (1.6 s) |
| `scripts/ci-local.ps1 -WithIntegration` | **PASS**: fmt/vet/build/test/lint/proto + full integration (623 s) |

Test-robustness fix found during this verification (test-only, no
production/security change): `TestM9S3BindingRemovalDropsCredentialRAMOnly`
asserted the signed-bundle cache directory immediately after the credential
landed in the collector's RAM set, racing the asynchronous bundle write on a
loaded host. The test now waits (bounded 5 s, 50 ms poll) for the first bundle
entry before running its unchanged security assertions (no credential-named
files, no plaintext on disk or in collector/server logs). Verified `-count=2`
plus the full gate.

### S3c.4 Limitations

- The follow-up monitoring-gap task is deferred (no task object yet).
- The sweep runs per organization in-process (the scheduler's existing
  cadence); a durable sweep heartbeat is M12.
- No_data applies to samples-absence rules only; poll-health absence is
  intentionally exempt (see S3c.1).

### S3c.5 Files changed

- `internal/modules/alerts/evaluator.go` (`NoDataMaxLifetime`,
  `ReasonUnknownState`, `SweepNoDataAlerts`, `EvaluateOnce` wiring, trigger
  monitoring-gap guard); `scheduler.go` (per-tick sweep); `metrics.go`
  (auto-resolve counter).
- `tests/integration/m11s3c_nodata_test.go`.
- This file.

## M11 gate readiness (P2-AC-27..34)

Recorded after M11-S1, S2, S3a, S3b and S3c. Authoritative regression:
`scripts/ci-local.ps1 -WithIntegration` - **PASS** (fmt/vet/build/test/lint/
proto + full integration, 623 s) - plus the web suite
`npx playwright test --workers=1` (45 tests).

| AC | Status | Evidence and notes |
|---|---|---|
| P2-AC-27 rule types (`threshold`/`absence`/`rate_of_change`) with `for_duration`, immutable versioning, `scope_selector`, 5 s query timeout, >= 5 m windows via CAGGs, no partial bucket unless `allow_partial` | **PASS** | S1.3/S1.5; evaluator unit + integration suites |
| P2-AC-28 state machine with timeline, recovery `for_duration`, device-down recovery after 2 successful polls, manual resolve capability+reason, `no_data` 24 h -> `unknown state` | **PASS** (p95 measurement deferred) | S1.3/S1.4, S3c; metric->state <= 60 s p95 is bounded by design (rule cadence + 15 s scheduler tick) but not load-measured - the load harness is M12 |
| P2-AC-29 one open alert per fingerprint, repeats update value/time, storm > 20/5 min | **PASS with deferrals** | S1.4; per-site 30/h notify budget with digest coalescing and topology parent/child suppression depend on the pending P2-D6 decision and the V2 topology model |
| P2-AC-30 ack/snooze/comment/resolve audited; snooze reactivates; windows and silences suppress while still recording/evaluating | **PASS with deferrals** | S1.4, S3a, S3b; recurring windows (RFC 5545 subset) are V2 - single scoped intervals shipped; the alerts workspace marks suppression, per-resource dashboard markers land with redesign Phases 3-4 |
| P2-AC-31 SMTP/webhook(HMAC)/Slack/Teams, at-least-once + dedup header, canonical backoff, breaker, severity buckets, duplicate suppression, delivery logs | **PASS with deferral** | S2; the > 5 % failures/15 min channel-failure watch emits a metric + log - the ops *self-alert* is M12's self-observability goal |
| P2-AC-32 curated default rule templates, sane out of the box | **PASS** | S2.6 (5-rule pack, install API, scheduler seeding for new orgs) |
| P2-AC-33 SSE `alert.*` stream, 20 s heartbeats, `Last-Event-ID` resume (10 min buffer + PG replay), site scoping; alert queue updates live; charts pull-based | **PASS** | S3a/S3b; path is `/v1/streams/events` (repo `/v1` convention); scoping is enforced from server-side bindings instead of a query filter |
| P2-AC-34 lifecycle e2e: unreachable -> Active -> one notification -> recovery -> Resolved, exactly one per fingerprint per transition | **PASS** | `m11_gate_lifecycle_test.go` (backend), `alerts.spec.ts` (UI) |

### Gate decisions requested

1. Accept the four documented deferrals above (P2-D6-dependent budget and
   child suppression; recurring windows; M12 self-alert; p95 load
   measurement), or schedule any of them back into M11 before sign-off.
2. Per-resource "maintenance" markers on device/site dashboards: currently
   only the alerts workspace renders them; recommend folding the dashboard
   marker into redesign Phases 3-4 rather than reopening M11.
