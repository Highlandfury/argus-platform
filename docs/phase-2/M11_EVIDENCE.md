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
