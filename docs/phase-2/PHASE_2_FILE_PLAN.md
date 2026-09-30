# PHASE-2 FILE PLAN

**Status:** Accepted with `PHASE_2_SPEC.md` (2026-09-30). Additive to the
repository; directories listed as "(new)" do not exist yet. One slice at a
time, tests land in the same slice as the code they cover, one commit per
slice.

**Ground rules**

- Migrations continue from `000008`; expand/contract policy, down migrations
  for dev (Phase-1 conventions).
- `openapi/argus.v1.yaml` is the API source of truth; new endpoints carry
  capability mappings (CI-enforced); generated stubs are committed with the
  existing drift check.
- `proto/` changes only in M9 (policy bundle credential materialization);
  `buf breaking` stays green.
- No production code without an acceptance criterion; no dependency on
  NATS/Redis/object storage; no scope from the Phase-2 out-of-scope table.

---

## M7 - Inventory and credentials (detailed)

### M7-S1 - Schema + RLS (first slice)

| File | Purpose |
|---|---|
| `migrations/000008_inventory.up.sql` / `.down.sql` | `devices`, `interfaces` (`UQ(device_id, if_index)`), `device_identity_history`, `device_groups` (`selector jsonb`); indexes, constraints, RLS policies per the M1/000005 patterns |
| `migrations/000009_credentials.up.sql` / `.down.sql` | `device_credentials` (envelope fields: `data_enc`, `kms_key_id`, context), `credential_bindings` (`credential_id`, `scope_type`, `scope_id`, `priority`); RLS |
| `tests/integration/inventory_schema_test.go` | migration up/down round-trip on a real DB; RLS isolation probes (two orgs) for the six new tables; constraint checks |

### M7-S2 - SecretsVault (envelope encryption, dev binding per P2-D2)

| File | Purpose |
|---|---|
| `internal/platform/secrets/` (new) | `SecretsVault` interface, envelope implementation (per-secret DEK, AES-256-GCM, encryption context), local master-key file backend (dev), rotation-of-DEK support |
| `internal/platform/secrets/*_test.go` | unit tests: envelope round-trip, context binding, tamper detection, crypto-shredding |
| `internal/platform/config/config.go` (+ env) | master-key file path config; compose dev env wiring |
| `tests/integration/credentials_at_rest_test.go` | DB dump + log scan finds no plaintext; deleted key material makes rows unreadable |

### M7-S3 - Devices / interfaces / groups API

| File | Purpose |
|---|---|
| `internal/modules/inventory/` (new) | models, store (org-scoped), handlers: `/devices`, `/interfaces`, `/device-groups`; validation; cursor pagination; problem+json |
| `openapi/argus.v1.yaml` | new paths + schemas + capability mappings |
| `internal/server/` wiring | route registration, capability middleware hooks, audit events |
| `tests/integration/inventory_api_test.go` | CRUD, scoping, pagination, merge/split with audit (P2-AC-02) |
| `tests/integration/security_suite_test.go` (extend) | S-series additions: new-endpoint authz + cross-tenant probes |

### M7-S4 - Credentials API + device-list UI skeleton

| File | Purpose |
|---|---|
| `internal/modules/credentials/` (new) | metadata list, write, rotate, `:bind`/unbind; use-hook interface for M9; audit on every op |
| `openapi/argus.v1.yaml` | `/credentials` paths + capabilities |
| `tests/integration/credentials_api_test.go` | write-only enforcement, rotation, binding enforcement at dispatch boundary |
| `web/` | devices list + credential metadata panel (skeleton; full device page is M10) |
| `web/` + `tests/e2e` or Playwright | devices-list smoke |

---

## M8 - Metrics pipeline completion (directory level)

- `migrations/000010_*`: CAGGs `metric_1m/5m/1h/1d` + refresh policies,
  compression (`series_id`, `ts DESC`, after 7 d), retention defaults,
  cardinality/quarantine state if not derivable.
- `internal/modules/metrics/`: resolution picker, `meta.resolution`, caps,
  cardinality guard + quarantine events, retirement job.
- `internal/modules/ingest/`: ADR-016 decision outcome (staging + `COPY` +
  `INSERT ... SELECT ON CONFLICT` path) behind the existing module interface.
- `tests/load/k6/` + harness updates; `docs/phase-2/LOAD_TEST_REPORT.md`;
  failure-suite additions (quarantine, retention/verification job).

## M9 - Polling engine (directory level)

- `internal/collector/poll/` (new): scheduler (tiers, backoff, jitter),
  ICMP prober, SNMP client (v2c/v3, GETBULK), counter state machine,
  template engine + `mibgen` output, rate/safety limits, poll health.
- `proto/argus/collector/v1/collector.proto`: policy-bundle credential
  materialization fields (per-session ECDH+AEAD); regenerated stubs.
- `internal/modules/collectors/`: policy bundle assembly + signing updates.
- `migrations/0000xx_poll_health` + `poll.health` events.
- Test fixtures: `tests/fixtures/snmpsim/` (new), pinned image in
  `VERSIONS.md`; integration + failure-suite additions (poll outage,
  credential revocation mid-run, counter wrap matrix).
- `deployments/compose/`: simulated-device target for e2e.

## M10 - Visibility v1 (directory level)

- `internal/modules/metrics/query`: `POST /metrics/query` contract + ETag.
- `web/`: `/devices/:id`, `/interfaces/:id`, `/sites/:id`, chart components
  (ribbon, brush, compare, resolution badge, heat strips), status rollups.
- `openapi/` additions; Playwright expansions; a11y pass.

## M11 - Alert engine + notifications (directory level)

- `internal/modules/alerts/` (new): rules (versioned), evaluator, state
  machine, dedup fingerprints, storm control, silences/windows, events.
- `internal/modules/notify/` (new): channel adapters (SMTP/webhook/Slack/
  Teams), retries/breaker, delivery logs, templates, HMAC webhooks.
- `migrations/0000xx_alerts`: rules, alerts, alert_events, silences,
  maintenance windows, notification deliveries.
- SSE: `internal/server` `/streams/events` + web live alert queue.
- `spec/default-rules/` (new) curated templates.
- Tests: evaluator semantics matrix, alert e2e (SMTP sink + webhook
  receiver containers), failure-suite (channel outage, storm, rule edit).

## M12 - Self-observability completion (directory level)

- Ops rule pack on a dedicated route; dead-man watchdog; `web/` health page;
  collector lag/queue/failure dashboards; alerts wiring from M8 verification
  jobs.

## Cross-milestone

- `.github/workflows/ci.yml`: new jobs (snmpsim fixtures, alert e2e, nightly
  soak); runner prerequisite NET_RAW/unprivileged ICMP documented in
  `RUNBOOK.md` section 17.
- `docs/phase-2/`: `PHASE_2_ACCEPTANCE.md`, `PHASE_2_SECURITY.md`,
  `PHASE_2_LOAD_TEST.md` (Phase-1 naming conventions).
- `VERSIONS.md`: snmpsim + any new test images pinned.
- `RUNBOOK.md`: polling ops, credential ops, alert ops, maintenance windows,
  ICMP/CI prerequisites.
