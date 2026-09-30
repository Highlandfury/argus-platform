# M7-EVIDENCE — Inventory API remediation (P2-D5, identity uniqueness/lifecycle)

Living evidence record for the M7-S3 remediation pass. It documents the three
remediation areas — capability + scope authorization (P2-D5), DB-enforced
identity uniqueness (P2-AC-01), and identity-history lifecycle on PATCH
(P2-AC-02/P2-D7) — plus the OpenAPI contract enforcement and the test evidence.
Historical phase documents are not rewritten.

References: `PHASE_2_SPEC.md` P2-AC-01/02, P2-D5, P2-D7; canonical docs/04 §6
(RBAC-SC, capability catalog), docs/07 §11.3-11.4 (identity semantics),
docs/11 §21 (tables/uniqueness), docs/12 §22.1/22.5/22.19 (API conventions),
docs/14 §24.4 (authorization layers).

## 1. Capability model (P2-D5)

Every one of the 18 M7-S3 inventory routes declares a capability + scope in the
route registry (`internal/api/routes.go`) and advertises the same metadata in
`openapi/argus.v1.yaml` (`x-argus-capability`, `x-argus-scope`).

Capability vocabulary (9 names), per route:

| Route | Capability | Scope |
|---|---|---|
| GET /v1/devices | `device.read` | site |
| POST /v1/devices | `device.write` | site |
| GET /v1/devices/{id} | `device.read` | device |
| PATCH /v1/devices/{id} | `device.write` | device |
| DELETE /v1/devices/{id} | `device.write` | device |
| GET /v1/devices/{id}/identity-history | `device.identity.read` | device |
| POST /v1/devices/{id}/merge | `device.merge` | device |
| POST /v1/devices/{id}/split | `device.split` | device |
| GET /v1/devices/{id}/interfaces | `interface.read` | device |
| POST /v1/devices/{id}/interfaces | `interface.write` | device |
| GET /v1/interfaces/{id} | `interface.read` | device |
| PATCH /v1/interfaces/{id} | `interface.write` | device |
| DELETE /v1/interfaces/{id} | `interface.write` | device |
| GET /v1/device-groups | `device_group.read` | device_group |
| POST /v1/device-groups | `device_group.write` | org |
| GET /v1/device-groups/{id} | `device_group.read` | device_group |
| PATCH /v1/device-groups/{id} | `device_group.write` | device_group |
| DELETE /v1/device-groups/{id} | `device_group.write` | device_group |

**Naming decision.** `device.read`, `device.write`, `interface.read`, and
`interface.write` are canonical catalog names (docs/04 §6.5). The canonical
catalog does not name identity-history reads, merge, split, or device-group
operations — docs/12 §22.5 maps those coarser (identity-history → `device.read`,
merge/split → `device.write`, device-groups → `device.write`) — so this
increment uses the fallback vocabulary fixed by the remediation spec:
`device.identity.read`, `device.merge`, `device.split`, `device_group.read`,
`device_group.write`. DELETE /v1/devices/{id} collapses under `device.write`
(the spec vocabulary) even though the canonical catalog also defines
`device.delete`; splitting it out later is a metadata-only change. The exact
vocabulary is pinned by `internal/platform/authz` and unit tests, so drift is
caught in CI.

**Role derivation (until roles become data-driven).** `admin` holds all 9
inventory capabilities; `viewer` holds the four read capabilities
(`device.read`, `device.identity.read`, `interface.read`, `device_group.read`);
unknown roles hold nothing (fail closed).

**Enforcement.** `authz.Allowed(role, capability)` runs in the router
(`internal/api/authz.go`, wrapping every route that declares a capability) after
session resolution and, for mutations, after CSRF verification. Existing
protections are unchanged and IN ADDITION: mutations still require the admin
role (`requireAdmin`) and CSRF. Capability denial is deterministic
`403 application/problem+json` with code `auth.forbidden`.

## 2. Scope model (P2-D5)

Scope types: `org`, `site`, `device_group`, `device` (the last is a resolution
granularity, see limitations). Bindings live in `user_scope_bindings`
(migration `000010_user_scope_bindings`): `org_id`, `user_id`, `scope_type`
CHECK (`org|site|device_group`), `scope_id`, UNIQUE(user_id, scope_type,
scope_id), RLS enabled+forced with `user_scope_bindings_tenant` (000005
pattern); `argus_app` DML comes from the 000005 default privileges.

Semantics (implemented by `internal/platform/authz` + inventory handlers):

- No bindings → org-wide access per role capabilities (preserves pre-P2-D5
  behavior). An explicit `org` binding behaves the same (inherits down).
- A user WITH bindings is restricted to the bound subtrees:
  - `site` binding: the site's devices, their interfaces, and their identity
    history.
  - `device_group` binding: listing/reading the group row itself.
  - Bindings are evaluated server-side; `org_id` always comes from the session
    principal, never from the request.
- Collections are narrowed by the caller's scope as a query filter
  (`internal/modules/inventory/store.go`): device lists by bound sites, group
  lists by bound groups, fail-closed when restricted with no matching binding.
- Conflicting collection filter (`filter[site_id]` outside scope) → `403`
  `auth.forbidden`. Item access outside scope → `404` with the resource's
  canonical not-found code (enumeration resistance, docs/14 §24.4). Out-of-scope
  parent on create (device site) or split target site → `403`.

**Documented limitations (this increment):**

- Device-level bindings are not representable (migration CHECK is
  org|site|device_group per the remediation spec); device access resolves
  through the device's site. `x-argus-scope: device` therefore means "resolved
  at device granularity via its site".
- Device-group membership is a `selector jsonb` rule whose grammar is not yet
  pinned (docs/11 §21), so `selector` resolution (group → member devices) is
  deferred: a `device_group` binding covers the group row itself, and
  device listings for group-only callers are empty. When the selector grammar
  lands, membership resolution becomes a store-layer filter, no API change.
- Site bindings do not surface device groups (groups have no site column);
  groups are governed by org/device_group bindings. Same deferral rationale.

There is no generic authorization framework: capability metadata rides the
existing route registry, and scope resolution reuses `database.WithTenant`
(RLS) plus the `users.role` model.

## 3. OpenAPI metadata + CI contract

`openapi/argus.v1.yaml` inventory operations carry vendor extensions
`x-argus-capability` and `x-argus-scope` (documented in the spec description;
this matches docs/12 §22.19 "every endpoint declares auth type, required
capability, scope semantics" and its spec-lint gate). `tests/contract/
authz_contract_test.go` compares the route registry with the OpenAPI document
for every inventory path and method and fails CI when:

- an implemented inventory route lacks capability/scope metadata;
- an inventory operation lacks either vendor extension (scope mapping missing);
- route and OpenAPI method/path or metadata values disagree;
- the OpenAPI declares metadata the route registry does not enforce.

## 4. Identity uniqueness (P2-AC-01)

**Scope:** org-wide, per `(org_id, identifier_type, identifier_value)` for OPEN
windows only (`last_seen_at IS NULL`). Canonical docs/07 §11.4 treat identity
keys as identifying one live device (duplicates become merge-review items) and
docs/11 §21 keeps identity history as windowed SCD-2 rows; the migration makes
the open-window rule a database invariant. Closed rows may repeat (device
replacement, DHCP/IP reuse).

**Migration:** `000011_identity_uniqueness.up.sql` creates the partial unique
index `device_identity_history_open_uniq`; the existing lookup index
`device_identity_history_org_ident` is kept. Down drops the index.

> Migration numbering note: `docs/phase-2/PHASE_2_FILE_PLAN.md` indicatively
> reserved `000010_*` for the M8 CAGG migrations; this remediation uses
> `000010_user_scope_bindings` and `000011_identity_uniqueness` as instructed,
> so M8's CAGG migrations shift to `000012+`. Governance (`migrations.Latest`,
> down/up round-trip, RLS count invariants) is updated consistently.


**Conflict semantic (single, deterministic):** any attempt to create/keep a
second open window for the same key (create, PATCH transition, or a merge that
would leave duplicates) maps PostgreSQL `23505` on this index to
`409 device.identity_conflict` — the whole transaction rolls back. Conflicts on
other unique constraints keep their existing codes (`device.name_conflict`,
`interface.if_index_conflict`).

**Reuse:** soft-deleting a device closes its open windows in the same
transaction (`closeOpenIdentities`), so a replacement device can re-claim the
identity immediately. Merge reparents rows (never clones) and additionally
evaluates open-window uniqueness before commit as defense in depth.

**Upgrade note:** the index build fails loudly on a database that already
contains duplicate open windows (none can be produced through this API).

## 5. Identity-history lifecycle on PATCH (P2-AC-02)

Canonical device columns mapped to `identifier_type`:
`serial` → `serial`, `sys_object_id` → `sys_object_id`, `mgmt_ip` → `mgmt_ip`.
(`chassis_id`, `mac`, `hostname` exist only as explicit history rows; they have
no device column.)

For each canonical field present in a PATCH (`internal/modules/inventory/
identity.go`, executed in the device-update transaction):

- omitted field → history unchanged;
- same value → no row (history stable, idempotent);
- changed value → close the old open window and insert the new open window;
- explicit `null` → close the old window, insert nothing, column set NULL;
- value set from NULL → open a new window only.

All timestamps are the transaction's server `now()` (no client-supplied
times): the new row's `first_seen_at` equals the old row's `last_seen_at` for a
transition. `mgmt_ip` values are canonicalized via `net.ParseIP().String()` and
MAC identity values via `net.ParseMAC().String()` so equivalent encodings do
not create spurious windows. Split moves OPEN windows only (closed rows stay
history), derives the new device's columns from open windows, and clears source
columns whose open identity moved, so both devices stay consistent with their
history; no duplicate open windows can result.

## 6. Audit behavior

Unchanged sink (`AuditSink`/`SlogAudit`) and action catalog:
`device.create/update/delete/merge/split`,
`interface.create/update/delete`,
`device_group.create/update/delete`. Merge/split still emit exactly one audit
event with source ids, moved counts, and reason; identity transitions ride the
existing `device.update` event. Denied capability/scope requests never reach
the mutation handlers (no audit event, no state change); CSRF/capability
denials are visible in HTTP logs with the request id.

## 7. Test evidence

- `tests/integration/inventory_api_test.go`:
  - `TestInventoryCapabilityEnforcement` (S-18): 401 unauthenticated, viewer
    read matrix (devices/identity/interfaces/groups) 200, all 11 write cases 403
    with no state change.
  - `TestInventoryScopeEnforcement` (S-19): site-bound list narrowing, in/out
    item 404s, filter conflict 403, create 403/201, merge/split scope 404s,
    group-bound group visibility, group create 403, org-wide no-binding
    behavior.
  - `TestInventoryIdentityUniqueness`: duplicate serial / sys_object_id /
    mgmt_ip / MAC (case-insensitive) / hostname → 409; PATCH onto a foreign
    identity → 409 with history intact; closed-history and soft-delete reuse;
    cross-tenant duplicate allowed; concurrent duplicate create → exactly one
    201 + one 409; zero duplicate open windows in the DB.
  - `TestInventoryIdentityPatchLifecycle`: DB-row assertions for first/last
    seen, exactly one open row, no redundant row on same-value PATCH, omitted
    field untouched, null closes without opening, multi-field single-timestamp
    transition.
  - `TestInventoryMergeSplitIdentityRegressions`: create→patch→merge,
    create→merge→split, patch→split (source column cleared, old value
    reusable, new value conflicted), duplicate→merge, duplicate→split, no
    duplicate open windows anywhere.
  - `TestInventoryCSRFEnforcement` (S-20): every mutation without the
    double-submit header → 403 `auth.csrf` with no state change; with the
    header → success.
  - `TestInventoryCrossTenantS21` (S-21): foreign device/interface/group
    reads/mutations/merge/split → 404; foreign vs missing responses identical
    (enumeration resistance).
- `tests/integration/inventory_schema_test.go`: seven-table surface incl.
  `user_scope_bindings` (RLS isolation + foreign-insert denial), open-window
  uniqueness/history-repeat/reuse/cross-tenant constraint checks, unique index
  shape, down/up round-trip over 000011..000008.
- `tests/integration/migrations_test.go`: RLS table/policy counts 18.
- `tests/contract/authz_contract_test.go`: registry ↔ OpenAPI metadata gate.
- Unit: `internal/api/routes_test.go` (route metadata, CSRF, viewer write
  denial), `internal/platform/authz/authz_test.go` (role derivation, scope
  evaluation), `internal/modules/inventory/identity_test.go` (transition
  semantics, 23505 mapping, canonicalization).

Verification commands and observed results are recorded in the M7-S3
remediation report (build, inventory/security/full integration suites, unit
suites, contract tests, gofmt, golangci-lint v2.14.0).
