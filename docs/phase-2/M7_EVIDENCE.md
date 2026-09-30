# M7-EVIDENCE — Inventory + credentials (M7-S3 remediation, M7-S4 credentials API)

Living evidence record for the M7-S3 remediation pass and the M7-S4 credentials
increment. Sections 1-7 document the three M7-S3 remediation areas — capability
+ scope authorization (P2-D5), DB-enforced identity uniqueness (P2-AC-01), and
identity-history lifecycle on PATCH (P2-AC-02/P2-D7) — plus the OpenAPI
contract enforcement and the test evidence. Section 8 documents M7-S4.
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

## 8. M7-S4 — Credentials API (write-only) + device-list UI skeleton

References: `PHASE_2_SPEC.md` P2-AC-04/05; `PHASE_2_FILE_PLAN.md` M7-S4;
canonical docs/04 §6.4-6.5 (capability catalog + permission matrix),
docs/11 §21.1 (device_credentials / credential_bindings), docs/12 §22.11
(credentials endpoints), docs/14 §24.5 (envelope encryption, bindings,
rotation), docs/14 §24.2 (write-only secrets).

### 8.1 API surface

Six routes, session + CSRF, capability and scope metadata in both the route
registry (`internal/api/routes.go`) and OpenAPI (contract-gated):

| Route | Capability | Scope | CSRF |
|---|---|---|---|
| GET /v1/credentials | `credential.read_metadata` | org | – |
| POST /v1/credentials | `credential.write` | org | yes |
| GET /v1/credentials/{id} | `credential.read_metadata` | org | – |
| POST /v1/credentials/{id}/rotate | `credential.rotate` | org | yes |
| POST /v1/credentials/{id}/bind | `credential.write` | org | yes |
| POST /v1/credentials/{id}/unbind | `credential.write` | org | yes |

The canonical catalog (docs/04 §6.5) names `credential.read_metadata`,
`credential.write`, `credential.use`, and `credential.rotate`; those exact names
are used. Bind/unbind have no canonical name, so both are enforced under
`credential.write` (the canonical CRUD capability for `/credentials` in
docs/12 §22.11) — documented choice, no new vocabulary invented.
`credential.use` is pinned in the vocabulary for the M9 dispatch path but has
no HTTP route in this increment (the resolver is internal-only).

**Role mapping.** `admin` holds all four credential capabilities; `viewer`
holds NONE — not even `credential.read_metadata`. Rationale: the canonical
permission matrix (docs/04 §6.4) gives device-credential create/edit to Org
Admin (F) and Site Admin/Network Engineer (W) and "–" to IT Support, NOC,
Security Operator, Auditor, and Read-only; docs/04 §6.2 states credentials are
"never revealable to any role". Least privilege under the Phase-1 admin/viewer
model is therefore no credential capability for viewer; unknown roles hold
nothing (fail closed).

**Scope semantics.** Credential profiles are org-level rows (no site column)
whose bindings may target any scope type, so the whole credential surface
requires an org-wide caller (`authz.Scope.Unrestricted`); a caller with
scope bindings is denied deterministically with 403 `auth.forbidden`
(mirroring the M7-S3 device-group create rule). Binding targets are validated
server-side independently of caller scope (see 8.4). Finer site-scoped
credential administration is a documented limitation (8.10).

### 8.2 Write-only invariant

Responses are built exclusively from `CredentialMetadata`/`BindingSummary`
projections (`internal/modules/credentials/models.go`): id, name, kind,
descriptor metadata, rotated_at, created/updated, binding summaries. The
envelope columns (`data_enc`, `kms_key_id`, `key_version`,
`encryption_context`) are structurally absent from the projection, and list
queries never even select them. No endpoint reads a secret back: there is no
`GET .../secret` (404), `?reveal=true` is ignored (byte-identical metadata
response), and no handler returns plaintext. Create/rotate accept a `secret`
request field exactly once and seal it before any response is written. A unit
test marshals a credential row with a sentinel secret and asserts no envelope
field or secret byte appears; integration tests scan responses, audit payloads,
captured server logs, and full DB dumps for sentinel plaintext.

### 8.3 Encryption path

Create/rotate call `SecretsVault.Seal(orgID, kind, credentialID, plaintext)`
(P2-D2, M7-S2) and store the returned envelope 1:1 into the 000009 columns; the
encryption context `{org_id, secret_type, secret_id, version}` binds ciphertext
to tenant+record+version and is the AAD of both GCM layers. The server wires
the vault from `ARGUS_SECRETS_KEY_FILE`/`ARGUS_SECRETS_KEY_ID` at startup
(`cmd/argus-server`): dev generates the local master key (P2-D2), non-dev fails
closed, and an unloadable vault leaves the credential routes at 503 rather than
failing the process. Fixing the dev stack required creating
`/var/lib/argus/secrets` with the distroless nonroot ownership in
`deployments/compose/Dockerfile.server` (same pattern as the CA dir) — the
M7-S2 compose wiring was declared but only consumed now.

### 8.4 Binding validation + resolver semantics

Bind validates, inside the caller's tenant transaction and never from request
ids: the credential exists (RLS), and the target exists for its `scope_type`
(`site`→sites, `device_group`→device_groups, `device`→live devices, `org`→the
caller's own org id). Foreign and unknown targets are uniformly
404 `credential.target_not_found` (no existence oracle); duplicates are
409 `credential.binding_conflict` (UQ(credential_id, scope_type, scope_id));
invalid scope types/ids are 400. Unbind is by `(scope_type, scope_id)` and
deliberately does NOT resolve the target, so stale bindings can be cleaned up
after a target row is deleted; a missing binding is 404
`credential.binding_not_found`.

**Resolver (M9 hook, internal only).** `Resolver.ResolveForDevice(orgID,
deviceID)` selects the effective credential by the canonical precedence
docs/14 §24.5 + docs/11 §21.1: direct `device` binding > `device_group` >
`site` > `org`; within one level higher `priority` wins. The canonical docs do
not define a same-priority tie-break; this increment uses the lowest credential
id — UUIDv7 is time-sortable, so it is the OLDEST credential, deterministic and
stable (documented choice). Devices with no applicable binding fail with
`ErrNoCredential`; unknown/foreign devices with `ErrDeviceNotFound` (RLS).
`Resolver.Materialize` is the only plaintext path (envelope → vault `Open`),
never wired to HTTP; tests prove round-trip, determinism, and cross-tenant
rejection. Device-group membership is not resolvable from the current schema
(no devices→groups link; selector grammar unpinned, same limitation as M7-S3),
so the group tier is an extension point: `WithGroupMembership(fn)` lets M9 plug
selector evaluation in without changing the resolver; tests prove the tier is
unreachable by default and resolves when the hook is injected.

### 8.5 Rotation semantics

Rotation re-seals under a fresh per-secret DEK inside one transaction and
atomically replaces `data_enc`, `kms_key_id`, `key_version`,
`encryption_context`, stamps `rotated_at`/`updated_at` with server `now()`, and
returns metadata only. The stored `key_version` follows the vault's current KEK
version: with the dev key ring advanced to version 2, rotation stores version 2
and the version-1-only vault can no longer open the new envelope (integration
test extends the key file to two versions). Under an unchanged KEK the version
stays 1 while ciphertext/DEK change; a per-rotation generation counter is not
introduced because the M7-S2 vault equates context version with KEK version.

### 8.6 Audit events

`credential.create` / `credential.rotate` / `credential.bind` /
`credential.unbind` through the existing `AuditSink` pattern (same event shape
as inventory; action names follow `resource.action`). Events carry actor, org,
resource id, scope type/id/priority, never secret material. Only successful
mutations are audited: capability/CSRF denials and service-level failures
(name conflict, foreign target) produce no success event (asserted by count).

### 8.7 RLS, tenant, and leak tests

`device_credentials_tenant` and `credential_bindings_tenant` (000009,
enable+force+policy) remain the isolation floor; all store paths run inside
`database.WithTenant`. Integration evidence:
`TestCredentialsCrossTenantS24` — B sees no A rows in lists, all point
operations on A ids are 404 `credential.not_found`, foreign vs missing problem
bodies are byte-identical (modulo `request_id`), direct DB probes under B's
context return 0 rows, foreign-org INSERTs raise SQLSTATE 42501 for both
tables, and A's data is untouched afterwards. `TestCredentialsWriteOnlyLifecycle`
+ `TestCredentialsAuditAndLeakScan` scan response bodies, audit JSON, captured
slog output, and `row_to_json` dumps for sentinel plaintext (none found).

### 8.8 Test evidence

- `internal/modules/credentials/*_test.go`: API-safe serialization (no envelope
  fields/secret bytes), request validation, scope vocabulary, resolver
  precedence/priority/tie-break/fail-closed.
- `tests/integration/credentials_api_test.go`:
  `TestCredentialsWriteOnlyLifecycle` (create/list/detail/rotate, no secret
  endpoint, `?reveal=true` inert, at-rest ciphertext, pagination, validation,
  name conflict), `TestCredentialsBindUnbind` (all four scope types, duplicate
  409, invalid/foreign targets, foreign credential 404s, unbind semantics),
  `TestCredentialsEnumerationParity`, `TestCredentialsResolver` (unbound
  rejection, tier precedence, priority, deterministic tie-break, group hook,
  cross-tenant rejection, materialize), `TestCredentialsRotationEnvelopeVersion`,
  `TestCredentialsAuditAndLeakScan`, `TestCredentialsSchemaNoPlaintextColumn`
  (information_schema: only the envelope columns exist; no column name suggests
  raw credential material).
- `tests/integration/security_suite_test.go` extended with S-22
  (`TestCredentialsCapabilityEnforcement`: 401 unauthenticated, viewer 403 on
  all six endpoints), S-23 (`TestCredentialsCSRFEnforcement`: 403 `auth.csrf`
  before any state change), S-24 (`TestCredentialsCrossTenantS24`), S-25
  (`TestCredentialsScopeRestriction`).
- `tests/contract/authz_contract_test.go` extended to the credential surface:
  the registry now pins 18 inventory + 6 credential routes; missing,
  mismatched, out-of-vocabulary, or unenforced metadata fails CI (existing
  checks unchanged).
- Unit suites and route-metadata pins: `internal/api/routes_test.go`
  (6 credential routes, all protected, mutations CSRF, viewer holds none).

### 8.9 Frontend + E2E

- `web/src/app/(app)/devices/page.tsx` + `web/src/features/inventory/DevicesList.tsx`:
  device list (name, kind, site resolved via /v1/sites, status, mgmt IP,
  last-seen/updated) from the real `/v1/devices` API with deterministic
  loading/empty/error states. No device detail page (M10); no detail link is
  fabricated.
- `web/src/app/(app)/credentials/page.tsx` +
  `CreateCredentialForm`/`RotateCredential`: metadata-only panel (name, kind,
  metadata summary, binding summary, rotated/created/updated), admin-gated
  create form (secret submitted once, cleared immediately), per-row rotate.
  Nothing secret is rendered or placed in localStorage/sessionStorage; no
  "show password" affordance exists.
- Playwright (`web/e2e/devices.spec.ts`, `web/e2e/credentials.spec.ts`)
  extends the existing suite (one session per file to respect the 10/min login
  limiter; real API, no fake backend): device list renders a device created
  through the real API with session+CSRF; empty/error states via interception
  (existing metrics-spec pattern); credentials create + rotate never render or
  store sentinel secrets; a direct mutation without CSRF is 403 `auth.csrf`.
  Observed: **10 passed** (6 pre-existing + 4 new) twice against the dev
  compose stack.

### 8.10 Limitations (deliberate deferrals)

- M9 consumption is NOT wired: the resolver/materializer exist and are tested,
  but nothing polls, dispatches, or delivers credentials; `credential.use` has
  no route. No SNMP/ICMP/polling/discovery/alerting/M8/M10 behavior was added.
- Device-group membership resolution is an extension point (see 8.4); the
  group tier resolves only when M9 injects selector evaluation.
- The credential surface requires org-wide scope; site-scoped credential
  administration is deferred (8.1).
- Binding management has no UI yet (API-only; noted on the credentials page).
- `key_version` tracks the KEK version, not a per-rotation counter (8.5).

### 8.11 Verification (all commands run in this increment)

| Command | Result |
|---|---|
| `go build ./...` | pass |
| `go test ./internal/... -count=1` | pass (all packages) |
| `go test -race ./internal/modules/credentials/...` | not runnable on this Windows host: `-race requires cgo`, no `gcc` on PATH |
| `go test ./tests/contract/... -count=1` | pass |
| `go test ./tests/integration/ -run 'TestCredentials' -count=1 -v` | pass (M7-S4 suite incl. schema probe, plus M7-S2 at-rest) |
| `go test ./tests/integration/ -run 'TestSecuritySuite' -count=1 -v` | pass (S-01..S-25) |
| `go test ./tests/integration/ -count=1` | pass (full suite, 114 s) |
| `gofmt -l internal cmd tests` | empty |
| golangci-lint v2.14.0 (docker) `run --timeout 10m ./...` | 0 issues |
| `npm run build` (web) | pass (new /devices + /credentials routes) |
| `npx playwright test` | 10 passed |
