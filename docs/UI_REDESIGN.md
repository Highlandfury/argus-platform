# Argus Web UI Redesign — Evidence

**Phase 1 — Application shell, navigation and design system.**

Scope: establish the product skeleton and design language and migrate every
existing page into it without breaking functionality, test ids or backend
contracts. Individual feature pages keep their current internals (Phases 2-9
own them). Web-only: no backend, API or schema changes.

Reference: `docs/FEATURE_HORIZONS.md` labels each capability as real, current
phase, later MVP phase, V2 or V3. Every placeholder route cites it.

---

## 1. Design tokens (`web/src/app/tokens.css`)

Imported by `web/src/app/layout.tsx` before `globals.css`, so tokens are a
single source of truth and legacy styles keep working.

| Token group | Values (summary) |
|---|---|
| Surfaces | `--bg-app #0d1117`, `--bg-surface #161b22`, `--bg-surface-2 #1c2128`, `--bg-inset #0a0e13`, hover/active overlays |
| Borders | `--border #30363d`, `--border-muted #262c34`, `--border-strong #444c56` |
| Text | `--text #e6edf3`, `--text-muted #9aa7b4`, `--text-faint #6e7b8a` |
| Accent | `--accent #4c9aff`, `--accent-strong #79b8ff`, `--accent-dim` |
| Status | healthy `#3fb950`, degraded `#d29922`, down `#f85149`, unknown `#8b949e`, maintenance `#58a6ff`, pending `#a371f7` (each with a 12% background) |
| Type scale | 10/11/12/13/14/16/18/22 px; body 13px, line-height 1.45; sans + mono stacks |
| Spacing | 4/8/12/16/20/24/32/40 px (`--sp-1`…`--sp-10`) |
| Radii | 3/4/6/8 px + pill — restrained, no oversized rounding |
| Shadows | two subtle overlay shadows only (`--shadow-sm/md/lg`) |
| Layout | `--sidebar-w 232px`, `--topbar-h 48px`, `--content-max 1680px` |

Status semantics are canonical and reused everywhere: `up/active/completed`
→ Healthy, `degraded/warning/stale` → Degraded, `down/failed/revoked/critical`
→ Down, `unknown/no data` → Unknown, `maintenance/acknowledged` → Maintenance,
`pending/new/snoozed` → Pending. Status is never color-only: the
`StatusIndicator` always renders a glyph plus the text label (the existing
`StatusChip` a11y rule generalized).

Legacy aliases (`--panel`, `--muted`, `--danger`) and every feature CSS class
(`.panel`, `.status-*`, `.btn-*`, `.metric-*`, `.ribbon-*`, `.kv`, `.util`,
`.stat-card`, …) were preserved and remapped to tokens, so existing pages
inherit the new density (13px body, 6px table cells) without feature edits.

## 2. Shell behavior

`web/src/components/shell/AppShell.tsx` (client) is rendered by
`web/src/app/(app)/layout.tsx` after resolving `GET /v1/me`:

- **Sidebar** (232px, fixed): product mark + ARGUS / “Network Observability”,
  then four groups — OVERVIEW, OBSERVABILITY, OPERATIONS, ADMIN. Active state
  follows the pathname (`/devices/{id}` keeps Devices lit; `/` matches
  exactly). Planned items get a subtle hollow marker (title/tooltip “planned”).
- **Topbar** (48px, sticky): global search (Enter → `/devices?q=<query>`; a
  `⌘K` chip is shown with a tooltip that the command palette is planned),
  live alert indicator (polls `GET /v1/alerts?filter[state]=active&limit=100`
  every 60s; links to `/alerts`; hidden when the endpoint is
  absent/forbidden/unreachable; `100+` when the response is capped), help link
  (repo docs), organization from `/v1/me` (`data-testid="org-name"`), user menu
  with identity and Sign out (`data-testid="logout"` preserved).
- **Responsive**: desktop-first. Below 900px the sidebar becomes an off-canvas
  panel toggled by the topbar `☰` (`data-testid="nav-toggle"`) with a backdrop;
  the org chip hides, the user e-mail truncates. No fake desktop-only dead ends.
- **Failure behavior**: 401 redirects to `/login` (unchanged); an unreachable
  API renders an explicit outage surface instead of a blank shell.

## 3. Nav map — real vs planned

| Route | Nav group | Status today | Notes / horizon |
|---|---|---|---|
| `/` | Overview | **Real** | Dashboard: real sites/devices/collectors/active-alert counts, capped pages labeled; `sites-table` test id kept (AC-12) |
| `/sites` (new) | Overview | **Real** | List from `GET /v1/sites` → `/sites/{id}` (dashboard unchanged) |
| `/devices`, `/devices/{id}` | Overview | **Real** | Existing list + device visibility page untouched inside the shell |
| `/topology` | Overview | Planned | Phase 3 · Step 10/11 (§4) |
| `/interfaces` | Overview | Planned index | Per-device registers and `/interfaces/{id}` charts are real; org-wide inventory needs Step 10 |
| `/wan` | Overview | Planned | Phase 3 · Step 13 v1 (§3) |
| `/services` | Overview | Planned | V2 item 21; HTTP/TLS checks v1 Step 12 |
| `/checks` | Observability | **Real** | Existing ledger + poll-failure feed |
| `/metrics` | Observability | Planned index | M8 engine + collector chart are real at `/collectors/{id}`; page links there |
| `/flows` | Observability | Planned | V3 item 5 |
| `/logs` | Observability | Planned | Audit rows recorded; viewer V2 item 42 |
| `/incidents` | Observability | Planned | V2 item 14 |
| `/alerts` | Observability | Planned UI | Backend M11-S1 live (rules + lifecycle API); queue UI is M11-S3, full experience Phase 8 |
| `/collectors`, `/collectors/{id}` | Operations | **Real** | Enrollment, detail, metrics chart |
| `/config` | Operations | Planned | V2 items 16/17 |
| `/credentials` | Operations | **Real** | Metadata/bindings only |
| `/ipam` | Operations | Planned | V2 item 24 |
| `/device-groups` | Admin | **Real** | CRUD + selector validation |
| `/users` | Admin | Planned | RBAC core built (M7); management UI later |
| `/settings` | Admin | Planned | Org/site settings later |

Every planned route renders `ui/ComingSoon`: “planned / not yet available”
badge, milestone, `FEATURE_HORIZONS.md` section reference and the concrete
planned capabilities. No fabricated data anywhere.

## 4. Component inventory (`web/src/ui/`)

| Primitive | Purpose |
|---|---|
| `PageHeader` | Breadcrumbs, single h1, description, actions, optional URL tabs |
| `StatusIndicator` | Canonical raw→tone mapping + glyph + label (`statusTone` exported) |
| `Badge` | Text-first labels; neutral/accent/status variants |
| `Button`, `ButtonLink` | primary/secondary/ghost/danger, sm/md |
| `Panel` | The one card/panel container: head (uppercase title), body, footer, `flush` tables |
| `Tabs` | URL-param-driven tabs that preserve other query params |
| `Drawer` | Basic left/right sheet, overlay/Escape close |
| `Dialog` | Basic modal, overlay/Escape close |
| `EmptyState` | Honest empty surfaces with optional actions |
| `ErrorState` | Server-authored failure messages |
| `Skeleton` (+`SkeletonLines`) | Loading placeholders |
| `Timeline` | Compact event rail using canonical tones |
| `MetricCard` | KPI tile (label/value/unit/hint/tone/href) |
| `ComingSoon` | Shared planned-page placeholder built on `EmptyState` |

Shell components live in `web/src/components/shell/` (`AppShell`, `Sidebar`,
`Topbar`, `GlobalSearch`, `AlertIndicator`, `UserMenu`, `nav.ts`).

## 5. Migrations and test compatibility

- `(app)/layout.tsx` replaces the old horizontal nav with the AppShell;
  `org-name` moved to the topbar (same test id and exact text).
- `devices`, `checks`, `credentials`, `device-groups`, `collectors`,
  `collectors/{id}`, `sites/{id}`, `devices/{id}`, `interfaces/{id}` wrappers
  now use `PageHeader`/`ErrorState`; feature components and their test ids are
  unchanged.
- `login.spec.ts`: logout now opens `user-menu` first (the shell genuinely
  changed to a user menu); the rest of the assertions are intact.
- `shell.spec.ts` (new, one shared login): grouped nav/active state/global
  search + planned-route states.

## 6. Decisions

1. **`filter[state]=active`** is the real M11 API filter (the task note said
   `state=active`; the server only reads `filter[state]`, verified in
   `internal/modules/alerts/http.go`). The badge never invents a count: hidden
   when the endpoint fails, `100+` when capped.
2. **Planned pages, not fake progress.** Placeholders name the milestone and
   horizon; `/metrics` deliberately links to the real collector chart surface.
3. **Dark-only NOC theme.** No theme toggle in this phase; tokens are
   centralized so a light theme is possible later.
4. **No new dependencies**: tokens + CSS + React primitives only; charts still
   use the existing ECharts surface.
5. **Dashboard counts are capped and labeled** (“first page”, “100+”) rather
   than implying totals the API does not expose.
6. **Legacy CSS kept** (classes remapped) to migrate pages incrementally
   instead of rewriting feature internals in Phase 1.

## 7. Verification

| Check | Command | Result |
|---|---|---|
| Web build | `npm run build` (web/) | pass — 23 routes compiled, TypeScript clean |
| Stack rebuild | `docker compose -f deployments/compose/docker-compose.dev.yml build web` + `up -d --no-deps web` | pass — web up on :3000 |
| Playwright (baseline, old build) | `npx playwright test --workers=1 --reporter=list` | 30 passed / 3 failed / 3 did not run (36 tests) |
| Playwright (final, new shell) | same command | **32 passed / 3 failed / 3 did not run (38 tests)** |
| Focused shell/login run | `npx playwright test e2e/shell.spec.ts e2e/login.spec.ts --workers=1 --reporter=list` | 4 passed (20.9s) |

Final run delta: +2 genuine tests (the new `shell.spec.ts`), both green; every
baseline pass stayed green, including the migrated login/logout flow and both
specs that click the old nav test ids (`nav-checks`, `nav-device-groups`).
The 3 failures are identical to the baseline on the old build (same tests, same
assertions, untouched feature files):

1. `checks.spec.ts` — seeded ledger row not visible after selecting its
   terminal status filter (dev-stack data/list timing).
2. `metrics.spec.ts` — ECharts canvas reports hidden (container sizing).
3. `visibility.spec.ts` — `device-recent-checks` table not found after an
   on-demand ICMP check (dev-stack timing/data).

The 3 “did not run” entries are the serial-mode dependents skipped after each
failure (checks 2nd test, visibility 4th/5th tests), same as baseline. These
are pre-existing dev-stack flakiness, not shell regressions; no spec was
weakened and no functional assertion was removed.

## 8. Limitations / next

- Feature page interiors (tables, forms, charts, detail layouts) are Phase 2-9;
  they still use the legacy `StatusChip`/classes and inherit tokens only.
- The alert queue, command palette (`⌘K`), Topology, WAN and the other planned
  surfaces stay deliberately empty until their milestones.
- Dashboard device/alert cards read the first 100 rows and state it; a real
  count endpoint is a backend follow-up.
- `/users` and `/settings` are planned-only despite the RBAC core existing.
- No Go changes were made; no backend contract was touched.
