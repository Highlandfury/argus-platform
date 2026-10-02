import {
  test,
  expect,
  type BrowserContext,
  type Page,
} from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByTestId("login-org").fill("dev");
  await page.getByTestId("login-email").fill("admin@dev.local");
  await page
    .getByTestId("login-password")
    .fill(process.env.ARGUS_DEV_ADMIN_PASSWORD ?? "dev-admin-change-me");
  await page.getByTestId("login-submit").click();
  await expect(page).toHaveURL(/\/$/);
}

// M11-S3b alert surfaces. One session for the whole file: the login endpoint
// is rate-limited per IP (10/min), so specs must not multiply login attempts.
// All org objects (devices, rules, silences, maintenance windows) are created
// through the real API with session + CSRF. The evaluator has no HTTP path to
// ingest samples, so the deterministic alert rows/events this suite acts on
// are seeded through the dev database exactly like the Go integration fixture
// helpers do (m11s1_helpers_test.go); the suppression test additionally drives
// a real rule + poll-health failure through the running evaluator end to end.
test.describe.configure({ mode: "serial" });

const DB_CONTAINER = process.env.ARGUS_E2E_DB_CONTAINER ?? "argus-dev-db-1";

function db(sql: string): string {
  return execFileSync(
    "docker",
    [
      "exec",
      DB_CONTAINER,
      "psql",
      "-U",
      "argus_owner",
      "-d",
      "argus",
      "-v",
      "ON_ERROR_STOP=1",
      "-t",
      "-A",
      "-c",
      sql,
    ],
    { encoding: "utf8" },
  ).trim();
}

// q renders a SQL single-quoted literal (JSON text) for the psql fixture
// inserts; embedded single quotes are escaped for the SQL parser.
function q(value: unknown): string {
  return `'${(JSON.stringify(value) ?? "null").replaceAll("'", "''")}'`;
}

function localInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate(),
  )}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

let context: BrowserContext;
let page: Page;
let csrf = "";
let siteID = "";
let siteName = "";
let orgID = "";
let collectorID = "";
let deviceA = "";
let deviceAName = "";
let deviceB = "";
let deviceBName = "";
let ruleID = "";
let ruleName = "";
let alertA = "";
let alertB = "";
let seedCounter = 0;

function uniqueIP(prefix: string): string {
  const now = Date.now();
  return `${prefix}.${((now / 1000) % 250) | 0}.${(now % 249) + 1}`;
}

async function createDevice(name: string, prefix: string): Promise<string> {
  const res = await page.request.post("/api/v1/devices", {
    headers: { "X-CSRF-Token": csrf },
    data: {
      site_id: siteID,
      name,
      kind: "switch",
      mgmt_ip: uniqueIP(prefix),
      serial: `SN-${name}`,
    },
  });
  expect(res.status()).toBe(201);
  return ((await res.json()) as { id: string }).id;
}

async function createRule(data: Record<string, unknown>): Promise<string> {
  const res = await page.request.post("/api/v1/alert-rules", {
    headers: { "X-CSRF-Token": csrf },
    data,
  });
  expect(res.status()).toBe(201);
  return ((await res.json()) as { rule_id: string }).rule_id;
}

// seedAlert inserts one deterministic active alert plus its timeline. The
// rule it points at is disabled (see beforeAll), so the running evaluator
// never mutates the fixture and every state assertion is stable.
function seedAlert(options: {
  deviceID: string;
  ruleID: string;
  ruleVersion: number;
  state: "active" | "pending";
  severity: "critical" | "warning";
  value: Record<string, unknown>;
  dimensionSubset: Record<string, unknown>;
  startedOffset: string;
}): string {
  seedCounter += 1;
  const id = randomUUID();
  const fingerprint = createHash("sha256")
    .update(`e2e|${id}|${seedCounter}`)
    .digest("hex");
  const events = [
    ["pending", `now() - interval '${options.startedOffset}'`],
    ["activated", `now() - interval '${options.startedOffset}' + interval '10 seconds'`],
    ["updated", "now() - interval '30 seconds'"],
  ]
    .map(
      ([kind, ts]) =>
        `('${randomUUID()}', '${orgID}', '${id}', '${kind}', ${q({
          from: kind === "pending" ? undefined : "pending",
          to: kind,
          value: options.value,
        })}::jsonb, ${ts})`,
    )
    .join(",\n");
  db(`
begin;
set local app.current_org='${orgID}';
insert into alerts (id, org_id, rule_id, rule_version, fingerprint, resource_type, resource_id, dimension_subset, state, severity, value, started_at, last_evaluated_at)
values ('${id}', '${orgID}', '${options.ruleID}', ${options.ruleVersion}, '${fingerprint}', 'device', '${options.deviceID}', ${q(
    options.dimensionSubset,
  )}::jsonb, '${options.state}', '${options.severity}', ${q(
    options.value,
  )}::jsonb, now() - interval '${options.startedOffset}', now() - interval '30 seconds');
insert into alert_events (id, org_id, alert_id, kind, data, ts) values
${events};
commit;
`);
  return id;
}

// seedPollFailure writes one scheduled poll-health failure so the real
// absence rule fires on the next evaluator tick (the fixture path from
// m11s1_helpers_test.go, restricted to the public poll-health shape).
function seedPollFailure(deviceID: string, consecutive: number) {
  db(`
begin;
set local app.current_org='${orgID}';
insert into poll_health (id, org_id, collector_id, device_id, ts, poll_type, latency_ms, outcome, error_class, consecutive_failures, origin)
values ('${randomUUID()}', '${orgID}', '${collectorID}', '${deviceID}', now(), 'icmp', 0, 'failure', 'timeout', ${consecutive}, 'scheduled');
commit;
`);
}

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext();
  page = await context.newPage();
  await login(page);
  csrf =
    (await page.context().cookies()).find((c) => c.name === "argus_csrf")
      ?.value ?? "";
  expect(csrf).not.toBe("");

  const meRes = await page.request.get("/api/v1/me");
  expect(meRes.ok()).toBeTruthy();
  orgID = ((await meRes.json()) as { org: { id: string } }).org.id;

  const sitesRes = await page.request.get("/api/v1/sites?limit=100");
  expect(sitesRes.ok()).toBeTruthy();
  const sites = ((await sitesRes.json()) as {
    data: { id: string; name: string }[];
  }).data;
  siteID = sites[0].id;
  siteName = sites[0].name;

  const collectorsRes = await page.request.get("/api/v1/collectors?limit=1");
  if (collectorsRes.ok()) {
    const collectors = ((await collectorsRes.json()) as {
      data: { id: string }[];
    }).data;
    if (collectors.length > 0) collectorID = collectors[0].id;
  }
  if (collectorID === "") {
    collectorID = db("select id from collectors limit 1");
  }
  expect(collectorID).not.toBe("");

  const suffix = Date.now();
  deviceAName = `e2e-alerts-main-${suffix}`;
  deviceBName = `e2e-alerts-live-${suffix}`;
  deviceA = await createDevice(deviceAName, "203.9");
  deviceB = await createDevice(deviceBName, "203.10");

  ruleName = `e2e alerts rule ${suffix}`;
  ruleID = await createRule({
    name: ruleName,
    type: "threshold",
    severity: "critical",
    condition: { agg: "avg", op: "gt", value: 1, window: "1m" },
    scope_selector: { device_ids: [deviceA], metric_key: "e2e.alerts.metric" },
  });
  // Disable the rule (version 2) so the evaluator never touches the seeded
  // fixtures; the pinned rule version moves with the immutable version.
  const disableRes = await page.request.patch(`/api/v1/alert-rules/${ruleID}`, {
    headers: { "X-CSRF-Token": csrf },
    data: { enabled: false },
  });
  expect(disableRes.ok()).toBeTruthy();
  const disabledRule = (await disableRes.json()) as { version: number };

  alertA = seedAlert({
    deviceID: deviceA,
    ruleID,
    ruleVersion: disabledRule.version,
    state: "active",
    severity: "critical",
    value: { value: 93.5, op: "gt", threshold: 80, phase: "trigger" },
    dimensionSubset: { interface: "Gi0/1" },
    startedOffset: "6 minutes",
  });
  alertB = seedAlert({
    deviceID: deviceB,
    ruleID,
    ruleVersion: disabledRule.version,
    state: "active",
    severity: "warning",
    value: { value: 7, op: "gt", threshold: 5, phase: "trigger" },
    dimensionSubset: {},
    startedOffset: "3 minutes",
  });
});

test.afterAll(async () => {
  await context.close();
});

test("queue: real rows, resource links and URL-driven filters", async () => {
  await page.goto("/");
  await page.getByTestId("nav-alerts").click();
  await expect(page).toHaveURL(/\/alerts$/);
  await expect(page.getByTestId("alerts-view")).toBeVisible();
  await expect(page.getByTestId("alerts-panel")).toBeVisible();

  // The seeded alert is a real row: filter by its device and assert content.
  await page.getByTestId("alerts-filter-device").selectOption(deviceA);
  await expect(page).toHaveURL(new RegExp(`device=${deviceA}`));
  const row = page.getByTestId(`alerts-row-${alertA}`);
  await expect(row).toBeVisible({ timeout: 15_000 });
  await expect(row).toHaveAttribute("data-state", "active");
  await expect(row).toHaveAttribute("data-severity", "critical");
  await expect(row.getByTestId(`alert-device-${alertA}`)).toHaveAttribute(
    "href",
    `/devices/${deviceA}`,
  );
  await expect(row.getByTestId(`alert-severity-${alertA}`)).toContainText(
    "Critical",
  );
  await expect(row.getByTestId(`alert-state-${alertA}`)).toContainText("Active");
  await expect(row.getByTestId(`alert-rule-${alertA}`)).toContainText(ruleName);
  await expect(row.getByTestId(`alert-link-${alertA}`)).toContainText(
    "93.5 > 80",
  );

  // State filter: the active alert disappears under Pending and returns.
  await page.getByTestId("alerts-filter-state").selectOption("pending");
  await expect(page).toHaveURL(/state=pending/);
  await expect(page.getByTestId(`alerts-row-${alertA}`)).toHaveCount(0);
  await page.getByTestId("alerts-filter-state").selectOption("active");
  await expect(page.getByTestId(`alerts-row-${alertA}`)).toBeVisible({
    timeout: 15_000,
  });

  // Severity filter.
  await page.getByTestId("alerts-filter-severity").selectOption("warning");
  await expect(page).toHaveURL(/severity=warning/);
  await expect(page.getByTestId(`alerts-row-${alertA}`)).toHaveCount(0);
  await page.getByTestId("alerts-filter-severity").selectOption("critical");
  await expect(page.getByTestId(`alerts-row-${alertA}`)).toBeVisible({
    timeout: 15_000,
  });

  // Rule filter.
  await page.getByTestId("alerts-filter-rule").selectOption(ruleID);
  await expect(page).toHaveURL(new RegExp(`rule=${ruleID}`));
  await expect(page.getByTestId(`alerts-row-${alertA}`)).toBeVisible({
    timeout: 15_000,
  });

  // Clear filters returns the URL-driven state to the unfiltered queue.
  await page.getByTestId("alerts-clear-filters").click();
  await expect(page).not.toHaveURL(/rule=/);

  // Row click opens the detail.
  await page.getByTestId("alerts-filter-device").selectOption(deviceA);
  await expect(page.getByTestId(`alerts-row-${alertA}`)).toBeVisible({
    timeout: 15_000,
  });
  await page.getByTestId(`alerts-row-${alertA}`).click();
  await expect(page).toHaveURL(new RegExp(`/alerts/${alertA}$`));
});

test("detail: context, evidence, timeline and the honest deliveries empty state", async () => {
  await page.goto(`/alerts/${alertA}`);
  await expect(page.getByTestId("alert-detail-state")).toContainText("Active");
  await expect(page.getByTestId("alert-detail-severity")).toContainText(
    "Critical",
  );
  await expect(page.getByTestId("alert-detail-rule")).toContainText(ruleName);
  await expect(page.getByTestId("alert-detail-device")).toHaveAttribute(
    "href",
    `/devices/${deviceA}`,
  );
  await expect(page.getByTestId("alert-detail-device")).toContainText(
    deviceAName,
  );
  await expect(page.getByTestId("alert-detail-site")).toHaveAttribute(
    "href",
    `/sites/${siteID}`,
  );
  await expect(page.getByTestId("alert-detail-dimensions")).toContainText(
    "interface=Gi0/1",
  );
  await expect(page.getByTestId("alert-detail-value")).toContainText("93.5");
  await expect(page.getByTestId("alert-detail-value")).toContainText(
    "Threshold",
  );

  // Timeline from the alert payload (real seeded alert_events).
  await expect(page.getByTestId("alert-timeline")).toBeVisible();
  const items = page.getByTestId("alert-timeline").locator("li");
  expect(await items.count()).toBeGreaterThanOrEqual(3);
  await expect(page.getByTestId("alert-timeline")).toContainText("Fired");

  // Deliveries: this alert was never transitioned by the notify engine, so the
  // panel must state that instead of fabricating a delivery.
  await expect(page.getByTestId("alert-deliveries-panel")).toBeVisible();
  await expect(page.getByTestId("alert-deliveries-empty")).toContainText(
    "No notification deliveries",
  );
});

test("actions: ack, snooze, comment and resolve update the alert", async () => {
  await page.goto(`/alerts/${alertA}`);

  await page.getByTestId("alert-action-ack").click();
  await expect(page.getByTestId("alert-detail-state")).toContainText(
    "Acknowledged",
    { timeout: 10_000 },
  );
  await expect(page.getByTestId("alert-timeline")).toContainText(
    "Acknowledged",
  );

  await page.getByTestId("alert-action-snooze").click();
  await expect(page.getByTestId("alert-snooze-dialog")).toBeVisible();
  await page.getByTestId("alert-snooze-duration").selectOption("3600");
  await page.getByTestId("alert-snooze-reason").fill("e2e snooze window");
  await page.getByTestId("alert-snooze-submit").click();
  await expect(page.getByTestId("alert-detail-state")).toContainText("Snoozed", {
    timeout: 10_000,
  });

  await page.getByTestId("alert-action-comment").click();
  await expect(page.getByTestId("alert-comment-dialog")).toBeVisible();
  await page.getByTestId("alert-comment-text").fill("e2e operator comment");
  await page.getByTestId("alert-comment-submit").click();
  await expect(page.getByTestId("alert-timeline")).toContainText(
    "e2e operator comment",
    { timeout: 10_000 },
  );

  // Manual resolve requires a reason; the dialog enforces it before the API.
  await page.getByTestId("alert-action-resolve").click();
  await expect(page.getByTestId("alert-resolve-dialog")).toBeVisible();
  await page.getByTestId("alert-resolve-submit").click();
  await expect(page.getByTestId("alert-resolve-error")).toContainText(
    "reason is required",
  );
  await page.getByTestId("alert-resolve-reason").fill("e2e: mitigated");
  await page.getByTestId("alert-resolve-submit").click();
  await expect(page.getByTestId("alert-detail-state")).toContainText(
    "Resolved",
    { timeout: 10_000 },
  );
  await expect(page.getByTestId("alert-timeline")).toContainText(
    "Manually resolved",
  );
});

test("maintenance windows: create an active window, list it, delete it", async () => {
  await page.goto("/alerts?tab=maintenance");
  await expect(page.getByTestId("maintenance-view")).toBeVisible();

  const windowName = `e2e maintenance ${Date.now()}`;
  await page.getByTestId("maintenance-create-open").click();
  await expect(page.getByTestId("maintenance-create-dialog")).toBeVisible();
  await page.getByTestId("maintenance-name").fill(windowName);
  await page.getByTestId("maintenance-scope-sites").selectOption(siteID);
  await page.getByTestId("maintenance-scope-kinds").selectOption("switch");
  await page
    .getByTestId("maintenance-starts")
    .fill(localInput(new Date(Date.now() - 5 * 60_000)));
  await page
    .getByTestId("maintenance-ends")
    .fill(localInput(new Date(Date.now() + 30 * 60_000)));
  await page.getByTestId("maintenance-submit").click();
  await expect(page.getByTestId("maintenance-notice")).toContainText("created", {
    timeout: 15_000,
  });

  // Cross-check through the API, then assert the rendered row.
  const listRes = await page.request.get("/api/v1/maintenance-windows?limit=100");
  expect(listRes.ok()).toBeTruthy();
  const windows = ((await listRes.json()) as {
    data: { id: string; name: string }[];
  }).data;
  const created = windows.find((w) => w.name === windowName);
  expect(created, "created window must be listed by the API").toBeTruthy();
  const row = page.getByTestId(`maintenance-row-${created!.id}`);
  await expect(row).toBeVisible({ timeout: 15_000 });
  await expect(row).toContainText("Active");
  await expect(row).toContainText("switch");
  if (siteName !== "") {
    await expect(row).toContainText(siteName);
  }

  // Delete through the confirm dialog; the row and the API object disappear.
  await page.getByTestId(`maintenance-delete-${created!.id}`).click();
  await expect(page.getByTestId("maintenance-delete-dialog")).toBeVisible();
  await page.getByTestId("maintenance-delete-confirm").click();
  await expect(page.getByTestId(`maintenance-row-${created!.id}`)).toHaveCount(
    0,
    { timeout: 15_000 },
  );
  const afterRes = await page.request.get(
    "/api/v1/maintenance-windows?limit=100",
  );
  const after = ((await afterRes.json()) as { data: { id: string }[] }).data;
  expect(after.some((w) => w.id === created!.id)).toBeFalsy();
});

test("live updates: SSE patches the queue on API transitions", async () => {
  await page.goto(`/alerts?device=${deviceB}`);
  const row = page.getByTestId(`alerts-row-${alertB}`);
  await expect(row).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("alerts-sse-status")).toHaveAttribute(
    "data-live",
    "live",
    { timeout: 15_000 },
  );

  // Acknowledge through the API while the queue is open: the alert.updated
  // event must patch the visible row without a reload.
  const ackRes = await page.request.post(`/api/v1/alerts/${alertB}/ack`, {
    headers: { "X-CSRF-Token": csrf },
  });
  expect(ackRes.ok()).toBeTruthy();
  await expect(row).toHaveAttribute("data-state", "acknowledged", {
    timeout: 15_000,
  });

  // Resolve through the API: alert.resolved patches the row again.
  const resolveRes = await page.request.post(
    `/api/v1/alerts/${alertB}/resolve`,
    {
      headers: { "X-CSRF-Token": csrf },
      data: { reason: "e2e live resolve" },
    },
  );
  expect(resolveRes.ok()).toBeTruthy();
  await expect(row).toHaveAttribute("data-state", "resolved", {
    timeout: 15_000,
  });
});

test("live updates fallback: unavailable stream keeps manual refresh honest", async () => {
  await page.route("**/api/v1/streams/events", (route) => route.abort());
  await page.goto("/alerts");
  await expect(page.getByTestId("alerts-sse-status")).toHaveAttribute(
    "data-live",
    "unavailable",
    { timeout: 15_000 },
  );
  // Manual refresh still renders the real list (table or the honest empty).
  await page.getByTestId("alerts-refresh").click();
  await expect(
    page.getByTestId("alerts-table").or(page.getByTestId("alerts-empty")),
  ).toBeVisible({ timeout: 15_000 });
  await page.unroute("**/api/v1/streams/events");
});

test("silence: dialog creates a silence and the alert becomes Suppressed", async () => {
  // This test drives the real evaluator: create a device + absence rule,
  // seed one scheduled poll failure, wait for the alert to fire, silence it
  // from the detail dialog, and wait for the suppression projection at the
  // next evaluation (cadence is 30 s for this rule).
  test.setTimeout(300_000);

  const suffix = Date.now();
  const deviceC = await createDevice(`e2e-alerts-silence-${suffix}`, "203.11");
  const ruleC = await createRule({
    name: `e2e silence rule ${suffix}`,
    type: "absence",
    severity: "critical",
    condition: {
      source: "poll_health",
      consecutive_failures: 1,
      recovery_successes: 2,
      check_interval: "10s",
    },
    scope_selector: { device_ids: [deviceC] },
  });
  seedPollFailure(deviceC, 1);

  // Wait (bounded) for the real alert to fire.
  let silencedAlert = "";
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const res = await page.request.get(
      `/api/v1/alerts?filter[device_id]=${deviceC}&limit=1`,
    );
    if (res.ok()) {
      const body = (await res.json()) as { data: { id: string }[] };
      if (body.data.length > 0) {
        silencedAlert = body.data[0].id;
        break;
      }
    }
    await page.waitForTimeout(2000);
  }
  expect(silencedAlert, "the absence rule must fire a real alert").not.toBe("");

  await page.goto(`/alerts/${silencedAlert}`);
  await expect(page.getByTestId("alert-detail-state")).toContainText(
    /Active|Pending/,
    { timeout: 15_000 },
  );

  // Mandatory reason is enforced before the API.
  await page.getByTestId("alert-action-silence").click();
  await expect(page.getByTestId("alert-silence-dialog")).toBeVisible();
  await page.getByTestId("alert-silence-submit").click();
  await expect(page.getByTestId("alert-silence-error")).toContainText(
    "reason is required",
  );
  await page.getByTestId("alert-silence-duration").selectOption("3600");
  const silenceReason = `e2e silence ${suffix}`;
  await page.getByTestId("alert-silence-reason").fill(silenceReason);
  await page.getByTestId("alert-silence-submit").click();
  await expect(page.getByTestId("alert-action-result")).toContainText(
    "Silence created",
    { timeout: 15_000 },
  );

  // The silence is listed with its alert target.
  const silencesRes = await page.request.get("/api/v1/silences?limit=100");
  expect(silencesRes.ok()).toBeTruthy();
  const silences = ((await silencesRes.json()) as {
    data: { id: string; reason: string; match: { alert_id?: string } }[];
  }).data;
  const created = silences.find(
    (s) => s.match.alert_id === silencedAlert && s.reason === silenceReason,
  );
  expect(created, "the created silence must be listed").toBeTruthy();

  await page.goto("/alerts?tab=silences");
  const silenceRow = page.getByTestId(`silences-row-${created!.id}`);
  await expect(silenceRow).toBeVisible({ timeout: 15_000 });
  await expect(silenceRow).toContainText("Active");
  await expect(silenceRow).toContainText(silenceReason);
  await expect(silenceRow).toContainText(
    `Alert ${silencedAlert.slice(0, 8)}`,
  );

  // Wait for the evaluator to project the silence onto the alert.
  await page.goto(`/alerts/${silencedAlert}`);
  await expect(page.getByTestId("alert-detail-state")).toContainText(
    "Suppressed",
    { timeout: 120_000 },
  );
  await expect(page.getByTestId("alert-detail-suppression")).toContainText(
    "Silence",
  );

  // Clean up through the UI: deleting the silence removes the row.
  await page.goto("/alerts?tab=silences");
  await page.getByTestId(`silence-delete-${created!.id}`).click();
  await expect(page.getByTestId("silence-delete-dialog")).toBeVisible();
  await page.getByTestId("silence-delete-confirm").click();
  await expect(page.getByTestId(`silences-row-${created!.id}`)).toHaveCount(0, {
    timeout: 15_000,
  });
  expect(ruleC).not.toBe("");
});
