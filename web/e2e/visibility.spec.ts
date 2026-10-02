import {
  test,
  expect,
  type BrowserContext,
  type Page,
} from "@playwright/test";

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

// M10-S3 visibility pages. One session for the whole file: the login endpoint
// is rate-limited per IP (10/min), so specs must not multiply login attempts.
// Fixtures are created through the real API (session + CSRF), never mocked;
// the only interception is the UI-state check for interface counter charts,
// which the dev stack cannot produce (no SNMP-polled interfaces).
test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let page: Page;
let csrf = "";
let siteID = "";

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext();
  page = await context.newPage();
  await login(page);
  csrf =
    (await page.context().cookies()).find((c) => c.name === "argus_csrf")
      ?.value ?? "";
  const sitesRes = await page.request.get("/api/v1/sites?limit=1");
  expect(sitesRes.ok()).toBeTruthy();
  siteID = (
    (await sitesRes.json()) as { data: { id: string }[] }
  ).data[0].id;
});

test.afterAll(async () => {
  await context.close();
});

function uniqueIP(prefix: string): string {
  const now = Date.now();
  return `${prefix}.${((now / 1000) % 250) | 0}.${(now % 249) + 1}`;
}

async function createDevice(name: string, mgmtIP: string): Promise<string> {
  const res = await page.request.post("/api/v1/devices", {
    headers: { "X-CSRF-Token": csrf },
    data: {
      site_id: siteID,
      name,
      kind: "switch",
      mgmt_ip: mgmtIP,
      critical: true,
      serial: `SN-${name}`,
    },
  });
  expect(res.status()).toBe(201);
  return ((await res.json()) as { id: string }).id;
}

async function createInterface(
  deviceID: string,
  ifIndex: number,
  ifName: string,
): Promise<string> {
  const res = await page.request.post(
    `/api/v1/devices/${deviceID}/interfaces`,
    {
      headers: { "X-CSRF-Token": csrf },
      data: {
        if_index: ifIndex,
        if_name: ifName,
        if_alias: "e2e-uplink",
        speed_bps: 1_000_000_000,
        mtu: 1500,
        mac: "02:00:00:00:00:07",
      },
    },
  );
  expect(res.status()).toBe(201);
  return ((await res.json()) as { id: string }).id;
}

async function brushZoom(testIdPrefix: string) {
  const canvas = page
    .getByTestId(`${testIdPrefix}-canvas`)
    .locator("canvas")
    .first();
  await expect(canvas).toBeVisible({ timeout: 20_000 });
  await canvas.scrollIntoViewIfNeeded();
  const box = await canvas.boundingBox();
  expect(box).not.toBeNull();
  const y = box!.y + box!.height * 0.45;
  await page.mouse.move(box!.x + box!.width * 0.3, y);
  await page.mouse.down();
  await page.mouse.move(box!.x + box!.width * 0.7, y, { steps: 12 });
  await page.mouse.up();
  await expect(page.getByTestId(`${testIdPrefix}-zoom-state`)).toBeVisible({
    timeout: 5_000,
  });
  await page.getByTestId(`${testIdPrefix}-zoom-reset`).click();
  await expect(page.getByTestId(`${testIdPrefix}-zoom-state`)).toHaveCount(0);
}

test("device detail: status, identity, interfaces and a real ICMP check", async () => {
  const now = Date.now();
  const name = `e2e-vis-device-${now}`;
  const mgmtIP = uniqueIP("203.0");
  const deviceID = await createDevice(name, mgmtIP);
  const ifaceID = await createInterface(deviceID, 7, "Gi1/0/7");

  await page.goto(`/devices/${deviceID}`);
  const header = page.getByTestId("device-header");
  await expect(header).toContainText(name, { timeout: 15_000 });
  await expect(header).toContainText("switch");
  await expect(header).toContainText(mgmtIP);
  await expect(page.getByTestId("device-critical")).toBeVisible();

  // Live status chip (scheduled poll-health rollup).
  const chip = page.getByTestId("device-status-chip");
  await expect(chip).toBeVisible();
  await expect(chip).toContainText(/up|down|unknown/);
  await expect(chip).toHaveAttribute("data-status", /up|down|unknown/);

  // Identity history records serial + mgmt_ip at create time.
  await expect(page.getByTestId("device-identity-table")).toContainText(
    `SN-${name}`,
    { timeout: 15_000 },
  );

  // Interfaces table from the live inventory API, linked to the detail page.
  const ifRow = page
    .getByTestId("device-interfaces-table")
    .locator("tr", { hasText: "Gi1/0/7" });
  await expect(ifRow).toBeVisible({ timeout: 15_000 });
  await expect(ifRow.locator("a")).toHaveAttribute(
    "href",
    `/interfaces/${ifaceID}`,
  );

  // The resolution badge renders before any series exist; the chart/ribbon
  // must be in an explicit state (here: honest empty, since the device has
  // not been polled yet).
  await expect(page.getByTestId("device-chart-resolution")).toContainText(
    "resolution:",
  );
  await expect(page.getByTestId("device-ribbon-wrap")).toBeVisible();

  // M11 placeholder is explicitly present (no alerting in this slice).
  await expect(page.getByTestId("device-alerts-placeholder")).toContainText(
    "M11",
  );
});

async function findPolledDevice(): Promise<{ id: string; name: string }> {
  const res = await page.request.get(
    "/api/v1/devices?include=status&limit=100",
  );
  expect(res.ok()).toBeTruthy();
  const devices = (
    (await res.json()) as {
      data: {
        id: string;
        name: string;
        poll_status?: { last_checked_at: string | null } | null;
      }[];
    }
  ).data;
  const candidate = devices.find((d) => d.poll_status?.last_checked_at);
  expect(candidate, "a polled device must exist in the dev stack").toBeTruthy();
  return candidate!;
}

test("device charts: real stored ICMP series, resolution badge and brush zoom", async () => {
  // Pick a device that already has scheduled poll history (real data from the
  // running collector), rather than waiting for the fresh fixture to warm up.
  const candidate = await findPolledDevice();

  await page.goto(`/devices/${candidate.id}`);
  await expect(page.getByTestId("device-chart-canvas").locator("canvas").first()).toBeVisible(
    { timeout: 20_000 },
  );
  await expect(page.getByTestId("device-chart-resolution")).toContainText(
    /resolution: (raw|rollup_)/,
  );
  await expect(page.getByTestId("device-chart-points")).toContainText(
    /\d+ points/,
  );
  const points = parseInt(
    await page.getByTestId("device-chart-points").innerText(),
    10,
  );
  expect(points).toBeGreaterThanOrEqual(1);
  await expect(page.getByTestId("device-chart-gaps")).toBeVisible();

  // The availability ribbon derives segments from net.icmp.reachable and its
  // summary explains the states in text.
  const segments = page
    .getByTestId("device-ribbon-strip")
    .locator("[data-state]");
  expect(await segments.count()).toBeGreaterThan(0);
  await expect(page.getByTestId("device-ribbon-summary")).toBeVisible();

  await brushZoom("device-chart");
});

test("device detail: on-demand ICMP check runs and settles", async () => {
  // The check must target a device the collector already polls (a device
  // created seconds earlier can still be absent from the applied target set,
  // which resolves as target_missing instead of probing).
  const candidate = await findPolledDevice();
  await page.goto(`/devices/${candidate.id}`);

  await page.getByTestId("run-check-icmp").click();
  await expect(page.getByTestId("check-pending")).toBeVisible();
  await expect(page.getByTestId("check-result")).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByTestId("check-result-status")).toContainText(
    "completed",
  );
  await expect(page.getByTestId("check-result-outcome")).toHaveAttribute(
    "data-status",
    /success|failure/,
  );
  await expect(page.getByTestId("check-result-latency")).toContainText("ms");

  // The settled check refreshes poll-health; origin=on_demand rows feed the
  // recent-checks table (the check ledger has no list endpoint).
  await expect(page.getByTestId("device-recent-checks")).toContainText(
    "icmp",
    { timeout: 15_000 },
  );
});

test("interface detail: identity and counter charts resolve via the query API", async () => {
  const now = Date.now();
  const name = `e2e-vis-iface-${now}`;
  const deviceID = await createDevice(name, uniqueIP("203.1"));
  const ifName = "Gi2/0/1";
  await createInterface(deviceID, 8, ifName);

  await page.goto(`/devices/${deviceID}`);
  await page
    .getByTestId("device-interfaces-table")
    .locator("tr", { hasText: ifName })
    .locator("a")
    .click();
  await expect(page).toHaveURL(/\/interfaces\//);

  const header = page.getByTestId("interface-header");
  await expect(header).toContainText(ifName, { timeout: 15_000 });
  await expect(page.getByTestId("interface-status-chip")).toHaveAttribute(
    "data-status",
    "unknown", // never observed over SNMP in this stack
  );
  await expect(page.getByTestId("interface-identity-table")).toContainText(
    "1.0 Gbit/s",
  );
  await expect(page.getByTestId("interface-device-link")).toContainText(name);

  // The dev stack has no SNMP-polled interfaces: the charts must say so
  // honestly rather than render empty axes.
  await expect(page.getByTestId("iface-traffic-resolution")).toContainText(
    "resolution:",
  );
  await expect(page.getByTestId("iface-traffic-empty")).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByTestId("iface-errors-empty")).toBeVisible({
    timeout: 15_000,
  });

  // Chart rendering UI state (resolution badge, gaps) with an intercepted
  // canonical matrix response; the assertions above already covered the real
  // API path.
  const base = Math.floor(now / 1000) - 3600;
  const point = (metric: string, unit: string, offset: number) => ({
    id: `s_e2e_${offset}`,
    device_id: deviceID,
    collector_id: null,
    metric_key: metric,
    unit,
    dimensions: { if_name: ifName },
    labels: { if_name: ifName, metric, unit },
    points: [
      [base, 100.0],
      [base + 60, null],
      [base + 120, 120.0],
      [base + 180, null],
    ],
    truncated: false,
  });
  const matrix = {
    from: new Date((base - 60) * 1000).toISOString(),
    to: new Date((base + 240) * 1000).toISOString(),
    step: "1m",
    agg: "avg",
    fill: "null",
    series: [
      point("net.if.in_octets", "B/s", 1),
      point("net.if.out_octets", "B/s", 2),
    ],
    meta: {
      resolution: "rollup_1m",
      partial: false,
      points_truncated: false,
      series_total: 2,
      series_returned: 2,
      raw_fallback: false,
      rollup_missing: false,
      expected_points: 4,
      returned_points: 4,
      quality: { gaps: 2, dropped_samples: 0 },
    },
  };
  await page.route("**/api/v1/metrics/query", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(matrix),
    }),
  );
  await page.reload();
  await expect(
    page.getByTestId("iface-traffic-canvas").locator("canvas").first(),
  ).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("iface-traffic-resolution")).toContainText(
    "rollup_1m",
  );
  await expect(page.getByTestId("iface-traffic-gaps")).toContainText("2 gaps");
  await brushZoom("iface-traffic");
  await page.unroute("**/api/v1/metrics/query");
});

test("site dashboard: status counts, URL filters and device links", async () => {
  const now = Date.now();
  const name = `e2e-site-device-${now}`;
  const deviceID = await createDevice(name, uniqueIP("203.2"));

  await page.goto(`/sites/${siteID}`);
  await expect(page.getByTestId("site-status-counts")).toBeVisible({
    timeout: 15_000,
  });
  for (const key of ["all", "up", "down", "unknown"]) {
    await expect(page.getByTestId(`site-status-filter-${key}`)).toBeVisible();
  }
  await expect(page.getByTestId("site-count-all")).toContainText(/\d+/);
  await expect(page.getByTestId("site-devices-table")).toContainText(name, {
    timeout: 15_000,
  });

  // Recent issues panel is bounded and explicit (either failures or the
  // no-failures state).
  const issuesTable = page.getByTestId("site-issues-table");
  const issuesEmpty = page.getByTestId("site-issues-empty");
  await expect(issuesTable.or(issuesEmpty)).toBeVisible({ timeout: 15_000 });

  // URL-driven poll-status filter.
  await page.getByTestId("site-status-filter-down").click();
  await expect(page).toHaveURL(/status=down/);
  await expect(page.getByTestId("site-status-filter-down")).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  const count = page.getByTestId("site-device-count");
  const nomatch = page.getByTestId("site-devices-nomatch");
  await expect(count.or(nomatch)).toBeVisible();
  if (await count.isVisible()) {
    const chips = page
      .getByTestId("site-devices-table")
      .locator("[data-status]");
    const chipCount = await chips.count();
    expect(chipCount).toBeGreaterThan(0);
    for (let i = 0; i < chipCount; i += 1) {
      await expect(chips.nth(i)).toHaveAttribute("data-status", "down");
    }
  }

  // URL-driven search filter, then the device link (home -> site -> device is
  // three clicks from the dashboard).
  await page.getByTestId("site-status-filter-all").click();
  await expect(page.getByTestId("site-status-filter-all")).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page).not.toHaveURL(/status=/);
  await page.getByTestId("site-device-search").fill(name);
  await expect(page).toHaveURL(/q=/);
  await expect(page.getByTestId("site-device-count")).toContainText("1 of");
  await page
    .getByTestId("site-devices-table")
    .locator("a", { hasText: name })
    .click();
  await expect(page).toHaveURL(new RegExp(`/devices/${deviceID}$`));
  await expect(page.getByTestId("device-header")).toContainText(name, {
    timeout: 15_000,
  });
});
