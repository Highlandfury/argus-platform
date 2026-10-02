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

// M10-S3b-3 checks page. One session for the whole file: the login endpoint is
// rate-limited per IP (10/min), so specs must not multiply login attempts.
// Fixtures are created through the real API (session + CSRF); the poll-health
// panel is asserted against the API's own truth (the dev stack's e2e devices
// produce scheduled failures, but a freshly seeded database must not make the
// page's real-data assertion vacuous).
test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let page: Page;
let csrf = "";
let siteID = "";
let seededDeviceID = "";
let seededCheckID = "";
let seededCheckStatus = "";
let healthHasFailures1h = false;
let healthHasFailures24h = false;

function uniqueIP(prefix: string): string {
  const now = Date.now();
  return `${prefix}.${((now / 1000) % 250) | 0}.${(now % 249) + 1}`;
}

async function feedHasFailures(sinceMs: number): Promise<boolean> {
  const since = new Date(Date.now() - sinceMs).toISOString();
  const res = await page.request.get(
    `/api/v1/poll-health?outcome=failure&limit=1&since=${encodeURIComponent(since)}`,
  );
  expect(res.ok()).toBeTruthy();
  const body = (await res.json()) as { data: unknown[] };
  return body.data.length > 0;
}

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext();
  page = await context.newPage();
  await login(page);
  csrf =
    (await page.context().cookies()).find((c) => c.name === "argus_csrf")
      ?.value ?? "";
  const sitesRes = await page.request.get("/api/v1/sites?limit=1");
  expect(sitesRes.ok()).toBeTruthy();
  siteID = ((await sitesRes.json()) as { data: { id: string }[] }).data[0].id;

  // Seed an on-demand check through the real API on a fresh device. The row is
  // terminal quickly: either the collector probes it (completed) or reports
  // target_missing (completed/failure); failed = TTL expiry, not expected here.
  const deviceRes = await page.request.post("/api/v1/devices", {
    headers: { "X-CSRF-Token": csrf },
    data: {
      site_id: siteID,
      name: `e2e-checks-device-${Date.now()}`,
      kind: "switch",
      mgmt_ip: uniqueIP("203.9"),
      critical: true,
      serial: `SN-e2e-checks-${Date.now()}`,
    },
  });
  expect(deviceRes.status()).toBe(201);
  seededDeviceID = ((await deviceRes.json()) as { id: string }).id;

  const checkRes = await page.request.post(
    `/api/v1/devices/${seededDeviceID}/checks`,
    {
      headers: {
        "X-CSRF-Token": csrf,
        "Idempotency-Key": `e2e-checks-${Date.now()}`,
      },
      data: { poll_type: "icmp" },
    },
  );
  expect(checkRes.status()).toBe(202);
  seededCheckID = ((await checkRes.json()) as { check_id: string }).check_id;
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const res = await page.request.get(`/api/v1/checks/${seededCheckID}`);
    if (res.ok()) {
      const body = (await res.json()) as { status: string };
      if (body.status !== "pending") {
        seededCheckStatus = body.status;
        break;
      }
    }
    await page.waitForTimeout(500);
  }
  expect(seededCheckStatus, "seeded check must reach a terminal status").not.toBe(
    "",
  );

  healthHasFailures1h = await feedHasFailures(60 * 60 * 1000);
  healthHasFailures24h = await feedHasFailures(24 * 60 * 60 * 1000);
});

test.afterAll(async () => {
  await context.close();
});

test("checks page: nav link, real ledger data and URL filters", async () => {
  await page.goto("/");
  await page.getByTestId("nav-checks").click();
  await expect(page).toHaveURL(/\/checks$/);

  // The seeded API check is a real ledger row with its device link.
  await expect(page.getByTestId("checks-table")).toBeVisible({
    timeout: 15_000,
  });
  const row = page.getByTestId(`checks-row-${seededCheckID}`);
  await expect(row).toBeVisible();
  await expect(row).toContainText("icmp");
  await expect(row).toHaveAttribute("data-status", seededCheckStatus);
  await expect(row.getByTestId(`checks-device-${seededCheckID}`)).toHaveAttribute(
    "href",
    `/devices/${seededDeviceID}`,
  );

  // URL-driven poll-type filter: the icmp check disappears on snmp.
  await page.getByTestId("checks-filter-poll-type").selectOption("snmp");
  await expect(page).toHaveURL(/poll_type=snmp/);
  await expect(page.getByTestId(`checks-row-${seededCheckID}`)).toHaveCount(0);

  // URL-driven status filter: a terminal check disappears on pending.
  await page.getByTestId("checks-filter-poll-type").selectOption("");
  await page.getByTestId("checks-filter-status").selectOption("pending");
  await expect(page).toHaveURL(/status=pending/);
  await expect(page.getByTestId(`checks-row-${seededCheckID}`)).toHaveCount(0);

  // Selecting the terminal status brings it back (status=completed or failed
  // depending on the collector path).
  await page
    .getByTestId("checks-filter-status")
    .selectOption(seededCheckStatus);
  await expect(page.getByTestId(`checks-row-${seededCheckID}`)).toBeVisible({
    timeout: 15_000,
  });
});

test("recent poll failures: bounded feed, window selector and device links", async () => {
  await page.goto("/checks");
  await expect(page.getByTestId("poll-health-note")).toContainText("24-hour");

  // Default window (1 h): assert against the API's own truth so the test is
  // honest on both a busy dev stack (failures exist) and a fresh one.
  if (healthHasFailures1h) {
    await expect(page.getByTestId("poll-health-table")).toBeVisible({
      timeout: 15_000,
    });
    const rows = page
      .getByTestId("poll-health-table")
      .locator("tbody tr");
    expect(await rows.count()).toBeGreaterThan(0);
    const first = rows.first();
    await expect(first.locator("a")).toHaveAttribute("href", /\/devices\//);
    await expect(first.locator("td").nth(2)).toContainText(/icmp|snmp/);
    await expect(first.locator("[data-error-class]")).toBeVisible();
  } else {
    await expect(page.getByTestId("poll-health-empty")).toBeVisible({
      timeout: 15_000,
    });
  }

  // Widen to 24 h through the URL-driven selector.
  await page.getByTestId("poll-health-filter-since").selectOption("24h");
  await expect(page).toHaveURL(/since=24h/);
  if (healthHasFailures24h) {
    await expect(page.getByTestId("poll-health-table")).toBeVisible({
      timeout: 15_000,
    });
  } else {
    await expect(page.getByTestId("poll-health-empty")).toBeVisible({
      timeout: 15_000,
    });
  }
});
