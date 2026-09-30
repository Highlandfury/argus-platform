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

// One session for the whole file: the login endpoint is rate-limited per IP
// (10/min), so specs must not multiply login attempts.
test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let page: Page;

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext();
  page = await context.newPage();
  await login(page);
});

test.afterAll(async () => {
  await context.close();
});

// M7-S4 (UI half): the devices list renders real inventory from /v1/devices.
// The fixture device is created through the real API with the session cookie +
// CSRF header (no mocked backend).
test("device list renders real inventory data", async () => {
  const sitesRes = await page.request.get("/api/v1/sites?limit=1");
  expect(sitesRes.ok()).toBeTruthy();
  const site = ((await sitesRes.json()) as { data: { id: string }[] }).data[0];
  const name = `e2e-device-${Date.now()}`;
  // Identity uniqueness is org-wide: derive a unique management IP per run so
  // repeated runs cannot collide with a previous fixture device.
  const now = Date.now();
  const mgmtIP = `192.0.${((now / 1000) % 250) | 0}.${(now % 249) + 1}`;
  const csrf =
    (await page.context().cookies()).find((c) => c.name === "argus_csrf")
      ?.value ?? "";
  const createRes = await page.request.post("/api/v1/devices", {
    headers: { "X-CSRF-Token": csrf },
    data: { site_id: site.id, name, kind: "switch", mgmt_ip: mgmtIP },
  });
  expect(createRes.status()).toBe(201);

  await page.goto("/devices");
  await expect(page.getByTestId("devices-table")).toContainText(name, {
    timeout: 15_000,
  });
  const row = page.getByTestId("devices-table").locator("tr", { hasText: name });
  await expect(row).toContainText("switch");
  await expect(row).toContainText(mgmtIP);
});

// Empty and error states are functional (API interception mirrors the
// existing metrics-spec pattern; the test above uses the real API).
test("device list empty and error states", async () => {
  await page.route("**/api/v1/devices*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ data: [], next_cursor: null, has_more: false }),
    }),
  );
  await page.goto("/devices");
  await expect(page.getByTestId("devices-empty")).toBeVisible();

  await page.unroute("**/api/v1/devices*");
  await page.route("**/api/v1/devices*", (route) => route.abort());
  await page.goto("/devices");
  await expect(page.getByTestId("devices-error")).toBeVisible();
});
