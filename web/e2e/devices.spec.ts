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
// (10/min), so specs must not multiply login attempts. Tests run in file
// order; the API-interception tests stay last so their routes never leak into
// the real-backend smokes above them.
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

// M7-S4a: the Add device form posts /v1/devices with the session + CSRF pair
// and the new device appears in the list without a manual reload.
test("add device form creates a device that appears in the list", async () => {
  const sitesRes = await page.request.get("/api/v1/sites?limit=1");
  expect(sitesRes.ok()).toBeTruthy();
  const site = (
    (await sitesRes.json()) as { data: { id: string; name: string }[] }
  ).data[0];
  const now = Date.now();
  const name = `e2e-ui-device-${now}`;
  const mgmtIP = `198.18.${((now / 1000) % 250) | 0}.${(now % 249) + 1}`;
  const serial = `SN-E2E-${now}`;
  const sysObjectID = `1.3.6.1.4.1.9999.${now}`;

  await page.goto("/devices");
  await page.getByTestId("device-name").fill(name);
  await page.getByTestId("device-site").selectOption(site.id);
  await page.getByTestId("device-kind").selectOption("router");
  await page.getByTestId("device-mgmt-ip").fill(mgmtIP);
  await page.getByTestId("device-serial").fill(serial);
  await page.getByTestId("device-sys-object-id").fill(sysObjectID);
  await page.getByTestId("device-submit").click();

  await expect(page.getByTestId("device-create-result")).toContainText(name, {
    timeout: 15_000,
  });
  // The list refreshed in place: the row shows the selected kind + site.
  await expect(page.getByTestId("devices-table")).toContainText(name);
  const row = page.getByTestId("devices-table").locator("tr", { hasText: name });
  await expect(row).toContainText("router");
  await expect(row).toContainText(site.name);
  await expect(row).toContainText(mgmtIP);
});

// M7-S4a: problem+json mapping — server validation renders the field error
// next to the form and the row is not added.
test("add device form renders validation failures", async () => {
  const name = `e2e-invalid-device-${Date.now()}`;
  await page.goto("/devices");
  await page.getByTestId("device-name").fill(name);
  await page.getByTestId("device-mgmt-ip").fill("not-an-ip");
  await page.getByTestId("device-submit").click();

  await expect(page.getByTestId("device-create-error")).toContainText(
    "invalid device",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("device-create-field-errors")).toContainText(
    "mgmt_ip",
  );
  await expect(page.getByTestId("device-create-result")).toHaveCount(0);
  await expect(page.getByTestId("devices-table")).not.toContainText(name);
});

// M7-S4a: problem+json mapping — a 403 (capability revoked server-side while
// the page is open) renders the forbidden state, not a generic failure.
test("add device form renders forbidden problems", async () => {
  await page.route("**/api/v1/devices*", (route) =>
    route.request().method() === "POST"
      ? route.fulfill({
          status: 403,
          contentType: "application/problem+json",
          body: JSON.stringify({
            type: "about:blank",
            title: "Forbidden",
            status: 403,
            code: "auth.forbidden",
            detail: "insufficient capability: device.write",
          }),
        })
      : route.continue(),
  );
  await page.goto("/devices");
  await page.getByTestId("device-name").fill(`e2e-forbidden-${Date.now()}`);
  await page.getByTestId("device-submit").click();
  await expect(page.getByTestId("device-create-error")).toContainText(
    "insufficient capability",
    { timeout: 15_000 },
  );
  await page.unroute("**/api/v1/devices*");
});

// Empty and error states are functional (API interception mirrors the
// existing metrics-spec pattern; the smokes above use the real API).
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
  // The empty state points at the manual add form rather than a dead end.
  await expect(page.getByTestId("devices-empty")).toContainText("Add device");

  await page.unroute("**/api/v1/devices*");
  await page.route("**/api/v1/devices*", (route) => route.abort());
  await page.goto("/devices");
  await expect(page.getByTestId("devices-error")).toBeVisible();
  await page.unroute("**/api/v1/devices*");
});
