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

// M10-S3b-4: row-level delete with a two-step confirm - no detail-page trip.
test("device list row delete removes a device without opening its detail", async () => {
  const sitesRes = await page.request.get("/api/v1/sites?limit=1");
  expect(sitesRes.ok()).toBeTruthy();
  const site = ((await sitesRes.json()) as { data: { id: string }[] }).data[0];
  const name = `e2e-rowdel-${Date.now()}`;
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
  const row = page.getByTestId("devices-table").locator("tr", { hasText: name });
  await expect(row).toBeVisible({ timeout: 15_000 });
  await row.getByTestId("device-row-delete").click();
  await row.getByTestId("device-row-delete-confirm").click();
  await expect(
    page.getByTestId("devices-table").locator("tr", { hasText: name }),
  ).toHaveCount(0, { timeout: 15_000 });
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
  // M10-S0: critical devices lower the collector failure-backoff ceiling to
  // 5 minutes; the checkbox posts `critical: true` and the row shows a badge.
  await page.getByTestId("device-critical").check();
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
  await expect(row).toContainText("critical");
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

// M10-S3b-1: identity attributes recorded at create appear in the device's
// identity history. The form posts identities[]; an invalid MAC renders the
// indexed server problem field error before the valid value succeeds.
test("add device form records a MAC identity visible on the detail page", async () => {
  const sitesRes = await page.request.get("/api/v1/sites?limit=1");
  expect(sitesRes.ok()).toBeTruthy();
  const site = (
    (await sitesRes.json()) as { data: { id: string; name: string }[] }
  ).data[0];
  const now = Date.now();
  const name = `e2e-identity-device-${now}`;
  const mgmtIP = `198.19.${((now / 1000) % 250) | 0}.${(now % 249) + 1}`;
  const hex = now.toString(16).slice(-10).padStart(10, "0");
  const mac = `02:${hex.slice(0, 2)}:${hex.slice(2, 4)}:${hex.slice(4, 6)}:${hex.slice(6, 8)}:${hex.slice(8, 10)}`;

  await page.goto("/devices");
  await page.getByTestId("device-name").fill(name);
  await page.getByTestId("device-site").selectOption(site.id);
  await page.getByTestId("device-kind").selectOption("switch");
  await page.getByTestId("device-mgmt-ip").fill(mgmtIP);
  await page.getByTestId("device-identity-add").click();
  await page.getByTestId("device-identity-type-0").selectOption("mac");
  await page.getByTestId("device-identity-value-0").fill("not-a-mac");
  await page.getByTestId("device-submit").click();
  await expect(page.getByTestId("device-create-field-errors")).toContainText(
    "identities[0].value",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("device-create-result")).toHaveCount(0);

  await page.getByTestId("device-identity-value-0").fill(mac);
  await page.getByTestId("device-submit").click();
  await expect(page.getByTestId("device-create-result")).toContainText(name, {
    timeout: 15_000,
  });
  const row = page.getByTestId("devices-table").locator("tr", { hasText: name });
  await expect(row).toBeVisible();
  await row.locator("a").click();
  await expect(page.getByTestId("device-identity-table")).toContainText(mac, {
    timeout: 15_000,
  });
  const identityRow = page
    .getByTestId("device-identity-table")
    .locator("tr", { hasText: mac });
  await expect(identityRow).toContainText("open window");
});

// M10-S3b-1: the list filters are URL-driven (site/status/kind/q). Site and
// kind filter server-side; the S1 poll status and the name/mgmt-IP search are
// applied client-side over the loaded rows (the device API has no text query
// and filter[status] is the inventory lifecycle, not the poll-health rollup).
test("device list: URL filters, search and server-refetch", async () => {
  const sitesRes = await page.request.get("/api/v1/sites?limit=1");
  expect(sitesRes.ok()).toBeTruthy();
  const site = (
    (await sitesRes.json()) as { data: { id: string; name: string }[] }
  ).data[0];
  const now = Date.now();
  const name = `e2e-list-device-${now}`;
  const mgmtIP = `198.20.${((now / 1000) % 250) | 0}.${(now % 249) + 1}`;
  const csrf =
    (await page.context().cookies()).find((c) => c.name === "argus_csrf")
      ?.value ?? "";
  const createRes = await page.request.post("/api/v1/devices", {
    headers: { "X-CSRF-Token": csrf },
    data: { site_id: site.id, name, kind: "printer", mgmt_ip: mgmtIP },
  });
  expect(createRes.status()).toBe(201);

  // URL-driven search by name over the loaded rows.
  await page.goto(`/devices?q=${encodeURIComponent(name)}`);
  await expect(page.getByTestId("devices-search")).toHaveValue(name);
  await expect(page.getByTestId("devices-table")).toContainText(name, {
    timeout: 15_000,
  });
  await expect(page.getByTestId("devices-filter-count")).toContainText("match");

  // URL-driven poll-status filter: every rendered chip carries the value (or
  // the honest no-match state is shown).
  await page.getByTestId("devices-filter-status").selectOption("up");
  await expect(page).toHaveURL(/status=up/);
  await expect(page.getByTestId("devices-filter-status")).toHaveValue("up");
  const count = page.getByTestId("devices-filter-count");
  const nomatch = page.getByTestId("devices-nomatch");
  await expect(count.or(nomatch).first()).toBeVisible({ timeout: 15_000 });
  if (await page.getByTestId("devices-table").isVisible().catch(() => false)) {
    const chips = page.getByTestId("devices-table").locator("[data-status]");
    const chipCount = await chips.count();
    for (let i = 0; i < chipCount; i += 1) {
      await expect(chips.nth(i)).toHaveAttribute("data-status", "up");
    }
  }

  // Kind and site refetch server-side and stay in the URL.
  await page.getByTestId("devices-filter-status").selectOption("all");
  await expect(page).not.toHaveURL(/status=/);
  await page.getByTestId("devices-filter-kind").selectOption("printer");
  await expect(page).toHaveURL(/kind=printer/);
  await page.getByTestId("devices-filter-site").selectOption(site.id);
  await expect(page).toHaveURL(new RegExp(`site=${site.id}`));
  await expect(page.getByTestId("devices-table")).toContainText(name, {
    timeout: 15_000,
  });
  await expect(page.getByTestId("devices-search")).toHaveValue(name);
});

// M10-S3b-1: "Load more" follows next_cursor and appends the next page. The
// two-page response is deterministic via interception; the real cursor path is
// covered by the integration tests.
test("device list load more appends the next cursor page", async () => {
  const page2Cursor = "00000000-0000-7000-8000-000000000002";
  const device = (id: string, name: string) => ({
    id,
    site_id: "00000000-0000-0000-0000-000000000001",
    name,
    kind: "switch",
    status: "new",
    critical: false,
    mgmt_ip: null,
    first_seen_at: new Date().toISOString(),
    last_seen_at: null,
    updated_at: new Date().toISOString(),
    poll_status: { status: "unknown", last_checked_at: null },
  });
  await page.route("**/api/v1/devices*", (route) => {
    const url = new URL(route.request().url());
    const body =
      url.searchParams.get("cursor") === page2Cursor
        ? {
            data: [device("00000000-0000-7000-8000-0000000000b2", "e2e-loadmore-b")],
            next_cursor: null,
            has_more: false,
          }
        : {
            data: [device("00000000-0000-7000-8000-0000000000a1", "e2e-loadmore-a")],
            next_cursor: page2Cursor,
            has_more: true,
          };
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(body),
    });
  });
  await page.goto("/devices");
  await expect(page.getByTestId("devices-table")).toContainText(
    "e2e-loadmore-a",
  );
  await page.getByTestId("devices-load-more").click();
  await expect(page.getByTestId("devices-table")).toContainText(
    "e2e-loadmore-b",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("devices-table")).toContainText(
    "e2e-loadmore-a",
  );
  // Last page: the button disappears.
  await expect(page.getByTestId("devices-load-more")).toHaveCount(0);
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
