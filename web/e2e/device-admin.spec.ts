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

// M10-S3a device admin surface. One session for the whole file: the login
// endpoint is rate-limited per IP (10/min), so specs must not multiply login
// attempts. Fixtures are created through the real API (session + CSRF), never
// mocked; only the 403 paths are intercepted (the dev caller is org-wide).
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
      serial: `SN-${name}`,
    },
  });
  expect(res.status()).toBe(201);
  return ((await res.json()) as { id: string }).id;
}

async function createCredential(name: string): Promise<string> {
  const res = await page.request.post("/api/v1/credentials", {
    headers: { "X-CSRF-Token": csrf },
    data: { name, kind: "snmp_v2c", secret: `e2e-community-${name}` },
  });
  expect(res.status()).toBe(201);
  return ((await res.json()) as { id: string }).id;
}

// M10-S3a: PATCH /v1/devices/{id} edits the device in place. The server
// problem+json field errors render on the form; a valid change refreshes the
// header immediately.
test("device edit: updates mgmt_ip and renders validation problems", async () => {
  const name = `e2e-admin-device-${Date.now()}`;
  const mgmtIP = uniqueIP("198.51");
  const deviceID = await createDevice(name, mgmtIP);

  await page.goto(`/devices/${deviceID}`);
  await expect(page.getByTestId("device-header")).toContainText(mgmtIP, {
    timeout: 15_000,
  });

  await page.getByTestId("device-edit-open").click();
  await expect(page.getByTestId("device-edit-form")).toBeVisible();
  // Server-side validation failure path (400 problem+json + field errors).
  await page.getByTestId("device-edit-mgmt-ip").fill("not-an-ip");
  await page.getByTestId("device-edit-submit").click();
  await expect(page.getByTestId("device-edit-error")).toContainText(
    "invalid device update",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("device-edit-field-errors")).toContainText(
    "mgmt_ip",
  );

  // Fix the address; the header reflects it without a manual reload.
  const newIP = uniqueIP("198.52");
  await page.getByTestId("device-edit-mgmt-ip").fill(newIP);
  await page.getByTestId("device-edit-submit").click();
  await expect(page.getByTestId("device-edit-result")).toContainText(
    "Device updated",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("device-header")).toContainText(newIP, {
    timeout: 15_000,
  });
  await expect(page.getByTestId("device-edit-form")).toHaveCount(0);
});

// M10-S3a: bind/unbind through the panel. The credential is created through
// the API; binding a fresh device with priority 5 must show up as the
// device-scope binding and as the effective credential (device tier wins);
// a duplicate bind renders the 409 binding_conflict problem; unbind removes it.
test("device credentials: bind, conflict, effective and unbind", async () => {
  const now = Date.now();
  const credName = `e2e-admin-cred-${now}`;
  const credID = await createCredential(credName);
  const deviceName = `e2e-admin-cred-device-${now}`;
  const deviceID = await createDevice(deviceName, uniqueIP("198.53"));

  await page.goto(`/devices/${deviceID}`);
  const panel = page.getByTestId("device-credentials-panel");
  await expect(panel).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("device-credentials-empty")).toBeVisible({
    timeout: 15_000,
  });
  // The create hint links to the existing credential form.
  await expect(page.getByTestId("device-credentials-create-link")).toHaveAttribute(
    "href",
    "/credentials",
  );

  await page.getByTestId("device-credentials-bind-select").selectOption(credID);
  await page.getByTestId("device-credentials-bind-priority").fill("5");
  await page.getByTestId("device-credentials-bind-submit").click();

  const row = page.getByTestId(`device-credential-row-${credName}`);
  await expect(row).toBeVisible({ timeout: 15_000 });
  await expect(row).toContainText("snmp_v2c");
  await expect(row).toContainText("5");
  await expect(page.getByTestId("device-credentials-effective")).toContainText(
    credName,
  );
  await expect(page.getByTestId("device-credentials-effective")).toContainText(
    "device binding",
  );

  // Duplicate binding -> deterministic 409 render.
  await page.getByTestId("device-credentials-bind-submit").click();
  await expect(page.getByTestId("device-credentials-bind-error")).toContainText(
    "already bound",
    { timeout: 15_000 },
  );

  await page.getByTestId(`device-credential-unbind-${credName}`).click();
  await expect(row).toHaveCount(0, { timeout: 15_000 });
  await expect(page.getByTestId("device-credentials-empty")).toBeVisible();
  await expect(page.getByTestId("device-credentials-bind-result")).toContainText(
    "Unbound",
  );
});

// M10-S3a: delete is a confirm step then DELETE /v1/devices/{id}; the API
// soft-deletes and the UI returns to /devices, whose list hides the device.
test("device delete: confirm, soft-delete and back to the list", async () => {
  const name = `e2e-admin-del-${Date.now()}`;
  await createDevice(name, uniqueIP("198.54"));

  await page.goto(`/devices`);
  const listRow = page.getByTestId("devices-table").locator("tr", {
    hasText: name,
  });
  await expect(listRow).toBeVisible({ timeout: 15_000 });
  await listRow.locator("a").click();
  await expect(page.getByTestId("device-header")).toContainText(name, {
    timeout: 15_000,
  });

  // The confirm step can be cancelled without deleting.
  await page.getByTestId("device-delete-open").click();
  await expect(page.getByTestId("device-delete-confirm-step")).toBeVisible();
  await page.getByTestId("device-delete-cancel").click();
  await expect(page.getByTestId("device-delete-confirm-step")).toHaveCount(0);

  await page.getByTestId("device-delete-open").click();
  await page.getByTestId("device-delete-confirm").click();
  await expect(page).toHaveURL(/\/devices$/, { timeout: 15_000 });
  await expect(page.getByTestId("devices-table")).not.toContainText(name, {
    timeout: 15_000,
  });
});

// M10-S3a: 403 paths render the server problem detail (admin role on device
// writes; org-wide scope on the credential surface). The dev caller is
// org-wide, so both are asserted with intercepted problem+json responses.
test("device admin and bind render forbidden problems", async () => {
  const now = Date.now();
  const credName = `e2e-admin-forbidden-cred-${now}`;
  const credID = await createCredential(credName);
  const name = `e2e-admin-forbidden-${now}`;
  const deviceID = await createDevice(name, uniqueIP("198.55"));

  await page.route(`**/api/v1/devices/${deviceID}`, (route) =>
    route.request().method() === "PATCH"
      ? route.fulfill({
          status: 403,
          contentType: "application/problem+json",
          body: JSON.stringify({
            type: "about:blank",
            title: "Forbidden",
            status: 403,
            code: "auth.forbidden",
            detail: "admin role required",
          }),
        })
      : route.continue(),
  );
  await page.goto(`/devices/${deviceID}`);
  await page.getByTestId("device-edit-open").click();
  await page.getByTestId("device-edit-submit").click();
  await expect(page.getByTestId("device-edit-error")).toContainText(
    "admin role required",
    { timeout: 15_000 },
  );
  await page.unroute(`**/api/v1/devices/${deviceID}`);

  await page.route("**/api/v1/credentials/*/bind", (route) =>
    route.fulfill({
      status: 403,
      contentType: "application/problem+json",
      body: JSON.stringify({
        type: "about:blank",
        title: "Forbidden",
        status: 403,
        code: "auth.forbidden",
        detail: "credential management requires org-wide scope",
      }),
    }),
  );
  await page.reload();
  await expect(
    page.getByTestId("device-credentials-bind-select").locator(
      `option[value="${credID}"]`,
    ),
  ).toHaveCount(1, { timeout: 15_000 });
  await page.getByTestId("device-credentials-bind-select").selectOption(credID);
  await page.getByTestId("device-credentials-bind-submit").click();
  await expect(page.getByTestId("device-credentials-bind-error")).toContainText(
    "org-wide scope",
    { timeout: 15_000 },
  );
  await page.unroute("**/api/v1/credentials/*/bind");
});
