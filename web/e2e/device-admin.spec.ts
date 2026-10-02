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
        if_alias: "e2e-seed-alias",
        speed_bps: 1_000_000_000,
        mtu: 1500,
        mac: `02:00:00:00:0${ifIndex % 10}:${(ifIndex % 90) + 10}`,
      },
    },
  );
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

// M10-S3b-1: identity windows on an existing device. The add control posts
// /v1/devices/{id}/identities (indexed server field error for a bad MAC is
// rendered), repeats are idempotent, and Close stamps the open window.
test("device identities: add (idempotent) and close a window", async () => {
  const now = Date.now();
  const name = `e2e-admin-identity-${now}`;
  const deviceID = await createDevice(name, uniqueIP("198.56"));
  const hostname = `e2e-host-${now}`;

  await page.goto(`/devices/${deviceID}`);
  await expect(page.getByTestId("device-identity-table")).toBeVisible({
    timeout: 15_000,
  });

  // Bad MAC -> indexed server problem field error; nothing is added.
  await page.getByTestId("device-identity-add-type").selectOption("mac");
  await page.getByTestId("device-identity-add-value").fill("not-a-mac");
  await page.getByTestId("device-identity-add-submit").click();
  await expect(page.getByTestId("device-identity-field-errors")).toContainText(
    "value",
    { timeout: 15_000 },
  );

  await page.getByTestId("device-identity-add-type").selectOption("hostname");
  await page.getByTestId("device-identity-add-value").fill(hostname);
  await page.getByTestId("device-identity-add-submit").click();
  await expect(page.getByTestId("device-identity-action-result")).toContainText(
    "added",
    { timeout: 15_000 },
  );
  const row = page
    .getByTestId("device-identity-table")
    .locator("tr", { hasText: hostname });
  await expect(row).toContainText("open window");

  // Idempotent repeat on the same device: still exactly one window row.
  await page.getByTestId("device-identity-add-value").fill(hostname);
  await page.getByTestId("device-identity-add-submit").click();
  await expect(page.getByTestId("device-identity-action-result")).toContainText(
    "added",
    { timeout: 15_000 },
  );
  await expect(
    page.getByTestId("device-identity-table").locator("tr", { hasText: hostname }),
  ).toHaveCount(1);

  // Close: the window is stamped and the button disappears.
  await page.getByTestId(`device-identity-close-${hostname}`).click();
  await expect(page.getByTestId("device-identity-action-result")).toContainText(
    "closed",
    { timeout: 15_000 },
  );
  await expect(row).not.toContainText("open window");
  await expect(page.getByTestId(`device-identity-close-${hostname}`)).toHaveCount(
    0,
  );
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

// M10-S3b-2: interface CRUD from the device detail page. The add form posts
// POST /v1/devices/{id}/interfaces, edit PATCHes /v1/interfaces/{id} (ifIndex
// immutable) and delete is a confirm step over DELETE /v1/interfaces/{id}.
// Server problem+json field errors and the 409 ifIndex conflict render.
test("device interfaces: add, edit and delete", async () => {
  const now = Date.now();
  const name = `e2e-admin-iface-${now}`;
  const deviceID = await createDevice(name, uniqueIP("198.57"));

  await page.goto(`/devices/${deviceID}`);
  await expect(page.getByTestId("device-interfaces-empty")).toBeVisible({
    timeout: 15_000,
  });

  // Add with an invalid MAC: the server's indexed 400 field error renders.
  await page.getByTestId("device-interface-add-open").click();
  await page.getByTestId("device-interface-if-index").fill("1");
  await page.getByTestId("device-interface-if-name").fill("Gi1/0/1");
  await page.getByTestId("device-interface-if-alias").fill("e2e-iface");
  await page.getByTestId("device-interface-role").selectOption("uplink");
  await page.getByTestId("device-interface-speed").fill("1000000000");
  await page.getByTestId("device-interface-mtu").fill("1500");
  await page.getByTestId("device-interface-mac").fill("not-a-mac");
  await page.getByTestId("device-interface-submit").click();
  await expect(page.getByTestId("device-interface-form-error")).toContainText(
    "invalid interface",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("device-interface-field-errors")).toContainText(
    "mac",
  );

  // Fix the MAC; the row appears with the alias and canonical speed.
  await page.getByTestId("device-interface-mac").fill("02:00:00:00:00:21");
  await page.getByTestId("device-interface-submit").click();
  await expect(page.getByTestId("device-interface-result")).toContainText(
    "added",
    { timeout: 15_000 },
  );
  const row = page
    .getByTestId("device-interfaces-table")
    .locator("tr", { hasText: "Gi1/0/1" });
  await expect(row).toBeVisible();
  await expect(row).toContainText("e2e-iface");
  await expect(row).toContainText("1.0 Gbit/s");

  // Duplicate ifIndex -> deterministic 409 problem rendered.
  await page.getByTestId("device-interface-add-open").click();
  await page.getByTestId("device-interface-if-index").fill("1");
  await page.getByTestId("device-interface-if-name").fill("Gi1/0/2");
  await page.getByTestId("device-interface-submit").click();
  await expect(page.getByTestId("device-interface-form-error")).toContainText(
    "if_index already exists",
    { timeout: 15_000 },
  );
  await page.getByTestId("device-interface-cancel").click();

  // Edit: a bad MAC renders a field error, then a valid change saves.
  await page.getByTestId("device-interface-edit-Gi1/0/1").click();
  await expect(page.getByTestId("device-interface-form")).toContainText(
    "Edit Gi1/0/1",
  );
  await page.getByTestId("device-interface-mac").fill("nope");
  await page.getByTestId("device-interface-submit").click();
  await expect(page.getByTestId("device-interface-field-errors")).toContainText(
    "mac",
    { timeout: 15_000 },
  );
  await page.getByTestId("device-interface-if-alias").fill("e2e-edited");
  await page.getByTestId("device-interface-role").selectOption("trunk");
  await page.getByTestId("device-interface-mac").fill("02:00:00:00:00:22");
  await page.getByTestId("device-interface-submit").click();
  await expect(page.getByTestId("device-interface-result")).toContainText(
    "updated",
    { timeout: 15_000 },
  );
  await expect(row).toContainText("e2e-edited");

  // Delete: confirm step with a cancel, then the row disappears.
  await page.getByTestId("device-interface-delete-Gi1/0/1").click();
  await expect(
    page.getByTestId("device-interface-delete-confirm-step-Gi1/0/1"),
  ).toBeVisible();
  await page.getByTestId("device-interface-delete-cancel-Gi1/0/1").click();
  await expect(row).toBeVisible();
  await page.getByTestId("device-interface-delete-Gi1/0/1").click();
  await page.getByTestId("device-interface-delete-confirm-Gi1/0/1").click();
  await expect(page.getByTestId("device-interface-result")).toContainText(
    "deleted",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("device-interfaces-empty")).toBeVisible();
});

// M10-S3b-2: merge source -> target. The picker excludes the target and
// searches over the loaded first page; the confirm step counts identity
// windows + interfaces before posting /v1/devices/{id}/merge. On success the
// source's identity windows and interfaces belong to the target, the source is
// soft-deleted (uniform 404), and the inventory stops matching it.
test("device merge: moves identity + interfaces and hides the source", async () => {
  const now = Date.now();
  const targetName = `e2e-merge-target-${now}`;
  const sourceName = `e2e-merge-source-${now}`;
  const targetID = await createDevice(targetName, uniqueIP("198.58"));
  const sourceID = await createDevice(sourceName, uniqueIP("198.59"));
  const ifaceName = "Gi9/0/1";
  await createInterface(sourceID, 9, ifaceName);

  await page.goto(`/devices/${targetID}`);
  await expect(page.getByTestId("device-merge-panel")).toBeVisible({
    timeout: 15_000,
  });
  // The picker excludes the target device itself (wait for the list first so
  // the absence is meaningful, then assert the target is not an option).
  await expect(page.getByTestId("device-merge-list")).toBeVisible({
    timeout: 15_000,
  });
  await expect(
    page.getByTestId(`device-merge-option-${targetName}`),
  ).toHaveCount(0);

  await page.getByTestId("device-merge-search").fill(sourceName);
  await page.getByTestId(`device-merge-option-${sourceName}`).check();
  await page.getByTestId("device-merge-submit").click();

  // Confirmation lists what moves before anything is written.
  const summary = page.getByTestId("device-merge-confirm-summary");
  await expect(summary).toContainText(sourceName, { timeout: 15_000 });
  await expect(summary).toContainText("identity window(s)");
  await expect(summary).toContainText("interface(s)");
  await page.getByTestId("device-merge-confirm").click();

  await expect(page.getByTestId("device-merge-result")).toContainText(
    "Merged 1 device(s)",
    { timeout: 15_000 },
  );
  // Interfaces and identity windows were re-pointed to the target.
  await expect(page.getByTestId("device-interfaces-table")).toContainText(
    ifaceName,
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("device-identity-table")).toContainText(
    `SN-${sourceName}`,
    { timeout: 15_000 },
  );

  // The source is soft-deleted: uniform 404 and absent from inventory.
  const gone = await page.request.get(`/api/v1/devices/${sourceID}`);
  expect(gone.status()).toBe(404);
  await page.goto(`/devices?q=${encodeURIComponent(sourceName)}`);
  await expect(page.getByTestId("devices-nomatch")).toBeVisible({
    timeout: 15_000,
  });
  await page.goto(`/devices/${targetID}`);
  await expect(page.getByTestId("device-header")).toContainText(targetName, {
    timeout: 15_000,
  });
});

// M10-S3b-2: the merge atomicity contract surfaces as a 409 problem. A source
// interface with the same ifIndex as a target interface aborts the whole
// merge; both devices stay untouched.
test("device merge: ifIndex collision renders the 409 conflict", async () => {
  const now = Date.now();
  const targetName = `e2e-merge-conflict-target-${now}`;
  const sourceName = `e2e-merge-conflict-source-${now}`;
  const targetID = await createDevice(targetName, uniqueIP("198.60"));
  const sourceID = await createDevice(sourceName, uniqueIP("198.61"));
  await createInterface(targetID, 5, "Gi5/0/1");
  await createInterface(sourceID, 5, "Gi5/0/2");

  await page.goto(`/devices/${targetID}`);
  await page.getByTestId("device-merge-search").fill(sourceName);
  await page.getByTestId(`device-merge-option-${sourceName}`).check();
  await page.getByTestId("device-merge-submit").click();
  await expect(page.getByTestId("device-merge-confirm-summary")).toContainText(
    sourceName,
    { timeout: 15_000 },
  );
  await page.getByTestId("device-merge-confirm").click();
  await expect(page.getByTestId("device-merge-error")).toContainText(
    "collide interfaces",
    { timeout: 15_000 },
  );

  // Atomic: the source is still live after the aborted merge.
  const still = await page.request.get(`/api/v1/devices/${sourceID}`);
  expect(still.status()).toBe(200);
});

// M10-S3b-2: split detaches open identity windows into a new device. The name
// conflict is a real server 409 (device.name_conflict); the successful path
// moves the selected window off the source and onto a new device.
test("device split: open identity windows move into a new device", async () => {
  const now = Date.now();
  const name = `e2e-split-source-${now}`;
  const siblingName = `e2e-split-sibling-${now}`;
  const deviceID = await createDevice(name, uniqueIP("198.62"));
  await createDevice(siblingName, uniqueIP("198.63"));
  const serialValue = `SN-${name}`;

  await page.goto(`/devices/${deviceID}`);
  await expect(page.getByTestId("device-identity-table")).toContainText(
    serialValue,
    { timeout: 15_000 },
  );

  await page
    .getByTestId(`device-identity-split-select-${serialValue}`)
    .check();

  // A name already used in the site renders the server 409 verbatim.
  await page.getByTestId("device-split-name").fill(siblingName);
  await page.getByTestId("device-split-submit").click();
  await expect(page.getByTestId("device-split-error")).toContainText(
    "already exists",
    { timeout: 15_000 },
  );

  const newName = `e2e-split-new-${now}`;
  await page.getByTestId("device-split-name").fill(newName);
  await page.getByTestId("device-split-submit").click();
  await expect(page.getByTestId("device-split-result")).toContainText(
    `into ${newName}`,
    { timeout: 15_000 },
  );

  // The serial window moved off the source...
  await expect(
    page
      .getByTestId("device-identity-table")
      .locator("tr", { hasText: serialValue }),
  ).toHaveCount(0, { timeout: 15_000 });

  // ...and onto the new device the result links to.
  await page.getByTestId("device-split-new-link").click();
  await expect(page.getByTestId("device-header")).toContainText(newName, {
    timeout: 15_000,
  });
  await expect(page.getByTestId("device-identity-table")).toContainText(
    serialValue,
    { timeout: 15_000 },
  );
});
