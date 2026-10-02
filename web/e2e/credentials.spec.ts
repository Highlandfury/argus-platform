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

async function storageDump(page: Page): Promise<string> {
  return page.evaluate(() => {
    const dump = (storage: Storage) => {
      const entries: Record<string, string> = {};
      for (let i = 0; i < storage.length; i += 1) {
        const key = storage.key(i);
        if (key !== null) entries[key] = storage.getItem(key) ?? "";
      }
      return entries;
    };
    return JSON.stringify({ local: dump(localStorage), session: dump(sessionStorage) });
  });
}

// One session for the whole file: the login endpoint is rate-limited per IP
// (10/min), so specs must not multiply login attempts.
test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let page: Page;
let csrf = "";

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext();
  page = await context.newPage();
  await login(page);
  csrf =
    (await page.context().cookies()).find((c) => c.name === "argus_csrf")
      ?.value ?? "";
});

test.afterAll(async () => {
  await context.close();
});

// M7-S4 (UI half): the credential metadata surface lists safe metadata, the
// create form submits the secret exactly once, and rotation replaces it — no
// secret is ever rendered or persisted client-side.
test("credential metadata surface never renders or stores secrets", async () => {
  const name = `e2e-cred-${Date.now()}`;
  const secret1 = `e2e-secret-1-${Date.now()}`;
  const secret2 = `e2e-secret-2-${Date.now()}`;

  await page.goto("/credentials");
  await page.getByTestId("credential-name").fill(name);
  await page.getByTestId("credential-kind").selectOption("snmp_v2c");
  await page.getByTestId("credential-secret").fill(secret1);
  await page.getByTestId("credential-submit").click();
  await expect(page.getByTestId("credential-create-result")).toContainText(
    name,
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("credentials-table")).toContainText(name);

  // Metadata only: the submitted secret never appears in the rendered page or
  // in browser storage.
  await expect(page.locator("body")).not.toContainText(secret1);
  expect(await storageDump(page)).not.toContain(secret1);

  // Rotate with a second sentinel: response is metadata-only and neither the
  // old nor the new secret is rendered or persisted.
  await page.getByTestId(`credential-rotate-open-${name}`).click();
  await page.getByTestId(`credential-rotate-secret-${name}`).fill(secret2);
  await page.getByTestId(`credential-rotate-submit-${name}`).click();
  await expect(
    page.getByTestId(`credential-rotate-result-${name}`),
  ).toContainText("Rotated", { timeout: 15_000 });
  await page.reload();
  await expect(page.getByTestId("credentials-table")).toContainText(name);
  await expect(page.locator("body")).not.toContainText(secret1);
  await expect(page.locator("body")).not.toContainText(secret2);
  expect(await storageDump(page)).not.toContain(secret2);
});

// Mutations require the session + CSRF pair: the UI form carries the token,
// and a direct request without it is rejected before any state change.
test("credential mutations require the session CSRF pair", async () => {
  const res = await page.request.post("/api/v1/credentials", {
    data: { name: `e2e-csrf-${Date.now()}`, kind: "snmp_v2c", secret: "x" },
  });
  expect(res.status()).toBe(403);
  const body = (await res.json()) as { code: string };
  expect(body.code).toBe("auth.csrf");
});

// M10-S3b-1: the per-credential binding surface binds to a site and a device
// group, renders the deterministic 409 binding_conflict on a duplicate, and
// unbinds per row. An intercepted 403 renders the org-wide scope rule.
test("credential bindings: site and device-group bind, conflict, unbind", async () => {
  const now = Date.now();
  const credName = `e2e-bind-cred-${now}`;
  const createRes = await page.request.post("/api/v1/credentials", {
    headers: { "X-CSRF-Token": csrf },
    data: { name: credName, kind: "snmp_v2c", secret: `e2e-community-${now}` },
  });
  expect(createRes.status()).toBe(201);

  const groupName = `e2e-bind-group-${now}`;
  const groupRes = await page.request.post("/api/v1/device-groups", {
    headers: { "X-CSRF-Token": csrf },
    data: { name: groupName, selector: { kinds: ["switch"] } },
  });
  expect(groupRes.status()).toBe(201);
  const groupID = ((await groupRes.json()) as { id: string }).id;

  const sitesRes = await page.request.get("/api/v1/sites?limit=1");
  expect(sitesRes.ok()).toBeTruthy();
  const siteID = (
    (await sitesRes.json()) as { data: { id: string }[] }
  ).data[0].id;

  await page.goto("/credentials");
  const card = page.getByTestId(`credential-bindings-${credName}`);
  await expect(card).toBeVisible({ timeout: 15_000 });
  const scopeSelect = card.getByTestId(`credential-binding-scope-${credName}`);
  const targetSelect = card.getByTestId(`credential-binding-target-${credName}`);
  const submit = card.getByTestId(`credential-binding-submit-${credName}`);

  // Site binding with priority 3.
  await scopeSelect.selectOption("site");
  await targetSelect.selectOption(siteID);
  await card.getByTestId(`credential-binding-priority-${credName}`).fill("3");
  await submit.click();
  const siteRow = card.getByTestId(
    `credential-binding-row-${credName}-site-${siteID}`,
  );
  await expect(siteRow).toBeVisible({ timeout: 15_000 });
  await expect(siteRow).toContainText("3");

  // Duplicate binding -> deterministic 409 binding_conflict detail.
  await submit.click();
  await expect(
    card.getByTestId(`credential-binding-error-${credName}`),
  ).toContainText("already bound", { timeout: 15_000 });

  // Device-group binding (target picker switches with the scope type).
  await scopeSelect.selectOption("device_group");
  await expect(
    targetSelect.locator(`option[value="${groupID}"]`),
  ).toHaveCount(1);
  await targetSelect.selectOption(groupID);
  await submit.click();
  const groupRow = card.getByTestId(
    `credential-binding-row-${credName}-device_group-${groupID}`,
  );
  await expect(groupRow).toBeVisible({ timeout: 15_000 });
  await expect(groupRow).toContainText(groupName);

  // Unbind the site row; the group row stays.
  await card
    .getByTestId(`credential-binding-unbind-${credName}-site-${siteID}`)
    .click();
  await expect(siteRow).toHaveCount(0, { timeout: 15_000 });
  await expect(groupRow).toBeVisible();
  await expect(
    card.getByTestId(`credential-binding-result-${credName}`),
  ).toContainText("Unbound");

  // The credential surface is org-wide: a 403 renders the server detail.
  await page.route("**/api/v1/credentials/*/unbind", (route) =>
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
  await card
    .getByTestId(`credential-binding-unbind-${credName}-device_group-${groupID}`)
    .click();
  await expect(
    card.getByTestId(`credential-binding-error-${credName}`),
  ).toContainText("org-wide scope", { timeout: 15_000 });
  await page.unroute("**/api/v1/credentials/*/unbind");
});
