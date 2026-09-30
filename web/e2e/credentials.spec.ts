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

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext();
  page = await context.newPage();
  await login(page);
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
