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

// M10-S3b-2 device-groups page. One session for the whole file: the login
// endpoint is rate-limited per IP (10/min), so specs must not multiply login
// attempts. Fixtures are created through the real API or the real UI; only the
// 403 path is intercepted (the dev caller is org-wide).
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

// M10-S3b-2: the nav link leads to /device-groups; the page states the
// membership-resolution deferral; create/edit/delete go through the real CRUD
// endpoints and the duplicate name renders the server's 409 problem.
test("device groups: create, edit, duplicate-name conflict and delete", async () => {
  const now = Date.now();
  const name = `e2e-group-${now}`;
  const renamed = `e2e-group-renamed-${now}`;

  await page.goto("/");
  await page.getByTestId("nav-device-groups").click();
  await expect(page).toHaveURL(/\/device-groups$/);
  await expect(page.getByTestId("device-groups-membership-note")).toContainText(
    "deferred",
  );

  // Create with a JSON selector.
  await page.getByTestId("device-groups-name").fill(name);
  await page
    .getByTestId("device-groups-selector")
    .fill('{"kinds":["switch"],"site_ids":[]}');
  await page.getByTestId("device-groups-submit").click();
  await expect(page.getByTestId("device-groups-result")).toContainText(
    "created",
    { timeout: 15_000 },
  );
  const row = page.getByTestId(`device-groups-row-${name}`);
  await expect(row).toBeVisible();
  await expect(row).toContainText('{"kinds":["switch"],"site_ids":[]}');

  // Duplicate name -> real server 409 (device_group.name_conflict).
  await page.getByTestId("device-groups-name").fill(name);
  await page.getByTestId("device-groups-selector").fill("{}");
  await page.getByTestId("device-groups-submit").click();
  await expect(page.getByTestId("device-groups-form-error")).toContainText(
    "already exists",
    { timeout: 15_000 },
  );

  // Edit: rename and replace the selector.
  await page.getByTestId(`device-groups-edit-${name}`).click();
  await expect(page.getByTestId("device-groups-submit")).toContainText(
    "Save changes",
  );
  await page.getByTestId("device-groups-name").fill(renamed);
  await page.getByTestId("device-groups-selector").fill('{"kinds":["router"]}');
  await page.getByTestId("device-groups-submit").click();
  await expect(page.getByTestId("device-groups-result")).toContainText(
    "updated",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId(`device-groups-row-${renamed}`)).toContainText(
    '{"kinds":["router"]}',
  );

  // Delete with the confirm step (cancel first, then confirm).
  await page.getByTestId(`device-groups-delete-${renamed}`).click();
  await expect(
    page.getByTestId(`device-groups-delete-confirm-step-${renamed}`),
  ).toBeVisible();
  await page.getByTestId(`device-groups-delete-cancel-${renamed}`).click();
  await expect(page.getByTestId(`device-groups-row-${renamed}`)).toBeVisible();
  await page.getByTestId(`device-groups-delete-${renamed}`).click();
  await page.getByTestId(`device-groups-delete-confirm-${renamed}`).click();
  await expect(page.getByTestId("device-groups-result")).toContainText(
    "deleted",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId(`device-groups-row-${renamed}`)).toHaveCount(0);
});

// M10-S3b-2: selector validation. The client mirrors the server's one rule
// (selector must be a JSON object) so malformed JSON and arrays never reach
// the API; the server's problem+json is still rendered verbatim (403 path
// intercepted because the dev caller is org-wide).
test("device groups: selector validation and server problems", async () => {
  await page.goto("/device-groups");
  const name = `e2e-group-invalid-${Date.now()}`;
  await page.getByTestId("device-groups-name").fill(name);

  await page.getByTestId("device-groups-selector").fill("{broken");
  await page.getByTestId("device-groups-submit").click();
  await expect(page.getByTestId("device-groups-form-error")).toContainText(
    "valid JSON",
  );

  await page.getByTestId("device-groups-selector").fill("[1,2]");
  await page.getByTestId("device-groups-submit").click();
  await expect(page.getByTestId("device-groups-form-error")).toContainText(
    "JSON object",
  );
  // The validation hints come from the API contract and are visible.
  await expect(page.getByTestId("device-groups-selector-hint")).toContainText(
    "must be a JSON object",
  );

  await page.getByTestId("device-groups-selector").fill("{}");
  await page.route("**/api/v1/device-groups", (route) =>
    route.request().method() === "POST"
      ? route.fulfill({
          status: 403,
          contentType: "application/problem+json",
          body: JSON.stringify({
            type: "about:blank",
            title: "Forbidden",
            status: 403,
            code: "auth.forbidden",
            detail: "creating a device group requires org-wide scope",
          }),
        })
      : route.continue(),
  );
  await page.getByTestId("device-groups-submit").click();
  await expect(page.getByTestId("device-groups-form-error")).toContainText(
    "org-wide scope",
    { timeout: 15_000 },
  );
  await page.unroute("**/api/v1/device-groups");
});
