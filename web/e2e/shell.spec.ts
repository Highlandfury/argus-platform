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

// Phase 1 shell smoke: one session for both tests (login endpoint is
// rate-limited per IP; see the other specs).
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

test("shell: grouped navigation, active state and URL-driven global search", async () => {
  // Sidebar groups and stable item ids.
  await expect(page.getByTestId("sidebar")).toBeVisible();
  for (const group of ["Overview", "Observability", "Operations", "Admin"]) {
    await expect(page.getByTestId("sidebar")).toContainText(group);
  }
  for (const testId of [
    "nav-dashboard",
    "nav-devices",
    "nav-checks",
    "nav-collectors",
    "nav-credentials",
    "nav-device-groups",
    "nav-alerts",
  ]) {
    await expect(page.getByTestId(testId)).toBeVisible();
  }

  // Active state follows the route (/devices/{id} keeps Devices lit too).
  await page.getByTestId("nav-devices").click();
  await expect(page).toHaveURL(/\/devices$/);
  await expect(page.getByTestId("nav-devices")).toHaveClass(/is-active/);
  await expect(page.getByTestId("nav-dashboard")).not.toHaveClass(/is-active/);

  // Global search: Enter routes to /devices?q=<query>.
  const query = `shell-smoke-${Date.now()}`;
  await page.getByTestId("global-search").fill(query);
  await page.getByTestId("global-search").press("Enter");
  await expect(page).toHaveURL(new RegExp(`/devices\\?q=${query}`));
  await expect(page.getByTestId("devices-search")).toHaveValue(query);
});

test("shell: planned routes render an explicit ComingSoon state", async () => {
  await page.goto("/topology");
  await expect(page.getByTestId("coming-soon")).toBeVisible();
  await expect(page.getByTestId("coming-soon")).toContainText(
    "planned / not yet available",
  );
  await expect(page.getByTestId("coming-soon")).toContainText(
    "FEATURE_HORIZONS.md",
  );
  await expect(page.getByTestId("nav-topology")).toBeVisible();

  // Alerts is a real M11-S3b workspace now (queue + suppression tabs): the
  // nav marker is gone and the queue renders its own loading/empty state.
  await page.goto("/alerts");
  await expect(page.getByTestId("alerts-view")).toBeVisible();
  await expect(page.getByTestId("alerts-tabs")).toBeVisible();
  await expect(page.getByTestId("nav-alerts")).not.toHaveAttribute(
    "data-planned",
    "true",
  );

  // Metrics points at the real collector chart surface.
  await page.goto("/metrics");
  await expect(
    page.getByRole("link", { name: "Open collector metrics" }),
  ).toHaveAttribute("href", "/collectors");

  // Sites is a real list page (empty or populated) and details stay linked.
  await page.goto("/sites");
  const table = page.getByTestId("sites-list-table");
  const empty = page.getByTestId("sites-empty");
  await expect(table.or(empty)).toBeVisible({ timeout: 15_000 });
  if (await table.isVisible()) {
    await expect(table).toContainText("HQ");
  }
});
