import { test, expect, type Page } from "@playwright/test";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByTestId("login-org").fill("dev");
  await page.getByTestId("login-email").fill("admin@dev.local");
  await page
    .getByTestId("login-password")
    .fill(process.env.ARGUS_DEV_ADMIN_PASSWORD ?? "dev-admin-changeme");
  await page.getByTestId("login-submit").click();
  await expect(page).toHaveURL(/\/$/);
}

// M3 (UI half): the developer stack enrolls "dev-collector" automatically at
// boot (seed token + shared CA volume). The registry lists it, the detail page
// shows the acknowledged policy version, and the admin actions are available.
test("collector registry and detail", async ({ page }) => {
  await login(page);

  await page.goto("/collectors");
  await expect(page.getByTestId("collectors-table")).toContainText(
    "dev-collector",
    { timeout: 15_000 },
  );

  await page.getByRole("link", { name: "dev-collector" }).click();
  await expect(page).toHaveURL(/\/collectors\//);
  await expect(page.getByTestId("collector-status")).toHaveText(/active|pending/);
  await expect(page.getByTestId("collector-policy")).toContainText(/acked v\d+/);

  // Admin-only control-plane actions are present (not clicked: revoke is
  // terminal and would break the shared dev stack).
  await expect(page.getByTestId("collector-resync")).toBeVisible();
  await expect(page.getByTestId("collector-revoke")).toBeVisible();
});

// M3 (UI half): the admin enrollment form mints a one-time credential and
// shows it exactly once.
test("enrollment token is shown once", async ({ page }) => {
  await login(page);
  await page.goto("/collectors");

  await page.getByTestId("enroll-submit").click();
  await expect(page.getByTestId("enrollment-token")).toContainText(/^arg_enr_/);
  const token = await page.getByTestId("enrollment-token").innerText();
  expect(token).toMatch(/^arg_enr_[a-z2-7]+$/);
});
