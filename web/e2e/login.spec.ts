import { test, expect } from "@playwright/test";

// AC-12 (UI half): login issues a session, the shell renders the org, logout
// revokes it and returns to the login page.
test("login, dashboard, logout", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);

  await page.getByTestId("login-org").fill("dev");
  await page.getByTestId("login-email").fill("admin@dev.local");
  await page
    .getByTestId("login-password")
    .fill(process.env.ARGUS_DEV_ADMIN_PASSWORD ?? "dev-admin-change-me");
  await page.getByTestId("login-submit").click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByTestId("org-name")).toHaveText("Dev Org");
  await expect(page.getByTestId("sites-table")).toContainText("HQ");

  await page.getByTestId("logout").click();
  await expect(page).toHaveURL(/\/login$/);

  // After logout the session is revoked: going back re-challenges.
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
});

test("wrong password shows a problem message", async ({ page }) => {
  await page.goto("/login");
  await page.getByTestId("login-org").fill("dev");
  await page.getByTestId("login-email").fill("admin@dev.local");
  await page.getByTestId("login-password").fill("definitely-wrong");
  await page.getByTestId("login-submit").click();
  await expect(page.getByTestId("login-error")).toContainText("incorrect");
});
