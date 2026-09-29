import { defineConfig } from "@playwright/test";

// Runs against a locally started web app (npm run build && npm run start)
// with the dev compose stack (API on :8080) running.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:3000",
  },
});
