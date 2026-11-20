import { defineConfig } from "@playwright/test";
import { PORT } from "./harness";

export default defineConfig({
  testDir: ".",
  outputDir: "../../e2e-report/test-output",
  globalSetup: "./global-setup.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  forbidOnly: !!process.env.CI,
  reporter: [["list"], ["./reporter.ts"]],
  use: {
    baseURL: `https://127.0.0.1:${PORT}`,
    // The server uses its own CA; tests check its pin separately.
    ignoreHTTPSErrors: true,
    trace: "off",
    screenshot: "only-on-failure",
    viewport: { width: 1280, height: 860 },
  },
  projects: [
    { name: "flow", testMatch: "flow.spec.ts" },
    {
      name: "security",
      testMatch: "security.spec.ts",
      dependencies: ["flow"],
    },
  ],
});
