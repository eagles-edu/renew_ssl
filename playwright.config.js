const path = require("path")
const { defineConfig, devices } = require("@playwright/test")
require("dotenv").config({ path: path.resolve(__dirname, ".env"), override: true, quiet: true })

const BASE_URL = process.env.TARGET_URL || process.env.BASE_URL || "https://example.com"
const isCI = !!process.env.CI
const includeWebkit = process.env.PLAYWRIGHT_ENABLE_WEBKIT === "1"
const headless = process.env.HEADLESS !== "false"

module.exports = defineConfig({
  testDir: "./tests",
  timeout: 45_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: true,
  forbidOnly: isCI,
  retries: isCI ? 2 : 0,
  workers: isCI ? 2 : undefined,
  reporter: isCI
    ? [
        ["github"],
        ["junit", { outputFile: "test-results/results.xml" }],
        ["html", { open: "never" }],
      ]
    : [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: BASE_URL,
    headless,
    viewport: { width: 1280, height: 720 },
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: "retain-on-failure",
    video: "retain-on-failure",
    screenshot: "only-on-failure",
    ignoreHTTPSErrors: false,
    acceptDownloads: false,
    permissions: [],
    bypassCSP: false,
    locale: "en-US",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], baseURL: BASE_URL } },
    { name: "firefox", use: { ...devices["Desktop Firefox"], baseURL: BASE_URL } },
    ...(includeWebkit
      ? [{ name: "webkit", use: { ...devices["Desktop Safari"], baseURL: BASE_URL } }]
      : []),
  ],
  outputDir: "test-results",
  metadata: {
    target: BASE_URL,
  },
})
