const { test, expect } = require("@playwright/test")

const BASE_URL = process.env.TARGET_URL || process.env.BASE_URL || "https://example.com"
const enforceSecurityHeaders = BASE_URL !== "https://example.com"

const normalizeHeaders = (headers = {}) =>
  Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [
      key.toLowerCase(),
      Array.isArray(value) ? value.join(", ") : value,
    ])
  )

test.describe("SSL posture", () => {
  test("homepage is reachable over HTTPS", async ({ page, baseURL }) => {
    test.skip(!baseURL, "baseURL is not configured.")

    const response = await page.goto("/")
    expect(response, "navigation failed").toBeTruthy()
    expect(response.ok(), "non-2xx response").toBeTruthy()

    const current = new URL(page.url())
    expect(current.protocol).toBe("https:")
  })

  test("security headers are present", async ({ request, baseURL }) => {
    test.skip(
      !baseURL || !enforceSecurityHeaders,
      "Set TARGET_URL to your host to enforce security headers."
    )

    const response = await request.get(baseURL, { failOnStatusCode: false })
    expect(response.status(), "target did not return success").toBeLessThan(400)

    const headers = normalizeHeaders(response.headers())
    expect.soft(headers["strict-transport-security"]).toMatch(/max-age=/i)
    expect.soft(headers["x-content-type-options"]).toMatch(/nosniff/i)
    expect.soft(headers["x-frame-options"]).toMatch(/(deny|sameorigin)/i)
    expect.soft(headers["content-security-policy"]).toBeTruthy()
    expect.soft(headers["referrer-policy"]).toBeTruthy()
  })
})
