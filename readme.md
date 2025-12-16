# renew_ssl

Toolkit for safely renewing SSL certificates via manual DNS validation and verifying the deployed site’s TLS posture.

## What’s here

- `acme_dns_manual_nginx_swap.sh`: Bash workflow that swaps Nginx configs, performs ACME manual DNS challenges, validates TXT records against public/authoritative resolvers, and rolls back safely on failure.
- Playwright harness (`playwright.config.js`, `tests/ssl-health.spec.js`) to assert the target site is reachable over HTTPS and reports expected security headers.
- Lint/format tooling: ESLint 9 flat config (`eslint.config.mjs`) and Prettier config (`.prettierrc`).
- MCP server wiring in `.vscode/mcp.json` for GitHub, Playwright, Codacy, Upstash Context7, Serena, Snyk, and JFrog (tokens required).

## Prereqs

- Node `20.19.4` (`.nvmrc` / `.node-version` are provided). Use `nvm use` before installing.
- npm and local shell access for Playwright browser downloads.

## Setup

1. `nvm use` (or source `~/.nvm/nvm.sh` then `nvm use 20.19.4`)
2. `npm install`
3. `npm run pw:install` (downloads Chromium/Firefox/WebKit for tests)

## Commands

- `npm run lint` / `npm run lint:fix`
- `npm run format` / `npm run format:check`
- `npm test` → Playwright suite; `npm run test:debug` for UI mode; `npm run test:report` to open the HTML report after a run.

## Playwright config

- Set `TARGET_URL` (or `BASE_URL`) in `.env` to point tests at your host. Default is `https://example.com`.
- Security-header assertions are enforced only when `TARGET_URL` is set to a non-default host.
- Reports live in `playwright-report/` (HTML) and `test-results/` (artifacts/traces).

## Notes

- `.env` is intentionally ignored; keep secrets out of git.
- If browsers complain about missing system libraries, install the listed libs (see Playwright install output) or run inside the recommended container image.
