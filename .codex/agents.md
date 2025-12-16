# AGENTS.md - Agents Operating Manual

YOU ARE AUTHORIZED TO AUTOMATICALLY, UPDATE, EXPAND, AND MAINTAIN THIS DOCUMENT CONTINUOUSLY IN REALTIME, WITHOUT ASKING ME.

## Instructions for Coding

Mindset of a 15+ yr full-stack, AI-enabled app dev.

### Core behaviors

_Critically, consistently, and before every coding attempt, ALWAYS reread agents.md instructions._

**Prepare to continue** dev by:

1. rescanning repo,
2. identifying all changed files in repo,
3. fully purging your working memory,
4. refreshing repo working memory with current canonical repo state,
5. verifying repo working memory state is equal to canonical repo state, and
6. performing All per agents.md rules.

#### MANDATORY

> **_BEFORE_** you (codex) evaluates any code to suggest edits and/or provide unified differential patches, you MUST ALWAYS, WITHOUT EXCEPTION:

1. RESCAN REPO FOR CHANGED CANONICAL files,

2. COMPLETELY FLUSH working memory (head),

3. REFRESH working memory with freshly updated canonical state.

4. ALWAYS Cautious, incremental, validation-first problem solving.

5. **No assumptions**; clarify missing context with focused questions.

6. **Recency obsession**: verify versions, syntax, deprecations, and compatibility online, **from today to your (the GPT model’s) info cutoff date** before advising.

7. **Defer to current sources** when legacy conflicts appear; note impacts.

8. **Focused-diff edits**; change only what’s required; avoid over-engineering.

9. Break down large problems into multiple simple, specific, detailed steps when creating Implementation steps.

10. Dont '**reinvent the wheel**' or **modify existing code** unless requested or absolutely necessary to fulfill this documents instructions.

11. Look for ways to implement changes by using existing code first; then, if not possible, create new code solutions.

12. Work slowly and go step-by-step to make compact, requirement fulfilling, working, elegant, best-practices code.

### Delivery

- Provide complete, executable code when asked (POIA); never abridge.

- Mention the filename + full path for every file you touch in your summary.

- **Prefer focused diffs**: annotate notable CSS/JS changes with succinct inline comments when the intent is not obvious.

- **Keep prose purposeful**; use short checklists (3+ items) followed by focused steps when outlining work.

- Close each major edit or suggestion with a one-line **validation of the expected outcome**.

- **Never reprint edits** that have already been provided unless additional clarification is explicitly required (POIA).

- **Unified Diff Format forever**: include an aggregated unified diff snippet (e.g., from `git diff --unified`) for every change set, even when full files are provided elsewhere in the response.

### Scope & safety rails

- Stay strictly within the user’s scope. Don’t modify or mention unrelated code or files.

- Discuss material changes before implementation when risk/impact is high; otherwise proceed with documented intent.

- If anything is unclear or risky, pause and ask.

### Memory & continuity

- Track and recall project versions, toolchains, linters, build targets, browser support, and prior decisions. Reuse working patterns; avoid past mistakes.

### Detailed App Description (log)

- Record Detailed App Description sequentially, by subroutine, below and update details in realtime of every subsequent change, update, addition, subtraction, and deprecation.

### Standard Operating Procedures (SOP) (log)

- Record Standard Operating Procedures below and apply them in all subsequent sessions.

### Lessons Learned

- Record lessons learned (successes/failures) below and apply them in all subsequent sessions.

### Detailed App Description

- Baseline: Bash utility `acme_dns_manual_nginx_swap.sh` drives manual DNS ACME renewals with Nginx config swapping, public/authoritative TXT validation, and trap-based rollback.
- Tooling: Node 20.19.4 runtime (`.nvmrc` / `.node-version`) with ESLint 9 flat config (`eslint.config.mjs`) and Prettier formatting (`.prettierrc`).
- Testing: Playwright harness (`playwright.config.js`, `tests/ssl-health.spec.js`) asserts HTTPS reachability and expected security headers against `TARGET_URL`/`BASE_URL`.
- Docs/IDE: VS Code settings tuned for Prettier + ESLint; MCP servers configured in `.vscode/mcp.json` (GitHub, Playwright, Codacy, Context7, Serena, Snyk, JFrog) and require tokens/inputs.

### Standard Operating Procedures (SOP)

- Use Node 20.19.4 via `nvm use` before any npm scripts; `.npmrc` enforces engine-strict.
- Install deps with `npm install` then `npm run pw:install` to fetch browsers; run `npm run check` for lint+format+tests.
- Configure Playwright targets through `TARGET_URL` or `BASE_URL` in `.env`; security-header test skips unless pointing at a non-default host.
- Keep secrets in `.env` (git-ignored); do not commit node_modules or Playwright artifacts (`playwright-report/`, `test-results/`).

### Lessons Learned (log)

- Playwright install reports missing system libraries; resolve per installer output or run inside the recommended container image.
- Use `nvm exec 20.19.4 <command>` when scripting to avoid falling back to the system Node 22.x.
