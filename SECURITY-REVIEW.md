# Security Review — rss_ai

**Branch:** `bmsull560-security-audit`
**Scope:** Injection, auth bypass, secrets in code, unsafe dependencies across all services.

## Findings and Fixes

### 1. 🔴 CRITICAL — Hardcoded shared secret in nginx config (FIXED)

**File:** `nginx/conf.d/default.conf` (~line 265)

The real `X-Alt-Shared-Secret` value was committed to source. Anyone with repository
read access could forge authenticated requests to `alt-backend` by setting the header
directly, bypassing auth-hub entirely.

**Fix:** Replaced the literal with an `__AUTH_SHARED_SECRET__` placeholder. The existing
secret-injection chain (`99-inject-secret.sh`, mounted via
`/docker-entrypoint.d`) substitutes the value at container start from
`/run/secrets/auth_shared_secret` (gitignored `./secrets/auth_shared_secret.txt`).

### 2. 🟠 HIGH — Unauthenticated admin endpoints (FIXED)

**File:** `alt-backend/app/rest/scraping_domain_handlers.go` (lines 45–52)

The `/admin` route group (add/delete scraping domains) registered no auth middleware,
unlike every other admin route. Any network-reachable client could mutate scraping
configuration.

**Fix:** Created `middleware_custom.NewAuthMiddleware(logger.Logger, cfg.Auth.SharedSecret, cfg)`
and applied `.RequireAuth()` to the group, matching the pattern used elsewhere.

### 3. 🟠 HIGH — SSRF bypass via link-local IPs (FIXED)

**Files:** `alt-backend/app/rest/utils.go`, `alt-backend/app/rest/rest_feeds/utils.go` (lines 111–135)

`IsAllowedURL` relied on `net.IP.IsPrivate()`, which does **not** cover link-local
`169.254.0.0/16`. Feed URLs pointing at cloud metadata endpoints
(e.g. `http://169.254.169.254/...`) passed validation, letting the fetcher retrieve
instance credentials. The check was duplicated in two files; both were vulnerable.

**Fix:** Both copies now also reject `IsLinkLocalUnicast()`, `IsLinkLocalMulticast()`,
and `IsUnspecified()` addresses.

**Residual risk:** DNS rebinding TOCTOU remains — the URL is resolved for the check,
then re-resolved by the fetcher. A complete fix requires a pinned-IP dialer.
A comprehensive (currently unused) `SSRFValidator` exists at
`alt-backend/app/utils/security/ssrf_validator.go`.

### 4. 🟠 HIGH — Unauthenticated LLM service (FIXED)

**Files:** `news-creator/app/main.py` (lines 117–140), `pre-processor/app/config/types.go`,
`pre-processor/app/config/load.go`, `pre-processor/app/driver/summarizer_api.go`,
`pre-processor/app/repository/external_api_repository.go`, `compose.yaml`

news-creator's LLM endpoints (`/api/generate`, `/v1/summary/generate`, `/api/v1/summarize`)
accepted requests with no authentication. Any client that could reach the service could
burn GPU credits or poison generated summaries. pre-processor was the only legitimate
caller and sent no auth header.

**Fix:**
- Added an `X-Service-Token` HTTP middleware in news-creator: constant-time comparison
  (`hmac.compare_digest`), `/health` exempt, fails secure (401 if the secret is unset),
  logs a warning on rejection.
- pre-processor now sends `X-Service-Token` on all news-creator requests (sync + stream)
  and on alt-backend `GetSystemUserID` calls.
- Config gained `ServiceToken` fields with `_FILE` fallback loading
  (`NEWS_CREATOR_SERVICE_TOKEN_FILE`, `ALT_BACKEND_SERVICE_TOKEN_FILE`) so the env var
  and docker secret cannot silently diverge.
- `compose.yaml` mounts the `service_secret` docker secret into pre-processor.

### 5. 🟠 HIGH — Stored XSS via unsanitized `{@html}` (FIXED)

**Files:** `alt-frontend-sv/src/lib/server/sanitize-html.ts` (new),
`alt-frontend-sv/src/routes/api/v1/articles/summary/+server.ts`,
`alt-frontend-sv/src/routes/api/v1/articles/content/+server.ts`

Feed article HTML was rendered through Svelte's `{@html}` without sanitization. A
malicious feed could inject `<script>`, event handlers, or `javascript:` URLs,
executing in the user's session (stored XSS).

**Fix:** Added a dependency-free allowlist sanitizer (`sanitizeArticleHtml`) applied
server-side in both routes. It drops dangerous elements with their content
(script/iframe/object/embed/svg/math/form/...), strips `on*` and `style` attributes,
neutralizes `javascript:`/`vbscript:`/`data:` URLs, removes comments, and escapes
quotes when rebuilding attributes.

**Note:** The legacy `alt-frontend` (Next.js) app has a similar unsanitized
`dangerouslySetInnerHTML` at `src/app/desktop/articles/[id]/page.tsx:62` plus a dead
`/v1/articles/:id` API call — not fixed here (separate app, route doesn't exist).

### 6. 🟡 MEDIUM — Non-constant-time secret comparisons (FIXED)

**Files:** `alt-backend/app/middleware/auth_middleware.go`,
`alt-backend/app/middleware/service_auth_middleware.go`,
`tag-generator/app/auth_service.py`

Shared-secret and service-token comparisons used `==`/`!=`, which short-circuit on the
first differing byte — a timing side channel that can leak secret length and prefix
content byte-by-byte.

**Fix:** Go middleware now uses `subtle.ConstantTimeCompare(...) == 1`; the Python
service uses `hmac.compare_digest`.

### 7. 🟡 MEDIUM — Unauthenticated internal endpoint (FIXED)

**File:** `alt-backend/app/rest/internal_handlers.go`

`/v1/internal/system-user` returned the internal system user ID with no
authentication, disclosing internal identity details to any reachable client.

**Fix:** Registered `middleware_custom.NewServiceAuthMiddleware(logger.Logger)` and
applied `.RequireServiceAuth()` to the route (reads `SERVICE_SECRET` env or
`SERVICE_SECRET_FILE`, fails secure if unset).

## Noted, Not Fixed (documented residual risk)

- **Unauthenticated dashboard/SSE/recap/augur routes** — SSE endpoints cannot send
  auth headers (EventSource limitation); a full fix needs nginx cookie-based
  `auth_request`. Design decision required.
- **CSRF middleware disabled** in `alt-backend/app/rest/routes.go` (~line 62) —
  existing design decision, left as-is.
- **Legacy `alt-frontend` (Next.js)** — dead `/v1/articles/:id` API call and
  unsanitized `dangerouslySetInnerHTML` (`src/app/desktop/articles/[id]/page.tsx:62`);
  `searchArticles` interpolates the query unencoded.
- **DNS rebinding TOCTOU** in `IsAllowedURL` (see finding 3).
- **`.env.template` weak dev defaults** (e.g. placeholder secrets) — dev-only.
- **Optional-profile services** (`recap-subworker`, `rag-orchestrator`) have no auth.

## Validation

| Check | Result |
| --- | --- |
| `alt-backend`: `go build ./...` | ✅ pass |
| `alt-backend`: `go test ./rest/... ./middleware/...` | ✅ pass |
| `pre-processor`: `go build ./...` | ✅ pass |
| `pre-processor`: `go test ./config/... ./driver/... ./repository/...` | ✅ pass (config/repository/driver-summarizer) |
| `news-creator`: `pytest` | ✅ 51/57 pass — 6 recap failures are pre-existing (verified by stashing the fix; Pydantic model drift in this environment) |
| `tag-generator`: `pytest tests/unit` | ✅ 55 pass |
| SvelteKit sanitizer | ⚠️ not compiled (`node_modules` absent in `alt-frontend-sv`) |

Pre-existing issues unrelated to this review:
- `pre-processor` `TestDatabaseConfig_SSLValidation` fails on Windows (test writes a
  temp cert to `C:\WINDOWS\` — access denied).
- `news-creator/app/tests/config/test_config.py` had an IndentationError blocking the
  suite (fixed here: one stray space, line 12).
- `bleach` was declared in `news-creator/app/requirements.txt` but missing from the
  local environment (installed for test runs).
