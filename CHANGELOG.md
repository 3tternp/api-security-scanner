# Changelog

## Unreleased

### Changed
- **Full tech stack upgrade** — runtimes, containers, and dependencies bumped to current stable releases (verified against PyPI/npm/Docker Hub registries, not just incremented by feel):
  - **Runtimes**: Python 3.13 → 3.14 (backend Dockerfile + both CI pipelines), Node 22 → 24 LTS (frontend Dockerfile + both CI pipelines). CI previously pinned Python 3.11 / Node 18 — far behind what the Dockerfiles actually shipped; both now match.
  - **Containers**: `nginx:1.27-alpine` → `nginx:1.31-alpine`; removed the obsolete Compose `version: '3.8'` key (ignored by current Compose and a documented no-op). `postgres:18-alpine` was already current.
  - **Backend**: `uvicorn` 0.37 → 0.53, `alembic` 1.19 → 1.20, `psycopg2-binary` 2.9.12 → 2.9.13, `pytest` 8.3 → 9.1, `pytest-asyncio` 0.25 → 1.4 (verified cp314 wheels exist for the C-extension packages before pinning Python 3.14). `fastapi`, `pydantic`, `sqlalchemy`, `httpx` were already on current stable and left unchanged.
  - **Frontend**: `react`/`react-dom` → 19.3, `vite` 7 → 8 (now Rolldown-powered) with matching `@vitejs/plugin-react` 5 → 6, `eslint` 9 → 10 with `@eslint/js`/`globals` bumped to match, `lucide-react` 0.563 → 1.45, `typescript` 5.9 → 6.0.3. **Not** bumped to `typescript` 7 (the new Go-native compiler) — `typescript-eslint` 8.70 (current latest) declares a peer range of `>=4.8.4 <6.1.0` and would break; revisit once `typescript-eslint` adds 7.x support.
  - **Tailwind CSS 3 → 4**: migrated `postcss.config.js` to `@tailwindcss/postcss`, `src/index.css` from `@tailwind base/components/utilities` to `@import "tailwindcss"` with explicit `@source` globs, and removed `tailwind.config.js` and the now-redundant `autoprefixer` (Tailwind v4's Lightning CSS handles vendor prefixing). No visual or behavioral change — verified against every page in the browser.
  - GitHub Actions bumped to `actions/checkout@v7`, `actions/setup-python@v7`, `actions/setup-node@v7`.
  - `nginx.conf` modernized: HTTP/2 enabled via the current `http2 on;` directive (the old `listen ... http2` combined form nginx deprecated), plus `ssl_session_cache`/`ssl_session_timeout` and `ssl_prefer_server_ciphers off` (current TLS best practice — client cipher order is preferred over a server-dictated one).
  - `backend/app/main.py` moved off the deprecated `@app.on_event("startup")` to a `lifespan` context manager; `backend/app/schemas/scan.py` moved off the deprecated class-based `class Config:` to `model_config = ConfigDict(...)` — both were flagged by the upgraded FastAPI/Pydantic as due for removal.
  - README badges and the Tech Stack table updated to match (also corrected a stale "React Router v6" — the project has been on v7 since before this change).

### Added
- Automated scan checks:
  - TLS enforcement (HTTP vs HTTPS / redirects)
  - Cookie security flags (HttpOnly / Secure / SameSite)
  - Technology fingerprinting headers (e.g., `Server`, `X-Powered-By`)

### Fixed
- Backend security headers middleware no longer raises an exception when removing the `Server` header.
- Docker backend healthcheck no longer depends on `curl` being present in the image.
- Frontend Docker image installs the dependencies required to run the Vite dev server and avoids permission issues when installing packages.
- Scan results API now supports non-dict `details` payloads produced by some rules (prevents 500 when viewing results).
- Frontend login flow no longer gets stuck in a redirect loop on failed login and shows the backend error detail when available.
- Nginx `reverse-proxy` is now optional and only starts when the Compose profile `tls` is enabled.
