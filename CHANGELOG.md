# Changelog

## Unreleased

### Changed
- Refreshed all README screenshots (`docs/screenshots/`) to match the current no-login UI — dashboard, scans list, scan detail, and findings list. The previous images predated the removal of authentication and no longer matched the app (they showed a login screen and a `/users` page that don't exist anymore).
- `scripts/capture-screenshots.js` rewritten to visit the app's actual routes (`/`, `/scans`, `/scans/:id`) instead of the removed `/login` and `/users` pages.
- `scripts/seed_demo_data.py` no longer hardcodes an absolute, machine-specific database path — it now resolves `backend/app.db` relative to the script's own location.

### Removed
- `scripts/ss/`, a stray, unreferenced duplicate of the screenshot capture script with the same stale `/login` and `/users` routes.

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

### Changed
- Nginx `reverse-proxy` is now optional and only starts when the Compose profile `tls` is enabled.
