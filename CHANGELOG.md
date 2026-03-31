# Changelog

## Unreleased

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
