# Changelog

## Unreleased

### Fixed
- Backend security headers middleware no longer raises an exception when removing the `Server` header.
- Docker backend healthcheck no longer depends on `curl` being present in the image.
- Frontend Docker image installs the dependencies required to run the Vite dev server and avoids permission issues when installing packages.

### Changed
- Nginx `reverse-proxy` is now optional and only starts when the Compose profile `tls` is enabled.
