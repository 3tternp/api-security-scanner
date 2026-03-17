# Security Architecture

---

## Authentication

### JWT Tokens

- Algorithm: **HS256** (HMAC-SHA256)
- Secret: loaded from `SECRET_KEY` env var — never hardcoded
- Lifetime: 8 hours (configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`)
- Claims: `sub` (email), `exp` (expiry), `iat` (issued at)
- Tokens are stateless — no server-side session storage

### Token Storage (Frontend)

- Stored in `localStorage`
- Automatically attached to every API request via Axios interceptor
- Cleared on 401/403 response → redirects to login

---

## Password Storage

Passwords are hashed with **bcrypt** (work factor auto-selected by passlib):

- Salted per-user — rainbow table attacks are impossible
- Bcrypt 4.2.1 with passlib 1.7.4
- Plain-text passwords are never logged or stored

### Password Requirements

| Rule | Value |
|---|---|
| Minimum length | 12 characters |
| Uppercase | Required |
| Lowercase | Required |
| Digit | Required |
| Special character | Required |

Enforced at: admin setup, user creation, `ADMIN_PASSWORD` env var bootstrap.

---

## Account Lockout

| Setting | Default |
|---|---|
| Attempts before lockout | 5 |
| Lockout duration | 15 minutes |

On lockout: `locked_until` timestamp is written to the database. Subsequent login attempts return HTTP 429 with the remaining wait time. The counter resets to 0 on a successful login.

---

## Authorization

Role-based access control (RBAC) with two roles:

| Role | Can Do |
|---|---|
| `admin` | All operations including user management and scan deletion |
| `auditor` | Read scans, read findings, change finding status, export reports |

Enforced via FastAPI `Depends()` chains — unauthenticated or unauthorized requests receive appropriate HTTP errors (401/403).

User enumeration is prevented: login returns a generic `"Incorrect email or password"` regardless of whether the email exists.

---

## Security Headers

Every API response includes:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` |
| `Cache-Control` | `no-store` |

The `Server` header is stripped to remove version fingerprinting.

---

## Database Security

- **PostgreSQL 18** — no SQLite (avoids file-based access risks)
- Credentials passed via environment variables — never hardcoded
- Connection pool with `pool_pre_ping` to detect stale connections
- SQLAlchemy ORM — parameterized queries prevent SQL injection
- Columns: `hashed_password` only (never plain-text)

---

## Container Security

- Backend and frontend containers run as a **non-root** system user (`appuser`)
- `.dockerignore` prevents `.env` files and dev databases from being baked into images
- Backend image built from `python:3.13-slim` (minimal attack surface)
- Frontend served via `nginx:1.27-alpine` (static files only — no Node in production)

---

## TLS

- Nginx terminates TLS (TLS 1.2 / 1.3 only, strong ciphers)
- Backend and frontend communicate over the internal Docker network (plaintext is acceptable inside the Docker network)
- Generate self-signed certs for local testing; use Let's Encrypt or your PKI for production

---

## Production Hardening Checklist

- [ ] Set a unique 64-char `SECRET_KEY`
- [ ] Use a strong `POSTGRES_PASSWORD`
- [ ] Remove `ADMIN_EMAIL` / `ADMIN_PASSWORD` after first boot
- [ ] Set `ENVIRONMENT=production` (disables `/docs` and `/redoc`)
- [ ] Configure `BACKEND_CORS_ORIGINS` to your exact domain(s) only
- [ ] Use a proper TLS certificate (not self-signed)
- [ ] Restrict port 8000 and 5432 to internal network only
- [ ] Enable PostgreSQL pg_audit extension for database-level audit logging
- [ ] Set up automated backups for the `postgres_data` Docker volume
- [ ] Rotate `SECRET_KEY` periodically (requires all users to re-login)
