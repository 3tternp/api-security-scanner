# Configuration

All configuration is driven by environment variables loaded from a `.env` file at the repository root. Copy `.env.example` to `.env` before starting the stack.

> **Security rule:** Never commit `.env` to version control. The `.gitignore` already excludes it.

---

## Required Variables

| Variable | Description | Example |
|---|---|---|
| `SECRET_KEY` | JWT signing key — 64-char hex random string | `820f2c66bd9c...` |
| `POSTGRES_USER` | PostgreSQL username | `apiscanner` |
| `POSTGRES_PASSWORD` | PostgreSQL password (strong) | `S3cur3P@ssw0rd!` |

Generate `SECRET_KEY`:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Optional Variables

### Database

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DB` | `apiscanner` | Database name |
| `POSTGRES_SERVER` | `localhost` | DB host (set to `db` in Docker Compose automatically) |
| `POSTGRES_PORT` | `5432` | DB port |

### Application

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `production` | `development` enables `/docs` and `/redoc` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | JWT lifetime (8 hours) |

### CORS

| Variable | Default | Description |
|---|---|---|
| `BACKEND_CORS_ORIGINS` | `["http://localhost:5173"]` | JSON array of allowed origins |

Example for production:
```
BACKEND_CORS_ORIGINS=["https://scanner.yourdomain.com"]
```

### Security Policy

| Variable | Default | Description |
|---|---|---|
| `MAX_LOGIN_ATTEMPTS` | `5` | Failed logins before lockout |
| `LOCKOUT_MINUTES` | `15` | Minutes account stays locked |
| `MIN_PASSWORD_LENGTH` | `12` | Minimum password length |

### First-Run Bootstrap (optional)

Set these **only** for the first boot to auto-create the admin via `prestart.sh`. Remove or unset them afterward.

| Variable | Description |
|---|---|
| `ADMIN_EMAIL` | Email for the initial admin account |
| `ADMIN_PASSWORD` | Password — must meet strength requirements |

Password requirements: ≥12 characters, uppercase, lowercase, digit, special character.

---

## Complete `.env` Example

```env
ENVIRONMENT=production
SECRET_KEY=820f2c66bd9c2d6344d433299d0135df42316a5f99a2b65f4e0980aebdbe8cfa

POSTGRES_USER=apiscanner
POSTGRES_PASSWORD=MyStr0ng#DBPass!
POSTGRES_SERVER=db
POSTGRES_PORT=5432
POSTGRES_DB=apiscanner

BACKEND_CORS_ORIGINS=["https://scanner.yourdomain.com"]
ACCESS_TOKEN_EXPIRE_MINUTES=480

MAX_LOGIN_ATTEMPTS=5
LOCKOUT_MINUTES=15
MIN_PASSWORD_LENGTH=12

# Remove after first boot
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=MyStr0ng#AdminPass!
```

---

## Docker Build Arguments

The frontend image accepts one build argument:

| Argument | Default | Description |
|---|---|---|
| `VITE_API_URL` | `/api/v1` | Backend API base URL baked into the React build |

In production (behind Nginx reverse proxy) the default `/api/v1` is correct — Nginx routes `/api/*` to the backend. Override only if running the frontend separately:

```bash
docker build --build-arg VITE_API_URL=https://api.example.com/api/v1 -t frontend ./frontend
```
