# First-Run Setup

The scanner has **no default credentials**. On the very first boot, an administrator account must be created. There are two ways to do this.

---

## Method 1 — Environment Variables (Automated / CI)

Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in your `.env` before starting the stack. The `prestart.sh` script detects that no admin exists and creates one automatically.

```env
ADMIN_EMAIL=admin@yourcompany.com
ADMIN_PASSWORD=MyStr0ng#AdminPass!
```

Then start the stack:
```bash
docker compose up -d
```

Watch the backend logs to confirm:
```bash
docker compose logs backend | grep "admin"
# INFO: Initial admin account created: admin@yourcompany.com
```

> **Security:** After confirming the admin was created, remove `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `.env` and restart:
> ```bash
> docker compose restart backend
> ```

---

## Method 2 — Setup Wizard (Interactive / Web UI)

If `ADMIN_EMAIL`/`ADMIN_PASSWORD` are not set, the backend logs a warning and the frontend shows the **Setup** page automatically.

1. Open `http://localhost` (or `https://localhost`)
2. The app detects no admin exists and redirects to `/setup`
3. Fill in:
   - Full name (optional)
   - Admin email address
   - Password (must meet strength requirements)
   - Confirm password
4. Click **Create Admin Account**
5. You are redirected to the Login page

![Setup page screenshot](../screenshots/setup-page.png)

### Password Requirements

The live strength meter validates:

| Rule | Requirement |
|---|---|
| Length | At least 12 characters |
| Uppercase | At least one uppercase letter (A–Z) |
| Lowercase | At least one lowercase letter (a–z) |
| Digit | At least one number (0–9) |
| Special character | At least one of `!@#$%^&*()-_=+[]{}` etc. |

---

## Method 3 — API Directly

```bash
# Check if setup is needed
curl http://localhost:8000/api/v1/setup/status
# {"setup_required": true}

# Create the admin
curl -X POST http://localhost:8000/api/v1/setup/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourcompany.com",
    "password": "MyStr0ng#AdminPass!",
    "full_name": "System Administrator"
  }'
# {"message": "Admin account created successfully.", "email": "admin@yourcompany.com"}
```

---

## After Setup

Once any admin account exists:
- The `/setup` endpoint permanently returns **403 Forbidden**
- The `/setup` UI page is no longer accessible (redirects to `/login`)
- New users can only be created by an authenticated admin via the Users page
