# User Management

Only users with the `admin` role can create, view, or delete other users.

---

## Roles

| Role | Permissions |
|---|---|
| `admin` | Full access: create/delete users, run scans, view all results, export reports |
| `auditor` | Read-only: view scans and results, export reports. Cannot manage users or delete scans |

---

## Creating a User

1. Log in as an admin
2. Navigate to **Users** in the sidebar
3. Fill in the **Create New User** form:
   - Email address
   - Password (must meet strength policy)
   - Role (`admin` or `auditor`)
4. Click **Create User**

Via the API:
```bash
curl -X POST http://localhost:8000/api/v1/users/ \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "auditor@yourcompany.com",
    "password": "AuditorP@ss#2024",
    "role": "auditor"
  }'
```

---

## Password Policy

All passwords must satisfy:

- Minimum **12 characters**
- At least one **uppercase** letter
- At least one **lowercase** letter
- At least one **digit**
- At least one **special character** (`!@#$%^&*` etc.)

Passwords that fail validation return HTTP 422 with a descriptive error.

---

## Account Lockout

After **5 consecutive failed login attempts**, an account is locked for **15 minutes**.

| Setting | Default | `.env` variable |
|---|---|---|
| Max failed attempts | 5 | `MAX_LOGIN_ATTEMPTS` |
| Lockout duration | 15 minutes | `LOCKOUT_MINUTES` |

During lockout, the login endpoint returns:
```json
{"detail": "Account locked due to too many failed attempts. Try again in 14 minute(s)."}
```

The lockout counter resets automatically on a successful login.

> **Admin note:** There is currently no UI to manually unlock accounts. To unlock via the database:
> ```sql
> UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE email = 'user@example.com';
> ```

---

## Deleting a User

Via the Users page, click the delete icon next to a user.

Via the API:
```bash
curl -X DELETE http://localhost:8000/api/v1/users/42 \
  -H "Authorization: Bearer <your-token>"
```

> Admins cannot delete their own account.

---

## User Audit Fields

Each user record stores:

| Field | Description |
|---|---|
| `created_at` | When the account was created |
| `last_login` | Timestamp of the most recent successful login |
| `failed_login_attempts` | Current count of consecutive failures |
| `locked_until` | Null unless account is locked |
