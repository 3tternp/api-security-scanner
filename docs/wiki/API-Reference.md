# API Reference

Base URL: `http://localhost:8000/api/v1`

All endpoints except `/login/access-token`, `/setup/status`, and `POST /setup/` require a Bearer token in the `Authorization` header.

> **Interactive docs:** Set `ENVIRONMENT=development` in `.env` and visit `http://localhost:8000/docs` for the full Swagger UI.

---

## Authentication

### `POST /login/access-token`

Obtain a JWT access token.

**Request** (form data):
```
username=admin@example.com&password=MyPassword!
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer"
}
```

**Errors:**
| Code | Reason |
|---|---|
| 401 | Incorrect email or password |
| 429 | Account locked (too many failed attempts) |
| 403 | Account disabled |

---

## Setup

### `GET /setup/status`

Returns whether initial setup is required.

```json
{"setup_required": true}
```

### `POST /setup/`

Create the initial admin account. Returns 403 once any admin exists.

**Request:**
```json
{
  "email": "admin@company.com",
  "password": "MyStr0ng#Pass!",
  "full_name": "System Admin"
}
```

**Response (201):**
```json
{"message": "Admin account created successfully.", "email": "admin@company.com"}
```

---

## Users

All require `admin` role.

### `GET /users/`
List all users.

### `GET /users/me`
Return the currently authenticated user (any role).

### `POST /users/`
Create a new user.

```json
{
  "email": "auditor@company.com",
  "password": "AuditP@ss#99",
  "role": "auditor",
  "full_name": "Jane Smith"
}
```

### `DELETE /users/{id}`
Delete a user. Cannot delete your own account.

---

## Scans

### `GET /scans/`
List all scans (paginated). Returns lightweight summary including `finding_count`.

Query params: `skip` (default 0), `limit` (default 100)

### `POST /scans/`
Create and start a new scan.

```json
{
  "target_url": "https://api.example.com",
  "spec_url": "https://api.example.com/openapi.json",
  "config": {
    "auth_token": "Bearer eyJ..."
  }
}
```

### `GET /scans/{id}`
Get full scan details including all results.

### `DELETE /scans/{id}`
Delete a scan and its results. Admin only.

### `GET /scans/{id}/results`
Get paginated finding results for a scan.

Query params: `skip`, `limit`, `severity` (filter), `status` (filter)

### `PATCH /scans/{id}/results/{result_id}`
Update finding status.

```json
{"status": "Fixed"}
```

Valid statuses: `Open`, `In Progress`, `Fixed`, `Accepted Risk`

### `GET /scans/{id}/report/docx`
Download the DOCX report. Returns binary file.

### `GET /scans/stats/dashboard`
Get dashboard statistics.

```json
{
  "total_scans": 42,
  "completed_scans": 38,
  "running_scans": 1,
  "total_findings": 156,
  "open_findings": 89,
  "critical_findings": 5,
  "high_findings": 23,
  "medium_findings": 61,
  "low_findings": 67,
  "info_findings": 0,
  "findings_by_rule": {"BOLA-IDOR": 12, ...},
  "owasp_counts": {"API1": 12, "API2": 8, ...}
}
```

---

## Error Format

All errors follow this structure:

```json
{
  "detail": "Human-readable error message"
}
```

| HTTP Code | Meaning |
|---|---|
| 400 | Bad request / validation error |
| 401 | Unauthenticated |
| 403 | Forbidden (wrong role or setup complete) |
| 404 | Resource not found |
| 409 | Conflict (duplicate email) |
| 422 | Unprocessable entity (validation failed) |
| 429 | Too many requests (account locked) |
| 500 | Internal server error |
