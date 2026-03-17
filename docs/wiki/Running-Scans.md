# Running Scans

---

## Starting a Scan

1. Navigate to **Scans** in the sidebar
2. Click **New Scan**
3. Fill in the scan form:

| Field | Required | Description |
|---|---|---|
| Target URL | Yes | Base URL of the API to scan (e.g. `https://api.example.com`) |
| OpenAPI Spec URL | No | URL to the OpenAPI/Swagger JSON or YAML spec |
| Auth Token | No | Bearer token for authenticated endpoints |
| Additional Config | No | JSON object with per-rule configuration |

4. Click **Start Scan**

Via the API:
```bash
curl -X POST http://localhost:8000/api/v1/scans/ \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://api.example.com",
    "spec_url": "https://api.example.com/openapi.json",
    "config": {
      "auth_token": "Bearer eyJhbGc..."
    }
  }'
```

---

## Scan Lifecycle

```
pending → running → completed
                 ↘ failed
```

| Status | Description |
|---|---|
| `pending` | Scan queued, not yet started |
| `running` | Rules executing against the target |
| `completed` | All rules finished; results available |
| `failed` | Scan aborted due to an unrecoverable error |

The scan detail page auto-refreshes every 5 seconds while a scan is running.

---

## The 17 Security Rules

| Rule ID | OWASP Category | What It Tests |
|---|---|---|
| `BOLA-IDOR` | API1 — BOLA | Object-level authorization by manipulating IDs |
| `AUTH-MISSING` | API2 — Broken Auth | Endpoints accessible without authentication |
| `JWT-001` | API2 — Broken Auth | JWT alg:none, weak secrets, expired tokens |
| `SENSITIVE-DATA` | API3 — Sensitive Data | PII, API keys, credentials in responses |
| `MASS-ASSIGN-001` | API3 — Sensitive Data | Unprotected writable fields |
| `RATE-LIMIT` | API4 — Resource & Rate Limiting | Missing or bypassable rate limiting |
| `FUZZING` | API4 — Resource & Rate Limiting | Parameter fuzzing for crashes/errors |
| `BFLA-001` | API5 — Function Auth | Function-level authorization bypass |
| `BUSINESS-LOGIC` | API6 — Business Logic | Payment/order flow logic bypasses |
| `SSRF-001` | API7 — SSRF | Server-Side Request Forgery payloads |
| `SEC-HEADERS` | API8 — Security Misconfiguration | Missing/weak security headers |
| `CORS-001` | API8 — Security Misconfiguration | Wildcard or arbitrary origin reflection |
| `HTML-INJ-001` | API8 — Security Misconfiguration | HTML/script injection in responses |
| `PATH-TRAV-001` | API8 — Security Misconfiguration | Directory traversal patterns |
| `OPENAPI-CONTRACT` | API9 — Improper Inventory | OpenAPI spec compliance violations |
| `INJECTION-BASIC` | API10 — Unsafe Consumption | SQL/code injection probes |
| `DESERIALIZATION` | API10 — Unsafe Consumption | Unsafe deserialization indicators |

---

## Providing an OpenAPI Spec

Providing a spec URL significantly improves scan coverage:
- Endpoints are parsed from the spec rather than discovered heuristically
- Request/response schema validation is performed
- The `OPENAPI-CONTRACT` rule can flag deviations

Supported formats: **OpenAPI 3.x** (JSON or YAML).

---

## Scan Configuration Options

Pass a JSON `config` object when creating a scan:

```json
{
  "auth_token": "Bearer eyJhbGciOiJIUzI1NiJ9...",
  "custom_headers": {
    "X-API-Key": "your-api-key"
  }
}
```

---

## Cancelling / Deleting a Scan

- Scans cannot be cancelled mid-run in the current version
- Completed or failed scans can be deleted from the Scans list (admin only)
