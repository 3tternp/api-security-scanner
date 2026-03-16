"""Seed the database with generic demo data for screenshot capture."""
import sqlite3
import datetime

DB = r'C:\Users\ASUS\Documents\Github\API vulnerability scanner\.claude\worktrees\mystifying-knuth\backend\sql_app_v2.db'
conn = sqlite3.connect(DB)
cur = conn.cursor()

# Clear existing scan data
cur.execute("DELETE FROM scan_results")
cur.execute("DELETE FROM scan_jobs")

# ── Insert 2 completed scan jobs ──────────────────────────────────────────────
now = datetime.datetime.now(datetime.UTC)
jobs = [
    (1, 'https://demo-api.example.com', 'https://demo-api.example.com/openapi.json', 'completed',
     (now - datetime.timedelta(days=1)).isoformat(), now.isoformat(), '{}'),
    (2, 'https://petstore3.swagger.io/api/v3', 'https://petstore3.swagger.io/api/v3/openapi.json', 'completed',
     (now - datetime.timedelta(days=3)).isoformat(), (now - datetime.timedelta(days=3) + datetime.timedelta(minutes=12)).isoformat(), '{}'),
]
cur.executemany(
    "INSERT INTO scan_jobs (id, target_url, spec_url, status, created_at, completed_at, config) VALUES (?,?,?,?,?,?,?)",
    jobs
)

# ── Helper ────────────────────────────────────────────────────────────────────
def ins(cur, job_id, rule_id, severity, description, endpoint, method, impact, remediation, poc, status="Open", cvss=""):
    cur.execute(
        "INSERT INTO scan_results (job_id, rule_id, severity, description, endpoint, method, impact, remediation, proof_of_concept, status, cvss_score) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (job_id, rule_id, severity, description, endpoint, method, impact, remediation, poc, status, cvss)
    )

# ── Findings for Scan #1 (demo-api.example.com) ───────────────────────────────
endpoints = [
    'users','orders','payments','invoices','accounts','transactions','products',
    'customers','subscriptions','reports','webhooks','tokens','sessions','roles',
    'permissions','audit-logs','exports','imports','notifications','preferences',
    'addresses','cards','transfers','refunds','disputes','statements','limits',
    'settings','profiles','organizations'
]
methods = ['POST', 'GET', 'PUT', 'DELETE', 'PATCH']

for i, ep in enumerate(endpoints):
    ins(cur, 1, "OPENAPI-CONTRACT", "Critical",
        f"Missing authentication on /{ep} — no security scheme defined in OpenAPI contract.",
        f"/api/v1/{ep}", methods[i % 5],
        "Unauthenticated callers can access or modify sensitive resources.",
        "Add BearerAuth security requirement to this operation in the OpenAPI spec and enforce it server-side.",
        f"curl -X {methods[i % 5]} https://demo-api.example.com/api/v1/{ep}\n# Returns 200 OK without Authorization header",
        cvss="9.8")

ins(cur, 1, "SEC-HEADERS", "Low",
    "Missing security headers: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy.",
    "/", "GET",
    "Allows clickjacking, MIME sniffing, and XSS attacks.",
    "Add X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy: default-src 'self' to all responses.",
    "curl -I https://demo-api.example.com/",
    cvss="4.3")

ins(cur, 1, "RATE-LIMIT", "High",
    "No rate limiting on authentication endpoint — brute-force attacks are possible.",
    "/api/v1/auth/login", "POST",
    "Enables credential brute-forcing and account takeover at scale.",
    "Implement rate limiting: max 5 failed attempts per IP per 15 minutes with exponential backoff and account lockout.",
    "for i in $(seq 1 200); do\n  curl -X POST https://demo-api.example.com/api/v1/auth/login \\\n    -d '{\"email\":\"admin@example.com\",\"password\":\"guess'$i'\"}'\ndone\n# No 429 responses observed",
    cvss="7.5")

ins(cur, 1, "BOLA-IDOR", "Critical",
    "BOLA/IDOR: incrementing the user ID parameter returns other users' data without ownership check.",
    "/api/v1/users/{id}", "GET",
    "Full exposure of other users' profile and account data.",
    "Validate that the authenticated user owns the requested resource. Return 403 Forbidden if ownership check fails.",
    "curl -H 'Authorization: Bearer <token>' https://demo-api.example.com/api/v1/users/1001\ncurl -H 'Authorization: Bearer <token>' https://demo-api.example.com/api/v1/users/1002\n# Returns a different user's data — ownership not enforced",
    cvss="9.1")

ins(cur, 1, "AUTH-MISSING", "Critical",
    "Administrative endpoint accessible without any authentication.",
    "/api/v1/admin/users/{id}", "DELETE",
    "Any unauthenticated caller can permanently delete arbitrary user accounts.",
    "Require a valid JWT with an admin role claim. Return 401 for missing tokens and 403 for insufficient privileges.",
    "curl -X DELETE https://demo-api.example.com/api/v1/admin/users/42\n# Returns HTTP 200 OK — account deleted without credentials",
    cvss="9.8")

ins(cur, 1, "MASS-ASSIGN-001", "High",
    "Mass assignment vulnerability: client-supplied role field accepted during user update.",
    "/api/v1/users/{id}", "PUT",
    "Any authenticated user can escalate their own role to admin.",
    "Whitelist only the fields the caller is allowed to update. Never bind request body directly to ORM models.",
    'curl -X PUT https://demo-api.example.com/api/v1/users/99 \\\n  -H "Authorization: Bearer <token>" \\\n  -d \'{"name":"Alice","role":"admin"}\'\n# Returns 200 — role updated to admin',
    cvss="8.8")

ins(cur, 1, "JWT-001", "High",
    "JWT accepted with 'none' algorithm — signature verification bypassed.",
    "/api/v1/auth/verify", "POST",
    "Attacker can forge arbitrary JWT claims without a valid signing key.",
    "Reject tokens with 'none' or unexpected algorithm values. Explicitly allowlist accepted algorithms (e.g. RS256, HS256).",
    "# Craft a JWT with alg=none:\nheader=$(echo -n '{\"alg\":\"none\",\"typ\":\"JWT\"}' | base64)\npayload=$(echo -n '{\"sub\":\"1\",\"role\":\"admin\"}' | base64)\ncurl -H \"Authorization: Bearer $header.$payload.\" https://demo-api.example.com/api/v1/admin/users\n# Returns 200 — admin access granted",
    cvss="9.0")

# ── Findings for Scan #2 (petstore3.swagger.io) ───────────────────────────────
ins(cur, 2, "SEC-HEADERS", "Low",
    "HSTS header absent — protocol downgrade attack is possible.",
    "/api/v3/pet", "GET",
    "Allows man-in-the-middle protocol downgrade to plain HTTP.",
    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses.",
    "curl -I https://petstore3.swagger.io/api/v3/pet\n# No Strict-Transport-Security header in response",
    cvss="4.0")

ins(cur, 2, "CORS-001", "High",
    "Overly permissive CORS policy — Access-Control-Allow-Origin: * allows any origin to read responses.",
    "/api/v3/store/inventory", "GET",
    "Cross-origin data leakage to any attacker-controlled website.",
    "Restrict CORS to known, trusted origins. Never use wildcard (*) on authenticated or sensitive endpoints.",
    "curl -H 'Origin: https://evil.example.com' https://petstore3.swagger.io/api/v3/store/inventory\n# Response: Access-Control-Allow-Origin: *",
    cvss="6.5")

ins(cur, 2, "SENSITIVE-DATA", "High",
    "PII exposed in response body — email, phone, and password hash returned without field-level access control.",
    "/api/v3/user/{username}", "GET",
    "Exposure of personally identifiable information and credential hashes to authenticated clients.",
    "Apply response field filtering based on the caller's role. Never return password hashes or sensitive tokens in API responses.",
    'curl https://petstore3.swagger.io/api/v3/user/testuser\n# Response body includes:\n# { "email": "test@example.com", "phone": "555-0100", "password": "$2b$12$abc..." }',
    cvss="7.5")

conn.commit()

# Verify
cur.execute("SELECT COUNT(*) FROM scan_jobs")
print(f"Scan jobs: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM scan_results")
print(f"Scan results: {cur.fetchone()[0]}")
cur.execute("SELECT id, status, target_url FROM scan_jobs")
for row in cur.fetchall():
    print(f"  Scan #{row[0]}: {row[1]} — {row[2]}")
conn.close()
print("Done!")
