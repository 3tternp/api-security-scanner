"""Seed the database with realistic demo data for screenshot capture."""
import sqlite3
import datetime

DB = r'C:\Users\ASUS\Documents\Github\API vulnerability scanner\.claude\worktrees\mystifying-knuth\backend\sql_app_v2.db'
conn = sqlite3.connect(DB)
cur = conn.cursor()

# Clear existing scan data
cur.execute("DELETE FROM scan_results")
cur.execute("DELETE FROM scan_jobs")

# ── Insert 2 completed scan jobs ──────────────────────────────────────────────
now = datetime.datetime.utcnow()
jobs = [
    (1, 'https://api-vendor.citywalletnp.com/swagger/index.html', None, 'completed',
     (now - datetime.timedelta(days=1)).isoformat(), now.isoformat(), '{}'),
    (2, 'https://petstore3.swagger.io/api/v3', 'https://petstore3.swagger.io/api/v3/openapi.json', 'completed',
     (now - datetime.timedelta(days=3)).isoformat(), (now - datetime.timedelta(days=3, minutes=-12)).isoformat(), '{}'),
]
cur.executemany(
    "INSERT INTO scan_jobs (id, target_url, spec_url, status, created_at, completed_at, config) VALUES (?,?,?,?,?,?,?)",
    jobs
)

# ── Findings for Scan #1 ──────────────────────────────────────────────────────
def ins(cur, job_id, rule_id, severity, description, endpoint, method, impact, remediation, poc, status="Open", cvss=""):
    cur.execute(
        "INSERT INTO scan_results (job_id, rule_id, severity, description, endpoint, method, impact, remediation, proof_of_concept, status, cvss_score) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (job_id, rule_id, severity, description, endpoint, method, impact, remediation, poc, status, cvss)
    )

# ── Findings for Scan #1 ──────────────────────────────────────────────────────
endpoints = [
    'CheckStatus','LoadBankForAggregator','CooperativeCashPayout','GetBalance','Transfer',
    'Withdraw','Deposit','CreateAccount','UpdateProfile','DeleteAccount','ListTransactions','GetStatement',
    'ProcessPayment','ValidateToken','RefreshToken','GetUserInfo','UpdateBalance','CloseAccount',
    'GenerateReport','ExportData','ImportData','BatchProcess','Reconcile','AuditLog',
    'GetLimits','SetLimits','GetFees','CalculateFee','GetExchangeRate','ConvertCurrency'
]
methods = ['POST','GET','PUT','DELETE','PATCH']
for i, ep in enumerate(endpoints[:50]):
    ins(cur, 1, "OPENAPI-CONTRACT", "Critical",
        f"Missing Authentication & Authorization Controls in API Contract — endpoint /api/v1/Cooperative/{ep} has no security scheme defined.",
        f"/api/v1/Cooperative/{ep}", methods[i % 5],
        "Unauthenticated access to sensitive financial operations.",
        "Add BearerAuth security requirement to this operation in the OpenAPI spec and enforce server-side.",
        f"curl -X {methods[i % 5]} https://api-vendor.citywalletnp.com/api/v1/Cooperative/{ep}\n# Returns 200 without Authorization header",
        cvss="9.8")

ins(cur, 1, "SEC-HEADERS", "Low",
    "Missing security headers: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy",
    "/", "GET",
    "Allows clickjacking, MIME sniffing, and XSS attacks.",
    "Add X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy: default-src 'self'",
    "curl -I https://api-vendor.citywalletnp.com/",
    cvss="4.3")

ins(cur, 1, "RATE-LIMIT", "High",
    "No rate limiting detected on authentication endpoint — brute force is possible.",
    "/api/v1/auth/login", "POST",
    "Enables credential brute-forcing and account takeover.",
    "Implement rate limiting: max 5 failed attempts per IP per 15 minutes with exponential backoff.",
    "for i in $(seq 1 100); do curl -X POST https://api-vendor.citywalletnp.com/api/v1/auth/login -d '{\"user\":\"admin\",\"pass\":\"guess\"}'; done",
    cvss="7.5")

ins(cur, 1, "BOLA-IDOR", "Critical",
    "BOLA/IDOR: incrementing account ID returns other users account data without ownership validation.",
    "/api/v1/accounts/{id}", "GET",
    "Full exposure of other users' financial account data.",
    "Validate authenticated user owns the requested resource. Return 403 if not the owner.",
    "curl https://api-vendor.citywalletnp.com/api/v1/accounts/1001\ncurl https://api-vendor.citywalletnp.com/api/v1/accounts/1002 # returns different user data",
    cvss="9.1")

ins(cur, 1, "AUTH-MISSING", "Critical",
    "Administrative endpoint accessible without authentication — any caller can delete user accounts.",
    "/api/v1/admin/users/{id}", "DELETE",
    "Unauthorized deletion of any user account.",
    "Require JWT with admin role. Return 401 for unauthenticated, 403 for insufficient privilege.",
    "curl -X DELETE https://api-vendor.citywalletnp.com/api/v1/admin/users/42\n# Returns 200 OK — user deleted",
    cvss="9.8")

# ── Findings for Scan #2 ─────────────────────────────────────────────────────
ins(cur, 2, "SEC-HEADERS", "Low",
    "HSTS header missing on HTTPS endpoint — protocol downgrade attack possible.",
    "/api/v3/pet", "GET",
    "Allows man-in-the-middle protocol downgrade.",
    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "curl -I https://petstore3.swagger.io/api/v3/pet",
    cvss="4.0")

ins(cur, 2, "CORS-001", "High",
    "Overly permissive CORS: Access-Control-Allow-Origin: * allows any origin to read responses.",
    "/api/v3/store/inventory", "GET",
    "Cross-origin data leakage to attacker-controlled sites.",
    "Restrict CORS to known trusted origins. Never use wildcard for authenticated APIs.",
    "curl -H 'Origin: https://evil.com' https://petstore3.swagger.io/api/v3/store/inventory",
    cvss="6.5")

ins(cur, 2, "SENSITIVE-DATA", "High",
    "PII exposed in response: email, phone, and password hash returned without field-level access control.",
    "/api/v3/user/{username}", "GET",
    "Exposure of personally identifiable information and credential hashes.",
    "Filter response fields by role. Never return password hashes in API responses.",
    'curl https://petstore3.swagger.io/api/v3/user/testuser\n# Returns: {"email":"test@example.com","phone":"555-1234","password":"$2b$12$..."}',
    cvss="7.5")

conn.commit()

# Verify
cur.execute("SELECT COUNT(*) FROM scan_jobs")
print(f"Scan jobs: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM scan_results")
print(f"Scan results: {cur.fetchone()[0]}")
cur.execute("SELECT id, status, target_url FROM scan_jobs")
for row in cur.fetchall():
    print(f"  Scan #{row[0]}: {row[1]} — {row[2][:60]}")
conn.close()
print("Done!")
