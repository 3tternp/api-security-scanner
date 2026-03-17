# Troubleshooting

---

## Backend fails to start — "connection refused" to PostgreSQL

**Symptom:** Backend exits immediately; logs show `psycopg2.OperationalError: could not connect to server`

**Cause:** PostgreSQL isn't ready yet when the backend starts.

**Fix:** The `prestart.sh` script polls PostgreSQL before starting uvicorn. If you're running without Docker, ensure PostgreSQL is running first:
```bash
docker compose up db -d
# wait for healthy, then:
docker compose up backend
```

---

## "Setup has already been completed" on `/setup`

**Symptom:** POST to `/setup/` returns 403.

**Cause:** An admin account already exists. This is by design — setup can only run once.

**Fix:** Log in with your existing admin account. If credentials are lost, reset via the database:
```sql
UPDATE users SET hashed_password = '<new-bcrypt-hash>' WHERE role = 'admin';
```
Generate a hash:
```bash
python -c "from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('NewP@ssword!123'))"
```

---

## "Incorrect email or password" even with correct credentials

**Check 1 — Account locked?**
```bash
docker compose exec db psql -U ${POSTGRES_USER} -d apiscanner \
  -c "SELECT email, failed_login_attempts, locked_until FROM users;"
```
Unlock:
```sql
UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE email = 'you@example.com';
```

**Check 2 — Account inactive?**
```sql
UPDATE users SET is_active = true WHERE email = 'you@example.com';
```

---

## DOCX download returns an error

**Symptom:** Clicking Download DOCX shows "Failed to download DOCX report"

**Check 1 — Is the scan completed?**
The DOCX button is disabled for running/pending scans. Wait for the scan to complete.

**Check 2 — Backend logs**
```bash
docker compose logs backend | grep "docx\|ERROR"
```

**Check 3 — python-docx version**
Must be ≥ 1.1.2. If an older version is installed:
```bash
docker compose exec backend pip install "python-docx>=1.1.2"
```

---

## CORS error in browser console

**Symptom:** `Access to XMLHttpRequest at 'http://localhost:8000' from origin 'http://localhost:5173' has been blocked by CORS policy`

**Fix:** Add your frontend origin to `BACKEND_CORS_ORIGINS` in `.env`:
```env
BACKEND_CORS_ORIGINS=["http://localhost:5173","http://localhost:5174"]
```
Then restart the backend.

---

## Frontend shows spinner forever on load

**Symptom:** The loading spinner never goes away after opening the app.

**Cause:** The frontend is checking `/setup/status` but the backend isn't reachable.

**Fix:**
```bash
# Check backend is up
curl http://localhost:8000/api/v1/setup/status

# If connection refused, start the backend
docker compose up backend -d
```

---

## Environment variable not taking effect

**Symptom:** Config change in `.env` has no effect.

**Fix:** Rebuild/restart the affected container:
```bash
docker compose restart backend
# Or for a full rebuild:
docker compose up -d --build backend
```

---

## PostgreSQL data lost after `docker compose down`

**Cause:** The named volume `postgres_data` is deleted when `down -v` is used.

**Prevention:** Never use `docker compose down -v` unless you intend to wipe the database.

**Backup before maintenance:**
```bash
docker compose exec db pg_dump -U ${POSTGRES_USER} ${POSTGRES_DB} > backup.sql
```

**Restore:**
```bash
cat backup.sql | docker compose exec -T db psql -U ${POSTGRES_USER} ${POSTGRES_DB}
```

---

## Getting Help

- Open an issue: [github.com/3tternp/api-security-scanner/issues](https://github.com/3tternp/api-security-scanner/issues)
- Check backend logs: `docker compose logs -f backend`
- Check all logs: `docker compose logs -f`
