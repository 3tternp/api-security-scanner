# API Security Scanner

OWASP-focused API security scanner built with FastAPI and React.

It performs static analysis of OpenAPI contracts and dynamic checks against live APIs, then presents findings in a web dashboard and exportable PDF reports.

---

## Features

- OWASP API Top 10–oriented checks
- OpenAPI contract analysis:
  - Missing or weak authentication on endpoints
  - Unrestricted file uploads
  - PII exposure in request/response schemas (request and response bodies)
- Dynamic checks against a target API:
  - Security headers and basic CORS misconfiguration
  - Rate limiting and resource consumption
  - BOLA / IDOR attempts by modifying object identifiers
  - Sensitive data patterns in responses (emails, SSNs, API keys, etc.)
- Dashboard:
  - List of scans, status, and timestamps
  - OWASP API Top 10 coverage summary
  - Ability to delete scan history
- PDF report export with:
  - Grouped findings
  - Impact, remediation, and CVSS-style metadata
  - OWASP category summary
- Basic authentication and roles (admin vs regular user)
- Multi-user management UI for creating admin/auditor accounts
- Optional HTTPS reverse proxy via Nginx with TLS

---

## Tech Stack

- Backend
  - FastAPI
  - SQLAlchemy
  - Uvicorn
  - SQLite by default (via config), Postgres when using Docker Compose
- Frontend
  - React + Vite
  - React Router
  - @tanstack/react-query
  - Axios
  - jsPDF and jsPDF-autotable
  - lucide-react icons
- Containerization
  - Docker and Docker Compose
  - Nginx as HTTPS reverse proxy

---

## Project Structure

High-level layout:

- `backend/`
  - `app/main.py` – FastAPI application entrypoint
  - `app/api/api_v1/endpoints/` – login, users, scans endpoints
  - `app/scanner/engine.py` – orchestration of scanner rules
  - `app/scanner/rules/` – individual scanning rules (security headers, BOLA, OpenAPI contract, etc.)
  - `app/models/` – SQLAlchemy models for users, scans, results
  - `app/schemas/` – Pydantic schemas for API I/O
  - `app/core/config.py` – configuration (CORS, DB URL, etc.)
  - `app/initial_data.py` – bootstrap admin user and tables
- `frontend/`
  - `src/main.jsx` – React entrypoint
  - `src/App.jsx` – routing and layout
  - `src/api.js` – Axios client and API helpers
  - `src/pages/` – Login, Dashboard, ScanList, ScanDetail, Users pages
- `docker-compose.yml` – backend, frontend, database, and reverse-proxy services
- `nginx.conf` – Nginx config for HTTPS termination and routing
 - `.github/workflows/ci.yml` – GitHub Actions example pipeline
 - `.gitlab-ci.yml` – GitLab CI example pipeline

---

## Getting Started (Local Development)

These steps run the backend and frontend directly on your machine without Docker.

### 1. Clone the repository

```bash
git clone https://github.com/3tternp/api-security-scanner.git
cd api-security-scanner
```

### 2. Backend (FastAPI)

Create and activate a virtual environment:

```bash
cd backend
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# Linux/macOS (bash/zsh)
# source .venv/bin/activate
```

Install dependencies:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Initialize the database and admin user:

```bash
python -m app.initial_data
```

This creates:

- Database tables
- Admin user:
  - Email: `admin@example.com`
  - Password: `admin123`

Run the API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

The API is now available at:

- `http://localhost:8001/api/v1`

### 3. Frontend (React)

In a new terminal:

```bash
cd api-security-scanner/frontend
npm install
npm run dev
```

By default the frontend runs at:

- `http://localhost:5173`

Log in using:

- Email: `admin@example.com`
- Password: `admin123`

You can now create scans, view findings, delete scan history, and export PDF reports.

---

## Getting Started (Docker)

If you prefer containers, you can run the full stack via Docker Compose.

### Prerequisites

- Docker
- Docker Compose

### 1. Clone the repository

```bash
git clone https://github.com/3tternp/api-security-scanner.git
cd api-security-scanner
```

### 2. Optional: create self-signed TLS certificates

If you want HTTPS on `https://localhost/` via Nginx:

```bash
mkdir certs
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -subj "/CN=localhost"
```

### 3. Build and run

```bash
docker compose build
docker compose up
```

Services:

- `backend` – FastAPI API (port 8000 inside Docker network)
- `frontend` – React app (port 5173)
- `reverse-proxy` – Nginx TLS reverse proxy (port 443)
- `db` – Postgres (if configured in docker-compose)

Access:

- Via HTTPS reverse proxy: `https://localhost/`  
  (you may need to accept the self-signed certificate)
- Or directly to the frontend: `http://localhost:5173/`

Default admin credentials are the same:

- Email: `admin@example.com`
- Password: `admin123`

---

## Usage

1. Log in as the admin user.
2. Go to the Scans dashboard.
3. Click **New Scan** and provide:
   - Target URL (e.g. `https://api.example.com`)
   - Optional OpenAPI spec:
     - URL, or
     - JSON file upload
   - Optional auth:
     - Bearer token
     - Basic auth (username/password)
4. Start the scan.
5. Monitor status:
   - Running, completed, failed
   - Progress banner when scans are running
6. View scan details:
   - Findings grouped by rule and description
   - OWASP API Top 10 mapping where applicable
7. Export a PDF report for audit or sharing.
8. Delete old scans using the **Delete** action in the scans table.
9. (Admin only) Go to the **Users** page to create additional admin/auditor accounts.

---

## CI Examples

This repository includes minimal CI configurations:

- GitHub Actions: `.github/workflows/ci.yml`
  - Installs backend dependencies and runs a Python compile check.
  - Installs frontend dependencies and runs `npm run build`.
- GitLab CI: `.gitlab-ci.yml`
  - Backend stage using Python image and compile check.
  - Frontend stage using Node image and `npm run build`.

---

## Security Notes

- The default admin credentials (`admin@example.com` / `admin123`) are for local and demo use only. Change them in any shared or deployed environment.
- Do not expose this tool directly to the internet without:
  - Strong authentication and access control
  - HTTPS (TLS) termination
  - Network and infrastructure hardening (firewalls, WAF, etc.)
- Some dynamic checks may send multiple requests (for example when testing rate limiting). Avoid running against production systems without appropriate coordination.

---

## Roadmap Ideas

Some areas to extend this tool further:

- Deeper business-logic test scenarios (workflow-level abuse cases)
- Additional injection and deserialization checks
- Fuzzing-based parameter and payload testing
- More granular role-based access control visualization in the UI

---

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
