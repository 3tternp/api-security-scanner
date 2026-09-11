# 🔐 API Security Scanner

OWASP-focused API security scanner built with FastAPI and React.

![CI](https://github.com/3tternp/api-security-scanner/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/3tternp/api-security-scanner)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Node](https://img.shields.io/badge/Node-18%2B-brightgreen)

It performs static analysis of OpenAPI contracts and dynamic checks against live APIs, then presents findings in a web dashboard with exportable PDF and DOCX reports.

---

## 📸 Screenshots

### Security Dashboard
> Real-time metrics: total scans, findings, severity breakdown, risk score gauge, and interactive OWASP API Coverage Map

![Security Dashboard](docs/screenshots/dashboard.png)

---

### Scans List
> All past scans with completion status, timestamps, and per-scan finding counts

![Scans list](docs/screenshots/scans-list.png)

---

### Scan Detail — Findings
> Severity summary boxes, filter bar (by severity and triage status), and paginated findings list with rule badges and endpoint paths

![Scan detail](docs/screenshots/scan-detail-top.png)

---

### Findings — Scrolled View
> Each finding shows the HTTP method, full endpoint path, severity badge, and inline triage status dropdown

![Findings list](docs/screenshots/scan-findings.png)

---

## ⚙️ Features

- 🧭 OWASP API Top 10–oriented checks
- 📄 OpenAPI contract analysis:
  - Missing or weak authentication on endpoints
  - Unrestricted file uploads
  - PII exposure in request/response schemas
- 🛰️ Dynamic checks against a live target API:
  - Security headers and CORS misconfiguration
  - Rate limiting and resource consumption
  - BOLA / IDOR attempts by modifying object identifiers
  - Business-logic checks against sensitive flows (payments, orders, checkouts)
  - Fuzzing-based robustness tests for query parameters and JSON bodies
  - Error-based indicators of unsafe deserialization
  - Sensitive data patterns in responses (emails, SSNs, API keys, etc.)
  - JWT algorithm confusion (e.g. `alg: none` bypass)
  - Mass assignment via unprotected writeable fields
  - TLS enforcement (HTTP vs HTTPS / redirects)
  - Cookie security flags (HttpOnly / Secure / SameSite)
  - Fingerprinting headers (e.g. `Server`, `X-Powered-By`)
- 📊 Dashboard:
  - Real-time metrics (total scans, findings, open issues)
  - Severity breakdown with weighted risk score (0–100)
  - Interactive OWASP API Coverage Map grid
  - Recent scans summary
- 🎯 Confidence scoring on every finding (Low / Medium / High), based on how many independent, corroborating signals fired — baseline diffing, control requests, and re-fetch confirmation are used to cut down false positives instead of flagging on a single status code or keyword match
- 🔎 Scan detail:
  - Per-finding severity, confidence, rule ID, endpoint, and HTTP method
  - Inline triage status (Open / In Progress / Fixed / Accepted Risk)
  - Filter by severity, confidence, and status
- 🧾 Report export:
  - **PDF** — multi-page professional report with cover page, severity summary, OWASP coverage table, and per-finding detail sections
  - **DOCX** — structured Word document with colour-coded severity rows
- 🌐 No login required — the dashboard and scan APIs are open by design; run it only on a trusted network (see Security Notes)
- 🛡️ Optional HTTPS reverse proxy via Nginx with TLS

---

## 🧱 Tech Stack

| Layer | Technologies |
|---|---|
| Backend | FastAPI 0.141 · SQLAlchemy 2.0 · Uvicorn · SQLite (dev) / PostgreSQL (Docker) |
| Frontend | React + Vite · React Router v6 · TanStack Query · Axios · Tailwind CSS · Lucide icons |
| Reports | jsPDF + jspdf-autotable (PDF) · python-docx 1.x (DOCX) |
| Container | Docker · Docker Compose · Nginx (HTTPS reverse proxy) |

---

## 📁 Project Structure

```
api-security-scanner/
├── backend/
│   └── app/
│       ├── main.py                        # FastAPI entrypoint
│       ├── api/api_v1/endpoints/          # scans endpoints (no auth — open by design)
│       ├── scanner/
│       │   ├── engine.py                  # Rule orchestration, baseline cache, dedup
│       │   ├── signals.py                 # Confidence scoring + response-diffing helpers
│       │   ├── allowlists.py              # Shared keyword/field-name allowlists
│       │   ├── baseline.py                # Per-scan baseline request cache
│       │   └── rules/                     # Individual scanning rules
│       ├── models/                        # SQLAlchemy ORM models
│       ├── schemas/                       # Pydantic I/O schemas
│       └── core/config.py                 # App configuration
├── frontend/
│   └── src/
│       ├── App.jsx                        # Routing + sidebar layout
│       ├── api.js                         # Axios client
│       └── pages/                         # Dashboard · Scans · ScanDetail
├── docs/screenshots/                      # README screenshots
├── scripts/                               # Dev utilities (seed data, screenshot capture)
├── docker-compose.yml
└── nginx.conf
```

---

## 🚀 Getting Started (Local Development)

### 1. Clone the repository

```bash
git clone https://github.com/3tternp/api-security-scanner.git
cd api-security-scanner
```

### 2. Backend (FastAPI)

```bash
cd backend

# Create and activate a virtual environment
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux / macOS
# source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

# Start the API server
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

API is available at `http://localhost:8001/api/v1`

### 3. Frontend (React + Vite)

```bash
cd frontend
npm install

# Point the frontend at the local backend (optional, default is http://localhost:8000/api/v1)
# Windows PowerShell:
#   $env:VITE_API_URL="http://localhost:8001/api/v1"
# Linux / macOS:
#   export VITE_API_URL="http://localhost:8001/api/v1"
npm run dev
```

Frontend runs at `http://localhost:5173` and opens directly to the dashboard — there's no login step.

---

## 🐳 Getting Started (Docker)

### Prerequisites

- Docker and Docker Compose

### 1. Clone and configure

```bash
git clone https://github.com/3tternp/api-security-scanner.git
cd api-security-scanner
```

### 2. (Optional) Generate self-signed TLS certificates for HTTPS

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
# Run without the HTTPS reverse proxy (recommended for local development)
docker compose up --build db backend frontend

# If you're using the standalone docker-compose binary:
# docker-compose up --build db backend frontend
```

| Service | Description |
|---|---|
| `backend` | FastAPI API on port 8000 (internal) |
| `frontend` | React app on port 5173 |
| `reverse-proxy` | Nginx TLS termination on port 443 (optional; enable via Compose profile `tls`) |
| `db` | PostgreSQL (when configured) |

Access the app:
- Direct frontend: `http://localhost:5173/`
- Via HTTPS (optional): create certs, then run `docker compose --profile tls up --build` and open `https://localhost/` *(accept the self-signed cert)*

---

## 🟦 Windows: Run on Startup (Docker)

If you want the app to automatically start again after a PC restart, use the provided PowerShell scripts.

### Run now

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-app.ps1
```

Foreground mode (shows logs in the terminal):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-app.ps1 -Detach:$false
```

### Install auto-start

At user logon (recommended):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-startup-task.ps1
```

At system startup (requires Administrator):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-startup-task.ps1 -AtStartup
```

To remove the task later:

```powershell
Unregister-ScheduledTask -TaskName "ApiSecurityScanner" -Confirm:$false
```

---

## 📊 Usage

1. Open the dashboard — no login required.
2. Go to **Scans → New Scan** and provide:
   - Target URL (e.g. `https://api.example.com`)
   - Optional OpenAPI spec URL or JSON file upload
   - Optional auth: Bearer token or Basic credentials (for the *target* API being scanned)
3. Start the scan and monitor its status (Running → Completed / Failed).
4. Open the scan to view findings:
   - Filter by severity (Critical / High / Medium / Low / Info)
   - Filter by confidence (Low / Medium / High)
   - Filter by triage status (Open / In Progress / Fixed / Accepted Risk)
   - Update each finding's status inline
5. Export a **PDF** or **DOCX** report for audit or sharing.
6. Delete old scans from the Scans list.

---

## 🔬 Demo: Scan a Local Vulnerable API

### 1. Start the scanner backend and frontend

```bash
# Terminal 1 — backend
cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8001

# Terminal 2 — frontend
cd frontend && npm run dev
```

### 2. Start a demo vulnerable API

Create a `demo_api.py` (outside this project) with intentionally weak endpoints, then run:

```bash
uvicorn demo_api:app --host 0.0.0.0 --port 9002
```

Confirm it's running at:
- Swagger UI: `http://localhost:9002/docs`
- OpenAPI spec: `http://localhost:9002/openapi.json`

### 3. Run a scan from the UI

1. Open `http://localhost:5173/`.
2. **Scans → New Scan**
3. Fill in:
   - Target URL: `http://localhost:9002`
   - OpenAPI Spec URL: `http://localhost:9002/openapi.json`
4. Click **Start Scan** and wait for completion.
5. View findings in the scan detail page.

Expected findings from a vulnerable demo API:
- Business-logic checks on sensitive POST flows
- Fuzzing-induced 5xx errors on malformed inputs
- Deserialization indicators in error messages

---

## 🧪 CI Examples

| Platform | File | What it does |
|---|---|---|
| GitHub Actions | `.github/workflows/ci.yml` | Backend compile check + frontend `npm run build` |
| GitLab CI | `.gitlab-ci.yml` | Backend stage (Python) + frontend stage (Node) |

---

## 🔒 Security Notes

- **This app has no authentication.** The dashboard and scan APIs (including creating and deleting scans) are open to anyone who can reach the server. It's designed for local/internal use, not public exposure.
- Do not expose this tool to the internet without adding your own access control in front of it (e.g. a reverse proxy with auth, a VPN, or network-level restrictions) plus:
  - HTTPS (TLS) termination
  - Network hardening (firewalls, WAF)
- Some dynamic checks send multiple HTTP requests (e.g. rate-limit probing). **Do not run against production systems** without coordination.

---

## 🧭 Roadmap Ideas

- Deeper workflow modeling and stateful multi-step test scenarios
- Additional SSRF and outbound-call abuse heuristics
- Fuzzing of file uploads and multipart endpoints
- Visualisations of cross-scan trends and risk scoring over time
- Per-rule confidence-threshold tuning and a false-positive feedback loop

---

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
