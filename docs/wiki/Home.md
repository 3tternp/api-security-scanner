# API Security Scanner — Wiki

**API Security Scanner** is an open-source security testing platform that automatically audits REST APIs against the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/). It combines a FastAPI backend, a React dashboard, and a PostgreSQL database into a single Docker-deployable stack.

---

## Quick Navigation

| Topic | Description |
|---|---|
| [Installation](Installation) | Docker Compose setup, prerequisites |
| [Configuration](Configuration) | All environment variables and `.env` setup |
| [First-Run Setup](First-Run-Setup) | Creating the initial administrator account |
| [User Management](User-Management) | Roles, creating users, account lockout |
| [Running Scans](Running-Scans) | How to launch and monitor a scan |
| [Understanding Results](Understanding-Results) | Severity levels, OWASP mapping, CVSS |
| [Reports](Reports) | Exporting PDF and DOCX reports |
| [Security Architecture](Security-Architecture) | Auth model, encryption, hardening decisions |
| [API Reference](API-Reference) | Key REST endpoints |
| [Troubleshooting](Troubleshooting) | Common issues and fixes |

---

## Feature Highlights

- **17 automated security rules** covering all OWASP API Top 10 categories
- **Interactive OWASP Coverage Map** — live heatmap of findings per category
- **Risk Score gauge** — weighted 0–100 score from severity distribution
- **First-run setup wizard** — no hardcoded credentials; admin created by you on first boot
- **Account lockout** — brute-force protection with configurable thresholds
- **PDF & DOCX export** — professional reports with CVSS details and remediation steps
- **Role-based access** — `admin` and `auditor` roles
- **PostgreSQL 18** — encrypted credentials, connection pooling, audit timestamps

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| API Framework | FastAPI | 0.115.6 |
| Database | PostgreSQL | 18 |
| ORM | SQLAlchemy | 2.0.37 |
| Auth | JWT (HS256) + bcrypt | python-jose 3.3.0 / bcrypt 4.2.1 |
| Frontend | React + Vite | 19 / 7 |
| Styling | Tailwind CSS | 3.4 |
| HTTP Client | Axios | 1.x |
| Data Fetching | TanStack Query | 5.x |
| Container Runtime | Docker + Compose | — |
| Reverse Proxy | Nginx | 1.27 |
| Python Runtime | Python | 3.13 |
| Node Runtime | Node.js | 22 LTS |

---

## Architecture Overview

```
Browser
  │
  ▼
Nginx (443 / TLS)
  ├── /api/*  ──► FastAPI backend (port 8000)
  │                    │
  │                    ▼
  │              PostgreSQL 18 (port 5432)
  │
  └── /*      ──► React SPA (nginx-served static build)
```
