# Installation

## Prerequisites

| Requirement | Minimum Version |
|---|---|
| Docker | 24+ |
| Docker Compose | 2.20+ |
| (Optional) Python | 3.13 (local dev only) |
| (Optional) Node.js | 22 LTS (local dev only) |

---

## Option 1 — Docker Compose (Recommended)

This starts the full stack: PostgreSQL 18, FastAPI backend, React frontend, and Nginx.

### 1. Clone the repository

```bash
git clone https://github.com/3tternp/api-security-scanner.git
cd api-security-scanner
```

### 2. Create your `.env` file

```bash
cp .env.example .env
```

Edit `.env` and fill in **all required values** (see [Configuration](Configuration)):

```bash
# Generate a strong SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. (Optional) Generate TLS certificates for HTTPS

```bash
mkdir certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=localhost"
```

Skip this step if you don't need HTTPS locally — comment out the `reverse-proxy` service in `docker-compose.yml`.

### 4. Start the stack

```bash
docker compose up -d
```

Docker will:
1. Pull `postgres:18-alpine`, `nginx:1.27-alpine`
2. Build the FastAPI backend (Python 3.13)
3. Build the React frontend (Node 22 → static nginx build)
4. Wait for PostgreSQL to be healthy before starting the backend
5. Run `prestart.sh` to bootstrap the first admin (if `ADMIN_EMAIL`/`ADMIN_PASSWORD` are set in `.env`)

### 5. Open the app

- **HTTP (no TLS):** `http://localhost:80`
- **HTTPS:** `https://localhost:443`
- **API docs (dev only):** `http://localhost:8000/docs`

On first load the Setup wizard will appear if no admin account exists yet.

---

## Option 2 — Development (Hot-Reload)

Uses source-mounted volumes so both frontend and backend hot-reload on file changes.

```bash
cp .env.example .env   # fill in values
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

The dev override:
- Mounts `./backend` into the backend container (uvicorn `--reload`)
- Mounts `./frontend` into the frontend container (Vite HMR)
- Skips the prestart DB-wait loop (assumes DB is already healthy)

Frontend available at `http://localhost:5173`, backend at `http://localhost:8000`.

---

## Option 3 — Bare-metal (no Docker)

### Backend

```bash
cd backend

# Create and activate a virtual environment
python3.13 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env             # edit values

# Start PostgreSQL separately, then run:
python app/initial_data.py       # bootstrap admin (if ADMIN_EMAIL/PASSWORD set)
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
VITE_API_URL=http://localhost:8000/api/v1 npm run dev
```

---

## Verifying the Installation

```bash
# Check all containers are healthy
docker compose ps

# Tail logs
docker compose logs -f backend

# Test the API
curl http://localhost:8000/api/v1/setup/status
# Expected: {"setup_required": false}  (after admin created)
```
