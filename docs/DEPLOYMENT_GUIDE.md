# DEPLOYMENT & OPERATIONS GUIDE

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. System Requirements

### Hardware Prerequisites
- **Processor:** 4 Core x86_64 or ARM64 CPU (8+ cores recommended for high-volume log ingestion).
- **Memory (RAM):** 8 GB minimum (16 GB recommended for multi-session in-memory analysis).
- **Storage:** 20 GB available SSD storage (NVMe recommended for SQLite/PostgreSQL persistence).
- **Network:** Outbound HTTPS (Port 443) connectivity if live VirusTotal threat intelligence lookups are enabled.

### Software Prerequisites
- **Operating System:** Linux (Ubuntu 22.04 LTS / Debian 12 / RHEL 9), macOS 13+, or Windows 11.
- **Python Runtime:** Python 3.12, 3.13, or 3.14.
- **Node.js Runtime:** Node.js v18.18+ or v20+ (with `npm` v9+).
- **Database (Optional for Production):** PostgreSQL 15+ (or cloud-hosted Supabase instance).

---

## 2. Environment Configuration

Create a `.env` configuration file in the `backend/` directory:

```bash
# ------------------------------------------------------------------------------
# MICHAEL - Environment Configuration Template
# (Do NOT commit real credentials to version control)
# ------------------------------------------------------------------------------

# Persistence Configuration
# Options: 'memory' (testing/dev), 'sqlite' (local file), 'postgres' (production)
PERSISTENCE_BACKEND=sqlite

# Database URL (Required if PERSISTENCE_BACKEND is 'postgres' or custom 'sqlite' path)
# SQLite local file example:
DATABASE_URL=sqlite:///./michael.db
# PostgreSQL / Supabase example:
# DATABASE_URL=postgresql+asyncpg://db_user:db_password@db_host:5432/michael_db

# Threat Intelligence Configuration
# Set to enable live VirusTotal v3 lookups; if absent, system defaults to offline mock
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Network & CORS Security
# Comma-separated list of allowed frontend origins
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Server Binding
HOST=0.0.0.0
PORT=8000
```

Create a `.env.local` configuration file in the `frontend/` directory:

```bash
# Frontend API Base URL
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## 3. Backend Installation & Deployment

### Step 1: Clone Repository & Create Virtual Environment
```bash
git clone https://github.com/organization/michael-guardian-ai.git
cd "michael-guardian-ai/backend"

# Create Python virtual environment
python -m venv venv

# Activate virtual environment
# On Linux / macOS:
source venv/bin/activate
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
```

### Step 2: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Run Validation & Regression Tests
Before launching the service, verify that the environment passes all unit, integration, and security tests:
```bash
python -m unittest discover -s tests -p "test_*.py"
```
*Expected Outcome:* `412 / 412 tests PASS`.

### Step 4: Launch Backend Service
```bash
# Development Mode (with hot-reload):
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Production Mode (using production server):
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Verify service vitality:
```bash
curl http://localhost:8000/api/health
# Response: {"status":"operational", ...}

curl http://localhost:8000/api/ready
# Response: {"status":"ready", "persistence_backend":"sqlite", "db_status":"connected", ...}
```

---

## 4. Frontend Installation & Production Build

### Step 1: Navigate to Frontend Directory
```bash
cd "../frontend"
```

### Step 2: Install Node Dependencies
```bash
npm install
```

### Step 3: Compile Production Build
```bash
npm run build
```
*Expected Outcome:* `15 / 15 static routes prerendered cleanly with 0 TypeScript errors`.

### Step 4: Launch Frontend Production Server
```bash
npm run start
```
The SOC Dashboard will be accessible in a web browser at:  
`http://localhost:3000`

---

## 5. Production Database Configuration (PostgreSQL / Supabase)

To transition from the zero-dependency SQLite file mode to an enterprise PostgreSQL or Supabase database:

1. Provision a PostgreSQL 15+ database or create a new Supabase project.
2. Retrieve the standard PostgreSQL connection URI.
3. Update `backend/.env`:
   ```bash
   PERSISTENCE_BACKEND=postgres
   DATABASE_URL=postgresql+asyncpg://postgres:[PASSWORD]@[HOST]:5432/postgres
   ```
4. On startup, SQLAlchemy automatically verifies connectivity and creates all 12 tables (`sessions`, `events`, `anomalies`, `model_metrics`, `incidents`, `attack_chains`, `iocs`, `ioc_evidence`, `threat_intel_results`, `threat_assessments`, `threat_correlations`, `audit_records`) if they do not exist.
5. Verify connectivity:
   ```bash
   curl http://localhost:8000/api/ready
   ```
   Ensure `"db_status": "connected"` and `"persistence_backend": "postgres"`.

