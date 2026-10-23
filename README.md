# AI-Powered Insider Threat Behavioral Intelligence System (SOC 2.0)

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React_18_Vite-61DAFB.svg)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/UI-TailwindCSS_Dark_SOC-38B2AC.svg)](https://tailwindcss.com/)
[![PyTorch](https://img.shields.io/badge/Deep%20Learning-PyTorch%20GNN-EE4C2C.svg)](https://pytorch.org/)
[![Tests](https://img.shields.io/badge/Tests-13%20Passed-brightgreen.svg)]()

An enterprise-grade, AI-powered Insider Threat Behavioral Intelligence Platform designed for Security Operations Centers (SOCs), enterprise security teams, and cyber risk officers. The system continuously monitors multi-source telemetry, learns employee behavioral baselines, detects multi-modal anomalies, computes mathematically-weighted insider threat risk scores, and orchestrates incident investigations.

---

## 🎯 Executive Overview & Capabilities

- **Role-Based Access Control (RBAC):** Dedicated dashboards for **Security Analyst**, **SOC Engineer**, **Security Manager**, and **Administrator**.
- **Multi-Source Activity Monitoring:** Ingestion across 9 activity channels: Logins, File Operations, USB Peripherals, Emails (NLP Keyword Flags), Network Outbound Egress, Applications, Remote VPN Sessions, Privilege Changes, and Data Transfers.
- **5-Model AI Anomaly Detection Suite:**
  1. **Isolation Forest:** Tree-depth partitioning for spatial outliers.
  2. **One-Class SVM:** Non-linear RBF kernel decision boundary.
  3. **Neural Autoencoder:** Bottleneck MSE reconstruction loss.
  4. **Graph Centrality:** Degree & Betweenness centrality across bipartite entity graphs.
  5. **PyTorch Graph Neural Network (GNN):** Graph Convolution Network (GCN) autoencoder for node embeddings.
- **Explainable AI (XAI):** SHAP feature attributions and LIME local surrogate weights directly accessible in the UI.
- **Official Weighted Insider Risk Scoring Engine:** Exact PDF mathematical formula:
  $$\text{Insider Risk Score} = 0.35 \times \text{Behavioral} + 0.25 \times \text{Privilege} + 0.20 \times \text{Data Access} + 0.10 \times \text{Access Pattern} + 0.10 \times \text{Historical Events}$$
- **Threat Case & Investigation Workspace:** Correlated chronological activity timelines, forensic evidence vault (PCAP, Memory, Registry hashes), investigator journals, and one-click containment actions (quarantine host, suspend account).
- **Automated Report Generation:** Real-time generation of styled **PDFs** (ReportLab), formatted multi-tab **Excel spreadsheets** (OpenPyXL), and **CSVs**.

---

## 🗺️ Milestone Implementation Mapping

| Milestone | Modules & Features Implemented | Implementation Status |
| :--- | :--- | :---: |
| **Milestone 1: Core Setup & Ingestion** (Weeks 1-2) | JWT Auth, RBAC (4 roles), Employee/Identity Profiles, Asset & Privilege mapping, Multi-source Activity Ingestion | ✅ **Complete** |
| **Milestone 2: Behavioral Intelligence & ML** (Weeks 3-4) | UEBA Profiling, Peer Group Baselines, Isolation Forest, One-Class SVM, Autoencoders, PyTorch GNN, SHAP/LIME XAI | ✅ **Complete** |
| **Milestone 3: Risk Scoring & Threat Management** (Weeks 5-6) | 5-Factor Weighted Risk Scoring, Alert Generation & Triage, Incident Workflows, Case Timelines, Forensic Vault | ✅ **Complete** |
| **Milestone 4: Dashboards, Reports & Deployment** (Weeks 7-8) | Role-Aware Dashboards (4 personas), PDF/Excel/CSV Exporters, Pytest Test Suite, Docker & Docker Compose | ✅ **Complete** |

---

## 👥 Default Operator Credentials (RBAC)

The system comes pre-seeded with 4 default personas. You can log in using any of them, or switch instantly using the top navigation persona selector:

These demo credentials are for the full local/Docker profile only. The Vercel
serverless profile does not create them; create its administrator with the
bootstrap procedure below. Never reuse demo passwords for a production account.

| Role | Email | Password | Primary Purpose |
| :--- | :--- | :--- | :--- |
| **Security Analyst** | `analyst@soc.corp` | `analyst123` | Triage alert feed, inspect XAI SHAP/LIME diagnostics, investigate incidents |
| **SOC Engineer** | `soc@soc.corp` | `soc123` | Inspect raw telemetry stream, interactive entity graph, ML model health |
| **Security Manager** | `manager@soc.corp` | `manager123` | Enterprise risk posture, compliance metrics, department threat trends |
| **Administrator** | `admin@soc.corp` | `admin123` | User administration, ML retraining trigger, live Red Team attack simulator |

---

## 🚀 Quickstart & Run Instructions

### Option 1: Standalone Local Run (Zero-Config SQLite / Python)

#### 1. Start the FastAPI Backend
```bash
# From project root:
$env:APP_ENV="development"
$env:PYTHONPATH="backend"
python -m uvicorn app.main:app --reload --port 8000
```
- Interactive API Documentation: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health Check: [http://localhost:8000/health](http://localhost:8000/health)

#### 2. Start the React Frontend
```bash
cd frontend
npm run dev
```
- Open your browser at: [http://localhost:5173](http://localhost:5173)

---

### Option 2: Docker Compose (PostgreSQL + FastAPI + Nginx Frontend)

Before starting the containers, create a `.env` file with unique values for
`SECRET_KEY`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, and
`DATABASE_URL`. Use an alphanumeric PostgreSQL password so it can be safely
included in the URL, for example:

```dotenv
SECRET_KEY=replace-with-a-unique-random-secret
POSTGRES_USER=soc_admin
POSTGRES_PASSWORD=replace-with-a-strong-alphanumeric-password
POSTGRES_DB=insider_threat_db
DATABASE_URL=postgresql://soc_admin:replace-with-a-strong-alphanumeric-password@postgres:5432/insider_threat_db
```

```bash
docker-compose up --build
```
- **Web Application:** [http://localhost:3000](http://localhost:3000)
- **FastAPI Backend API:** [http://localhost:8000](http://localhost:8000)
- **PostgreSQL Database:** `localhost:5432` (`insider_threat_db`)

### Option 3: Deploy the frontend and API to Vercel

This profile runs the static frontend and a reduced FastAPI serverless API on
Vercel. It still requires an external managed PostgreSQL database: Vercel
functions cannot persist the SQLite file. The serverless API deliberately
omits ML/UEBA/anomaly analysis, model retraining, attack simulation, and the
WAS security lab. The standard local and Docker deployments keep the full
backend.

Create two Vercel projects from this repository:

1. **Frontend project:** set **Root Directory** to `frontend`. Use
   `npm run build` and output directory `dist`. Add these build environment
   variables:
   - `VITE_API_BASE_URL=https://your-api-project.vercel.app/api/v1`
   - `VITE_SERVERLESS_PROFILE=true`
2. **API project:** set **Root Directory** to `backend`. Keep the project root
   at `backend` (not the repository root) so Vercel resolves `pyproject.toml`,
   `requirements.txt`, and the `app` package from the same directory.
   `pyproject.toml` explicitly selects `app.serverless_main:app`.
   Add these environment variables:
   - `SECRET_KEY`: a unique, securely generated value.
   - `DATABASE_URL`: the managed PostgreSQL connection URL.
   - `FRONTEND_URL`: the exact deployed frontend origin, such as
     `https://your-frontend-project.vercel.app` (no trailing slash).
3. Initialize the database and create the first administrator from a
   machine that can connect to the managed database. In PowerShell, from the
   repository root:

   ```powershell
   Set-Location backend
   python -m pip install -r requirements.txt
   $env:DATABASE_URL = "your-managed-postgresql-url"
   $env:SECRET_KEY = "your-production-secret"
   $env:BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
   $env:BOOTSTRAP_ADMIN_PASSWORD = "use-a-unique-password-at-least-12-characters"
   python -m app.initialize_serverless_db
   ```

   Use the same `DATABASE_URL` and `SECRET_KEY` in the API project's Vercel
   environment variables. The bootstrap script creates the schema and one
   administrator; it does not create demo users or sample records.
4. Deploy both projects. Check
   `https://your-api-project.vercel.app/api/health`, then sign in to the
   frontend with the bootstrap administrator. The frontend uses Vercel SPA
   routing for direct navigation to client-side pages.

The frontend's `/api/v1` default and Vite development proxy remain unchanged
when `VITE_API_BASE_URL` is not set.

---

## 🧪 Running Automated Test Suite

Run the full end-to-end integration and unit test suite:
```bash
$env:PYTHONPATH="backend"
python -m pytest tests -v
```
All 13 test suites verify:
- JWT Authentication & RBAC restrictions
- Mathematical validity of the 5-factor weighted risk formula
- Multi-source activity ingestion
- Multi-model anomaly score generation and SHAP/LIME explainability
- Incident investigation lifecycle and forensic note journal
- PDF, Excel (.xlsx), and CSV report binary exports

---

## 📂 Architecture & Directory Structure

```
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application & lifespan startup
│   │   ├── config.py                   # App settings (Postgres / SQLite fallback)
│   │   ├── database.py                 # SQLAlchemy engine & session maker
│   │   ├── models.py                   # Complete relational database models
│   │   ├── schemas.py                  # Pydantic request/response schemas
│   │   ├── auth.py                     # JWT token encode/decode & RBAC dependencies
│   │   ├── seed_data.py                # Database seed for employees, logs, users, ML
│   │   ├── ml_engine/
│   │   │   ├── simulator.py            # Multi-source log generator (9 event types)
│   │   │   ├── feature_engineering.py  # Behavioral feature extraction
│   │   │   ├── models.py               # Isolation Forest, SVM, Autoencoder suite
│   │   │   ├── graph_analytics.py      # NetworkX bipartite graph & centrality
│   │   │   ├── gnn_model.py            # PyTorch Graph Neural Network (GCN Autoencoder)
│   │   │   └── explainability.py       # SHAP feature attributions & LIME weights
│   │   ├── services/
│   │   │   ├── risk_service.py         # Exact 5-factor weighted insider risk formula
│   │   │   ├── ueba_service.py         # UEBA baseline & peer group deviations
│   │   │   ├── ml_service.py           # ML orchestration pipeline
│   │   │   ├── simulation_service.py   # Live interactive Red Team attack injections
│   │   │   └── report_service.py       # PDF, Excel, and CSV binary report builders
│   │   └── routers/                    # Complete REST API endpoints (12 routers)
├── frontend/
│   ├── src/
│   │   ├── context/AuthContext.jsx     # JWT Auth state & role switcher
│   │   ├── services/api.js             # Axios client for all backend endpoints
│   │   ├── components/                 # Navbar, Sidebar, StatsCard, EntityGraph, XAI Modal
│   │   └── pages/                      # 12 role-aware SOC pages & dashboards
├── tests/                              # Comprehensive Pytest test cases
├── docker-compose.yml                  # Docker Compose configuration
├── Dockerfile.backend                  # Backend Dockerfile
├── Dockerfile.frontend                 # Frontend Dockerfile
├── requirements.txt                    # Python dependencies
└── README.md
```
