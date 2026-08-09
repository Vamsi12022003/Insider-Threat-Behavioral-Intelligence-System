# Insider Threat Behavioral Intelligence System

An AI-powered platform that monitors employee activity, builds behavioral baselines, detects anomalies, and generates risk-scored security alerts to help organizations identify potential insider threats before they escalate into data breaches or security incidents.

## Overview

This project is being developed as part of the Infosys Springboard AI Internship program. It combines user behavior analytics (UBA), entity behavior analytics (UEBA), and machine learning-based anomaly detection to continuously assess insider risk across an organization.

## Objective

Traditional security tools focus on external threats. This system focuses on the harder problem — detecting suspicious behavior from within an organization by:

- Continuously monitoring employee digital activity (logins, device usage)
- Building individual behavioral baselines per employee
- Detecting statistically significant deviations from normal behavior
- Scoring and prioritizing insider risk
- Auto-generating alerts and supporting security teams with investigation workflows
- Demonstrating real-time-style prediction on incoming activity data
- Presenting role-appropriate views to different security roles

## Tech Stack

**Backend:** Python, FastAPI, JWT Authentication (OAuth2 password flow)
**Database:** SQLite (dev) — see Known Gaps
**Frontend:** HTML/CSS/JavaScript — role-gated multi-tab dashboard (Predict, Risk Scores, Incidents, Alerts) plus login page
**Machine Learning:** Scikit-learn (Isolation Forest), Pandas, NumPy, Joblib
**Deployment:** Docker (verified working locally)
**Testing:** pytest (17 automated tests)
**Dev Tools:** Git, GitHub, VS Code

## Project Status

🚧 In Development — Milestones 1–3 complete, Milestone 4 in progress

| Milestone | Focus | Status |
|---|---|---|
| Milestone 1 (Week 1-2) | Project setup, auth, RBAC, DB schema doc, wireframes | ✅ Complete (log ingestion still manual) |
| Milestone 2 (Week 3-4) | Behavioral profiling & anomaly detection | ✅ Complete |
| Milestone 3 (Week 5-6) | Risk scoring, threat investigation, UEBA, live prediction | ✅ Complete (scoped — see gaps) |
| Milestone 4 (Week 7-8) | Dashboards, alerts, testing & deployment | 🔄 In Progress |

## Features

**Done and verified:**

- ✅ User registration & login (JWT-based authentication, OAuth2 password flow)
- ✅ Role-based access control (security_analyst, security_manager, admin) — tested with real 403/200 responses, enforced on both backend routes and frontend tab visibility
- ✅ Employee profile management (CRUD, role-restricted)
- ✅ Behavioral baseline generation per employee (330k+ user-day profiles from CERT r4.2 logon/device data)
- ✅ Anomaly detection engine (Isolation Forest, 2% flag rate, explainable per-anomaly reasons)
- ✅ Insider risk scoring engine (Behavioral Anomalies only — see gaps)
- ✅ Risk scores API + role-gated HTML dashboard (summary cards, filterable table)
- ✅ Live prediction endpoint — feed a CSV, get per-row Insider/Normal predictions in real time, viewable in the dashboard's Predict tab
- ✅ Threat investigation module — incident creation, evidence pulled from real anomaly history, status workflow
- ✅ UEBA module — org-wide percentile comparison and monthly behavioral trend analysis (department-based peer comparison not possible — see gaps)
- ✅ Alert & notification system — auto-generates alerts from High/Critical risk scores, open → acknowledged → resolved workflow, dashboard tab with live counts and per-alert actions
- ✅ Role-based dashboard views — security_analyst sees all 4 tabs (Predict, Risk Scores, Incidents, Alerts); security_manager sees Risk Scores + Alerts only; admin sees everything
- ✅ Docker deployment — builds and runs locally, verified via live API calls inside the container
- ✅ Automated test suite — 17 pytest tests covering auth, RBAC, employees, risk scores, prediction, incidents, UEBA

**Not yet done:**

- ⬜ Automated/continuous activity log ingestion pipeline (currently a manual script)
- ⬜ Cloud deployment (AWS/Azure)
- ⬜ Reports & export system (PDF/Excel)
- ⬜ Monitoring/structured logging, /health endpoint
- ⬜ Dedicated Admin-only dashboard views (admin currently reuses the analyst view rather than having distinct screens)

## Known Gaps

Documented honestly rather than hidden:

- **Risk scoring** is scoped to Behavioral Anomalies only (100% weight). The original 5-category weighted model (Privilege Misuse, Data Access Violations, Access Pattern Deviations, Historical Security Events) isn't computable — the CERT logon/device dataset doesn't contain that data.
- **UEBA peer comparison** is org-wide, not department-based — the dataset has no department/role/org-chart fields, so true peer-group comparison isn't possible. Org-wide percentile comparison is used instead.
- **Storage** for risk scores, anomalies, alerts, and incidents is CSV/JSON files, not relational DB tables, despite the original architecture diagram implying PostgreSQL/MongoDB. Only users and employees are real DB tables.
- **No Asset Association** — device_info is a free-text field, not a structured/queryable asset table.
- **Role differentiation** is currently tab-visibility only (frontend) plus route-level checks (backend) — not fully separate, purpose-built dashboard layouts per role.
- DB schema documentation exists at `docs/DATABASE_SCHEMA.md` and includes these gaps explicitly.

## Project Structure

```
Insider-Threat-Behavioral-Intelligence-System/
├── backend/
│   └── app/
│       ├── auth.py
│       ├── models.py
│       ├── schemas.py
│       ├── rbac.py
│       ├── database.py
│       └── main.py
├── ml/
│   ├── behavioral_analytics.py
│   ├── risk_scoring_engine.py
│   ├── risk_api.py
│   ├── risk_dashboard.py
│   ├── predict_api.py
│   ├── investigation_api.py
│   ├── ueba_api.py
│   └── alerts_api.py
├── frontend/
│   ├── index.html
│   ├── dashboard.html
│   ├── predict.html
│   └── risk_scores.html
├── datasets/
├── docs/
│   ├── DATABASE_SCHEMA.md
│   └── wireframes/
├── tests/
│   └── test_api.py
├── docker/
├── Dockerfile
└── README.md
```

## Dataset

This project uses the CERT Insider Threat Dataset (r4.2) — logon and device activity logs — a widely-used academic dataset for insider threat research. Only `logon.csv` and `device.csv` were used; the full CERT release's ground-truth `answers/` folder (labeled malicious insiders) was not downloaded, so this project uses unsupervised anomaly detection rather than a labeled classifier.

## Getting Started

### Prerequisites

- Python 3.10+
- Docker (optional, for containerized run)

### Backend Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

### Running Tests

```bash
cd backend
python -m pytest ../tests/
```

### Docker

```bash
docker build --no-cache -t insider-threat-api .
docker run -p 8000:8000 insider-threat-api
```

## Author

**Krishna Vamsi Pallapu**
M.Tech AI & Data Science, KL University
AI Intern, Infosys Springboard

- GitHub: [Vamsi12022003](https://github.com/Vamsi12022003)
- LinkedIn: [pallapu-krishna-vamsi](https://linkedin.com/in/pallapu-krishna-vamsi)

## License

This project is developed for educational purposes as part of the Infosys Springboard internship program.