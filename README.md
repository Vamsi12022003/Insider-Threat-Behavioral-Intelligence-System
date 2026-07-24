# Insider Threat Behavioral Intelligence System

An AI-powered platform that monitors employee activity, builds behavioral baselines, detects anomalies, and generates risk-scored security alerts to help organizations identify potential insider threats before they escalate into data breaches or security incidents.

## Overview

This project is being developed as part of the Infosys Springboard AI Internship program. It combines user behavior analytics (UBA), entity behavior analytics (UEBA), and machine learning-based anomaly detection to continuously assess insider risk across an organization.

## Objective

Traditional security tools focus on external threats. This system focuses on the harder problem — detecting suspicious behavior from within an organization by:

- Continuously monitoring employee digital activity (logins, file access, email, device usage)
- Building individual behavioral baselines per employee
- Detecting statistically significant deviations from normal behavior
- Scoring and prioritizing insider risk
- Supporting security teams with investigation and alerting workflows

## Tech Stack

**Backend:** Python, FastAPI, JWT Authentication
**Database:** PostgreSQL
**Frontend:** JavaScript (React planned)
**Machine Learning:** Scikit-learn, Isolation Forest, Pandas, NumPy
**Dev Tools:** Git, GitHub, VS Code, Docker (planned)

## Project Status

🚧 **In Development — Milestone 2 of 4**

| Milestone | Focus | Status |
|-----------|-------|--------|
| Milestone 1 (Week 1-2) | Project setup, authentication, role-based access | ✅ Complete |
| Milestone 2 (Week 3-4) | Behavioral profiling & anomaly detection | 🔄 In Progress |
| Milestone 3 (Week 5-6) | Risk scoring & threat investigation | ⬜ Pending |
| Milestone 4 (Week 7-8) | Dashboards, testing & deployment | ⬜ Pending |

## Features (Planned & In Progress)

- ✅ Secure user registration & login (JWT-based authentication)
- ✅ Role-based access control (Security Analyst, SOC Engineer, Security Manager, Admin)
- 🔄 Behavioral baseline generation per employee
- 🔄 Anomaly detection engine (Isolation Forest)
- ⬜ Insider risk scoring engine
- ⬜ Threat investigation & incident management
- ⬜ Security dashboards for analysts and SOC teams

## Project Structure

```
Insider-Threat-Behavioral-Intelligence-System/
├── backend/
│   └── app/
│       ├── auth/
│       ├── models/
│       ├── routes/
│       ├── database.py
│       └── main.py
├── frontend/
├── datasets/
├── docker/
├── docker-compose.yml
└── README.md
```

## Dataset

This project uses a preprocessed, balanced subset derived from the **CERT Insider Threat Dataset**, a widely-used academic dataset for insider threat research covering login events, file access, email activity, and device usage.

## Getting Started

### Prerequisites
- Python 3.10+
- PostgreSQL
- Node.js (for frontend)

### Backend Setup
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Author

**Krishna Vamsi Pallapu**
M.Tech AI & Data Science, KL University
AI Intern, Infosys Springboard

- GitHub: [Vamsi12022003](https://github.com/Vamsi12022003)
- LinkedIn: [pallapu-krishna-vamsi](https://linkedin.com/in/pallapu-krishna-vamsi-850669245)

## License

This project is developed for educational purposes as part of the Infosys Springboard internship program.