# Insider Threat Behavioral Intelligence System - Backend API
#
# SCOPE NOTE: this builds and runs the FastAPI backend (auth, employees,
# risk scoring, prediction, investigation, UEBA endpoints). It does NOT
# retrain the ML model - it copies the already-generated model/data files
# (insider_model.pkl, user_baselines.csv, anomaly_report.csv, etc.) from
# ml/ into the image. If those files don't exist yet on your machine,
# run behavioral_analytics.py and risk_scoring_engine.py locally first
# to generate them, then build this image.

FROM python:3.12-slim

WORKDIR /app

# Install backend Python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend app code
COPY backend/app ./backend/app

# Copy ml/ - routers (risk_api.py, predict_api.py, investigation_api.py,
# ueba_api.py) live here and are imported via sys.path in main.py.
# This also brings in the pre-generated CSVs/model file the routers read
# at runtime (anomaly_report.csv, user_risk_scores.csv, insider_model.pkl,
# user_baselines.csv, user_daily_features.csv, incidents.json).
COPY ml ./ml

WORKDIR /app/backend

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
