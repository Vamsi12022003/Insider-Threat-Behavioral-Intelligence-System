"""
Insider Threat Behavioral Intelligence System
Milestone 3/4: API endpoint exposing insider risk scores

Run with:
    uvicorn risk_api:app --reload --port 8000

Endpoints:
    GET /risk-scores            -> full list, sorted by risk descending
    GET /risk-scores/{user}     -> single user's risk record
    GET /risk-scores/summary    -> counts per risk category

NOTE: This reads the CSV produced by risk_scoring_engine.py. In a real
deployment this would query the DB the Milestone 2/3 pipeline writes to;
for now it reads the file directly since no DB table for risk scores
exists yet - that wiring is future work, not done here.
"""

from fastapi import FastAPI, HTTPException
import pandas as pd
import os

app = FastAPI(title="Insider Risk Scoring API")

RISK_SCORES_PATH = os.path.join(os.path.dirname(__file__), "user_risk_scores.csv")


def load_scores():
    if not os.path.exists(RISK_SCORES_PATH):
        raise HTTPException(
            status_code=500,
            detail=f"{RISK_SCORES_PATH} not found. Run risk_scoring_engine.py first."
        )
    return pd.read_csv(RISK_SCORES_PATH)


@app.get("/risk-scores")
def get_all_risk_scores():
    df = load_scores()
    return df.to_dict(orient="records")


@app.get("/risk-scores/summary")
def get_summary():
    df = load_scores()
    return df["risk_category"].value_counts().to_dict()


@app.get("/risk-scores/{user}")
def get_user_risk(user: str):
    df = load_scores()
    row = df[df["user"] == user]
    if row.empty:
        raise HTTPException(status_code=404, detail=f"No risk record for user '{user}'")
    return row.to_dict(orient="records")[0]


@app.get("/health")
def health():
    return {"status": "ok"}
