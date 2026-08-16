from fastapi import APIRouter, HTTPException, Depends
from app.rbac import require_role
import pandas as pd
import os

router = APIRouter()

RISK_SCORES_PATH = os.path.join(os.path.dirname(__file__), "user_risk_scores.csv")


def load_scores():
    if not os.path.exists(RISK_SCORES_PATH):
        raise HTTPException(
            status_code=500,
            detail=f"{RISK_SCORES_PATH} not found. Run risk_scoring_engine.py first."
        )
    return pd.read_csv(RISK_SCORES_PATH)


@router.get("/risk-scores")
def get_all_risk_scores(current_user: dict = Depends(require_role("security_analyst", "security_manager", "admin"))):
    df = load_scores()
    return df.to_dict(orient="records")


@router.get("/risk-scores/summary")
def get_summary(current_user: dict = Depends(require_role("security_analyst", "security_manager", "admin"))):
    df = load_scores()
    return df["risk_category"].value_counts().to_dict()


@router.get("/risk-scores/{user}")
def get_user_risk(user: str, current_user: dict = Depends(require_role("security_analyst", "security_manager", "admin"))):
    df = load_scores()
    row = df[df["user"] == user]
    if row.empty:
        raise HTTPException(status_code=404, detail=f"No risk record for user '{user}'")
    return row.to_dict(orient="records")[0]