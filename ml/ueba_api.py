"""
Insider Threat Behavioral Intelligence System
Milestone 3: UEBA Intelligence Engine (peer comparison + trend analysis)

SCOPE NOTE
----------
True "peer group" comparison (comparing a user against others in the same
department/role) requires org-chart data - department, role, team fields.
That data does not exist anywhere in this project's datasets (logon.csv,
device.csv only have user/date/activity/pc). Building a fake peer group
would misrepresent what the system actually knows.

What IS implemented instead: ORG-WIDE population percentile comparison -
"this user's after-hours activity is higher than 95% of all other users."
This is a real, honest form of behavioral comparison (population baseline
rather than role baseline), and is a legitimate fallback UEBA approach when
org-chart data isn't available. It is documented here and in the API output
so it's never confused with true peer-group (departmental) comparison.

Trend analysis IS fully supported by the data: monthly anomaly counts per
user, to show whether a user's flagged behavior is increasing, decreasing,
or stable over time.
"""

from fastapi import APIRouter, HTTPException, Depends
from app.rbac import require_role
import pandas as pd
import os

router = APIRouter()

BASE_DIR = os.path.dirname(__file__)
FEATURES_PATH = os.path.join(BASE_DIR, "user_daily_features.csv")
ANOMALY_REPORT_PATH = os.path.join(BASE_DIR, "anomaly_report.csv")

FEATURE_COLS = ["logon_count", "logoff_count", "unique_pcs", "after_hours_ratio", "device_connects"]


def _load_features():
    if not os.path.exists(FEATURES_PATH):
        raise HTTPException(
            status_code=500,
            detail="user_daily_features.csv not found. Run behavioral_analytics.py first."
        )
    return pd.read_csv(FEATURES_PATH, parse_dates=["day"])


def _load_anomalies():
    if not os.path.exists(ANOMALY_REPORT_PATH):
        raise HTTPException(
            status_code=500,
            detail="anomaly_report.csv not found. Run behavioral_analytics.py first."
        )
    return pd.read_csv(ANOMALY_REPORT_PATH, parse_dates=["day"])


@router.get("/ueba/{user}/peer-comparison")
def peer_comparison(user: str, current_user: dict = Depends(require_role("security_analyst", "security_manager", "admin"))):
    """
    Org-wide population percentile comparison (NOT department/role peer
    comparison - see module scope note above).
    """
    df = _load_features()
    if user not in df["user"].values:
        raise HTTPException(status_code=404, detail=f"No feature data for user '{user}'")

    user_means = df[df["user"] == user][FEATURE_COLS].mean()

    # Per-user org-wide average, so we compare user-level behavior to
    # other users' typical behavior, not raw daily rows.
    org_user_means = df.groupby("user")[FEATURE_COLS].mean()

    result = {}
    for col in FEATURE_COLS:
        user_val = user_means[col]
        percentile = (org_user_means[col] < user_val).mean() * 100
        result[col] = {
            "user_average": round(float(user_val), 4),
            "org_average": round(float(org_user_means[col].mean()), 4),
            "percentile_vs_org": round(float(percentile), 1),
        }

    return {
        "user": user,
        "scope_note": "Comparison is against the entire org population, not a "
                       "department/role peer group - no org-chart data exists in this project.",
        "comparison": result,
    }


@router.get("/ueba/{user}/trend")
def trend_analysis(user: str, current_user: dict = Depends(require_role("security_analyst", "security_manager", "admin"))):
    """Monthly anomaly count for this user - is flagged behavior increasing or not."""
    df = _load_anomalies()
    user_anomalies = df[df["user"] == user].copy()

    if user_anomalies.empty:
        return {
            "user": user,
            "trend": [],
            "note": "No anomalies on record for this user.",
        }

    user_anomalies["month"] = user_anomalies["day"].dt.to_period("M").astype(str)
    monthly = user_anomalies.groupby("month").agg(
        anomaly_count=("day", "count"),
        avg_anomaly_score=("anomaly_score", "mean"),
    ).reset_index().sort_values("month")

    months = monthly["month"].tolist()
    counts = monthly["anomaly_count"].tolist()

    if len(counts) >= 2:
        first_half_avg = sum(counts[: len(counts) // 2]) / max(len(counts) // 2, 1)
        second_half_avg = sum(counts[len(counts) // 2:]) / max(len(counts) - len(counts) // 2, 1)
        if second_half_avg > first_half_avg * 1.2:
            direction = "increasing"
        elif second_half_avg < first_half_avg * 0.8:
            direction = "decreasing"
        else:
            direction = "stable"
    else:
        direction = "insufficient_data"

    return {
        "user": user,
        "monthly_breakdown": monthly.to_dict(orient="records"),
        "trend_direction": direction,
    }
