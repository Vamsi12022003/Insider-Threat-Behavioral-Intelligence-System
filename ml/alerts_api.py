"""
Alert & Notification System
Auto-generates alerts from risk scores (High/Critical) and lets analysts
acknowledge/resolve them. Alerts persist in ml/alerts.json, mirroring the
pattern used by investigation_api.py for incidents.

Wire into main.py the same way risk_api and investigation_api are wired:
    from ml.alerts_api import router as alerts_router
    app.include_router(alerts_router)
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
import os
import json
import pandas as pd

router = APIRouter()

BASE_DIR = os.path.dirname(__file__)
ALERTS_PATH = os.path.join(BASE_DIR, "alerts.json")
RISK_SCORES_PATH = os.path.join(BASE_DIR, "user_risk_scores.csv")

# Only these categories generate alerts automatically
ALERT_TRIGGER_CATEGORIES = {"High", "Critical"}

SEVERITY_MAP = {
    "Critical": "Critical",
    "High": "High",
}


class StatusUpdate(BaseModel):
    status: str  # "acknowledged" | "resolved"
    note: Optional[str] = None


def _load_alerts() -> List[dict]:
    if not os.path.exists(ALERTS_PATH):
        return []
    with open(ALERTS_PATH, "r") as f:
        return json.load(f)


def _save_alerts(alerts: List[dict]):
    with open(ALERTS_PATH, "w") as f:
        json.dump(alerts, f, indent=2)


def _load_risk_scores() -> pd.DataFrame:
    if not os.path.exists(RISK_SCORES_PATH):
        raise HTTPException(
            status_code=500,
            detail=f"{RISK_SCORES_PATH} not found. Run risk_scoring_engine.py first."
        )
    return pd.read_csv(RISK_SCORES_PATH)


@router.post("/alerts/generate")
def generate_alerts():
    """
    Scans current risk scores and creates a new alert for any user in
    High/Critical risk who doesn't already have an OPEN alert.
    Safe to call repeatedly (e.g. on a schedule, or after each dashboard load) —
    it will not duplicate alerts for users already alerted and unresolved.
    """
    df = _load_risk_scores()
    existing = _load_alerts()

    open_users = {
        a["user"] for a in existing if a["status"] == "open"
    }

    created = []
    next_seq = len(existing) + 1
    for _, row in df.iterrows():
        category = row.get("risk_category")
        if category not in ALERT_TRIGGER_CATEGORIES:
            continue
        user = row.get("user")
        if user in open_users:
            continue  # don't spam duplicate alerts for the same unresolved risk

        alert = {
            "id": f"ALT{next_seq:04d}",
            "user": user,
            "risk_score": row.get("insider_risk_score"),
            "risk_category": category,
            "severity": SEVERITY_MAP.get(category, "Medium"),
            "message": f"User '{user}' flagged as {category} insider risk "
                       f"(score {row.get('insider_risk_score')}).",
            "status": "open",  # open -> acknowledged -> resolved
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "note": None,
        }
        existing.append(alert)
        created.append(alert)
        next_seq += 1

    if created:
        _save_alerts(existing)

    return {"generated": len(created), "alerts": created}


@router.get("/alerts")
def list_alerts(status: Optional[str] = None, severity: Optional[str] = None):
    """Optional filters: ?status=open&severity=Critical"""
    alerts = _load_alerts()
    if status:
        alerts = [a for a in alerts if a["status"] == status]
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity]
    # newest first
    return sorted(alerts, key=lambda a: a["created_at"], reverse=True)


@router.get("/alerts/summary")
def alerts_summary():
    alerts = _load_alerts()
    summary = {"open": 0, "acknowledged": 0, "resolved": 0}
    for a in alerts:
        summary[a["status"]] = summary.get(a["status"], 0) + 1
    by_severity = {}
    for a in alerts:
        if a["status"] != "resolved":
            by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
    return {"by_status": summary, "open_by_severity": by_severity}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    alerts = _load_alerts()
    for a in alerts:
        if a["id"] == alert_id:
            return a
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")


@router.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, payload: StatusUpdate):
    if payload.status not in {"open", "acknowledged", "resolved"}:
        raise HTTPException(status_code=400, detail="status must be 'open', 'acknowledged', or 'resolved'")

    alerts = _load_alerts()
    for a in alerts:
        if a["id"] == alert_id:
            a["status"] = payload.status
            a["updated_at"] = datetime.now(timezone.utc).isoformat()
            if payload.note:
                a["note"] = payload.note
            _save_alerts(alerts)
            return a
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
