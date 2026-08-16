"""
Insider Threat Behavioral Intelligence System
Milestone 3: Threat Investigation Module

SCOPE NOTE
----------
"Correlation" here means: pulling every anomalous user-day already flagged
for this user by the Milestone 2 Isolation Forest pipeline (anomaly_report.csv)
into one timeline. It is real correlation of real flagged events, not a
black-box ML correlation engine - there's no additional model here, just
aggregation of existing verified anomaly data per user.

"Evidence" means: the actual anomaly rows (score + reason) attached to the
incident at creation time, so the record captures what was known when the
incident was opened, even if new anomalies get flagged for that user later.

Storage: a flat JSON file (incidents.json) in this folder. No new DB table -
this project's SQLAlchemy models/migrations were not modified, since the
schema wasn't shown/confirmed. If a persistent relational store is needed
later, this is the place to swap in a real Incident table.

Run via: wired into backend/app/main.py as a router (see instructions).
"""

from fastapi import APIRouter, HTTPException, Depends
from app.rbac import require_role
from pydantic import BaseModel
from typing import Optional, List
import pandas as pd
import json
import os
import uuid
from datetime import datetime, timezone

router = APIRouter()

BASE_DIR = os.path.dirname(__file__)
ANOMALY_REPORT_PATH = os.path.join(BASE_DIR, "anomaly_report.csv")
INCIDENTS_PATH = os.path.join(BASE_DIR, "incidents.json")

VALID_STATUSES = ["open", "investigating", "resolved", "closed"]


class IncidentCreate(BaseModel):
    user: str
    notes: Optional[str] = None


class StatusUpdate(BaseModel):
    status: str


def _load_incidents() -> List[dict]:
    if not os.path.exists(INCIDENTS_PATH):
        return []
    with open(INCIDENTS_PATH, "r") as f:
        return json.load(f)


def _save_incidents(incidents: List[dict]):
    with open(INCIDENTS_PATH, "w") as f:
        json.dump(incidents, f, indent=2, default=str)


def _get_user_timeline(user: str) -> List[dict]:
    """Real correlation: every anomalous day already flagged for this user."""
    if not os.path.exists(ANOMALY_REPORT_PATH):
        raise HTTPException(
            status_code=500,
            detail="anomaly_report.csv not found. Run behavioral_analytics.py first."
        )
    df = pd.read_csv(ANOMALY_REPORT_PATH)
    user_rows = df[df["user"] == user].sort_values("day")
    if user_rows.empty:
        return []
    return user_rows[["day", "anomaly_score", "primary_reason"]].to_dict(orient="records")


@router.post("/incidents")
def create_incident(payload: IncidentCreate, current_user: dict = Depends(require_role("security_analyst", "security_manager", "admin"))):
    timeline = _get_user_timeline(payload.user)
    if not timeline:
        raise HTTPException(
            status_code=404,
            detail=f"No anomalies on record for user '{payload.user}' — cannot open an "
                   f"incident with no correlating evidence. Check the username or run "
                   f"behavioral_analytics.py if this user should have data."
        )

    incidents = _load_incidents()
    incident_id = str(uuid.uuid4())[:8]

    new_incident = {
        "incident_id": incident_id,
        "user": payload.user,
        "status": "open",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "notes": payload.notes,
        "anomalous_day_count": len(timeline),
        "evidence": timeline,  # snapshot at creation time
    }
    incidents.append(new_incident)
    _save_incidents(incidents)
    return new_incident


@router.get("/incidents")
def list_incidents(current_user: dict = Depends(require_role("security_analyst", "security_manager", "admin"))):
    return _load_incidents()


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, current_user: dict = Depends(require_role("security_analyst", "security_manager", "admin"))):
    incidents = _load_incidents()
    for inc in incidents:
        if inc["incident_id"] == incident_id:
            # refresh timeline with any newer anomalies beyond the original snapshot
            current_timeline = _get_user_timeline(inc["user"])
            return {**inc, "current_timeline": current_timeline}
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@router.patch("/incidents/{incident_id}/status")
def update_status(incident_id: str, payload: StatusUpdate, current_user: dict = Depends(require_role("security_analyst", "security_manager", "admin"))):
    if payload.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Must be one of {VALID_STATUSES}"
        )
    incidents = _load_incidents()
    for inc in incidents:
        if inc["incident_id"] == incident_id:
            inc["status"] = payload.status
            inc["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_incidents(incidents)
            return inc
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
