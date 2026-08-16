"""
Insider Threat Behavioral Intelligence System
Module 11: Notification & Escalation System

SCOPE NOTE
----------
This module is a READ-ONLY aggregation view over data that already exists
in alerts.json (Module 9) and incidents.json (Module 7). It does not
introduce a new source of truth or a new storage file - notifications are
computed live from those two files every time this endpoint is called.

This avoids two systems (alerts vs notifications) silently drifting out of
sync, and matches the same "derive from source of truth" pattern already
used by investigation_api.py's current_timeline field.

What IS implemented (real data backing exists):
- Insider threat alerts       -> open/critical rows from alerts.json
- Investigation notifications -> incidents.json rows with status "investigating"
- Escalation alerts           -> any alert still "open" longer than
                                  ESCALATION_THRESHOLD_HOURS (computed live
                                  from created_at, nothing is silently
                                  auto-changed in alerts.json itself)
- Security event updates      -> newly created alerts/incidents, folded
                                  into the same feed with a "kind" field

What is NOT implemented, and why:
- Compliance notifications - no compliance module or compliance data
  source exists anywhere in this project. Rather than fabricate this,
  it is left out. If a compliance module is added later, this is the
  file to extend.
"""

from fastapi import APIRouter
from typing import List
from datetime import datetime, timezone
import os
import json

router = APIRouter()

BASE_DIR = os.path.dirname(__file__)
ALERTS_PATH = os.path.join(BASE_DIR, "alerts.json")
INCIDENTS_PATH = os.path.join(BASE_DIR, "incidents.json")

ESCALATION_THRESHOLD_HOURS = 24


def _load_json(path: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)


def _hours_since(iso_ts: str) -> float:
    then = datetime.fromisoformat(iso_ts)
    now = datetime.now(timezone.utc)
    return (now - then).total_seconds() / 3600.0


@router.get("/notifications")
def list_notifications():
    alerts = _load_json(ALERTS_PATH)
    incidents = _load_json(INCIDENTS_PATH)

    feed = []

    # Insider threat alerts + escalation (derived, not stored)
    for a in alerts:
        if a["status"] == "resolved":
            continue

        age_hours = _hours_since(a["created_at"])
        is_escalated = a["status"] == "open" and age_hours >= ESCALATION_THRESHOLD_HOURS

        feed.append({
            "kind": "escalation_alert" if is_escalated else "insider_threat_alert",
            "source_id": a["id"],
            "user": a["user"],
            "severity": a["severity"],
            "message": (
                f"ESCALATED (open {age_hours:.1f}h, threshold {ESCALATION_THRESHOLD_HOURS}h): {a['message']}"
                if is_escalated else a["message"]
            ),
            "status": a["status"],
            "created_at": a["created_at"],
        })

    # Investigation notifications
    for inc in incidents:
        if inc["status"] != "investigating":
            continue
        feed.append({
            "kind": "investigation_notification",
            "source_id": inc["incident_id"],
            "user": inc["user"],
            "severity": None,
            "message": f"Incident {inc['incident_id']} for user '{inc['user']}' is under investigation "
                       f"({inc['anomalous_day_count']} anomalous days on record).",
            "status": inc["status"],
            "created_at": inc["created_at"],
        })

    # newest first
    return sorted(feed, key=lambda n: n["created_at"], reverse=True)


@router.get("/notifications/summary")
def notifications_summary():
    feed = list_notifications()
    summary = {"insider_threat_alert": 0, "escalation_alert": 0, "investigation_notification": 0}
    for n in feed:
        summary[n["kind"]] = summary.get(n["kind"], 0) + 1
    return summary
