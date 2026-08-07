"""
Automated API tests -- Insider Threat Behavioral Intelligence System

Covers every endpoint wired into backend/app/main.py:
  - /register, /login (auth)
  - RBAC enforcement on /employees (403 for non-admin, 200 for admin)
  - /employees CRUD
  - /risk-scores, /risk-scores/summary, /risk-scores/{user}
  - /predict (CSV upload)
  - /incidents (create, list, get, patch status)
  - /ueba/{user}/peer-comparison, /ueba/{user}/trend

Uses FastAPI's TestClient against the real app (real SQLite/Postgres DB per
your DATABASE_URL, real CSV/JSON data files under ml/). This is NOT an
isolated unit-test suite with mocks -- it hits the same data your manual
testing hit, which is intentional: it re-verifies exactly what you already
confirmed by hand, just automated and repeatable.

NOTE: /predict, /incidents, and /ueba tests assume MPM0220 exists in
anomaly_report.csv / user_baselines.csv (per prior manual verification in
this project). If your data differs, replace TEST_USER below.

Run with:
    cd backend
    ./venv/Scripts/python.exe -m pytest ../tests/test_api.py -v
"""

import io
import uuid
import pytest
from fastapi.testclient import TestClient

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.main import app

client = TestClient(app)

TEST_USER = "MPM0220"  # known to have anomaly history per earlier manual testing


def _unique_username(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------

def test_root():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "status" in resp.json()


# ---------------------------------------------------------------------------
# Auth: register + login
# ---------------------------------------------------------------------------

def test_register_and_login_analyst():
    username = _unique_username("analyst")
    reg = client.post("/register", json={
        "username": username,
        "email": f"{username}@example.com",
        "password": "test1234",
        "role": "security_analyst",
    })
    assert reg.status_code == 200, reg.text
    assert reg.json()["role"] == "security_analyst"

    login = client.post("/login", data={
        "username": username,
        "password": "test1234",
    })
    assert login.status_code == 200, login.text
    body = login.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


def test_login_wrong_password_fails():
    username = _unique_username("baduser")
    client.post("/register", json={
        "username": username,
        "email": f"{username}@example.com",
        "password": "correctpass",
        "role": "security_analyst",
    })
    resp = client.post("/login", data={
        "username": username,
        "password": "wrongpass",
    })
    assert resp.status_code == 401


def test_register_duplicate_username_fails():
    username = _unique_username("dup")
    payload = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "test1234",
        "role": "security_analyst",
    }
    first = client.post("/register", json=payload)
    assert first.status_code == 200
    second = client.post("/register", json=payload)
    assert second.status_code == 400


# ---------------------------------------------------------------------------
# Helpers for authenticated requests
# ---------------------------------------------------------------------------

def _register_and_get_token(role: str) -> str:
    username = _unique_username(role)
    client.post("/register", json={
        "username": username,
        "email": f"{username}@example.com",
        "password": "test1234",
        "role": role,
    })
    login = client.post("/login", data={"username": username, "password": "test1234"})
    return login.json()["access_token"]


@pytest.fixture(scope="module")
def analyst_token():
    return _register_and_get_token("security_analyst")


@pytest.fixture(scope="module")
def admin_token():
    return _register_and_get_token("admin")


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# RBAC + Employee CRUD
# ---------------------------------------------------------------------------

def test_employees_requires_auth():
    resp = client.get("/employees")
    assert resp.status_code == 401


def test_create_employee_forbidden_for_analyst(analyst_token):
    resp = client.post(
        "/employees",
        json={"employee_id": _unique_username("EMP"), "full_name": "Should Fail"},
        headers=_auth(analyst_token),
    )
    assert resp.status_code == 403


def test_create_employee_allowed_for_admin(admin_token):
    emp_id = _unique_username("EMP")
    resp = client.post(
        "/employees",
        json={
            "employee_id": emp_id,
            "full_name": "Test Employee",
            "department": "IT",
            "designation": "Analyst",
        },
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["employee_id"] == emp_id

    get_resp = client.get(f"/employees/{emp_id}", headers=_auth(admin_token))
    assert get_resp.status_code == 200
    assert get_resp.json()["full_name"] == "Test Employee"

    delete_resp = client.delete(f"/employees/{emp_id}", headers=_auth(admin_token))
    assert delete_resp.status_code == 200


def test_delete_employee_forbidden_for_analyst(admin_token, analyst_token):
    emp_id = _unique_username("EMP")
    client.post(
        "/employees",
        json={"employee_id": emp_id, "full_name": "Temp"},
        headers=_auth(admin_token),
    )
    resp = client.delete(f"/employees/{emp_id}", headers=_auth(analyst_token))
    assert resp.status_code == 403

    # cleanup as admin
    client.delete(f"/employees/{emp_id}", headers=_auth(admin_token))


def test_list_employees_readable_by_analyst(analyst_token):
    resp = client.get("/employees", headers=_auth(analyst_token))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# Risk scores (Milestone 3)
# ---------------------------------------------------------------------------

def test_risk_scores_summary():
    resp = client.get("/risk-scores/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, dict)


def test_risk_scores_list():
    resp = client.get("/risk-scores")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_risk_score_for_known_user():
    resp = client.get(f"/risk-scores/{TEST_USER}")
    assert resp.status_code in (200, 404)  # 404 acceptable if data regenerated differently


# ---------------------------------------------------------------------------
# Predict (Milestone 3 -- live CSV prediction)
# ---------------------------------------------------------------------------

def test_predict_endpoint_with_sample_csv():
    csv_content = (
        "user,day,logon_count,logoff_count,unique_pcs,after_hours_ratio,device_connects\n"
        f"{TEST_USER},2010-08-05,15,15,3,0.6,2\n"
    )
    files = {"file": ("sample.csv", io.BytesIO(csv_content.encode()), "text/csv")}
    resp = client.post("/predict", files=files)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, dict)
    assert "predictions" in body
    assert body["count"] == 1
    prediction = body["predictions"][0]
    assert prediction["user"] == TEST_USER
    assert prediction["prediction"] in ("Insider", "Normal")


# ---------------------------------------------------------------------------
# Threat Investigation (Milestone 3)
# ---------------------------------------------------------------------------

def test_incident_lifecycle():
    create = client.post("/incidents", json={"user": TEST_USER, "notes": "pytest test incident"})
    assert create.status_code == 200, create.text
    incident = create.json()
    incident_id = incident["incident_id"]
    assert incident["user"] == TEST_USER

    get_one = client.get(f"/incidents/{incident_id}")
    assert get_one.status_code == 200
    assert get_one.json()["incident_id"] == incident_id

    list_all = client.get("/incidents")
    assert list_all.status_code == 200
    assert any(i["incident_id"] == incident_id for i in list_all.json())

    patch = client.patch(f"/incidents/{incident_id}/status", json={"status": "investigating"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "investigating"


def test_incident_creation_fails_for_unknown_user():
    resp = client.post("/incidents", json={"user": "NO_SUCH_USER_XYZ", "notes": None})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# UEBA (Milestone 3)
# ---------------------------------------------------------------------------

def test_ueba_peer_comparison():
    resp = client.get(f"/ueba/{TEST_USER}/peer-comparison")
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)


def test_ueba_trend():
    resp = client.get(f"/ueba/{TEST_USER}/trend")
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)
