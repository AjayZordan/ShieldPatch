# tests/test_risk_log.py
import json
from app import app, db
from models import RiskLog

def test_prediction_logging(monkeypatch):
    client = app.test_client()
    payload = {"cve_id": "CVE-TEST-0001", "features": {"cvss": 9.0}}

    # call endpoint
    resp = client.post("/predict-risk", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "predicted_score" in data
    assert data["logged"] is True
    assert data["log_id"] is not None

    # confirm in DB
    log = RiskLog.query.get(data["log_id"])
    assert log is not None
    assert log.cve_id == "CVE-TEST-0001"
    assert isinstance(log.input_payload, dict)
    # cleanup
    db.session.delete(log)
    db.session.commit()