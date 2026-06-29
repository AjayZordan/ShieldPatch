# tests/test_vulnlookup.py
import io
import json
import pytest
from flask import url_for

# Adjust import depending how you run app; here we assume app factory exposes `app`
from app import app as flask_app  # if your app is called app.py with Flask instance named app

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as client:
        yield client

def test_model_info(client):
    resp = client.get("/api/vulnlookup/model_info")
    assert resp.status_code == 200
    j = resp.get_json()
    assert "success" in j and j["success"] is True
    assert "model" in j

def test_batch_predict_json_valid(client):
    payload = [{
        "description_text": "unittest test",
        "cvss_score": 7.8,
        "references_count": 1,
        "weaknesses_count": 0,
        "os_count": 1,
        "severity": "HIGH",
        "years_since_published": 0.5
    }]
    resp = client.post("/api/vulnlookup/predict/batch", json=payload)
    assert resp.status_code == 200
    j = resp.get_json()
    assert j.get("success") is True
    assert j.get("count") == 1

def test_batch_predict_validation_missing_fields(client):
    payload = [{"description_text": "missing numbers"}]
    resp = client.post("/api/vulnlookup/predict/batch", json=payload)
    j = resp.get_json()
    assert resp.status_code == 400
    assert j.get("success") is False

def test_request_size_limit(client, monkeypatch):
    # monkeypatch the max size to a tiny number for the test
    from routes import vulnlookup_routes
    monkeypatch.setattr(vulnlookup_routes, "MAX_UPLOAD_BYTES", 1)  # 1 byte limit
    payload = [{
        "description_text": "test",
        "cvss_score": 1,
        "references_count": 1,
        "weaknesses_count": 1,
        "os_count": 1,
        "severity": "LOW",
        "years_since_published": 0
    }]
    resp = client.post("/api/vulnlookup/predict/batch", json=payload)
    assert resp.status_code in (400, 413)