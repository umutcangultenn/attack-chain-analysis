import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import db

client = TestClient(app)

def setup_function():
    db.clear()

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Attack Chain Analysis System API is running"}

def test_upload_flow():
    # 1. Upload ZAP Report
    with open("sample_data/zap_report_sample.json", "rb") as f:
        response = client.post("/api/v1/reports/zap", files={"file": ("report.json", f, "application/json")})
        assert response.status_code == 200
        assert response.json()["count"] > 0
        
    # 2. Upload Access Log
    with open("sample_data/sample_logs/access.log", "rb") as f:
        response = client.post("/api/v1/logs/upload", files={"file": ("access.log", f, "text/plain")}, data={"log_type": "access"})
        assert response.status_code == 200
        assert response.json()["count"] > 0

    # 3. Trigger Analysis
    response = client.post("/api/v1/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["chains_created"] > 0
    
    # 4. Get Scenarios
    response = client.get("/api/v1/scenarios")
    assert response.status_code == 200
    assert len(response.json()) > 0
