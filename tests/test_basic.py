import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_read_main():
    response = client.get("/")
    assert response.status_code == 200

def test_products_api():
    response = client.get("/api/v1/store/products")
    assert response.status_code == 200

def test_telemetry_no_key():
    response = client.post("/api/v1/telemetry", json={
        "session_id": "test",
        "page": "/",
        "browser": {}
    })
    # Should be rejected
    assert response.status_code == 401

def test_telemetry_valid_key():
    response = client.post("/api/v1/telemetry", headers={"X-Adamantine-Key": "adm_live_demo"}, json={
        "session_id": "test",
        "page": "/",
        "browser": {}
    })
    assert response.status_code == 200

def test_overview_api():
    response = client.get("/api/v1/overview")
    assert response.status_code == 200
    assert "tenant" in response.json()
