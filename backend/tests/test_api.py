from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_read_openapi():
    response = client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    assert "openapi" in response.json()
