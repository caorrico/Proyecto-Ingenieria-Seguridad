import io
import uuid

from fastapi.testclient import TestClient

from app.main import app


def test_complete_authenticated_workflow():
    client = TestClient(app)
    suffix = uuid.uuid4().hex[:10]
    username = f"user_{suffix}"
    password = "SecurePassword!2026"

    registered = client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
            "full_name": "Usuario de Prueba",
        },
    )
    assert registered.status_code == 201

    login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    uploaded = client.post(
        "/api/documents",
        files={"file": ("evidence.txt", io.BytesIO(b"immutable evidence"), "text/plain")},
        headers=headers,
    )
    assert uploaded.status_code == 201
    document_id = uploaded.json()["id"]
    assert len(uploaded.json()["sha256"]) == 64

    keys = client.post("/crypto/rsa/keys").json()
    signed = client.post(
        f"/api/documents/{document_id}/sign",
        data={"private_key": keys["private_key"]},
        headers=headers,
    )
    assert signed.status_code == 200
    assert signed.json()["signature"]

    verified = client.post(f"/api/documents/{document_id}/verify", headers=headers)
    assert verified.status_code == 200
    assert verified.json()["valid"] is True

    issued = client.post(
        "/api/certificates",
        json={"subject_cn": username, "public_key_pem": keys["public_key"], "subject_country": "EC"},
        headers=headers,
    )
    assert issued.status_code == 201
    certificate_id = issued.json()["id"]

    valid = client.post(f"/api/certificates/{certificate_id}/validate", headers=headers)
    assert valid.json() == {"valid": True, "reason": "VALID"}

    revoked = client.delete(f"/api/certificates/{certificate_id}", headers=headers)
    assert revoked.status_code == 200
    invalid = client.post(f"/api/certificates/{certificate_id}/validate", headers=headers)
    assert invalid.json() == {"valid": False, "reason": "REVOKED"}

    assert client.get("/api/documents").status_code == 401
