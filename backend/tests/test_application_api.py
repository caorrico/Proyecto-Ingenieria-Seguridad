import io
import uuid

from fastapi.testclient import TestClient
from reportlab.pdfgen import canvas
from pyhanko.pdf_utils.reader import PdfFileReader

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
    assert registered.json()["role"] == "user"

    login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    rejected = client.post(
        "/api/documents",
        files={"file": ("malware.exe", io.BytesIO(b"MZ-not-allowed"), "application/octet-stream")},
        headers=headers,
    )
    assert rejected.status_code == 415
    disguised = client.post(
        "/api/documents",
        files={"file": ("falso.pdf", io.BytesIO(b"not a real pdf"), "application/pdf")},
        headers=headers,
    )
    assert disguised.status_code == 415

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


def test_password_policy_profile_and_visible_pdf_signature():
    client = TestClient(app)
    suffix = uuid.uuid4().hex[:10]
    username = f"secure_{suffix}"
    weak_passwords = [
        "Short1!",
        "alllowercase1!",
        "NoNumberSpecial!",
        "NoSpecialNumber1",
    ]
    for password in weak_passwords:
        response = client.post(
            "/api/auth/register",
            json={
                "username": f"{username}_{len(password)}",
                "email": f"{len(password)}_{suffix}@example.com",
                "password": password,
                "full_name": "Prueba Débil",
            },
        )
        assert response.status_code == 422

    password = "StrongPassword!2026"
    registered = client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
            "full_name": "Firmante Inicial",
        },
    )
    assert registered.status_code == 201
    user_id = registered.json()["id"]
    login = client.post("/api/auth/login", json={"username": username, "password": password})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    profile = client.patch(
        f"/api/users/{user_id}",
        json={"full_name": "Firmante Actualizado", "email": f"new_{username}@example.com"},
        headers=headers,
    )
    assert profile.status_code == 200
    assert profile.json()["full_name"] == "Firmante Actualizado"

    changed = client.post(
        "/api/auth/change-password",
        json={"current_password": password, "new_password": "AnotherStrong!2027"},
        headers=headers,
    )
    assert changed.status_code == 204
    assert client.post(
        "/api/auth/login", json={"username": username, "password": "AnotherStrong!2027"}
    ).status_code == 200

    pdf_buffer = io.BytesIO()
    pdf = canvas.Canvas(pdf_buffer)
    pdf.drawString(72, 750, "Documento para firma visible")
    pdf.save()
    uploaded = client.post(
        "/api/documents",
        files={"file": ("contrato.pdf", io.BytesIO(pdf_buffer.getvalue()), "application/pdf")},
        headers=headers,
    )
    document_id = uploaded.json()["id"]
    keys = client.post("/crypto/rsa/keys").json()
    signed = client.post(
        f"/api/documents/{document_id}/visual-sign",
        json={
            "private_key": keys["private_key"],
            "signer_name": "Firmante Actualizado",
            "page": 1,
            "x": 0.65,
            "y": 0.75,
        },
        headers=headers,
    )
    assert signed.status_code == 200
    assert signed.json()["signature"]
    downloaded = client.get(f"/api/documents/{document_id}/download", headers=headers)
    adobe_reader = PdfFileReader(io.BytesIO(downloaded.content))
    assert len(adobe_reader.embedded_signatures) == 1
    assert adobe_reader.embedded_signatures[0].field_name.startswith("SecureSign_")
    public_check = client.get(f"/api/public/documents/{document_id}/verify")
    assert public_check.status_code == 200
    assert public_check.json()["signature_valid"] is True


def test_documents_are_strictly_private_between_users():
    client = TestClient(app)
    suffix = uuid.uuid4().hex[:10]
    password = "PrivateFiles!2026"
    headers = []

    for index in range(2):
        username = f"private_{index}_{suffix}"
        registered = client.post(
            "/api/auth/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": password,
                "full_name": f"Usuario Privado {index}",
            },
        )
        assert registered.status_code == 201
        login = client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
        headers.append({"Authorization": f"Bearer {login.json()['access_token']}"})

    uploaded = client.post(
        "/api/documents",
        files={"file": ("privado.txt", io.BytesIO(b"contenido privado"), "text/plain")},
        headers=headers[0],
    )
    assert uploaded.status_code == 201
    document_id = uploaded.json()["id"]

    assert any(item["id"] == document_id for item in client.get("/api/documents", headers=headers[0]).json())
    assert all(item["id"] != document_id for item in client.get("/api/documents", headers=headers[1]).json())

    private_routes = [
        ("get", f"/api/documents/{document_id}"),
        ("get", f"/api/documents/{document_id}/download"),
        ("post", f"/api/documents/{document_id}/verify"),
        ("delete", f"/api/documents/{document_id}"),
    ]
    for method, route in private_routes:
        response = getattr(client, method)(route, headers=headers[1])
        assert response.status_code == 403
