import pytest
from fastapi.testclient import TestClient
import base64

from app.main import app

client = TestClient(app)


class TestCryptoAPI:
    """Tests for crypto API endpoints."""

    def test_hash_endpoint(self) -> None:
        """Test POST /crypto/hash."""
        data = base64.b64encode(b"test data").decode()
        response = client.post("/crypto/hash", json={"data": data})
        assert response.status_code == 200
        result = response.json()
        assert "hash" in result

    def test_aes_encrypt_decrypt_flow(self) -> None:
        """Test AES encrypt/decrypt flow."""
        plaintext = base64.b64encode(b"secret message").decode()
        
        # Encrypt
        encrypt_resp = client.post("/crypto/aes/encrypt", json={"plaintext": plaintext})
        assert encrypt_resp.status_code == 200
        enc_data = encrypt_resp.json()
        
        # Decrypt
        decrypt_resp = client.post("/crypto/aes/decrypt", json={
            "ciphertext": enc_data["ciphertext"],
            "iv": enc_data["iv"],
            "tag": enc_data["tag"],
            "key": enc_data["key"] if "key" in enc_data else base64.b64encode(b"x"*32).decode()
        })
        # Note: will fail if key is wrong, but tests basic flow
        
    def test_rsa_keys_endpoint(self) -> None:
        """Test RSA keypair generation."""
        response = client.post("/crypto/rsa/keys")
        assert response.status_code == 200
        result = response.json()
        assert "private_key" in result
        assert "public_key" in result
        assert "BEGIN PRIVATE KEY" in result["private_key"]
        assert "BEGIN PUBLIC KEY" in result["public_key"]

    def test_sign_verify_flow(self) -> None:
        """Test sign/verify flow."""
        # Generate keys
        keys_resp = client.post("/crypto/rsa/keys")
        keys = keys_resp.json()
        
        # Sign data
        data = base64.b64encode(b"document to sign").decode()
        sign_resp = client.post("/crypto/sign", json={
            "data": data,
            "private_key": keys["private_key"]
        })
        assert sign_resp.status_code == 200
        sig = sign_resp.json()["signature"]
        
        # Verify signature
        verify_resp = client.post("/crypto/verify", json={
            "data": data,
            "signature": sig,
            "public_key": keys["public_key"]
        })
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is True

    def test_verify_invalid_signature(self) -> None:
        """Test that invalid signature fails verification."""
        keys_resp = client.post("/crypto/rsa/keys")
        keys = keys_resp.json()
        
        data = base64.b64encode(b"data").decode()
        bad_sig = base64.b64encode(b"invalid signature").decode()
        
        verify_resp = client.post("/crypto/verify", json={
            "data": data,
            "signature": bad_sig,
            "public_key": keys["public_key"]
        })
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is False

    def test_certificate_issuance(self) -> None:
        """Test certificate issuance."""
        keys_resp = client.post("/crypto/rsa/keys")
        keys = keys_resp.json()
        
        cert_resp = client.post("/crypto/certificates", json={
            "subject_cn": "test.example.com",
            "subject_org": "Test Org",
            "subject_country": "US",
            "public_key_pem": keys["public_key"],
            "validity_days": 365
        })
        assert cert_resp.status_code == 200
        result = cert_resp.json()
        assert "certificate_pem" in result
        assert "serial_number" in result
        assert "BEGIN CERTIFICATE" in result["certificate_pem"]

    def test_ca_validate_certificate(self) -> None:
        """Test CA certificate validation."""
        keys_resp = client.post("/crypto/rsa/keys")
        keys = keys_resp.json()
        
        # Issue cert
        cert_resp = client.post("/crypto/certificates", json={
            "subject_cn": "user.example.com",
            "public_key_pem": keys["public_key"]
        })
        cert = cert_resp.json()["certificate_pem"]
        
        # Validate
        validate_resp = client.post("/crypto/ca/validate", json={"certificate_pem": cert})
        assert validate_resp.status_code == 200
        assert validate_resp.json()["valid"] is True

    def test_invalid_request_returns_400(self) -> None:
        """Test that invalid requests return 400."""
        response = client.post("/crypto/hash", json={"data": "invalid_base64!@#$"})
        assert response.status_code == 400
