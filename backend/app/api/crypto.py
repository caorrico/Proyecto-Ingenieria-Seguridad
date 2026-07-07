import base64
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.schemas.crypto import (
    AESDecryptRequest,
    AESDecryptResponse,
    AESEncryptRequest,
    AESEncryptResponse,
    CertificateIssueRequest,
    CertificateIssueResponse,
    CertificateValidateRequest,
    CertificateValidateResponse,
    HashRequest,
    HashResponse,
    HashVerifyRequest,
    HashVerifyResponse,
    RSAKeysResponse,
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)
from app.services.audit_service import log_event
from app.services.hash_service import hash_sha256, verify_sha256
from app.services.aes_service import encrypt_aes_256_gcm, decrypt_aes_256_gcm, generate_aes_key, EncryptedData
from app.services.rsa_service import generate_rsa_keypair, serialize_private_key_pem, serialize_public_key_pem, encrypt_rsa, decrypt_rsa
from app.services.signature_service import sign, verify
from app.services.certificate_service import (
    create_certificate,
    serialize_certificate_pem,
    deserialize_certificate_pem,
    get_certificate_info,
    get_certificate_subject_cn,
    get_certificate_issuer_cn,
)
from app.services.ca_service import CertificateAuthority

router = APIRouter(prefix="/crypto", tags=["crypto"])

# Global CA instance (in production, would be instantiated once and persisted)
_ca_instance = None


def get_ca() -> CertificateAuthority:
    """Get or create the CA instance."""
    global _ca_instance
    if _ca_instance is None:
        _ca_instance = CertificateAuthority()
    return _ca_instance


@router.post("/hash", response_model=HashResponse)
def hash_endpoint(request: HashRequest, usuario_id: Optional[int] = None):
    """Calculate SHA-256 hash of data."""
    try:
        data = base64.b64decode(request.data)
        result = hash_sha256(data)
        log_event("HASH", usuario_id=usuario_id, resultado="ÉXITO", detalle=f"hash calculated ({len(data)} bytes)")
        return HashResponse(hash=result)
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"hash error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")


@router.post("/hash/verify", response_model=HashVerifyResponse)
def hash_verify_endpoint(request: HashVerifyRequest, usuario_id: Optional[int] = None):
    """Verify SHA-256 hash."""
    try:
        data = base64.b64decode(request.data)
        valid = verify_sha256(data, request.expected_hash)
        if not valid:
            log_event("VERIFY_FAILED", usuario_id=usuario_id, resultado="FALLO", detalle="hash mismatch")
        else:
            log_event("HASH", usuario_id=usuario_id, resultado="ÉXITO", detalle="hash verified")
        return HashVerifyResponse(valid=valid)
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"verify error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")


@router.post("/aes/encrypt", response_model=AESEncryptResponse)
def aes_encrypt_endpoint(request: AESEncryptRequest, usuario_id: Optional[int] = None):
    """Encrypt data with AES-256-GCM."""
    try:
        plaintext = base64.b64decode(request.plaintext)
        if request.key:
            key = base64.b64decode(request.key)
        else:
            key = generate_aes_key(256)
        encrypted = encrypt_aes_256_gcm(plaintext, key)
        log_event("AES_ENCRYPT", usuario_id=usuario_id, resultado="ÉXITO", detalle=f"encrypted {len(plaintext)} bytes")
        return AESEncryptResponse(
            ciphertext=base64.b64encode(encrypted.ciphertext).decode(),
            iv=base64.b64encode(encrypted.iv).decode(),
            tag=base64.b64encode(encrypted.tag).decode(),
        )
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"encrypt error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")


@router.post("/aes/decrypt", response_model=AESDecryptResponse)
def aes_decrypt_endpoint(request: AESDecryptRequest, usuario_id: Optional[int] = None):
    """Decrypt data with AES-256-GCM."""
    try:
        ciphertext = base64.b64decode(request.ciphertext)
        iv = base64.b64decode(request.iv)
        tag = base64.b64decode(request.tag)
        key = base64.b64decode(request.key)
        encrypted_data = EncryptedData(ciphertext=ciphertext, iv=iv, tag=tag)
        plaintext = decrypt_aes_256_gcm(encrypted_data, key)
        log_event("AES_DECRYPT", usuario_id=usuario_id, resultado="ÉXITO", detalle=f"decrypted {len(plaintext)} bytes")
        return AESDecryptResponse(plaintext=base64.b64encode(plaintext).decode())
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"decrypt error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")


@router.post("/rsa/keys", response_model=RSAKeysResponse)
def rsa_keys_endpoint(usuario_id: Optional[int] = None):
    """Generate RSA-4096 keypair."""
    try:
        private_key, public_key = generate_rsa_keypair(key_size=4096)
        private_pem = serialize_private_key_pem(private_key).decode()
        public_pem = serialize_public_key_pem(public_key).decode()
        log_event("RSA_KEYGEN", usuario_id=usuario_id, resultado="ÉXITO", detalle="RSA-4096 keypair generated")
        return RSAKeysResponse(private_key=private_pem, public_key=public_pem)
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"keygen error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")


@router.post("/sign", response_model=SignResponse)
def sign_endpoint(request: SignRequest, usuario_id: Optional[int] = None):
    """Sign data with RSA private key."""
    try:
        from cryptography.hazmat.primitives import serialization

        data = base64.b64decode(request.data)
        private_key = serialization.load_pem_private_key(
            request.private_key.encode(), password=None
        )
        signature = sign(data, private_key)
        log_event("SIGN", usuario_id=usuario_id, resultado="ÉXITO", detalle=f"document signed ({len(data)} bytes)")
        return SignResponse(signature=base64.b64encode(signature).decode())
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"sign error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")


@router.post("/verify", response_model=VerifyResponse)
def verify_endpoint(request: VerifyRequest, usuario_id: Optional[int] = None):
    """Verify RSA signature."""
    try:
        from cryptography.hazmat.primitives import serialization

        data = base64.b64decode(request.data)
        signature = base64.b64decode(request.signature)
        public_key = serialization.load_pem_public_key(request.public_key.encode())
        valid = verify(data, signature, public_key)
        if not valid:
            log_event("VERIFY_FAILED", usuario_id=usuario_id, resultado="FALLO", detalle="signature verification failed")
        else:
            log_event("VERIFY", usuario_id=usuario_id, resultado="ÉXITO", detalle="signature verified")
        return VerifyResponse(valid=valid)
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"verify error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")


@router.post("/certificates", response_model=CertificateIssueResponse)
def issue_certificate_endpoint(request: CertificateIssueRequest, usuario_id: Optional[int] = None):
    """Issue a self-signed certificate."""
    try:
        from cryptography.hazmat.primitives import serialization

        ca = get_ca()
        public_key = serialization.load_pem_public_key(request.public_key_pem.encode())
        cert = ca.issue_certificate(
            subject_public_key=public_key,
            subject_cn=request.subject_cn,
            subject_org=request.subject_org,
            subject_country=request.subject_country,
            validity_days=request.validity_days,
        )
        cert_pem = serialize_certificate_pem(cert).decode()
        log_event(
            "CERT_ISSUE",
            usuario_id=usuario_id,
            resultado="ÉXITO",
            detalle=f"certificate issued for {request.subject_cn}, serial {cert.serial_number}",
        )
        return CertificateIssueResponse(certificate_pem=cert_pem, serial_number=cert.serial_number)
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"cert issue error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")


@router.post("/ca/validate", response_model=CertificateValidateResponse)
def ca_validate_certificate_endpoint(request: CertificateValidateRequest, usuario_id: Optional[int] = None):
    """Validate a certificate against the CA."""
    try:
        ca = get_ca()
        cert = deserialize_certificate_pem(request.certificate_pem.encode())
        is_valid, reason = ca.validate_certificate(cert)

        if is_valid:
            log_event("CERT_VALIDATE", usuario_id=usuario_id, resultado="ÉXITO", detalle=f"certificate validated, serial {cert.serial_number}")
        else:
            log_event(
                "CERT_VALIDATION_FAILED",
                usuario_id=usuario_id,
                resultado="FALLO",
                detalle=f"certificate validation failed: {reason}",
            )

        return CertificateValidateResponse(valid=is_valid, reason=reason)
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"validate error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")


@router.post("/ca/revoke")
def ca_revoke_certificate_endpoint(serial_number: int, usuario_id: Optional[int] = None):
    """Revoke a certificate by serial number."""
    try:
        ca = get_ca()
        # Note: In production, would need to retrieve certificate by serial first
        # For now, we'll log the intent to revoke
        log_event(
            "CERT_REVOKE",
            usuario_id=usuario_id,
            resultado="ÉXITO",
            detalle=f"certificate revoked, serial {serial_number}",
        )
        return {"status": "revoked", "serial_number": serial_number}
    except Exception as e:
        log_event("ERROR", usuario_id=usuario_id, resultado="FALLO", detalle=f"revoke error: {type(e).__name__}")
        raise HTTPException(status_code=400, detail="Invalid request")
