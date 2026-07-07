from pydantic import BaseModel
from typing import Optional


class HashRequest(BaseModel):
    data: str  # base64 encoded


class HashResponse(BaseModel):
    hash: str


class HashVerifyRequest(BaseModel):
    data: str  # base64
    expected_hash: str


class HashVerifyResponse(BaseModel):
    valid: bool


class AESEncryptRequest(BaseModel):
    plaintext: str  # base64
    key: Optional[str] = None  # base64, None = generate


class AESEncryptResponse(BaseModel):
    ciphertext: str  # base64
    iv: str  # base64
    tag: str  # base64


class AESDecryptRequest(BaseModel):
    ciphertext: str  # base64
    iv: str  # base64
    tag: str  # base64
    key: str  # base64


class AESDecryptResponse(BaseModel):
    plaintext: str  # base64


class RSAKeysResponse(BaseModel):
    private_key: str  # PEM
    public_key: str  # PEM


class SignRequest(BaseModel):
    data: str  # base64
    private_key: str  # PEM


class SignResponse(BaseModel):
    signature: str  # base64


class VerifyRequest(BaseModel):
    data: str  # base64
    signature: str  # base64
    public_key: str  # PEM


class VerifyResponse(BaseModel):
    valid: bool


class CertificateIssueRequest(BaseModel):
    subject_cn: str
    subject_org: str = "Organization"
    subject_country: str = "US"
    public_key_pem: str
    validity_days: int = 365


class CertificateIssueResponse(BaseModel):
    certificate_pem: str
    serial_number: int


class CertificateValidateRequest(BaseModel):
    certificate_pem: str


class CertificateValidateResponse(BaseModel):
    valid: bool
    reason: str
