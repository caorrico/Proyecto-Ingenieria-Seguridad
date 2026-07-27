from datetime import datetime

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


def validate_strong_password(value: str) -> str:
    if len(value) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres")
    if not re.search(r"[A-Z]", value):
        raise ValueError("La contraseña debe incluir una letra mayúscula")
    if not re.search(r"\d", value):
        raise ValueError("La contraseña debe incluir un número")
    if not re.search(r"[^A-Za-z0-9]", value):
        raise ValueError("La contraseña debe incluir un carácter especial")
    return value


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(default="", max_length=120)

    _strong_password = field_validator("password")(validate_strong_password)


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=120)


class AdminUserUpdate(UserUpdate):
    role: Literal["admin", "user"] | None = None
    active: bool | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)

    _strong_password = field_validator("new_password")(validate_strong_password)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    email: str
    full_name: str
    role: str
    active: bool
    created_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    owner_id: int
    filename: str
    content_type: str
    sha256: str
    signature: str | None
    public_key: str | None
    created_at: datetime


class CertificateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    owner_id: int
    serial_number: str
    subject_cn: str
    certificate_pem: str
    revoked: bool
    created_at: datetime


class CertificateCreate(BaseModel):
    subject_cn: str = Field(min_length=2, max_length=120)
    subject_org: str = Field(default="ESPE", max_length=120)
    subject_country: str = Field(default="EC", min_length=2, max_length=2)
    public_key_pem: str
    validity_days: int = Field(default=365, ge=1, le=3650)


class VisualSignatureRequest(BaseModel):
    private_key: str
    signer_name: str = Field(min_length=2, max_length=120)
    page: int = Field(default=1, ge=1)
    x: float = Field(ge=0.0, le=1.0)
    y: float = Field(ge=0.0, le=1.0)
    size: int = Field(default=100, ge=60, le=200)
