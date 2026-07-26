from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    full_name: str = Field(default="", max_length=120)


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=120)
    password: str | None = Field(default=None, min_length=10, max_length=128)
    active: bool | None = None


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
