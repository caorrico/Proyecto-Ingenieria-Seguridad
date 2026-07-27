import base64

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.crypto import get_ca
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
    verify_password,
)
from app.models.audit import AuditLog
from app.models.entities import CertificateRecord, Document, User
from app.schemas.application import (
    AdminUserUpdate,
    CertificateCreate,
    CertificateOut,
    DocumentOut,
    LoginRequest,
    PasswordChange,
    TokenResponse,
    UserCreate,
    UserOut,
    UserUpdate,
    VisualSignatureRequest,
)
from app.services.audit_service import log_event
from app.services.certificate_service import deserialize_certificate_pem, serialize_certificate_pem
from app.services.hash_service import hash_sha256
from app.services.signature_service import sign, verify
from app.services.pdf_signature_service import add_visible_signature
from app.services.file_validation_service import validate_document
from app.services.pdf_embedded_signature_service import embed_adobe_compatible_signature

router = APIRouter(prefix="/api")


@router.post("/auth/register", response_model=UserOut, status_code=201, tags=["auth"])
def register(data: UserCreate, db: Session = Depends(get_db)):
    exists = db.scalar(
        select(User).where(or_(User.username == data.username, User.email == data.email))
    )
    if exists:
        raise HTTPException(409, "El usuario o correo ya está registrado")
    user = User(
        username=data.username,
        email=str(data.email).lower(),
        full_name=data.full_name,
        password_hash=hash_password(data.password),
        role="user",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_event("REGISTER", user.id, "ÉXITO", "Cuenta creada")
    return user


@router.post("/auth/login", response_model=TokenResponse, tags=["auth"])
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == data.username))
    if not user or not user.active or not verify_password(data.password, user.password_hash):
        log_event("LOGIN", resultado="FALLO", detalle="Credenciales inválidas")
        raise HTTPException(401, "Credenciales inválidas")
    log_event("LOGIN", user.id, "ÉXITO", "Inicio de sesión")
    return TokenResponse(access_token=create_access_token(user), user=user)


@router.get("/auth/me", response_model=UserOut, tags=["auth"])
def me(user: User = Depends(get_current_user)):
    return user


@router.get("/users", response_model=list[UserOut], tags=["users"])
def list_users(
    _: User = Depends(require_admin), db: Session = Depends(get_db)
):
    return list(db.scalars(select(User).order_by(User.created_at.desc())).all())


@router.get("/users/{user_id}", response_model=UserOut, tags=["users"])
def get_user(user_id: int, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current.id != user_id and current.role != "admin":
        raise HTTPException(403, "Acceso denegado")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    return user


@router.patch("/users/{user_id}", response_model=UserOut, tags=["users"])
def update_user(
    user_id: int,
    data: UserUpdate,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current.id != user_id and current.role != "admin":
        raise HTTPException(403, "Acceso denegado")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    changes = data.model_dump(exclude_unset=True)
    if "email" in changes:
        duplicate = db.scalar(select(User).where(User.email == str(changes["email"]), User.id != user_id))
        if duplicate:
            raise HTTPException(409, "El correo ya está registrado")
        changes["email"] = str(changes["email"]).lower()
    for key, value in changes.items():
        setattr(user, key, value)
    db.commit()
    db.refresh(user)
    log_event("USER_UPDATE", current.id, "ÉXITO", f"Usuario {user_id} actualizado")
    return user


@router.patch("/admin/users/{user_id}", response_model=UserOut, tags=["users"])
def admin_update_user(
    user_id: int,
    data: AdminUserUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    changes = data.model_dump(exclude_unset=True)
    if user.id == admin.id and changes.get("role") == "user":
        raise HTTPException(400, "No puede retirar su propio rol de administrador")
    if user.id == admin.id and changes.get("active") is False:
        raise HTTPException(400, "No puede desactivar su propia cuenta")
    if "email" in changes:
        duplicate = db.scalar(select(User).where(User.email == str(changes["email"]), User.id != user_id))
        if duplicate:
            raise HTTPException(409, "El correo ya está registrado")
        changes["email"] = str(changes["email"]).lower()
    for key, value in changes.items():
        setattr(user, key, value)
    db.commit()
    db.refresh(user)
    log_event("ADMIN_USER_UPDATE", admin.id, "ÉXITO", f"Usuario {user_id} actualizado")
    return user


@router.post("/auth/change-password", status_code=204, tags=["auth"])
def change_password(
    data: PasswordChange,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(data.current_password, user.password_hash):
        log_event("PASSWORD_CHANGE", user.id, "FALLO", "Contraseña actual incorrecta")
        raise HTTPException(400, "La contraseña actual es incorrecta")
    if verify_password(data.new_password, user.password_hash):
        raise HTTPException(400, "La nueva contraseña debe ser diferente")
    user.password_hash = hash_password(data.new_password)
    db.commit()
    log_event("PASSWORD_CHANGE", user.id, "ÉXITO", "Contraseña actualizada")


@router.delete("/users/{user_id}", status_code=204, tags=["users"])
def delete_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if admin.id == user_id:
        raise HTTPException(400, "No puede desactivar su propia cuenta")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    user.active = False
    db.commit()
    log_event("USER_DELETE", admin.id, "ÉXITO", f"Usuario {user_id} desactivado")


def owned_document(document_id: int, user: User, db: Session) -> Document:
    document = db.get(Document, document_id)
    if not document:
        raise HTTPException(404, "Documento no encontrado")
    if document.owner_id != user.id:
        raise HTTPException(403, "Acceso denegado")
    return document


@router.post("/documents", response_model=DocumentOut, status_code=201, tags=["documents"])
async def upload_document(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    content = await file.read(settings.max_file_size + 1)
    if not content:
        raise HTTPException(400, "El archivo está vacío")
    if len(content) > settings.max_file_size:
        raise HTTPException(413, "El archivo supera el límite de 5 MB")
    try:
        safe_name, canonical_type = validate_document(file.filename or "", content)
    except ValueError as exc:
        raise HTTPException(415, str(exc))
    document = Document(
        owner_id=user.id,
        filename=safe_name,
        content_type=canonical_type,
        content=content,
        sha256=hash_sha256(content),
    )
    db.add(document)
    db.commit()
    db.refresh(document)
    log_event("DOCUMENT_UPLOAD", user.id, "ÉXITO", f"Documento {document.id} cargado")
    return document


@router.get("/documents", response_model=list[DocumentOut], tags=["documents"])
def list_documents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    statement = (
        select(Document)
        .where(Document.owner_id == user.id)
        .order_by(Document.created_at.desc())
    )
    return list(db.scalars(statement).all())


@router.get("/documents/{document_id}", response_model=DocumentOut, tags=["documents"])
def get_document(document_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return owned_document(document_id, user, db)


@router.get("/documents/{document_id}/download", tags=["documents"])
def download_document(document_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    document = owned_document(document_id, user, db)
    return Response(
        document.content,
        media_type=document.content_type,
        headers={"Content-Disposition": f'attachment; filename="{document.filename}"'},
    )


@router.post("/documents/{document_id}/sign", response_model=DocumentOut, tags=["documents"])
def sign_document(
    document_id: int,
    private_key: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = owned_document(document_id, user, db)
    try:
        key = serialization.load_pem_private_key(private_key.encode(), password=None)
        document.signature = base64.b64encode(sign(document.content, key)).decode()
        document.public_key = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
    except (ValueError, TypeError):
        raise HTTPException(400, "Clave privada PEM inválida")
    db.commit()
    db.refresh(document)
    log_event("SIGN", user.id, "ÉXITO", f"Documento {document.id} firmado")
    return document


@router.post("/documents/{document_id}/visual-sign", response_model=DocumentOut, tags=["documents"])
def visual_sign_document(
    document_id: int,
    data: VisualSignatureRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = owned_document(document_id, user, db)
    if document.content_type != "application/pdf" and not document.filename.lower().endswith(".pdf"):
        raise HTTPException(400, "La firma visible solo está disponible para documentos PDF")
    try:
        key = serialization.load_pem_private_key(data.private_key.encode(), password=None)
        verification_text = f"{settings.public_base_url}/api/public/documents/{document.id}/verify"
        stamped = add_visible_signature(
            document.content, data.signer_name, verification_text, data.page, data.x, data.y, data.size
        )
        signed_pdf = embed_adobe_compatible_signature(stamped, key, data.signer_name)
        document.content = signed_pdf
        document.sha256 = hash_sha256(signed_pdf)
        document.signature = base64.b64encode(sign(signed_pdf, key)).decode()
        document.public_key = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc) if isinstance(exc, ValueError) else "Clave privada PEM inválida")
    db.commit()
    db.refresh(document)
    log_event("VISUAL_SIGN", user.id, "ÉXITO", f"Documento {document.id}, página {data.page}")
    return document


@router.get("/public/documents/{document_id}/verify", tags=["public-verification"])
def public_verify_document(document_id: int, db: Session = Depends(get_db)):
    """Public QR destination; reveals no document content or owner information."""
    document = db.get(Document, document_id)
    if not document or not document.signature or not document.public_key:
        raise HTTPException(404, "No existe una firma verificable para este documento")
    try:
        key = serialization.load_pem_public_key(document.public_key.encode())
        valid = verify(document.content, base64.b64decode(document.signature), key)
    except (ValueError, TypeError):
        valid = False
    return {
        "document_id": document.id,
        "filename": document.filename,
        "sha256": hash_sha256(document.content),
        "signature_valid": valid,
    }


@router.post("/documents/{document_id}/verify", tags=["documents"])
def verify_document(document_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    document = owned_document(document_id, user, db)
    if not document.signature or not document.public_key:
        raise HTTPException(400, "El documento no tiene firma")
    key = serialization.load_pem_public_key(document.public_key.encode())
    valid = verify(document.content, base64.b64decode(document.signature), key)
    log_event("VERIFY", user.id, "ÉXITO" if valid else "FALLO", f"Documento {document.id}")
    return {"valid": valid, "sha256": hash_sha256(document.content)}


@router.delete("/documents/{document_id}", status_code=204, tags=["documents"])
def delete_document(document_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    document = owned_document(document_id, user, db)
    db.delete(document)
    db.commit()
    log_event("DOCUMENT_DELETE", user.id, "ÉXITO", f"Documento {document_id} eliminado")


@router.post("/certificates", response_model=CertificateOut, status_code=201, tags=["certificates"])
def issue_certificate(
    data: CertificateCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        public_key = serialization.load_pem_public_key(data.public_key_pem.encode())
        cert = get_ca().issue_certificate(
            public_key, data.subject_cn, data.subject_org, data.subject_country.upper(), data.validity_days
        )
    except (ValueError, TypeError):
        raise HTTPException(400, "Datos o clave pública inválidos")
    record = CertificateRecord(
        owner_id=user.id,
        serial_number=str(cert.serial_number),
        subject_cn=data.subject_cn,
        certificate_pem=serialize_certificate_pem(cert).decode(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    log_event("CERT_ISSUE", user.id, "ÉXITO", f"Certificado {record.id} emitido")
    return record


@router.get("/certificates", response_model=list[CertificateOut], tags=["certificates"])
def list_certificates(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    statement = select(CertificateRecord).order_by(CertificateRecord.created_at.desc())
    if user.role != "admin":
        statement = statement.where(CertificateRecord.owner_id == user.id)
    return list(db.scalars(statement).all())


@router.post("/certificates/{certificate_id}/validate", tags=["certificates"])
def validate_certificate(certificate_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.get(CertificateRecord, certificate_id)
    if not record or (record.owner_id != user.id and user.role != "admin"):
        raise HTTPException(404, "Certificado no encontrado")
    if record.revoked:
        return {"valid": False, "reason": "REVOKED"}
    cert = deserialize_certificate_pem(record.certificate_pem.encode())
    valid, reason = get_ca().validate_certificate(cert)
    return {"valid": valid, "reason": reason}


@router.delete("/certificates/{certificate_id}", response_model=CertificateOut, tags=["certificates"])
def revoke_certificate(certificate_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.get(CertificateRecord, certificate_id)
    if not record or (record.owner_id != user.id and user.role != "admin"):
        raise HTTPException(404, "Certificado no encontrado")
    cert = deserialize_certificate_pem(record.certificate_pem.encode())
    get_ca().revoke_certificate(cert)
    record.revoked = True
    db.commit()
    db.refresh(record)
    log_event("CERT_REVOKE", user.id, "ÉXITO", f"Certificado {record.id} revocado")
    return record


@router.get("/audit", tags=["audit"])
def audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)).all()
    return [
        {
            "id": row.id,
            "timestamp": row.timestamp,
            "usuario_id": row.usuario_id,
            "tipo_evento": row.tipo_evento,
            "resultado": row.resultado,
            "detalle": row.detalle,
        }
        for row in rows
    ]
