from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.application import router as application_router
from app.api.crypto import router as crypto_router
from app.core.config import settings
from app.core.database import Base, SessionLocal, check_database_connection, engine
from app.core.security import hash_password
from app.models.entities import User
from app.schemas.application import validate_strong_password
from sqlalchemy import or_, select
from app import models  # noqa: F401

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="API base para firma digital, validacion criptografica y DevSecOps.",
)

Base.metadata.create_all(bind=engine)


def create_bootstrap_admin() -> None:
    """Create an initial admin only from explicit environment configuration."""
    if not all(
        [
            settings.bootstrap_admin_username,
            settings.bootstrap_admin_email,
            settings.bootstrap_admin_password,
        ]
    ):
        return
    validate_strong_password(settings.bootstrap_admin_password)
    with SessionLocal() as db:
        exists = db.scalar(
            select(User).where(
                or_(
                    User.username == settings.bootstrap_admin_username,
                    User.email == settings.bootstrap_admin_email,
                )
            )
        )
        if not exists:
            db.add(
                User(
                    username=settings.bootstrap_admin_username,
                    email=settings.bootstrap_admin_email.lower(),
                    full_name="Administrador del sistema",
                    password_hash=hash_password(settings.bootstrap_admin_password),
                    role="admin",
                )
            )
            db.commit()


create_bootstrap_admin()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[item.strip() for item in settings.allowed_origins.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(application_router)
app.include_router(crypto_router)


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/db", tags=["health"])
def database_health_check() -> dict[str, str]:
    check_database_connection()
    return {"database": "ok"}
