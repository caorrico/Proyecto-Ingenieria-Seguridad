from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.application import router as application_router
from app.api.crypto import router as crypto_router
from app.core.config import settings
from app.core.database import Base, check_database_connection, engine
from app import models  # noqa: F401

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="API base para firma digital, validacion criptografica y DevSecOps.",
)

Base.metadata.create_all(bind=engine)
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
