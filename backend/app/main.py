from fastapi import FastAPI

from app.core.config import settings
from app.core.database import check_database_connection

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="API base para firma digital, validacion criptografica y DevSecOps.",
)


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/db", tags=["health"])
def database_health_check() -> dict[str, str]:
    check_database_connection()
    return {"database": "ok"}
