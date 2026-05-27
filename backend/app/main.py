from fastapi import FastAPI

app = FastAPI(
    title="Plataforma Web Segura de Firma Digital",
    version="0.1.0",
    description="API base para firma digital, validacion criptografica y DevSecOps.",
)


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}
