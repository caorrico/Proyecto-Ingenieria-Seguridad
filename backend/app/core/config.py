from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Plataforma Web Segura de Firma Digital"
    environment: str = "development"
    database_url: str = "sqlite:///./app.db"
    secret_key: str = "change-this-secret-in-production"
    access_token_minutes: int = 60
    allowed_origins: str = "http://localhost:5173,http://localhost:5174"
    max_file_size: int = 5_242_880
    bootstrap_admin_username: str | None = None
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None
    public_base_url: str = "http://localhost:8000"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
