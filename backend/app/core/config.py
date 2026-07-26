from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Plataforma Web Segura de Firma Digital"
    environment: str = "development"
    database_url: str = "sqlite:///./app.db"
    secret_key: str = "change-this-secret-in-production"
    access_token_minutes: int = 60
    allowed_origins: str = "http://localhost:5173,http://localhost:5174"
    max_file_size: int = 5_242_880

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
