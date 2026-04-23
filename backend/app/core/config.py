from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "mobile-appsec-platform-backend"
    max_upload_size_bytes: int = 25 * 1024 * 1024


settings = Settings()
