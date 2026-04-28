from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "mobile-appsec-platform-backend"
    max_upload_size_bytes: int = 25 * 1024 * 1024  # 25 MB
    cors_allowed_origins: str = "http://localhost:3000"
    max_zip_extracted_bytes: int = 200 * 1024 * 1024  # 200 MB
    max_zip_files: int = 5_000
    max_text_file_size: int = 1_000_000  # 1 MB
    max_text_files_scanned: int = 200
    rate_limit_upload: str = "10/minute"
    rate_limit_default: str = "60/minute"
    database_url: str = "sqlite:///./appsec.sqlite3"
    default_project_name: str = "Default Project"
    policy_min_score: int = 70
    mobsf_enabled: bool = False
    mobsf_base_url: str | None = None
    mobsf_api_key: str | None = None
    mobsf_timeout_seconds: float = 30.0
    mobsf_re_scan: bool = False
    binary_analysis_enabled: bool = False
    binary_analysis_max_artifacts: int = 20
    binary_analysis_max_artifact_bytes: int = 5 * 1024 * 1024

    model_config = {"env_prefix": "APPSEC_"}

    @property
    def cors_origins_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.cors_allowed_origins.split(",")
            if origin.strip()
        ]


settings = Settings()
