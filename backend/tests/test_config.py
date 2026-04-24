import pytest

from app.core.config import Settings


def test_cors_origins_list_parses_comma_separated() -> None:
    s = Settings(cors_allowed_origins="http://localhost:3000, https://app.example.com")
    assert s.cors_origins_list == ["http://localhost:3000", "https://app.example.com"]


def test_cors_origins_list_single_value() -> None:
    s = Settings(cors_allowed_origins="http://localhost:3000")
    assert s.cors_origins_list == ["http://localhost:3000"]


def test_cors_origins_list_strips_whitespace() -> None:
    s = Settings(cors_allowed_origins="  http://a.com ,  http://b.com  ")
    assert s.cors_origins_list == ["http://a.com", "http://b.com"]


def test_default_max_upload_size() -> None:
    s = Settings()
    assert s.max_upload_size_bytes == 25 * 1024 * 1024


def test_default_max_zip_extracted_bytes() -> None:
    s = Settings()
    assert s.max_zip_extracted_bytes == 200 * 1024 * 1024


def test_default_rate_limit_values() -> None:
    s = Settings()
    assert s.rate_limit_upload == "10/minute"
    assert s.rate_limit_default == "60/minute"


def test_default_scanner_limits() -> None:
    s = Settings()
    assert s.max_zip_files == 5_000
    assert s.max_text_file_size == 1_000_000
    assert s.max_text_files_scanned == 200


def test_rate_limit_override_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APPSEC_RATE_LIMIT_UPLOAD", "5/minute")
    monkeypatch.setenv("APPSEC_RATE_LIMIT_DEFAULT", "30/minute")
    s = Settings()
    assert s.rate_limit_upload == "5/minute"
    assert s.rate_limit_default == "30/minute"


def test_scanner_limits_override_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APPSEC_MAX_ZIP_FILES", "1000")
    monkeypatch.setenv("APPSEC_MAX_TEXT_FILE_SIZE", "500000")
    monkeypatch.setenv("APPSEC_MAX_TEXT_FILES_SCANNED", "50")
    s = Settings()
    assert s.max_zip_files == 1000
    assert s.max_text_file_size == 500_000
    assert s.max_text_files_scanned == 50
