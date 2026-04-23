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
