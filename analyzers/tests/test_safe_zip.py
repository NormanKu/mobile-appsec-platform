from io import BytesIO
from zipfile import ZipFile

import pytest

from analyzers.safe_zip import ZipExtractionLimitExceeded, validate_zip_limits


def _make_zip_with_large_entry(uncompressed_size: int) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("big.txt", "A" * uncompressed_size)
    return buffer.getvalue()


def _make_zip_with_many_entries(count: int) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for i in range(count):
            archive.writestr(f"file_{i}.txt", f"content {i}")
    return buffer.getvalue()


def test_validate_zip_limits_passes_for_small_archive() -> None:
    data = _make_zip_with_large_entry(100)
    with ZipFile(BytesIO(data), "r") as archive:
        validate_zip_limits(archive)


def test_validate_zip_limits_rejects_oversized_extraction() -> None:
    data = _make_zip_with_large_entry(1000)
    with ZipFile(BytesIO(data), "r") as archive:
        with pytest.raises(ZipExtractionLimitExceeded, match="uncompressed size"):
            validate_zip_limits(archive, max_extracted_bytes=500)


def test_validate_zip_limits_rejects_too_many_files() -> None:
    data = _make_zip_with_many_entries(50)
    with ZipFile(BytesIO(data), "r") as archive:
        with pytest.raises(ZipExtractionLimitExceeded, match="entries"):
            validate_zip_limits(archive, max_files=10)


def test_android_scanner_returns_bomb_finding_on_limit_exceeded() -> None:
    from analyzers.android.scanner import analyze_android_package

    data = _make_zip_with_many_entries(6000)
    findings = analyze_android_package(
        file_name="bomb.apk", file_bytes=data, file_extension=".apk"
    )

    assert findings[0]["id"] == "ANDROID-ARCHIVE-BOMB"
    assert findings[0]["severity"] == "critical"


def test_ios_scanner_returns_bomb_finding_on_limit_exceeded() -> None:
    from analyzers.ios.scanner import analyze_ios_package

    data = _make_zip_with_many_entries(6000)
    findings = analyze_ios_package(
        file_name="bomb.ipa", file_bytes=data, file_extension=".ipa"
    )

    assert findings[0]["id"] == "IOS-ARCHIVE-BOMB"
    assert findings[0]["severity"] == "critical"
