from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from app.errors.exceptions import UploadValidationError
from app.services.report_builder import build_normalized_report


def _build_android_payload() -> tuple[bytes, str]:
    manifest = '''
    <manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:debuggable="true" android:allowBackup="true" />
    </manifest>
    '''
    content = "token=mysecretvalue\nurl=https://api.example.com"

    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("assets/config.txt", content)

    return buffer.getvalue(), ".apk"


def test_report_builder_routes_android_and_returns_extended_shape() -> None:
    file_bytes, extension = _build_android_payload()

    report = build_normalized_report(
        file_name="sample.apk",
        platform="android",
        file_bytes=file_bytes,
        file_extension=extension,
    )

    payload = report.model_dump()
    assert payload["platform"] == "android"
    assert payload["file_name"] == "sample.apk"
    assert {"platform", "file_name", "risk_level", "score", "summary", "findings", "categories", "metadata"}.issubset(
        payload.keys()
    )
    assert isinstance(payload["score"], int)
    assert all("source" in finding for finding in payload["findings"])
    assert sum(c["count"] for c in payload["categories"]) == payload["summary"]["total_findings"]


def test_report_builder_raises_for_invalid_android_archive() -> None:
    with pytest.raises(UploadValidationError) as exc_info:
        build_normalized_report(
            file_name="bad.apk",
            platform="android",
            file_bytes=b"not-a-zip",
            file_extension=".apk",
        )
    assert exc_info.value.code == "INVALID_ARCHIVE"


def test_report_builder_raises_for_android_archive_limit() -> None:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.example.limit" />')
        archive.writestr("assets/big.txt", "A" * 2_000)

    with pytest.raises(UploadValidationError) as exc_info:
        build_normalized_report(
            file_name="sample.apk",
            platform="android",
            file_bytes=buffer.getvalue(),
            file_extension=".apk",
            max_zip_extracted_bytes=500,
        )
    assert exc_info.value.code == "ARCHIVE_LIMIT_EXCEEDED"
