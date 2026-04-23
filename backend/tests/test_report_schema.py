from datetime import datetime, timezone
from io import BytesIO
import plistlib
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app, limiter
from app.models.report import NormalizedAnalysisReport

client = TestClient(app)


@pytest.fixture(autouse=True)
def disable_rate_limiter() -> None:
    original_enabled = limiter.enabled
    limiter.enabled = False
    limiter.reset()
    yield
    limiter.reset()
    limiter.enabled = original_enabled


def _assert_error_response(payload: dict, expected_code: str) -> None:
    assert "error" in payload
    assert payload["error"]["code"] == expected_code
    assert isinstance(payload["error"]["message"], str)
    assert "details" in payload["error"]


def _build_apk_payload() -> bytes:
    manifest = '''
    <manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:debuggable="true" />
    </manifest>
    '''
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("assets/config.txt", "token=mysecretvalue\nurl=https://api.example.com")
    return buffer.getvalue()


def _build_aab_payload() -> bytes:
    manifest = '''
    <manifest package="com.example.bundle" xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:debuggable="false" />
    </manifest>
    '''
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", manifest)
        archive.writestr("BundleConfig.pb", b"placeholder")
        archive.writestr("base/assets/config.txt", "url=https://bundle.example.com")
    return buffer.getvalue()


def _build_ipa_payload() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(
            "Payload/Sample.app/Info.plist",
            plistlib.dumps({"CFBundleIdentifier": "com.example.ios"}),
        )
        archive.writestr("Payload/Sample.app/config.txt", "url=https://ios.example.com")
    return buffer.getvalue()


def _build_zip_payload(entries: dict[str, bytes | str]) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_schema_accepts_valid_android_report() -> None:
    report = NormalizedAnalysisReport(
        platform="android",
        file_name="release.apk",
        risk_level="high",
        score=55,
        summary={
            "total_findings": 1,
            "by_severity": {"low": 0, "medium": 0, "high": 1, "critical": 0},
        },
        findings=[
            {
                "id": "ANDROID-1",
                "title": "Issue",
                "severity": "high",
                "category": "configuration",
                "description": "desc",
                "recommendation": "fix",
                "source": "AndroidManifest.xml",
            }
        ],
        categories=[
            {
                "name": "configuration",
                "count": 1,
                "max_severity": "high",
            }
        ],
        metadata={
            "generated_at": datetime.now(timezone.utc),
            "analyzer_version": "0.1.0-mvp",
            "analysis_mode": "static-placeholder",
            "file_extension": ".apk",
        },
    )

    assert report.platform == "android"
    assert report.score == 55
    assert report.summary.total_findings == 1


def test_schema_rejects_mismatched_category_count() -> None:
    with pytest.raises(ValueError):
        NormalizedAnalysisReport(
            platform="ios",
            file_name="release.ipa",
            risk_level="medium",
            score=70,
            summary={
                "total_findings": 1,
                "by_severity": {"low": 0, "medium": 1, "high": 0, "critical": 0},
            },
            findings=[
                {
                    "id": "IOS-1",
                    "title": "Issue",
                    "severity": "medium",
                    "category": "entitlements",
                    "description": "desc",
                    "recommendation": "fix",
                    "source": "Info.plist",
                }
            ],
            categories=[
                {
                    "name": "entitlements",
                    "count": 2,
                    "max_severity": "medium",
                }
            ],
            metadata={
                "generated_at": datetime.now(timezone.utc),
                "analyzer_version": "0.1.0-mvp",
                "analysis_mode": "static-placeholder",
                "file_extension": ".ipa",
            },
        )


def test_upload_endpoint_returns_extended_schema_for_apk() -> None:
    response = client.post(
        "/api/v1/upload",
        files={"file": ("sample.apk", _build_apk_payload(), "application/octet-stream")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["platform"] == "android"
    assert {"platform", "file_name", "risk_level", "score", "summary", "findings", "categories", "metadata"}.issubset(payload.keys())
    assert payload["summary"]["total_findings"] == len(payload["findings"])
    assert sum(category["count"] for category in payload["categories"]) == len(payload["findings"])
    assert all("source" in finding for finding in payload["findings"])


def test_upload_endpoint_returns_extended_schema_for_aab() -> None:
    response = client.post(
        "/api/v1/upload",
        files={"file": ("sample.aab", _build_aab_payload(), "application/octet-stream")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["platform"] == "android"
    assert payload["metadata"]["file_extension"] == ".aab"
    assert all(finding["id"] != "ANDROID-MANIFEST-404" for finding in payload["findings"])


def test_upload_endpoint_returns_extended_schema_for_ipa() -> None:
    response = client.post(
        "/api/v1/upload",
        files={"file": ("sample.ipa", _build_ipa_payload(), "application/octet-stream")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["platform"] == "ios"
    assert payload["metadata"]["file_extension"] == ".ipa"


def test_upload_endpoint_rejects_unsupported_extension_with_error_code() -> None:
    response = client.post(
        "/api/v1/upload",
        files={"file": ("notes.txt", b"placeholder", "text/plain")},
    )

    assert response.status_code == 400
    _assert_error_response(response.json(), "INVALID_FILE_TYPE")


def test_upload_endpoint_missing_file_returns_consistent_error() -> None:
    response = client.post("/api/v1/upload", files={})

    assert response.status_code == 400
    _assert_error_response(response.json(), "MISSING_FILE")


def test_upload_endpoint_rejects_oversized_upload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "max_upload_size_bytes", 4)

    response = client.post(
        "/api/v1/upload",
        files={"file": ("sample.apk", b"123456789", "application/octet-stream")},
    )

    assert response.status_code == 413
    _assert_error_response(response.json(), "FILE_TOO_LARGE")


def test_upload_endpoint_rejects_invalid_android_archive() -> None:
    response = client.post(
        "/api/v1/upload",
        files={"file": ("bad.apk", b"not-a-zip", "application/octet-stream")},
    )

    assert response.status_code == 400
    payload = response.json()
    _assert_error_response(payload, "INVALID_ARCHIVE")
    assert payload["error"]["details"]["finding_id"] == "ANDROID-ARCHIVE-001"


def test_upload_endpoint_rejects_missing_android_manifest() -> None:
    response = client.post(
        "/api/v1/upload",
        files={
            "file": (
                "broken.apk",
                _build_zip_payload({"assets/config.txt": "noop"}),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 400
    payload = response.json()
    _assert_error_response(payload, "INVALID_ARCHIVE")
    assert payload["error"]["details"]["finding_id"] == "ANDROID-MANIFEST-404"


def test_upload_endpoint_rejects_invalid_ios_archive() -> None:
    response = client.post(
        "/api/v1/upload",
        files={"file": ("bad.ipa", b"not-a-zip", "application/octet-stream")},
    )

    assert response.status_code == 400
    payload = response.json()
    _assert_error_response(payload, "INVALID_ARCHIVE")
    assert payload["error"]["details"]["finding_id"] == "IOS-ARCHIVE-001"


def test_upload_endpoint_rejects_missing_ios_info_plist() -> None:
    response = client.post(
        "/api/v1/upload",
        files={
            "file": (
                "broken.ipa",
                _build_zip_payload({"Payload/Sample.app/config.txt": "noop"}),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 400
    payload = response.json()
    _assert_error_response(payload, "INVALID_ARCHIVE")
    assert payload["error"]["details"]["finding_id"] == "IOS-PLIST-404"


def test_upload_endpoint_rejects_zip_archive_over_safe_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "max_upload_size_bytes", 10_000)
    monkeypatch.setattr(settings, "max_zip_extracted_bytes", 500)

    response = client.post(
        "/api/v1/upload",
        files={
            "file": (
                "limit.apk",
                _build_zip_payload(
                    {
                        "AndroidManifest.xml": '<manifest package="com.example.limit" />',
                        "assets/big.txt": "A" * 2_000,
                    }
                ),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 413
    payload = response.json()
    _assert_error_response(payload, "ARCHIVE_LIMIT_EXCEEDED")
    assert payload["error"]["details"]["finding_id"] == "ANDROID-ARCHIVE-BOMB"


def test_upload_endpoint_rejects_zip_archive_over_custom_file_count_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "max_upload_size_bytes", 10_000)
    monkeypatch.setattr(settings, "max_zip_files", 1)
    monkeypatch.setattr(limiter, "enabled", False)

    response = client.post(
        "/api/v1/upload",
        files={
            "file": (
                "limit.apk",
                _build_zip_payload(
                    {
                        "AndroidManifest.xml": '<manifest package="com.example.limit" />',
                        "assets/config.txt": "url=https://api.example.com",
                    }
                ),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 413
    payload = response.json()
    _assert_error_response(payload, "ARCHIVE_LIMIT_EXCEEDED")
    assert payload["error"]["details"]["finding_id"] == "ANDROID-ARCHIVE-BOMB"


def test_upload_endpoint_honors_custom_text_scan_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "max_text_files_scanned", 1)

    response = client.post(
        "/api/v1/upload",
        files={"file": ("sample.ipa", _build_ipa_payload(), "application/octet-stream")},
    )

    assert response.status_code == 200
    payload = response.json()
    ids = {finding["id"] for finding in payload["findings"]}

    assert "IOS-STRINGS-000" in ids
    assert "IOS-STRINGS-URL-001" not in ids
    assert "IOS-STRINGS-URL-002" not in ids


def test_upload_endpoint_enforces_rate_limit() -> None:
    limiter.enabled = True
    limiter.reset()

    statuses = [
        client.post(
            "/api/v1/upload",
            files={"file": ("bad.apk", b"not-a-zip", "application/octet-stream")},
        ).status_code
        for _ in range(11)
    ]

    assert statuses[:10] == [400] * 10
    assert statuses[10] == 429
