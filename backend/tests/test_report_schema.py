from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.models.report import NormalizedAnalysisReport

client = TestClient(app)


def _assert_error_response(payload: dict, expected_code: str) -> None:
    assert "error" in payload
    assert payload["error"]["code"] == expected_code
    assert isinstance(payload["error"]["message"], str)
    assert "details" in payload["error"]


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
        files={"file": ("sample.apk", b"placeholder", "application/octet-stream")},
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
        files={"file": ("sample.aab", b"PK\x03\x04", "application/octet-stream")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["platform"] == "android"
    assert payload["metadata"]["file_extension"] == ".aab"


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
