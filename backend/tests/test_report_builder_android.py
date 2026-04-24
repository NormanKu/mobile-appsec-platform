from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from analyzers.android.external_tools import (
    AndroidExternalToolResult,
    AndroidExternalToolSignal,
)
from app.errors.exceptions import UploadValidationError
from app.services.report_builder import build_normalized_report


def _build_android_payload() -> tuple[bytes, str]:
    manifest = """
    <manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:debuggable="true" android:allowBackup="true" />
    </manifest>
    """
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
    assert {
        "platform",
        "file_name",
        "risk_level",
        "score",
        "summary",
        "findings",
        "categories",
        "top_risks",
        "metadata",
    }.issubset(payload.keys())
    assert isinstance(payload["score"], int)
    assert all("source" in finding for finding in payload["findings"])
    assert all("confidence_level" in finding for finding in payload["findings"])
    assert all("evidence" in finding for finding in payload["findings"])
    assert all("detection_method" in finding for finding in payload["findings"])
    assert (
        sum(c["count"] for c in payload["categories"])
        == payload["summary"]["total_findings"]
    )
    assert payload["summary"]["by_platform"] == {
        "android": len(payload["findings"]),
        "ios": 0,
    }
    assert len(payload["top_risks"]) <= 3
    assert payload["top_risks"][0]["severity"] in ("critical", "high", "medium", "low")


def test_report_builder_routes_only_android_analyzer(monkeypatch) -> None:
    called = {"android": False, "ios": False}

    def fake_android_package(**_: object) -> list[dict[str, object]]:
        called["android"] = True
        return [
            {
                "id": "ANDROID-TEST-001",
                "title": "Test analyzer finding",
                "severity": "low",
                "category": "analysis",
                "description": "android analyzer route selected",
                "recommendation": "noop",
                "source": "android-test",
            }
        ]

    def fake_ios_package(**_: object) -> list[dict[str, object]]:
        called["ios"] = True
        raise AssertionError("iOS analyzer should not be called for Android reports")

    monkeypatch.setattr(
        "app.services.report_builder.analyze_android_package", fake_android_package
    )
    monkeypatch.setattr(
        "app.services.report_builder.analyze_ios_package", fake_ios_package
    )

    report = build_normalized_report(
        file_name="sample.apk",
        platform="android",
        file_bytes=b"placeholder",
        file_extension=".apk",
    )

    assert called == {"android": True, "ios": False}
    assert report.platform == "android"


def test_report_builder_raises_for_invalid_android_archive() -> None:
    with pytest.raises(UploadValidationError) as exc_info:
        build_normalized_report(
            file_name="bad.apk",
            platform="android",
            file_bytes=b"not-a-zip",
            file_extension=".apk",
        )
    assert exc_info.value.code == "INVALID_ARCHIVE"


def test_report_builder_returns_partial_report_for_invalid_android_archive() -> None:
    report = build_normalized_report(
        file_name="bad.apk",
        platform="android",
        file_bytes=b"not-a-zip",
        file_extension=".apk",
        allow_partial=True,
    )

    assert report.analysis_status == "partial"
    assert report.errors[0].code == "INVALID_ARCHIVE"
    assert report.errors[0].details["finding_id"] == "ANDROID-ARCHIVE-001"
    assert report.findings[0].id == "ANDROID-ARCHIVE-001"


def test_report_builder_raises_for_android_archive_limit() -> None:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(
            "AndroidManifest.xml", '<manifest package="com.example.limit" />'
        )
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


def test_report_builder_preserves_shared_shape_with_jadx_enrichment(
    monkeypatch,
) -> None:
    file_bytes, extension = _build_android_payload()
    monkeypatch.setattr(
        "analyzers.android.scanner.analyze_with_jadx",
        lambda **_: AndroidExternalToolResult(
            tool_name="jadx",
            available=True,
            executed=True,
            source_files_scanned=4,
            signals=(
                AndroidExternalToolSignal(
                    kind="hardcoded_url",
                    value="https://staging.example.com/api",
                    location="sources/com/example/internal/ApiClient.java",
                ),
            ),
        ),
    )

    report = build_normalized_report(
        file_name="sample.apk",
        platform="android",
        file_bytes=file_bytes,
        file_extension=extension,
    )

    payload = report.model_dump()
    assert payload["summary"]["total_findings"] == len(payload["findings"])
    jadx_finding = next(
        finding
        for finding in payload["findings"]
        if finding["id"] == "ANDROID-JADX-URL-001"
    )
    assert jadx_finding["confidence_level"] == "heuristic"
    assert jadx_finding["detection_method"] == "jadx-source-analysis"
    assert (
        jadx_finding["source_location"] == "sources/com/example/internal/ApiClient.java"
    )
    assert payload["metadata"]["file_extension"] == ".apk"


def test_report_builder_preserves_shape_when_jadx_is_unavailable(monkeypatch) -> None:
    file_bytes, extension = _build_android_payload()
    monkeypatch.setattr(
        "analyzers.android.scanner.analyze_with_jadx",
        lambda **_: AndroidExternalToolResult(
            tool_name="jadx", available=False, executed=False
        ),
    )

    report = build_normalized_report(
        file_name="sample.apk",
        platform="android",
        file_bytes=file_bytes,
        file_extension=extension,
    )

    payload = report.model_dump()
    assert payload["analysis_status"] == "warning"
    assert payload["warnings"][0]["code"] == "ANDROID-JADX-SKIPPED"
    assert payload["summary"]["total_findings"] == len(payload["findings"])
    assert all(
        not finding["id"].startswith("ANDROID-JADX-") for finding in payload["findings"]
    )


def test_report_builder_gracefully_falls_back_when_jadx_fails(monkeypatch) -> None:
    file_bytes, extension = _build_android_payload()
    monkeypatch.setattr(
        "analyzers.android.scanner.analyze_with_jadx",
        lambda **_: AndroidExternalToolResult(
            tool_name="jadx",
            available=True,
            executed=False,
            error="jadx timed out",
        ),
    )

    report = build_normalized_report(
        file_name="sample.apk",
        platform="android",
        file_bytes=file_bytes,
        file_extension=extension,
    )

    payload = report.model_dump()
    assert payload["analysis_status"] == "warning"
    assert payload["warnings"][0]["code"] == "ANDROID-JADX-FAILED"
    assert payload["summary"]["total_findings"] == len(payload["findings"])
    assert all(
        not finding["id"].startswith("ANDROID-JADX-") for finding in payload["findings"]
    )


def test_report_builder_wraps_android_analyzer_failures(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.report_builder.analyze_android_package",
        lambda **_: (_ for _ in ()).throw(RuntimeError("android analyzer boom")),
    )

    with pytest.raises(UploadValidationError) as exc_info:
        build_normalized_report(
            file_name="sample.apk",
            platform="android",
            file_bytes=b"placeholder",
            file_extension=".apk",
        )

    assert exc_info.value.code == "ANALYSIS_FAILED"
    assert exc_info.value.status_code == 500
    assert exc_info.value.details["stage"] == "android-analyzer"


def test_report_builder_isolates_android_analyzer_failure_in_partial_mode(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "app.services.report_builder.analyze_android_package",
        lambda **_: (_ for _ in ()).throw(RuntimeError("android analyzer boom")),
    )

    report = build_normalized_report(
        file_name="sample.apk",
        platform="android",
        file_bytes=b"placeholder",
        file_extension=".apk",
        allow_partial=True,
    )

    assert report.analysis_status == "partial"
    assert report.summary.total_findings == 0
    assert report.errors[0].code == "ANALYZER_STEP_FAILED"
    assert report.errors[0].stage == "android-analyzer"


def test_report_builder_wraps_malformed_android_output(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.report_builder.analyze_android_package",
        lambda **_: [{"id": "BROKEN-FINDING"}],
    )

    with pytest.raises(UploadValidationError) as exc_info:
        build_normalized_report(
            file_name="sample.apk",
            platform="android",
            file_bytes=b"placeholder",
            file_extension=".apk",
        )

    assert exc_info.value.code == "ANALYSIS_FAILED"
    assert exc_info.value.details["stage"] == "report-normalization"
