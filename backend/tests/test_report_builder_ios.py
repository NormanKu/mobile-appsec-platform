from io import BytesIO
import plistlib
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from app.errors.exceptions import UploadValidationError
from app.services.report_builder import build_normalized_report


def _build_ios_payload(include_entitlements: bool = False) -> tuple[bytes, str]:
    info_plist = {
        "CFBundleIdentifier": "com.example.ios",
        "CFBundleExecutable": "Sample",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    content = (
        "token=mysecretvalue\n"
        "url=http://legacy.example.com\n"
        "Authorization=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
    )

    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("Payload/Sample.app/Info.plist", plistlib.dumps(info_plist))
        archive.writestr("Payload/Sample.app/Sample", b"\xcf\xfa\xed\xfe")
        archive.writestr("Payload/Sample.app/config.txt", content)
        if include_entitlements:
            archive.writestr(
                "Payload/Sample.app/archived-expanded-entitlements.xcent",
                plistlib.dumps({"get-task-allow": True}),
            )

    return buffer.getvalue(), ".ipa"


def test_report_builder_routes_ios_and_returns_extended_shape() -> None:
    file_bytes, extension = _build_ios_payload()

    report = build_normalized_report(
        file_name="sample.ipa",
        platform="ios",
        file_bytes=file_bytes,
        file_extension=extension,
    )

    payload = report.model_dump()
    assert payload["platform"] == "ios"
    assert payload["file_name"] == "sample.ipa"
    assert {"platform", "file_name", "risk_level", "score", "summary", "findings", "categories", "metadata"}.issubset(
        payload.keys()
    )
    assert isinstance(payload["score"], int)
    assert all("source" in finding for finding in payload["findings"])
    assert all("confidence_level" in finding for finding in payload["findings"])
    assert all("evidence" in finding for finding in payload["findings"])
    assert all("detection_method" in finding for finding in payload["findings"])
    # Confidence prefixes are now extracted into confidence_level and stripped from titles
    assert all(
        finding["confidence_level"] in ("confirmed", "heuristic", "informational")
        for finding in payload["findings"]
    )
    assert all(
        not finding["title"].startswith(("Confirmed:", "Heuristic:", "Informational:"))
        for finding in payload["findings"]
    )
    assert sum(c["count"] for c in payload["categories"]) == payload["summary"]["total_findings"]


def test_report_builder_routes_only_ios_analyzer(monkeypatch) -> None:
    called = {"android": False, "ios": False}

    def fake_android_package(**_: object) -> list[dict[str, object]]:
        called["android"] = True
        raise AssertionError("Android analyzer should not be called for iOS reports")

    def fake_ios_package(**_: object) -> list[dict[str, object]]:
        called["ios"] = True
        return [
            {
                "id": "IOS-TEST-001",
                "title": "Test analyzer finding",
                "severity": "low",
                "category": "analysis",
                "description": "ios analyzer route selected",
                "recommendation": "noop",
                "source": "ios-test",
            }
        ]

    monkeypatch.setattr("app.services.report_builder.analyze_android_package", fake_android_package)
    monkeypatch.setattr("app.services.report_builder.analyze_ios_package", fake_ios_package)

    report = build_normalized_report(
        file_name="sample.ipa",
        platform="ios",
        file_bytes=b"placeholder",
        file_extension=".ipa",
    )

    assert called == {"android": False, "ios": True}
    assert report.platform == "ios"


def test_report_builder_raises_for_missing_ios_info_plist() -> None:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("Payload/Sample.app/config.txt", "noop")

    with pytest.raises(UploadValidationError) as exc_info:
        build_normalized_report(
            file_name="broken.ipa",
            platform="ios",
            file_bytes=buffer.getvalue(),
            file_extension=".ipa",
        )
    assert exc_info.value.code == "INVALID_ARCHIVE"


def test_report_builder_routes_ios_with_entitlements_and_token_findings() -> None:
    file_bytes, extension = _build_ios_payload(include_entitlements=True)

    report = build_normalized_report(
        file_name="sample.ipa",
        platform="ios",
        file_bytes=file_bytes,
        file_extension=extension,
    )

    payload = report.model_dump()
    ids = {finding["id"] for finding in payload["findings"]}

    assert "IOS-ENTITLEMENTS-DBG-001" in ids
    assert "IOS-STRINGS-TOKEN-001" in ids
    debug_finding = next(finding for finding in payload["findings"] if finding["id"] == "IOS-ENTITLEMENTS-DBG-001")
    assert debug_finding["confidence_level"] == "confirmed"
    assert debug_finding["detection_method"] == "entitlements-inspection"


def test_report_builder_gracefully_handles_missing_entitlements() -> None:
    file_bytes, extension = _build_ios_payload(include_entitlements=False)

    report = build_normalized_report(
        file_name="sample.ipa",
        platform="ios",
        file_bytes=file_bytes,
        file_extension=extension,
    )

    payload = report.model_dump()
    assert payload["summary"]["total_findings"] == len(payload["findings"])
    assert all(not finding["id"].startswith("IOS-ENTITLEMENTS-") for finding in payload["findings"])


def test_report_builder_wraps_ios_analyzer_failures(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.report_builder.analyze_ios_package",
        lambda **_: (_ for _ in ()).throw(RuntimeError("ios analyzer boom")),
    )

    with pytest.raises(UploadValidationError) as exc_info:
        build_normalized_report(
            file_name="sample.ipa",
            platform="ios",
            file_bytes=b"placeholder",
            file_extension=".ipa",
        )

    assert exc_info.value.code == "ANALYSIS_FAILED"
    assert exc_info.value.status_code == 500
    assert exc_info.value.details["stage"] == "ios-analyzer"
