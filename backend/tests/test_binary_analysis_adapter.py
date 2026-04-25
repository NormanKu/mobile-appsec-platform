from __future__ import annotations

from io import BytesIO
import plistlib
from zipfile import ZipFile

from analyzers.adapters.binary_analysis import (
    BinaryArtifact,
    BinaryAnalysisRouter,
    extract_binary_artifacts,
    run_optional_binary_analysis,
)
from app.core.config import settings
from app.services import report_builder


def _elf64_arm64_bytes(extra: bytes = b"") -> bytes:
    data = bytearray(b"\x7fELF")
    data.extend([2, 1, 1, 0])
    while len(data) < 18:
        data.append(0)
    data.extend((0xB7).to_bytes(2, byteorder="little"))
    data.extend(b"\0" * 64)
    data.extend(extra)
    return bytes(data)


def _macho64_arm64_bytes() -> bytes:
    return b"\xcf\xfa\xed\xfe" + (16777228).to_bytes(4, byteorder="little", signed=True) + b"\0" * 64


def _android_package_with_native_library(binary: bytes | None = None) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            '<manifest package="com.example.native"><application /></manifest>',
        )
        archive.writestr("lib/arm64-v8a/libnative.so", binary or _elf64_arm64_bytes())
    return buffer.getvalue()


def _ios_package_with_main_binary() -> bytes:
    info = {
        "CFBundleIdentifier": "com.example.ios",
        "CFBundleExecutable": "Runner",
    }
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("Payload/Runner.app/Info.plist", plistlib.dumps(info))
        archive.writestr("Payload/Runner.app/Runner", _macho64_arm64_bytes())
    return buffer.getvalue()


def test_extracts_android_native_libraries_for_binary_adapters() -> None:
    artifacts = extract_binary_artifacts(
        file_name="sample.apk",
        file_bytes=_android_package_with_native_library(),
        platform="android",
        file_extension=".apk",
    )

    assert len(artifacts) == 1
    assert artifacts[0].platform == "android"
    assert artifacts[0].kind == "android-native-library"
    assert artifacts[0].path == "lib/arm64-v8a/libnative.so"


def test_binary_metadata_adapter_routes_android_native_library() -> None:
    findings = run_optional_binary_analysis(
        enabled=True,
        file_name="sample.apk",
        file_bytes=_android_package_with_native_library(b"http://example.test" + _elf64_arm64_bytes()),
        platform="android",
        file_extension=".apk",
    )

    assert any(finding["category"] == "binary-metadata" for finding in findings)
    assert any(finding["category"] == "binary-network" for finding in findings)
    metadata = next(finding for finding in findings if finding["category"] == "binary-metadata")
    assert metadata["id"].startswith("BINARY-ANDROID-METADATA-")
    assert metadata["source"] == "binary-metadata/lib/arm64-v8a/libnative.so"
    assert "format=elf" in metadata["description"]
    assert "architecture=aarch64" in metadata["description"]


def test_binary_metadata_adapter_routes_ios_main_binary() -> None:
    findings = run_optional_binary_analysis(
        enabled=True,
        file_name="Runner.ipa",
        file_bytes=_ios_package_with_main_binary(),
        platform="ios",
        file_extension=".ipa",
    )

    assert len(findings) == 1
    assert findings[0]["id"].startswith("BINARY-IOS-METADATA-")
    assert findings[0]["source"] == "binary-metadata/Payload/Runner.app/Runner"
    assert "format=mach-o" in findings[0]["description"]
    assert "architecture=arm64" in findings[0]["description"]


def test_binary_analysis_falls_back_when_disabled_or_no_adapters() -> None:
    package = _android_package_with_native_library()

    assert (
        run_optional_binary_analysis(
            enabled=False,
            file_name="sample.apk",
            file_bytes=package,
            platform="android",
            file_extension=".apk",
        )
        == []
    )
    assert (
        run_optional_binary_analysis(
            enabled=True,
            file_name="sample.apk",
            file_bytes=package,
            platform="android",
            file_extension=".apk",
            adapters=[],
        )
        == []
    )


def test_binary_adapter_failure_is_isolated() -> None:
    class BrokenAdapter:
        name = "broken"

        def supports(self, artifact: BinaryArtifact) -> bool:
            return True

        def analyze(self, artifact: BinaryArtifact):
            raise RuntimeError("tool missing")

    findings = BinaryAnalysisRouter([BrokenAdapter()]).analyze_package(
        file_name="sample.apk",
        file_bytes=_android_package_with_native_library(),
        platform="android",
        file_extension=".apk",
    )

    assert findings == []


def test_report_builder_appends_binary_findings_when_enabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "binary_analysis_enabled", True)

    report = report_builder.build_normalized_report(
        file_name="sample.apk",
        platform="android",
        file_bytes=_android_package_with_native_library(),
        file_extension=".apk",
    )

    assert any(finding.source == "binary-metadata/lib/arm64-v8a/libnative.so" for finding in report.findings)
    assert report.summary.total_findings == len(report.findings)
    assert any(category.name == "binary-metadata" for category in report.categories)
