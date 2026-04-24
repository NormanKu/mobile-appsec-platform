from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from analyzers.android.external_tools import (
    AndroidExternalToolResult,
    AndroidExternalToolSignal,
)
from analyzers.android.scanner import analyze_android_package


def _build_android_archive(
    extension: str,
    manifest_text: str,
    extra_text: str,
    manifest_path: str | None = None,
    compression: int = ZIP_DEFLATED,
) -> tuple[str, bytes, str]:
    file_name = f"sample{extension}"
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=compression) as archive:
        archive.writestr(manifest_path or "AndroidManifest.xml", manifest_text)
        archive.writestr("assets/config.txt", extra_text)
    return file_name, buffer.getvalue(), extension


def test_android_apk_analyzer_extracts_metadata_and_security_findings() -> None:
    manifest = """
    <manifest package="com.example.app" android:versionName="1.2.3" android:versionCode="12"
      xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:debuggable="true" android:usesCleartextTraffic="true" android:allowBackup="true" />
      <activity android:name=".MainActivity" android:exported="true" />
    </manifest>
    """
    strings = "API_KEY=abcd1234SECRET\nendpoint=https://api.example.com/v1"
    name, raw, ext = _build_android_archive(".apk", manifest, strings)

    findings = analyze_android_package(
        file_name=name, file_bytes=raw, file_extension=ext
    )
    ids = {finding["id"] for finding in findings}

    assert "ANDROID-METADATA-001" in ids
    assert "ANDROID-MANIFEST-DBG-001" in ids
    assert "ANDROID-MANIFEST-NET-001" in ids
    assert "ANDROID-MANIFEST-BACKUP-001" in ids
    assert "ANDROID-MANIFEST-BACKUP-002" in ids
    assert "ANDROID-MANIFEST-EXP-001" in ids
    assert "ANDROID-STRINGS-URL-001" in ids
    assert "ANDROID-STRINGS-SECRET-001" in ids
    assert all("source" in finding for finding in findings)
    assert all("confidence_level" in finding for finding in findings)
    assert all("evidence" in finding for finding in findings)
    assert all("detection_method" in finding for finding in findings)
    debug_finding = next(
        finding for finding in findings if finding["id"] == "ANDROID-MANIFEST-DBG-001"
    )
    assert debug_finding["confidence_level"] == "confirmed"
    assert 'android:debuggable="true"' in debug_finding["evidence"]
    assert debug_finding["detection_method"] == "manifest-inspection"


def test_android_aab_supported() -> None:
    manifest = '<manifest package="com.example.bundle" xmlns:android="http://schemas.android.com/apk/res/android" />'
    name, raw, ext = _build_android_archive(
        ".aab",
        manifest,
        "noop",
        manifest_path="base/manifest/AndroidManifest.xml",
    )

    findings = analyze_android_package(
        file_name=name, file_bytes=raw, file_extension=ext
    )
    ids = {finding["id"] for finding in findings}
    metadata = next(f for f in findings if f["id"] == "ANDROID-METADATA-001")

    assert "package_type=aab" in metadata["description"]
    assert "manifest_path=base/manifest/AndroidManifest.xml" in metadata["description"]
    assert "ANDROID-MANIFEST-404" not in ids


def test_invalid_archive_returns_critical_finding() -> None:
    findings = analyze_android_package(
        file_name="bad.apk",
        file_bytes=b"not-a-zip",
        file_extension=".apk",
    )

    assert findings[0]["id"] == "ANDROID-ARCHIVE-001"
    assert findings[0]["severity"] == "critical"


def test_android_scanner_honors_custom_zip_limit() -> None:
    manifest = '<manifest package="com.example.limit" xmlns:android="http://schemas.android.com/apk/res/android" />'
    name, raw, ext = _build_android_archive(".apk", manifest, "A" * 2_000)

    findings = analyze_android_package(
        file_name=name,
        file_bytes=raw,
        file_extension=ext,
        max_extracted_bytes=500,
    )

    assert findings[0]["id"] == "ANDROID-ARCHIVE-BOMB"


def test_android_scanner_honors_custom_text_file_size_limit() -> None:
    manifest = '<manifest package="com.example.limit" xmlns:android="http://schemas.android.com/apk/res/android" />'
    name, raw, ext = _build_android_archive(
        ".apk", manifest, "token=mysecretvalue\nurl=https://api.example.com"
    )

    findings = analyze_android_package(
        file_name=name,
        file_bytes=raw,
        file_extension=ext,
        max_text_file_size=10,
    )
    ids = {finding["id"] for finding in findings}

    assert "ANDROID-STRINGS-000" in ids
    assert "ANDROID-STRINGS-URL-001" not in ids
    assert "ANDROID-STRINGS-SECRET-001" not in ids


def test_android_scanner_adds_jadx_enrichment_when_available(monkeypatch) -> None:
    manifest = '<manifest package="com.example.jadx" xmlns:android="http://schemas.android.com/apk/res/android" />'
    name, raw, ext = _build_android_archive(".apk", manifest, "noop")
    tool_result = AndroidExternalToolResult(
        tool_name="jadx",
        available=True,
        executed=True,
        source_files_scanned=7,
        signals=(
            AndroidExternalToolSignal(
                kind="readable_source",
                value="com.example.internal.ApiClient",
                location="sources/com/example/internal/ApiClient.java",
            ),
            AndroidExternalToolSignal(
                kind="hardcoded_url",
                value="https://staging.example.com/api",
                location="sources/com/example/internal/ApiClient.java",
            ),
            AndroidExternalToolSignal(
                kind="candidate_secret",
                value="API_KEY=abcdef...",
                location="sources/com/example/internal/TokenVault.kt",
            ),
            AndroidExternalToolSignal(
                kind="naming_pattern",
                value="com.example.internal.TokenVault",
                location="sources/com/example/internal/TokenVault.kt",
            ),
        ),
    )
    monkeypatch.setattr(
        "analyzers.android.scanner.analyze_with_jadx", lambda **_: tool_result
    )

    findings = analyze_android_package(
        file_name=name, file_bytes=raw, file_extension=ext
    )
    ids = {finding["id"] for finding in findings}
    jadx_findings = [
        finding for finding in findings if finding["id"].startswith("ANDROID-JADX-")
    ]

    assert {
        "ANDROID-JADX-CODE-001",
        "ANDROID-JADX-URL-001",
        "ANDROID-JADX-SECRET-001",
        "ANDROID-JADX-NAME-001",
    } <= ids
    assert all(finding["title"].startswith("Heuristic:") for finding in jadx_findings)
    assert all(finding["source"] == "jadx/source" for finding in jadx_findings)
    assert all(finding["confidence_level"] == "heuristic" for finding in jadx_findings)
    assert all(
        finding["detection_method"] == "jadx-source-analysis"
        for finding in jadx_findings
    )
    assert all(finding["source_location"] for finding in jadx_findings)


def test_android_scanner_gracefully_skips_unavailable_jadx(monkeypatch) -> None:
    manifest = '<manifest package="com.example.nojadx" xmlns:android="http://schemas.android.com/apk/res/android" />'
    name, raw, ext = _build_android_archive(".apk", manifest, "noop")
    monkeypatch.setattr(
        "analyzers.android.scanner.analyze_with_jadx",
        lambda **_: AndroidExternalToolResult(
            tool_name="jadx", available=False, executed=False
        ),
    )

    findings = analyze_android_package(
        file_name=name, file_bytes=raw, file_extension=ext
    )

    assert any(finding["id"] == "ANDROID-METADATA-001" for finding in findings)
    diagnostic = next(
        finding for finding in findings if finding["id"] == "ANDROID-JADX-SKIPPED"
    )
    assert diagnostic["diagnostic_level"] == "warning"
    assert diagnostic["diagnostic_tool"] == "jadx"


def test_android_scanner_reports_jadx_execution_failure_as_warning(monkeypatch) -> None:
    manifest = '<manifest package="com.example.jadxfail" xmlns:android="http://schemas.android.com/apk/res/android" />'
    name, raw, ext = _build_android_archive(".apk", manifest, "noop")
    monkeypatch.setattr(
        "analyzers.android.scanner.analyze_with_jadx",
        lambda **_: AndroidExternalToolResult(
            tool_name="jadx",
            available=True,
            executed=False,
            error="jadx timed out",
        ),
    )

    findings = analyze_android_package(
        file_name=name, file_bytes=raw, file_extension=ext
    )
    diagnostic = next(
        finding for finding in findings if finding["id"] == "ANDROID-JADX-FAILED"
    )

    assert diagnostic["diagnostic_level"] == "warning"
    assert diagnostic["diagnostic_details"]["error"] == "jadx timed out"
