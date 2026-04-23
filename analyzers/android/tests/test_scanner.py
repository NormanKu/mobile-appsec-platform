from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

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
    manifest = '''
    <manifest package="com.example.app" android:versionName="1.2.3" android:versionCode="12"
      xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:debuggable="true" android:usesCleartextTraffic="true" android:allowBackup="true" />
      <activity android:name=".MainActivity" android:exported="true" />
    </manifest>
    '''
    strings = "API_KEY=abcd1234SECRET\nendpoint=https://api.example.com/v1"
    name, raw, ext = _build_android_archive(".apk", manifest, strings)

    findings = analyze_android_package(file_name=name, file_bytes=raw, file_extension=ext)
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


def test_android_aab_supported() -> None:
    manifest = '<manifest package="com.example.bundle" xmlns:android="http://schemas.android.com/apk/res/android" />'
    name, raw, ext = _build_android_archive(
        ".aab",
        manifest,
        "noop",
        manifest_path="base/manifest/AndroidManifest.xml",
    )

    findings = analyze_android_package(file_name=name, file_bytes=raw, file_extension=ext)
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
