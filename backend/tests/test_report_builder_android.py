from io import BytesIO
from zipfile import ZipFile

from app.services.report_builder import build_normalized_report


def _build_android_payload() -> tuple[bytes, str]:
    manifest = """
    <manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:debuggable="true" android:allowBackup="true" />
    </manifest>
    """
    content = "token=mysecretvalue\nurl=https://api.example.com"

    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
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
        "metadata",
    }.issubset(payload.keys())
    assert isinstance(payload["score"], int)
    assert all("source" in finding for finding in payload["findings"])
    assert (
        sum(c["count"] for c in payload["categories"])
        == payload["summary"]["total_findings"]
    )
