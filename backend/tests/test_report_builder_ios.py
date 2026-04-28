from io import BytesIO
import plistlib
from zipfile import ZipFile

from app.services.report_builder import build_normalized_report


def _build_ios_payload() -> tuple[bytes, str]:
    info_plist = {
        "CFBundleIdentifier": "com.example.ios",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    content = "token=mysecretvalue\nurl=http://legacy.example.com"

    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("Payload/Sample.app/Info.plist", plistlib.dumps(info_plist))
        archive.writestr("Payload/Sample.app/config.txt", content)

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
