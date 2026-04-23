from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from io import BytesIO
import plistlib
from zipfile import ZipFile

from analyzers.ios.scanner import analyze_ios_package


def _build_ipa(info_plist: dict, extra_text: str) -> tuple[str, bytes, str]:
    file_name = "sample.ipa"
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("Payload/Sample.app/Info.plist", plistlib.dumps(info_plist))
        archive.writestr("Payload/Sample.app/config.txt", extra_text)
    return file_name, buffer.getvalue(), ".ipa"


def test_ios_ipa_analyzer_extracts_metadata_plist_and_string_findings() -> None:
    info_plist = {
        "CFBundleIdentifier": "com.example.ios",
        "CFBundleVersion": "42",
        "CFBundleShortVersionString": "1.2.3",
        "MinimumOSVersion": "15.0",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {
                "example.com": {
                    "NSExceptionAllowsInsecureHTTPLoads": True,
                }
            },
        },
        "LSApplicationQueriesSchemes": [f"scheme{i}" for i in range(25)],
    }
    strings = "client_secret=supersecretvalue\nendpoint=https://api.example.com\nlegacy=http://legacy.example.com"
    file_name, file_bytes, ext = _build_ipa(info_plist, strings)

    findings = analyze_ios_package(file_name=file_name, file_bytes=file_bytes, file_extension=ext)
    ids = {f["id"] for f in findings}

    assert "IOS-METADATA-001" in ids
    assert "IOS-PLIST-ATS-001" in ids
    assert "IOS-PLIST-ATS-002" in ids
    assert "IOS-PLIST-QUERY-001" in ids
    assert "IOS-STRINGS-URL-001" in ids
    assert "IOS-STRINGS-URL-002" in ids
    assert "IOS-STRINGS-SECRET-001" in ids
    assert all("source" in finding for finding in findings)


def test_ios_requires_ipa_extension() -> None:
    findings = analyze_ios_package(file_name="sample.zip", file_bytes=b"PK\x03\x04", file_extension=".zip")

    assert findings[0]["id"] == "IOS-FORMAT-001"


def test_invalid_ipa_returns_critical_finding() -> None:
    findings = analyze_ios_package(file_name="bad.ipa", file_bytes=b"not-a-zip", file_extension=".ipa")

    assert findings[0]["id"] == "IOS-ARCHIVE-001"
    assert findings[0]["severity"] == "critical"
