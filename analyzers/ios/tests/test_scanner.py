from io import BytesIO
import plistlib
from zipfile import ZIP_DEFLATED, ZipFile

from analyzers.ios.scanner import analyze_ios_package


def _build_mobileprovision(entitlements: dict[str, object]) -> bytes:
    embedded_plist = plistlib.dumps({"Entitlements": entitlements})
    return b"CMS-HEADER\n" + embedded_plist + b"\nCMS-FOOTER"


def _build_ipa(
    info_plist: dict[str, object] | bytes | None,
    extra_entries: dict[str, bytes | str] | None = None,
    entitlements: dict[str, object] | None = None,
    mobileprovision_entitlements: dict[str, object] | None = None,
) -> tuple[str, bytes, str]:
    file_name = "sample.ipa"
    buffer = BytesIO()
    app_root = "Payload/Sample.app"
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        if info_plist is not None:
            content = plistlib.dumps(info_plist) if isinstance(info_plist, dict) else info_plist
            archive.writestr(f"{app_root}/Info.plist", content)

        if entitlements is not None:
            archive.writestr(f"{app_root}/archived-expanded-entitlements.xcent", plistlib.dumps(entitlements))

        if mobileprovision_entitlements is not None:
            archive.writestr(
                f"{app_root}/embedded.mobileprovision",
                _build_mobileprovision(mobileprovision_entitlements),
            )

        for entry_name, content in (extra_entries or {}).items():
            archive.writestr(entry_name, content)

    return file_name, buffer.getvalue(), ".ipa"


def test_ios_ipa_analyzer_extracts_metadata_plist_entitlement_and_string_findings() -> None:
    info_plist = {
        "CFBundleIdentifier": "com.example.ios",
        "CFBundleName": "Sample",
        "CFBundleDisplayName": "Sample App",
        "CFBundleExecutable": "Sample",
        "CFBundleVersion": "42",
        "CFBundleShortVersionString": "1.2.3",
        "MinimumOSVersion": "15.0",
        "UIFileSharingEnabled": True,
        "LSSupportsOpeningDocumentsInPlace": True,
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSAllowsArbitraryLoadsInWebContent": True,
            "NSExceptionDomains": {
                "legacy.example.com": {
                    "NSExceptionAllowsInsecureHTTPLoads": True,
                    "NSExceptionMinimumTLSVersion": "TLSv1.0",
                }
            },
        },
        "LSApplicationQueriesSchemes": [f"scheme{i}" for i in range(25)],
    }
    entitlements = {
        "get-task-allow": True,
        "keychain-access-groups": [f"group{i}" for i in range(4)],
        "com.apple.security.application-groups": [f"shared{i}" for i in range(4)],
        "aps-environment": "development",
    }
    extra_entries = {
        "Payload/Sample.app/Sample": b"\xcf\xfa\xed\xfe",
        "Payload/Sample.app/config.txt": (
            "client_secret=supersecretvalue\n"
            "endpoint=https://api.example.com\n"
            "legacy=http://legacy.example.com\n"
            "staging=https://staging.example.com/api\n"
            "Authorization=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature\n"
        ),
    }
    file_name, file_bytes, ext = _build_ipa(
        info_plist=info_plist,
        extra_entries=extra_entries,
        entitlements=entitlements,
    )

    findings = analyze_ios_package(file_name=file_name, file_bytes=file_bytes, file_extension=ext)
    ids = {finding["id"] for finding in findings}
    metadata = next(finding for finding in findings if finding["id"] == "IOS-METADATA-001")

    assert "IOS-METADATA-001" in ids
    assert "IOS-PLIST-ATS-001" in ids
    assert "IOS-PLIST-ATS-002" in ids
    assert "IOS-PLIST-ATS-003" in ids
    assert "IOS-PLIST-ATS-004" in ids
    assert "IOS-PLIST-QUERY-001" in ids
    assert "IOS-PLIST-FILE-001" in ids
    assert "IOS-PLIST-FILE-002" in ids
    assert "IOS-ENTITLEMENTS-DBG-001" in ids
    assert "IOS-ENTITLEMENTS-KEYCHAIN-001" in ids
    assert "IOS-ENTITLEMENTS-GROUPS-001" in ids
    assert "IOS-ENTITLEMENTS-PUSH-001" in ids
    assert "IOS-STRINGS-URL-001" in ids
    assert "IOS-STRINGS-URL-002" in ids
    assert "IOS-STRINGS-URL-003" in ids
    assert "IOS-STRINGS-SECRET-001" in ids
    assert "IOS-STRINGS-TOKEN-001" in ids
    assert "payload_app_path=Payload/Sample.app" in metadata["description"]
    assert "entitlements_source=bundle-entitlements" in metadata["description"]
    assert "bundle_executable_present=True" in metadata["description"]
    assert all(
        finding["title"].startswith(("Confirmed:", "Heuristic:", "Informational:"))
        for finding in findings
    )
    assert all("confidence_level" in finding for finding in findings)
    assert all("evidence" in finding for finding in findings)
    assert all("detection_method" in finding for finding in findings)
    ats_finding = next(finding for finding in findings if finding["id"] == "IOS-PLIST-ATS-001")
    assert ats_finding["confidence_level"] == "confirmed"
    assert "NSAllowsArbitraryLoads=true" in ats_finding["evidence"]
    assert ats_finding["detection_method"] == "info-plist-inspection"


def test_ios_ipa_uses_mobileprovision_entitlements_when_bundle_entitlements_missing() -> None:
    info_plist = {
        "CFBundleIdentifier": "com.example.ios",
        "CFBundleExecutable": "Sample",
    }
    extra_entries = {
        "Payload/Sample.app/Sample": b"\xcf\xfa\xed\xfe",
        "Payload/Sample.app/config.txt": "noop",
    }
    file_name, file_bytes, ext = _build_ipa(
        info_plist=info_plist,
        extra_entries=extra_entries,
        mobileprovision_entitlements={"get-task-allow": True},
    )

    findings = analyze_ios_package(file_name=file_name, file_bytes=file_bytes, file_extension=ext)
    metadata = next(finding for finding in findings if finding["id"] == "IOS-METADATA-001")

    assert "entitlements_source=embedded-mobileprovision" in metadata["description"]
    assert any(finding["id"] == "IOS-ENTITLEMENTS-DBG-001" for finding in findings)
    debug_finding = next(finding for finding in findings if finding["id"] == "IOS-ENTITLEMENTS-DBG-001")
    assert debug_finding["source_location"] == "Payload/Sample.app/embedded.mobileprovision"


def test_ios_requires_ipa_extension() -> None:
    findings = analyze_ios_package(file_name="sample.zip", file_bytes=b"PK\x03\x04", file_extension=".zip")

    assert findings[0]["id"] == "IOS-FORMAT-001"
    assert findings[0]["title"].startswith("Confirmed:")


def test_invalid_ipa_returns_critical_finding() -> None:
    findings = analyze_ios_package(file_name="bad.ipa", file_bytes=b"not-a-zip", file_extension=".ipa")

    assert findings[0]["id"] == "IOS-ARCHIVE-001"
    assert findings[0]["severity"] == "critical"


def test_ios_scanner_reports_missing_info_plist_and_payload_fallbacks() -> None:
    file_name, file_bytes, ext = _build_ipa(
        info_plist=None,
        extra_entries={"Payload/Sample.app/config.txt": "noop"},
    )

    findings = analyze_ios_package(file_name=file_name, file_bytes=file_bytes, file_extension=ext)
    ids = {finding["id"] for finding in findings}

    assert "IOS-PLIST-404" in ids
    assert "IOS-METADATA-001" in ids


def test_ios_scanner_honors_custom_zip_limit() -> None:
    info_plist = {"CFBundleIdentifier": "com.example.limit", "CFBundleExecutable": "Sample"}
    file_name, file_bytes, ext = _build_ipa(
        info_plist=info_plist,
        extra_entries={
            "Payload/Sample.app/Sample": b"\xcf\xfa\xed\xfe",
            "Payload/Sample.app/config.txt": "A" * 2_000,
        },
    )

    findings = analyze_ios_package(
        file_name=file_name,
        file_bytes=file_bytes,
        file_extension=ext,
        max_extracted_bytes=500,
    )

    assert findings[0]["id"] == "IOS-ARCHIVE-BOMB"


def test_ios_scanner_honors_custom_text_file_size_limit() -> None:
    info_plist = {"CFBundleIdentifier": "com.example.limit", "CFBundleExecutable": "Sample"}
    file_name, file_bytes, ext = _build_ipa(
        info_plist=info_plist,
        extra_entries={
            "Payload/Sample.app/Sample": b"\xcf\xfa\xed\xfe",
            "Payload/Sample.app/config.txt": (
                "client_secret=supersecretvalue\n"
                "endpoint=https://api.example.com\n"
                "Authorization=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
            ),
        },
    )

    findings = analyze_ios_package(
        file_name=file_name,
        file_bytes=file_bytes,
        file_extension=ext,
        max_text_file_size=10,
    )
    ids = {finding["id"] for finding in findings}

    assert "IOS-STRINGS-000" in ids
    assert "IOS-STRINGS-URL-001" not in ids
    assert "IOS-STRINGS-SECRET-001" not in ids
    assert "IOS-STRINGS-TOKEN-001" not in ids


def test_ios_scanner_gracefully_handles_missing_entitlements() -> None:
    info_plist = {
        "CFBundleIdentifier": "com.example.noentitlements",
        "CFBundleExecutable": "Sample",
    }
    file_name, file_bytes, ext = _build_ipa(
        info_plist=info_plist,
        extra_entries={
            "Payload/Sample.app/Sample": b"\xcf\xfa\xed\xfe",
            "Payload/Sample.app/config.txt": "noop",
        },
    )

    findings = analyze_ios_package(file_name=file_name, file_bytes=file_bytes, file_extension=ext)
    metadata = next(finding for finding in findings if finding["id"] == "IOS-METADATA-001")

    assert "entitlements_path=missing" in metadata["description"]
    assert all(not finding["id"].startswith("IOS-ENTITLEMENTS-") for finding in findings)
