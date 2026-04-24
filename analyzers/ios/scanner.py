from __future__ import annotations

import logging
from dataclasses import dataclass
from io import BytesIO
import plistlib
import re
from urllib.parse import urlparse
from zipfile import BadZipFile, ZipFile

from analyzers.safe_zip import ZipExtractionLimitExceeded, validate_zip_limits

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|refresh[_-]?token|secret|token)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=:.]{8,})"
)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER_PATTERN = re.compile(r"(?i)bearer\s+([A-Za-z0-9\-._~+/=]{12,})")
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

TEXT_EXTENSIONS = {
    ".cfg",
    ".entitlements",
    ".h",
    ".json",
    ".js",
    ".mobileprovision",
    ".m",
    ".plist",
    ".strings",
    ".swift",
    ".txt",
    ".xcent",
    ".xml",
}
IGNORED_URLS = {
    "http://www.apple.com/dtds/propertylist-1.0.dtd",
}
NON_PRODUCTION_URL_KEYWORDS = (
    "dev",
    "debug",
    "internal",
    "localhost",
    "qa",
    "sandbox",
    "staging",
    "test",
    "uat",
)
WEAK_TLS_VALUES = {"tlsv1.0", "tlsv1.1"}
MAX_TEXT_FILE_SIZE = 1_000_000
MAX_TEXT_FILES_SCANNED = 200
MAX_SAMPLE_VALUES = 5


@dataclass
class IosPackageMetadata:
    archive_size_bytes: int
    file_count: int
    payload_app_path: str | None
    info_plist_path: str | None
    info_plist_readable: bool
    info_plist: dict[str, object] | None
    entitlements_path: str | None
    entitlements_source: str | None
    entitlements_readable: bool
    entitlements: dict[str, object] | None
    bundle_identifier: str | None
    bundle_name: str | None
    bundle_display_name: str | None
    bundle_executable: str | None
    bundle_executable_path: str | None
    bundle_executable_present: bool
    bundle_version: str | None
    bundle_short_version: str | None
    minimum_os_version: str | None


def analyze_ios_package(
    file_name: str,
    file_bytes: bytes,
    file_extension: str,
    max_extracted_bytes: int | None = None,
    max_files: int | None = None,
    max_text_file_size: int | None = None,
    max_text_files_scanned: int | None = None,
) -> list[dict[str, str]]:
    extension = file_extension.lower()
    if extension != ".ipa":
        return [
            _build_finding(
                id="IOS-FORMAT-001",
                title="Unsupported iOS package format",
                severity="high",
                category="file-format",
                description=f"File {file_name} has unsupported extension: {extension}",
                recommendation="Provide an iOS .ipa package",
                source="upload/extension",
                confidence="confirmed",
            )
        ]

    try:
        with ZipFile(BytesIO(file_bytes), "r") as archive:
            zip_limit_kwargs: dict[str, int] = {}
            if max_extracted_bytes is not None:
                zip_limit_kwargs["max_extracted_bytes"] = max_extracted_bytes
            if max_files is not None:
                zip_limit_kwargs["max_files"] = max_files
            validate_zip_limits(archive, **zip_limit_kwargs)

            metadata = _extract_basic_metadata(archive=archive, file_bytes=file_bytes)
            findings = _build_metadata_findings(file_name=file_name, metadata=metadata)
            findings.extend(_inspect_info_plist(metadata=metadata))
            findings.extend(_inspect_entitlements(metadata=metadata))
            findings.extend(
                _scan_archive_strings(
                    archive=archive,
                    max_text_file_size=MAX_TEXT_FILE_SIZE if max_text_file_size is None else max_text_file_size,
                    max_text_files_scanned=(
                        MAX_TEXT_FILES_SCANNED if max_text_files_scanned is None else max_text_files_scanned
                    ),
                )
            )
            return findings
    except ZipExtractionLimitExceeded as exc:
        return [
            _build_finding(
                id="IOS-ARCHIVE-BOMB",
                title="Archive exceeds safe extraction limits",
                severity="critical",
                category="file-format",
                description=str(exc),
                recommendation="Verify the archive is not maliciously crafted and retry with a smaller package",
                source="archive/zip",
                confidence="confirmed",
            )
        ]
    except BadZipFile:
        return [
            _build_finding(
                id="IOS-ARCHIVE-001",
                title="Invalid iOS archive",
                severity="critical",
                category="file-format",
                description=f"{file_name} is not a valid ZIP-based IPA archive",
                recommendation="Re-export the IPA and retry analysis",
                source="archive/zip",
                confidence="confirmed",
            )
        ]


def _extract_basic_metadata(archive: ZipFile, file_bytes: bytes) -> IosPackageMetadata:
    names = archive.namelist()
    payload_app_path = _resolve_payload_app_path(names)
    info_plist_path = _resolve_info_plist_path(names, payload_app_path)
    info_plist = _load_plist_entry(archive, info_plist_path)

    (
        entitlements_path,
        entitlements_source,
        entitlements,
        entitlements_readable,
    ) = _load_entitlements(archive, names=names, payload_app_path=payload_app_path)

    bundle_executable = _get_plist_value(info_plist, "CFBundleExecutable")
    bundle_executable_path = (
        f"{payload_app_path}/{bundle_executable}" if payload_app_path and bundle_executable else None
    )
    bundle_executable_present = bundle_executable_path in names if bundle_executable_path else False

    return IosPackageMetadata(
        archive_size_bytes=len(file_bytes),
        file_count=len(names),
        payload_app_path=payload_app_path,
        info_plist_path=info_plist_path,
        info_plist_readable=info_plist is not None,
        info_plist=info_plist,
        entitlements_path=entitlements_path,
        entitlements_source=entitlements_source,
        entitlements_readable=entitlements_readable,
        entitlements=entitlements,
        bundle_identifier=_get_plist_value(info_plist, "CFBundleIdentifier"),
        bundle_name=_get_plist_value(info_plist, "CFBundleName"),
        bundle_display_name=_get_plist_value(info_plist, "CFBundleDisplayName"),
        bundle_executable=bundle_executable,
        bundle_executable_path=bundle_executable_path,
        bundle_executable_present=bundle_executable_present,
        bundle_version=_get_plist_value(info_plist, "CFBundleVersion"),
        bundle_short_version=_get_plist_value(info_plist, "CFBundleShortVersionString"),
        minimum_os_version=_get_plist_value(info_plist, "MinimumOSVersion"),
    )


def _build_metadata_findings(file_name: str, metadata: IosPackageMetadata) -> list[dict[str, str]]:
    details = [
        f"archive_size_bytes={metadata.archive_size_bytes}",
        f"file_count={metadata.file_count}",
        f"payload_app_path={metadata.payload_app_path or 'missing'}",
        f"info_plist_path={metadata.info_plist_path or 'missing'}",
        f"info_plist_readable={metadata.info_plist_readable}",
        f"entitlements_path={metadata.entitlements_path or 'missing'}",
        f"entitlements_source={metadata.entitlements_source or 'none'}",
        f"entitlements_readable={metadata.entitlements_readable}",
    ]
    if metadata.bundle_identifier:
        details.append(f"bundle_identifier={metadata.bundle_identifier}")
    if metadata.bundle_name:
        details.append(f"bundle_name={metadata.bundle_name}")
    if metadata.bundle_display_name:
        details.append(f"bundle_display_name={metadata.bundle_display_name}")
    if metadata.bundle_executable:
        details.append(f"bundle_executable={metadata.bundle_executable}")
        details.append(f"bundle_executable_present={metadata.bundle_executable_present}")
    if metadata.bundle_version:
        details.append(f"bundle_version={metadata.bundle_version}")
    if metadata.bundle_short_version:
        details.append(f"bundle_short_version={metadata.bundle_short_version}")
    if metadata.minimum_os_version:
        details.append(f"minimum_os_version={metadata.minimum_os_version}")

    findings = [
        _build_finding(
            id="IOS-METADATA-001",
            title="iOS package metadata extracted",
            severity="low",
            category="metadata",
            description=f"Extracted metadata for {file_name}: " + ", ".join(details),
            recommendation="Review metadata consistency before release",
            source="archive/metadata",
            confidence="informational",
        )
    ]

    if not metadata.payload_app_path:
        findings.append(
            _build_finding(
                id="IOS-PAYLOAD-001",
                title="IPA payload app bundle not found",
                severity="high",
                category="file-format",
                description="IPA does not contain a Payload/*.app bundle structure",
                recommendation="Verify the IPA export contains a valid Payload/<App>.app bundle",
                source="Payload/*.app",
                confidence="confirmed",
            )
        )

    if not metadata.info_plist_path:
        findings.append(
            _build_finding(
                id="IOS-PLIST-404",
                title="Info.plist not found",
                severity="high",
                category="info-plist",
                description="IPA does not contain a Payload/*.app/Info.plist file",
                recommendation="Verify the IPA was generated correctly and includes app metadata",
                source="Payload/*.app/Info.plist",
                confidence="confirmed",
            )
        )
    elif not metadata.info_plist_readable:
        findings.append(
            _build_finding(
                id="IOS-PLIST-002",
                title="Info.plist could not be parsed",
                severity="medium",
                category="info-plist",
                description="Info.plist exists but could not be parsed via plistlib",
                recommendation="Validate plist format and export a readable Info.plist",
                source=metadata.info_plist_path,
                confidence="confirmed",
            )
        )

    if metadata.entitlements_path and not metadata.entitlements_readable:
        findings.append(
            _build_finding(
                id="IOS-ENTITLEMENTS-002",
                title="Entitlements could not be parsed",
                severity="low",
                category="entitlements",
                description="An entitlements source file was found but could not be parsed, so entitlement review was limited",
                recommendation="Verify the embedded entitlements or provisioning profile format if entitlement review is required",
                source=metadata.entitlements_path,
                confidence="informational",
            )
        )

    return findings


def _inspect_info_plist(metadata: IosPackageMetadata) -> list[dict[str, str]]:
    if not metadata.info_plist_path or not metadata.info_plist_readable or not isinstance(metadata.info_plist, dict):
        return []

    info = metadata.info_plist
    findings: list[dict[str, str]] = []

    ats = info.get("NSAppTransportSecurity")
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
        findings.append(
            _build_finding(
                id="IOS-PLIST-ATS-001",
                title="App Transport Security allows arbitrary loads",
                severity="high",
                category="network",
                description="NSAllowsArbitraryLoads=true weakens default network transport protections",
                recommendation="Disable arbitrary loads and use narrow ATS exceptions only when required",
                source=metadata.info_plist_path,
                confidence="confirmed",
            )
        )

    scoped_arbitrary_loads = []
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        scoped_arbitrary_loads.append("NSAllowsArbitraryLoadsInWebContent")
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoadsForMedia") is True:
        scoped_arbitrary_loads.append("NSAllowsArbitraryLoadsForMedia")
    if scoped_arbitrary_loads:
        findings.append(
            _build_finding(
                id="IOS-PLIST-ATS-003",
                title="Scoped ATS exceptions allow broader cleartext traffic",
                severity="medium",
                category="network",
                description="One or more ATS scoped arbitrary-load keys are enabled: " + ", ".join(scoped_arbitrary_loads),
                recommendation="Review whether scoped ATS relaxations are still required and remove them where possible",
                source=metadata.info_plist_path,
                confidence="confirmed",
            )
        )

    insecure_http_domains = _get_insecure_http_exception_domains(ats)
    if insecure_http_domains:
        findings.append(
            _build_finding(
                id="IOS-PLIST-ATS-002",
                title="ATS exception domains allow insecure HTTP",
                severity="medium",
                category="network",
                description=(
                    "ATS exception domains explicitly allow insecure HTTP loads, sample: "
                    + ", ".join(insecure_http_domains[:MAX_SAMPLE_VALUES])
                ),
                recommendation="Audit ATS exception domains and remove insecure HTTP allowances when possible",
                source=metadata.info_plist_path,
                confidence="confirmed",
            )
        )

    weak_tls_domains = _get_weak_tls_exception_domains(ats)
    if weak_tls_domains:
        findings.append(
            _build_finding(
                id="IOS-PLIST-ATS-004",
                title="ATS exception domains permit weak minimum TLS versions",
                severity="medium",
                category="network",
                description=(
                    "One or more ATS exception domains lower the minimum TLS version below modern defaults, sample: "
                    + ", ".join(weak_tls_domains[:MAX_SAMPLE_VALUES])
                ),
                recommendation="Raise minimum TLS requirements to TLS 1.2 or higher unless legacy systems are unavoidable",
                source=metadata.info_plist_path,
                confidence="confirmed",
            )
        )

    query_schemes = _get_string_list(info, "LSApplicationQueriesSchemes")
    if len(query_schemes) > 20:
        findings.append(
            _build_finding(
                id="IOS-PLIST-QUERY-001",
                title="Large number of queried URL schemes",
                severity="medium",
                category="privacy",
                description=f"LSApplicationQueriesSchemes contains {len(query_schemes)} entries",
                recommendation="Limit URL scheme queries to required integrations only",
                source=metadata.info_plist_path,
                confidence="heuristic",
            )
        )

    if info.get("UIFileSharingEnabled") is True:
        findings.append(
            _build_finding(
                id="IOS-PLIST-FILE-001",
                title="App file sharing is enabled",
                severity="medium",
                category="file-exposure",
                description="UIFileSharingEnabled=true exposes the app's Documents directory through user-controlled file sharing flows",
                recommendation="Disable file sharing unless end-user document export is an intentional product requirement",
                source=metadata.info_plist_path,
                confidence="confirmed",
            )
        )

    if info.get("LSSupportsOpeningDocumentsInPlace") is True:
        findings.append(
            _build_finding(
                id="IOS-PLIST-FILE-002",
                title="Documents can be opened in place",
                severity="low",
                category="file-exposure",
                description="LSSupportsOpeningDocumentsInPlace=true may broaden document access workflows depending on app behavior",
                recommendation="Review whether opening documents in place is necessary for the app's data model",
                source=metadata.info_plist_path,
                confidence="heuristic",
            )
        )

    if not metadata.bundle_identifier:
        findings.append(
            _build_finding(
                id="IOS-PLIST-BUNDLE-001",
                title="Bundle identifier is missing",
                severity="medium",
                category="info-plist",
                description="CFBundleIdentifier was not found in Info.plist",
                recommendation="Ensure CFBundleIdentifier is set and stable for each release channel",
                source=metadata.info_plist_path,
                confidence="confirmed",
            )
        )

    if not metadata.bundle_executable:
        findings.append(
            _build_finding(
                id="IOS-PLIST-BUNDLE-002",
                title="Bundle executable is missing",
                severity="medium",
                category="info-plist",
                description="CFBundleExecutable was not found in Info.plist",
                recommendation="Ensure CFBundleExecutable matches the packaged app binary name",
                source=metadata.info_plist_path,
                confidence="confirmed",
            )
        )
    elif not metadata.bundle_executable_present:
        findings.append(
            _build_finding(
                id="IOS-BINARY-001",
                title="Declared app executable is missing from the IPA bundle",
                severity="high",
                category="file-format",
                description=(
                    f"Info.plist declares executable {metadata.bundle_executable}, but {metadata.bundle_executable_path} was not found"
                ),
                recommendation="Verify the IPA contains the built app binary referenced by CFBundleExecutable",
                source=metadata.info_plist_path,
                confidence="confirmed",
            )
        )

    return findings


def _inspect_entitlements(metadata: IosPackageMetadata) -> list[dict[str, str]]:
    if not metadata.entitlements_readable or not isinstance(metadata.entitlements, dict) or not metadata.entitlements_path:
        return []

    entitlements = metadata.entitlements
    findings: list[dict[str, str]] = []

    if entitlements.get("get-task-allow") is True:
        findings.append(
            _build_finding(
                id="IOS-ENTITLEMENTS-DBG-001",
                title="Debuggable task attachment entitlement is enabled",
                severity="high",
                category="entitlements",
                description="get-task-allow=true permits debugger attachment on eligible devices and weakens production hardening",
                recommendation="Set get-task-allow=false for release builds and distribution profiles",
                source=metadata.entitlements_path,
                confidence="confirmed",
            )
        )

    keychain_groups = _get_string_list(entitlements, "keychain-access-groups")
    if len(keychain_groups) > 3:
        findings.append(
            _build_finding(
                id="IOS-ENTITLEMENTS-KEYCHAIN-001",
                title="Broad keychain access groups configured",
                severity="medium",
                category="entitlements",
                description=f"Detected {len(keychain_groups)} keychain access groups, sample: {', '.join(keychain_groups[:MAX_SAMPLE_VALUES])}",
                recommendation="Restrict keychain access groups to the minimum set needed for the app's sharing model",
                source=metadata.entitlements_path,
                confidence="heuristic",
            )
        )

    app_groups = _get_string_list(entitlements, "com.apple.security.application-groups")
    if len(app_groups) > 3:
        findings.append(
            _build_finding(
                id="IOS-ENTITLEMENTS-GROUPS-001",
                title="Broad application group sharing configured",
                severity="medium",
                category="entitlements",
                description=f"Detected {len(app_groups)} application groups, sample: {', '.join(app_groups[:MAX_SAMPLE_VALUES])}",
                recommendation="Review app group usage and remove shared containers that are no longer required",
                source=metadata.entitlements_path,
                confidence="heuristic",
            )
        )

    aps_environment = _get_plist_value(entitlements, "aps-environment")
    if aps_environment == "development":
        findings.append(
            _build_finding(
                id="IOS-ENTITLEMENTS-PUSH-001",
                title="Development push entitlement is present",
                severity="low",
                category="entitlements",
                description="aps-environment is set to development, which may indicate a non-production signing profile",
                recommendation="Confirm the signing profile matches the intended release environment",
                source=metadata.entitlements_path,
                confidence="heuristic",
            )
        )

    return findings


def _scan_archive_strings(
    archive: ZipFile,
    max_text_file_size: int = MAX_TEXT_FILE_SIZE,
    max_text_files_scanned: int = MAX_TEXT_FILES_SCANNED,
) -> list[dict[str, str]]:
    urls: set[str] = set()
    insecure_http_urls: set[str] = set()
    non_production_urls: set[str] = set()
    secrets: set[str] = set()
    tokens: set[str] = set()
    scanned_files = 0

    for entry in archive.infolist():
        if entry.is_dir() or scanned_files >= max_text_files_scanned:
            continue

        if not _looks_like_text(entry.filename, entry.file_size, max_text_file_size=max_text_file_size):
            continue

        scanned_files += 1
        try:
            content_bytes = archive.read(entry.filename)
        except (OSError, KeyError) as exc:
            logger.debug("Skipping unreadable archive entry %s: %s", entry.filename, exc)
            continue

        if entry.filename.endswith((".plist", ".xcent", ".entitlements")):
            content = _plist_to_string(content_bytes)
        else:
            content = content_bytes.decode("utf-8", errors="ignore")

        matched_urls = [url for url in URL_PATTERN.findall(content) if _is_noteworthy_url(url)]
        urls.update(matched_urls)
        insecure_http_urls.update(url for url in matched_urls if url.lower().startswith("http://"))
        non_production_urls.update(url for url in matched_urls if _looks_like_non_production_url(url))

        for match in SECRET_ASSIGNMENT_PATTERN.finditer(content):
            secrets.add(f"{match.group(1)}={_truncate_value(match.group(2))}")

        for match in BEARER_PATTERN.finditer(content):
            tokens.add(f"bearer={_truncate_value(match.group(1), prefix_length=8)}")

        for match in JWT_PATTERN.finditer(content):
            tokens.add(f"jwt={_truncate_value(match.group(0), prefix_length=8)}")

        if PRIVATE_KEY_PATTERN.search(content):
            secrets.add("private-key-material")

    findings: list[dict[str, str]] = []

    if urls:
        findings.append(
            _build_finding(
                id="IOS-STRINGS-URL-001",
                title="Candidate URLs discovered in IPA strings",
                severity="medium",
                category="strings",
                description=f"Detected {len(urls)} URL-like string(s), sample: {', '.join(sorted(urls)[:MAX_SAMPLE_VALUES])}",
                recommendation="Review hardcoded endpoints and keep environment-specific routing out of shipped bundles where possible",
                source="archive/strings",
                confidence="heuristic",
            )
        )

    if insecure_http_urls:
        findings.append(
            _build_finding(
                id="IOS-STRINGS-URL-002",
                title="Insecure HTTP URLs detected",
                severity="medium",
                category="network",
                description=(
                    "Detected HTTP endpoint(s) in scanned text assets, sample: "
                    + ", ".join(sorted(insecure_http_urls)[:MAX_SAMPLE_VALUES])
                ),
                recommendation="Prefer HTTPS endpoints and confirm any HTTP usage is intentionally constrained",
                source="archive/strings",
                confidence="heuristic",
            )
        )

    if non_production_urls:
        findings.append(
            _build_finding(
                id="IOS-STRINGS-URL-003",
                title="Non-production or internal URLs detected",
                severity="medium",
                category="network",
                description=(
                    "Detected URL(s) that look like staging, test, localhost, or internal endpoints, sample: "
                    + ", ".join(sorted(non_production_urls)[:MAX_SAMPLE_VALUES])
                ),
                recommendation="Verify non-production endpoints are excluded from release builds",
                source="archive/strings",
                confidence="heuristic",
            )
        )

    if secrets:
        findings.append(
            _build_finding(
                id="IOS-STRINGS-SECRET-001",
                title="Candidate secrets found in IPA strings",
                severity="high",
                category="secrets",
                description=(
                    "Detected candidate secret assignment(s) or key material in scanned text assets, sample: "
                    + ", ".join(sorted(secrets)[:MAX_SAMPLE_VALUES])
                ),
                recommendation="Remove embedded secrets from the app bundle and move credential issuance behind server-side controls",
                source="archive/strings",
                confidence="heuristic",
            )
        )

    if tokens:
        findings.append(
            _build_finding(
                id="IOS-STRINGS-TOKEN-001",
                title="Candidate bearer or JWT tokens found in IPA strings",
                severity="high",
                category="secrets",
                description=(
                    "Detected token-like values in scanned text assets, sample: "
                    + ", ".join(sorted(tokens)[:MAX_SAMPLE_VALUES])
                ),
                recommendation="Confirm tokens are not hardcoded test credentials and avoid shipping reusable bearer material inside the app bundle",
                source="archive/strings",
                confidence="heuristic",
            )
        )

    if not urls and not secrets and not tokens:
        findings.append(
            _build_finding(
                id="IOS-STRINGS-000",
                title="No URL or secret patterns detected in scanned text assets",
                severity="low",
                category="strings",
                description="No URL, token, or secret patterns matched in sampled text files",
                recommendation="Expand inspection depth to more bundle artifacts in future iterations if needed",
                source="archive/strings",
                confidence="informational",
            )
        )

    return findings


def _resolve_payload_app_path(names: list[str]) -> str | None:
    candidates = sorted(
        {
            entry.split(".app/", 1)[0] + ".app"
            for entry in names
            if entry.startswith("Payload/") and ".app/" in entry
        }
    )
    return candidates[0] if candidates else None


def _resolve_info_plist_path(names: list[str], payload_app_path: str | None) -> str | None:
    if payload_app_path:
        direct_path = f"{payload_app_path}/Info.plist"
        if direct_path in names:
            return direct_path

    return next((name for name in sorted(names) if name.startswith("Payload/") and name.endswith(".app/Info.plist")), None)


def _load_plist_entry(archive: ZipFile, path: str | None) -> dict[str, object] | None:
    if not path:
        return None

    try:
        parsed = plistlib.loads(archive.read(path))
    except (plistlib.InvalidFileException, ValueError, KeyError, OSError) as exc:
        logger.warning("Failed to parse plist at %s: %s", path, exc)
        return None

    return parsed if isinstance(parsed, dict) else None


def _load_entitlements(
    archive: ZipFile,
    names: list[str],
    payload_app_path: str | None,
) -> tuple[str | None, str | None, dict[str, object] | None, bool]:
    if not payload_app_path:
        return None, None, None, False

    entitlement_candidates = [
        path
        for path in sorted(names)
        if path.startswith(f"{payload_app_path}/") and path.endswith((".xcent", ".entitlements"))
    ]
    for candidate in entitlement_candidates:
        entitlements = _load_plist_entry(archive, candidate)
        if entitlements is not None:
            return candidate, "bundle-entitlements", entitlements, True
        return candidate, "bundle-entitlements", None, False

    mobileprovision_path = next(
        (
            path
            for path in sorted(names)
            if path.startswith(f"{payload_app_path}/") and path.endswith("embedded.mobileprovision")
        ),
        None,
    )
    if not mobileprovision_path:
        return None, None, None, False

    try:
        raw_profile = archive.read(mobileprovision_path)
        entitlements = _extract_entitlements_from_mobileprovision(raw_profile)
    except (plistlib.InvalidFileException, ValueError, KeyError, OSError) as exc:
        logger.warning("Failed to parse mobileprovision entitlements at %s: %s", mobileprovision_path, exc)
        return mobileprovision_path, "embedded-mobileprovision", None, False

    return mobileprovision_path, "embedded-mobileprovision", entitlements, entitlements is not None


def _extract_entitlements_from_mobileprovision(content: bytes) -> dict[str, object] | None:
    plist_bytes = _extract_embedded_plist_bytes(content)
    profile = plistlib.loads(plist_bytes)
    if not isinstance(profile, dict):
        return None

    entitlements = profile.get("Entitlements")
    return entitlements if isinstance(entitlements, dict) else None


def _extract_embedded_plist_bytes(content: bytes) -> bytes:
    start = content.find(b"<?xml")
    if start == -1:
        start = content.find(b"<plist")

    end = content.rfind(b"</plist>")
    if start == -1 or end == -1:
        raise plistlib.InvalidFileException("embedded plist payload not found")

    return content[start : end + len(b"</plist>")]


def _get_insecure_http_exception_domains(ats: object) -> list[str]:
    if not isinstance(ats, dict):
        return []

    exception_domains = ats.get("NSExceptionDomains")
    if not isinstance(exception_domains, dict):
        return []

    insecure_domains = []
    for domain, settings in exception_domains.items():
        if isinstance(settings, dict) and settings.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            insecure_domains.append(str(domain))
    return insecure_domains


def _get_weak_tls_exception_domains(ats: object) -> list[str]:
    if not isinstance(ats, dict):
        return []

    exception_domains = ats.get("NSExceptionDomains")
    if not isinstance(exception_domains, dict):
        return []

    weak_domains = []
    for domain, settings in exception_domains.items():
        if not isinstance(settings, dict):
            continue

        tls_version = settings.get("NSExceptionMinimumTLSVersion")
        if isinstance(tls_version, str) and tls_version.lower() in WEAK_TLS_VALUES:
            weak_domains.append(f"{domain}={tls_version}")
    return weak_domains


def _looks_like_text(file_name: str, size: int, max_text_file_size: int = MAX_TEXT_FILE_SIZE) -> bool:
    if size <= 0 or size > max_text_file_size:
        return False

    lower = file_name.lower()
    return any(lower.endswith(ext) for ext in TEXT_EXTENSIONS)


def _plist_to_string(content: bytes) -> str:
    try:
        parsed = plistlib.loads(content)
        return str(parsed)
    except (plistlib.InvalidFileException, ValueError, KeyError) as exc:
        logger.debug("Plist binary decode fallback for entry: %s", exc)
        return content.decode("utf-8", errors="ignore")


def _get_plist_value(info: dict[str, object] | None, key: str) -> str | None:
    if not isinstance(info, dict):
        return None

    value = info.get(key)
    return str(value) if value is not None else None


def _get_string_list(container: dict[str, object] | None, key: str) -> list[str]:
    if not isinstance(container, dict):
        return []

    value = container.get(key)
    if not isinstance(value, list):
        return []

    return [str(item) for item in value if item is not None]


def _is_noteworthy_url(url: str) -> bool:
    return url.lower() not in IGNORED_URLS


def _looks_like_non_production_url(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    return any(keyword in host or keyword in path for keyword in NON_PRODUCTION_URL_KEYWORDS)


def _truncate_value(value: str, prefix_length: int = 6) -> str:
    clean = value.strip()
    return f"{clean[:prefix_length]}..." if len(clean) > prefix_length else clean


def _build_finding(
    *,
    id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    recommendation: str,
    source: str,
    confidence: str,
    evidence: list[str] | None = None,
    detection_method: str | None = None,
    source_location: str | None = None,
) -> dict[str, object]:
    label = {
        "confirmed": "Confirmed",
        "heuristic": "Heuristic",
        "informational": "Informational",
    }[confidence]
    return {
        "id": id,
        "title": f"{label}: {title}",
        "severity": severity,
        "category": category,
        "description": description,
        "recommendation": recommendation,
        "source": source,
        "confidence_level": confidence,
        "evidence": evidence if evidence is not None else _infer_evidence(id=id, description=description),
        "detection_method": detection_method or _infer_detection_method(id=id),
        "source_location": source_location if source_location is not None else _infer_source_location(source),
    }


def _infer_detection_method(*, id: str) -> str:
    if id.startswith("IOS-METADATA"):
        return "archive-metadata-inspection"
    if id.startswith("IOS-PLIST"):
        return "info-plist-inspection"
    if id.startswith("IOS-ENTITLEMENTS"):
        return "entitlements-inspection"
    if id.startswith("IOS-STRINGS"):
        return "archive-string-scan"
    if id.startswith("IOS-PAYLOAD") or id.startswith("IOS-BINARY"):
        return "ipa-bundle-validation"
    if id.endswith("FORMAT-001"):
        return "extension-validation"
    if id.endswith("ARCHIVE-001") or id.endswith("ARCHIVE-BOMB"):
        return "zip-validation"
    return "ios-static-analysis"


def _infer_source_location(source: str) -> str | None:
    return None if source.startswith("archive/") or source.startswith("upload/") else source


def _infer_evidence(*, id: str, description: str) -> list[str]:
    if id == "IOS-METADATA-001":
        return description.split(": ", 1)[-1].split(", ")[:MAX_SAMPLE_VALUES]

    if "sample: " in description:
        sample = description.split("sample: ", 1)[1]
        return [item.strip() for item in sample.split(", ") if item.strip()][:MAX_SAMPLE_VALUES]

    explicit_evidence = {
        "IOS-PLIST-ATS-001": ["NSAllowsArbitraryLoads=true"],
        "IOS-PLIST-FILE-001": ["UIFileSharingEnabled=true"],
        "IOS-PLIST-FILE-002": ["LSSupportsOpeningDocumentsInPlace=true"],
        "IOS-PLIST-BUNDLE-001": ["CFBundleIdentifier missing"],
        "IOS-PLIST-BUNDLE-002": ["CFBundleExecutable missing"],
        "IOS-ENTITLEMENTS-DBG-001": ["get-task-allow=true"],
        "IOS-ENTITLEMENTS-PUSH-001": ["aps-environment=development"],
        "IOS-PLIST-404": ["Payload/*.app/Info.plist missing"],
        "IOS-PAYLOAD-001": ["Payload/*.app bundle missing"],
        "IOS-ARCHIVE-001": ["ZIP parsing failed"],
    }
    return explicit_evidence.get(id, [])
