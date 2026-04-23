from __future__ import annotations

import logging
from dataclasses import dataclass
from io import BytesIO
import plistlib
import re
from zipfile import BadZipFile, ZipFile

from analyzers.safe_zip import ZipExtractionLimitExceeded, validate_zip_limits

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|token|passwd|password|client[_-]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{8,})"
)
TEXT_EXTENSIONS = {".plist", ".strings", ".txt", ".json", ".xml", ".swift", ".m", ".h", ".js"}
MAX_TEXT_FILE_SIZE = 1_000_000
MAX_TEXT_FILES_SCANNED = 200


@dataclass
class IosPackageMetadata:
    archive_size_bytes: int
    file_count: int
    info_plist_path: str | None
    info_plist_readable: bool
    bundle_identifier: str | None
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
            {
                "id": "IOS-FORMAT-001",
                "title": "Unsupported iOS package format",
                "severity": "high",
                "category": "file-format",
                "description": f"File {file_name} has unsupported extension: {extension}",
                "recommendation": "Provide an iOS .ipa package",
                "source": "upload/extension",
            }
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
            findings.extend(_inspect_info_plist(archive=archive, metadata=metadata))
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
            {
                "id": "IOS-ARCHIVE-BOMB",
                "title": "Archive exceeds safe extraction limits",
                "severity": "critical",
                "category": "file-format",
                "description": str(exc),
                "recommendation": "Verify the archive is not maliciously crafted and retry with a smaller package",
                "source": "archive/zip",
            }
        ]
    except BadZipFile:
        return [
            {
                "id": "IOS-ARCHIVE-001",
                "title": "Invalid iOS archive",
                "severity": "critical",
                "category": "file-format",
                "description": f"{file_name} is not a valid ZIP-based IPA archive",
                "recommendation": "Re-export the IPA and retry analysis",
                "source": "archive/zip",
            }
        ]


def _extract_basic_metadata(archive: ZipFile, file_bytes: bytes) -> IosPackageMetadata:
    names = archive.namelist()
    info_plist_path = next((name for name in names if name.endswith(".app/Info.plist")), None)

    info = None
    if info_plist_path:
        try:
            info = plistlib.loads(archive.read(info_plist_path))
        except (plistlib.InvalidFileException, ValueError, KeyError) as exc:
            logger.warning("Failed to parse Info.plist at %s: %s", info_plist_path, exc)
            info = None

    return IosPackageMetadata(
        archive_size_bytes=len(file_bytes),
        file_count=len(names),
        info_plist_path=info_plist_path,
        info_plist_readable=info is not None,
        bundle_identifier=_get_plist_value(info, "CFBundleIdentifier"),
        bundle_version=_get_plist_value(info, "CFBundleVersion"),
        bundle_short_version=_get_plist_value(info, "CFBundleShortVersionString"),
        minimum_os_version=_get_plist_value(info, "MinimumOSVersion"),
    )


def _build_metadata_findings(file_name: str, metadata: IosPackageMetadata) -> list[dict[str, str]]:
    details = [
        f"archive_size_bytes={metadata.archive_size_bytes}",
        f"file_count={metadata.file_count}",
        f"info_plist_path={metadata.info_plist_path or 'missing'}",
        f"info_plist_readable={metadata.info_plist_readable}",
    ]
    if metadata.bundle_identifier:
        details.append(f"bundle_identifier={metadata.bundle_identifier}")
    if metadata.bundle_version:
        details.append(f"bundle_version={metadata.bundle_version}")
    if metadata.bundle_short_version:
        details.append(f"bundle_short_version={metadata.bundle_short_version}")
    if metadata.minimum_os_version:
        details.append(f"minimum_os_version={metadata.minimum_os_version}")

    findings = [
        {
            "id": "IOS-METADATA-001",
            "title": "iOS package metadata extracted",
            "severity": "low",
            "category": "metadata",
            "description": f"Extracted metadata for {file_name}: " + ", ".join(details),
            "recommendation": "Review metadata consistency before release",
            "source": "archive/metadata",
        }
    ]

    if not metadata.info_plist_path:
        findings.append(
            {
                "id": "IOS-PLIST-404",
                "title": "Info.plist not found",
                "severity": "high",
                "category": "info-plist",
                "description": "IPA does not contain an .app/Info.plist file",
                "recommendation": "Verify the IPA was generated correctly and includes app metadata",
                "source": "Payload/*.app/Info.plist",
            }
        )
    elif not metadata.info_plist_readable:
        findings.append(
            {
                "id": "IOS-PLIST-002",
                "title": "Info.plist could not be parsed",
                "severity": "medium",
                "category": "info-plist",
                "description": "Info.plist exists but could not be parsed via plistlib",
                "recommendation": "Validate plist format and add robust parser fallback",
                "source": metadata.info_plist_path,
            }
        )

    return findings


def _inspect_info_plist(archive: ZipFile, metadata: IosPackageMetadata) -> list[dict[str, str]]:
    if not metadata.info_plist_path or not metadata.info_plist_readable:
        return []

    info = plistlib.loads(archive.read(metadata.info_plist_path))
    findings: list[dict[str, str]] = []

    ats = info.get("NSAppTransportSecurity") if isinstance(info, dict) else None
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
        findings.append(
            {
                "id": "IOS-PLIST-ATS-001",
                "title": "App Transport Security allows arbitrary loads",
                "severity": "high",
                "category": "network",
                "description": "NSAllowsArbitraryLoads=true weakens default network transport protections",
                "recommendation": "Disable arbitrary loads and use scoped ATS exceptions only when required",
                "source": metadata.info_plist_path,
            }
        )

    if _has_insecure_http_exceptions(ats):
        findings.append(
            {
                "id": "IOS-PLIST-ATS-002",
                "title": "Heuristic: ATS domain exceptions allow insecure HTTP",
                "severity": "medium",
                "category": "network",
                "description": "Heuristic finding: one or more NSExceptionDomains entries set NSExceptionAllowsInsecureHTTPLoads=true",
                "recommendation": "Audit ATS exception domains and remove insecure HTTP allowances when possible",
                "source": metadata.info_plist_path,
            }
        )

    query_schemes = info.get("LSApplicationQueriesSchemes") if isinstance(info, dict) else None
    if isinstance(query_schemes, list) and len(query_schemes) > 20:
        findings.append(
            {
                "id": "IOS-PLIST-QUERY-001",
                "title": "Heuristic: large number of queried URL schemes",
                "severity": "medium",
                "category": "privacy",
                "description": f"Heuristic finding: LSApplicationQueriesSchemes contains {len(query_schemes)} entries",
                "recommendation": "Limit URL scheme queries to required integrations",
                "source": metadata.info_plist_path,
            }
        )

    if not metadata.bundle_identifier:
        findings.append(
            {
                "id": "IOS-PLIST-BUNDLE-001",
                "title": "Missing bundle identifier",
                "severity": "medium",
                "category": "info-plist",
                "description": "CFBundleIdentifier was not found in Info.plist",
                "recommendation": "Ensure CFBundleIdentifier is set and stable per release channel",
                "source": metadata.info_plist_path,
            }
        )

    return findings


def _scan_archive_strings(
    archive: ZipFile,
    max_text_file_size: int = MAX_TEXT_FILE_SIZE,
    max_text_files_scanned: int = MAX_TEXT_FILES_SCANNED,
) -> list[dict[str, str]]:
    urls: set[str] = set()
    insecure_http_urls: set[str] = set()
    secrets: set[str] = set()
    scanned_files = 0

    for entry in archive.infolist():
        if entry.is_dir() or scanned_files >= max_text_files_scanned:
            continue

        if not _looks_like_text(entry.filename, entry.file_size, max_text_file_size=max_text_file_size):
            continue

        scanned_files += 1
        content_bytes = archive.read(entry.filename)

        if entry.filename.endswith(".plist"):
            content = _plist_to_string(content_bytes)
        else:
            content = content_bytes.decode("utf-8", errors="ignore")

        matched_urls = URL_PATTERN.findall(content)
        urls.update(matched_urls)
        insecure_http_urls.update(url for url in matched_urls if url.lower().startswith("http://"))

        for match in SECRET_PATTERN.finditer(content):
            secrets.add(f"{match.group(1)}={match.group(2)[:6]}...")

    findings: list[dict[str, str]] = []

    if urls:
        findings.append(
            {
                "id": "IOS-STRINGS-URL-001",
                "title": "Candidate URLs discovered in IPA strings",
                "severity": "medium",
                "category": "strings",
                "description": f"Detected {len(urls)} URL-like string(s), sample: {', '.join(sorted(urls)[:5])}",
                "recommendation": "Review hardcoded endpoints and enforce secure transport controls",
                "source": "archive/strings",
            }
        )

    if insecure_http_urls:
        findings.append(
            {
                "id": "IOS-STRINGS-URL-002",
                "title": "Heuristic: insecure HTTP URLs detected",
                "severity": "medium",
                "category": "network",
                "description": f"Heuristic finding: detected {len(insecure_http_urls)} HTTP endpoint(s), sample: {', '.join(sorted(insecure_http_urls)[:5])}",
                "recommendation": "Prefer HTTPS endpoints and validate exceptions are intentional",
                "source": "archive/strings",
            }
        )

    if secrets:
        findings.append(
            {
                "id": "IOS-STRINGS-SECRET-001",
                "title": "Candidate tokens or secrets found in IPA strings",
                "severity": "high",
                "category": "secrets",
                "description": f"Detected {len(secrets)} candidate secret assignment(s), sample: {', '.join(sorted(secrets)[:5])}",
                "recommendation": "Remove embedded secrets and shift credentials to server-managed controls",
                "source": "archive/strings",
            }
        )

    if not urls and not secrets:
        findings.append(
            {
                "id": "IOS-STRINGS-000",
                "title": "No URL or secret patterns detected in scanned text assets",
                "severity": "low",
                "category": "strings",
                "description": "No URL/token/secret patterns matched in sampled text files",
                "recommendation": "Expand scanning depth to additional binary artifacts in future iterations",
                "source": "archive/strings",
            }
        )

    return findings


def _has_insecure_http_exceptions(ats: object) -> bool:
    if not isinstance(ats, dict):
        return False

    exception_domains = ats.get("NSExceptionDomains")
    if not isinstance(exception_domains, dict):
        return False

    for settings in exception_domains.values():
        if isinstance(settings, dict) and settings.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            return True
    return False


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


def _get_plist_value(info: dict | None, key: str) -> str | None:
    if not isinstance(info, dict):
        return None
    value = info.get(key)
    return str(value) if value is not None else None
