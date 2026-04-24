from __future__ import annotations

import logging
from dataclasses import dataclass
from io import BytesIO
import re
from zipfile import BadZipFile, ZipFile

from analyzers.android.external_tools import AndroidExternalToolResult, analyze_with_jadx
from analyzers.safe_zip import ZipExtractionLimitExceeded, validate_zip_limits

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{8,})"
)
MANIFEST_PACKAGE_PATTERN = re.compile(r'package\s*=\s*"([^"]+)"')
MANIFEST_VERSION_NAME_PATTERN = re.compile(r'android:versionName\s*=\s*"([^"]+)"')
MANIFEST_VERSION_CODE_PATTERN = re.compile(r'android:versionCode\s*=\s*"([^"]+)"')

TEXT_EXTENSIONS = {
    ".xml",
    ".txt",
    ".json",
    ".properties",
    ".yml",
    ".yaml",
    ".js",
    ".kt",
    ".java",
    ".smali",
    ".gradle",
}
MAX_TEXT_FILE_SIZE = 1_000_000
MAX_TEXT_FILES_SCANNED = 200
MAX_EXTERNAL_TOOL_SAMPLE_VALUES = 5


@dataclass
class AndroidPackageMetadata:
    package_type: str
    archive_size_bytes: int
    file_count: int
    manifest_path: str | None
    manifest_present: bool
    manifest_decodable: bool
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None


def analyze_android_package(
    file_name: str,
    file_bytes: bytes,
    file_extension: str,
    max_extracted_bytes: int | None = None,
    max_files: int | None = None,
    max_text_file_size: int | None = None,
    max_text_files_scanned: int | None = None,
) -> list[dict[str, str]]:
    extension = file_extension.lower()
    if extension not in {".apk", ".aab"}:
        return _finalize_findings(
            [
                {
                    "id": "ANDROID-FORMAT-001",
                    "title": "Unsupported Android package format",
                    "severity": "high",
                    "category": "file-format",
                    "description": f"File {file_name} has unsupported extension: {extension}",
                    "recommendation": "Provide an Android .apk or .aab package",
                    "source": "upload/extension",
                }
            ]
        )

    try:
        with ZipFile(BytesIO(file_bytes), "r") as archive:
            zip_limit_kwargs: dict[str, int] = {}
            if max_extracted_bytes is not None:
                zip_limit_kwargs["max_extracted_bytes"] = max_extracted_bytes
            if max_files is not None:
                zip_limit_kwargs["max_files"] = max_files
            validate_zip_limits(archive, **zip_limit_kwargs)
            metadata = _extract_basic_metadata(extension=extension, archive=archive, file_bytes=file_bytes)
            findings = _build_metadata_findings(file_name=file_name, metadata=metadata)
            findings.extend(_inspect_manifest(archive=archive, metadata=metadata))
            findings.extend(
                _scan_archive_strings(
                    archive=archive,
                    max_text_file_size=MAX_TEXT_FILE_SIZE if max_text_file_size is None else max_text_file_size,
                    max_text_files_scanned=(
                        MAX_TEXT_FILES_SCANNED if max_text_files_scanned is None else max_text_files_scanned
                    ),
                )
            )
            if extension == ".apk":
                findings.extend(_scan_external_android_tools(file_name=file_name, file_bytes=file_bytes))
            return _finalize_findings(findings)
    except ZipExtractionLimitExceeded as exc:
        return _finalize_findings(
            [
                {
                    "id": "ANDROID-ARCHIVE-BOMB",
                    "title": "Archive exceeds safe extraction limits",
                    "severity": "critical",
                    "category": "file-format",
                    "description": str(exc),
                    "recommendation": "Verify the archive is not maliciously crafted and retry with a smaller package",
                    "source": "archive/zip",
                }
            ]
        )
    except BadZipFile:
        return _finalize_findings(
            [
                {
                    "id": "ANDROID-ARCHIVE-001",
                    "title": "Invalid Android archive",
                    "severity": "critical",
                    "category": "file-format",
                    "description": f"{file_name} is not a valid ZIP-based Android package",
                    "recommendation": "Rebuild or re-export the application package and retry",
                    "source": "archive/zip",
                }
            ]
        )


def _extract_basic_metadata(extension: str, archive: ZipFile, file_bytes: bytes) -> AndroidPackageMetadata:
    names = archive.namelist()
    manifest_path = _resolve_manifest_path(extension=extension, names=names)
    manifest_present = manifest_path is not None
    manifest_content = archive.read(manifest_path) if manifest_path else b""

    manifest_text: str | None = None
    if manifest_content:
        try:
            manifest_text = manifest_content.decode("utf-8")
        except UnicodeDecodeError:
            manifest_text = None

    package_name = _extract_first(MANIFEST_PACKAGE_PATTERN, manifest_text)
    version_name = _extract_first(MANIFEST_VERSION_NAME_PATTERN, manifest_text)
    version_code = _extract_first(MANIFEST_VERSION_CODE_PATTERN, manifest_text)

    return AndroidPackageMetadata(
        package_type="apk" if extension == ".apk" else "aab",
        archive_size_bytes=len(file_bytes),
        file_count=len(names),
        manifest_path=manifest_path,
        manifest_present=manifest_present,
        manifest_decodable=manifest_text is not None if manifest_present else False,
        package_name=package_name,
        version_name=version_name,
        version_code=version_code,
    )


def _build_metadata_findings(file_name: str, metadata: AndroidPackageMetadata) -> list[dict[str, str]]:
    details = [
        f"package_type={metadata.package_type}",
        f"archive_size_bytes={metadata.archive_size_bytes}",
        f"file_count={metadata.file_count}",
        f"manifest_path={metadata.manifest_path or 'missing'}",
        f"manifest_present={metadata.manifest_present}",
        f"manifest_decodable={metadata.manifest_decodable}",
    ]
    if metadata.package_name:
        details.append(f"package_name={metadata.package_name}")
    if metadata.version_name:
        details.append(f"version_name={metadata.version_name}")
    if metadata.version_code:
        details.append(f"version_code={metadata.version_code}")

    findings = [
        {
            "id": "ANDROID-METADATA-001",
            "title": "Android package metadata extracted",
            "severity": "low",
            "category": "metadata",
            "description": f"Extracted metadata for {file_name}: " + ", ".join(details),
            "recommendation": "Review metadata for release sanity checks",
            "source": "archive/metadata",
        }
    ]

    if not metadata.manifest_present:
        findings.append(
            {
                "id": "ANDROID-MANIFEST-404",
                "title": "Android manifest not found",
                "severity": "high",
                "category": "manifest",
                "description": "Archive does not contain a supported Android manifest path",
                "recommendation": "Validate build output and ensure manifest is packaged",
                "source": "archive/manifest",
            }
        )
    elif not metadata.manifest_decodable:
        findings.append(
            {
                "id": "ANDROID-MANIFEST-002",
                "title": "Android manifest could not be decoded",
                "severity": "medium",
                "category": "manifest",
                "description": "Manifest may be binary encoded; text-level checks were limited",
                "recommendation": "Add binary AXML parsing for deeper manifest analysis",
                "source": metadata.manifest_path or "archive/manifest",
            }
        )

    return findings


def _inspect_manifest(archive: ZipFile, metadata: AndroidPackageMetadata) -> list[dict[str, str]]:
    if not metadata.manifest_present or not metadata.manifest_decodable or not metadata.manifest_path:
        return []

    manifest = archive.read(metadata.manifest_path).decode("utf-8")
    findings: list[dict[str, str]] = []

    if 'android:debuggable="true"' in manifest:
        findings.append(
            {
                "id": "ANDROID-MANIFEST-DBG-001",
                "title": "Debuggable flag enabled in manifest",
                "severity": "high",
                "category": "manifest",
                "description": "android:debuggable is true, which weakens production app security",
                "recommendation": "Set android:debuggable to false for release builds",
                "source": metadata.manifest_path,
            }
        )

    if 'android:usesCleartextTraffic="true"' in manifest:
        findings.append(
            {
                "id": "ANDROID-MANIFEST-NET-001",
                "title": "Cleartext traffic allowed",
                "severity": "medium",
                "category": "network",
                "description": "Manifest allows cleartext traffic",
                "recommendation": "Disable cleartext traffic and enforce TLS",
                "source": metadata.manifest_path,
            }
        )


    if 'android:allowBackup="true"' in manifest:
        findings.append(
            {
                "id": "ANDROID-MANIFEST-BACKUP-001",
                "title": "Heuristic: allowBackup enabled in manifest",
                "severity": "medium",
                "category": "backup",
                "description": "Heuristic finding: android:allowBackup=true may increase data extraction risk on compromised or debug-enabled devices",
                "recommendation": "Set android:allowBackup=false unless backup behavior is explicitly required",
                "source": metadata.manifest_path,
            }
        )

    if (
        'android:allowBackup="true"' in manifest
        and 'android:fullBackupContent=' not in manifest
        and 'android:dataExtractionRules=' not in manifest
    ):
        findings.append(
            {
                "id": "ANDROID-MANIFEST-BACKUP-002",
                "title": "Heuristic: backup rules not explicitly defined",
                "severity": "medium",
                "category": "backup",
                "description": "Heuristic finding: backup appears enabled but neither fullBackupContent nor dataExtractionRules is defined",
                "recommendation": "Define explicit backup/data extraction rules or disable backups for sensitive apps",
                "source": metadata.manifest_path,
            }
        )

    if 'android:exported="true"' in manifest:
        findings.append(
            {
                "id": "ANDROID-MANIFEST-EXP-001",
                "title": "Exported components present",
                "severity": "medium",
                "category": "manifest",
                "description": "One or more components are exported and may increase attack surface",
                "recommendation": "Validate exported components are intentional and permission-protected",
                "source": metadata.manifest_path,
            }
        )

    return findings


def _scan_archive_strings(
    archive: ZipFile,
    max_text_file_size: int = MAX_TEXT_FILE_SIZE,
    max_text_files_scanned: int = MAX_TEXT_FILES_SCANNED,
) -> list[dict[str, str]]:
    urls: set[str] = set()
    secrets: set[str] = set()
    scanned_files = 0

    for entry in archive.infolist():
        if entry.is_dir() or scanned_files >= max_text_files_scanned:
            continue

        file_name = entry.filename
        if not _looks_like_text(file_name=file_name, size=entry.file_size, max_text_file_size=max_text_file_size):
            continue

        scanned_files += 1
        try:
            content = archive.read(file_name).decode("utf-8", errors="ignore")
        except (OSError, KeyError) as exc:
            logger.debug("Skipping unreadable archive entry %s: %s", file_name, exc)
            continue

        urls.update(URL_PATTERN.findall(content))
        for match in SECRET_PATTERN.finditer(content):
            indicator = f"{match.group(1)}={match.group(2)[:6]}..."
            secrets.add(indicator)

    findings: list[dict[str, str]] = []

    if urls:
        sample = ", ".join(sorted(urls)[:5])
        findings.append(
            {
                "id": "ANDROID-STRINGS-URL-001",
                "title": "Candidate URLs discovered in package strings",
                "severity": "medium",
                "category": "strings",
                "description": f"Detected {len(urls)} URL-like string(s), sample: {sample}",
                "recommendation": "Review URLs for hardcoded test endpoints and insecure protocols",
                "source": "archive/strings",
            }
        )

    if secrets:
        sample = ", ".join(sorted(secrets)[:5])
        findings.append(
            {
                "id": "ANDROID-STRINGS-SECRET-001",
                "title": "Candidate tokens or secrets found in package strings",
                "severity": "high",
                "category": "secrets",
                "description": f"Detected {len(secrets)} candidate secret assignment(s), sample: {sample}",
                "recommendation": "Remove embedded secrets and load credentials from secure server-side controls",
                "source": "archive/strings",
            }
        )

    if not urls and not secrets:
        findings.append(
            {
                "id": "ANDROID-STRINGS-000",
                "title": "No URL or secret patterns detected in scanned text assets",
                "severity": "low",
                "category": "strings",
                "description": "No URL/token/secret patterns matched in sampled text files",
                "recommendation": "Expand scanning to native binaries and decompiled resources in future iterations",
                "source": "archive/strings",
            }
        )

    return findings


def _looks_like_text(file_name: str, size: int, max_text_file_size: int = MAX_TEXT_FILE_SIZE) -> bool:
    if size <= 0 or size > max_text_file_size:
        return False

    lower = file_name.lower()
    return any(lower.endswith(ext) for ext in TEXT_EXTENSIONS)


def _extract_first(pattern: re.Pattern[str], text: str | None) -> str | None:
    if not text:
        return None

    match = pattern.search(text)
    return match.group(1) if match else None


def _resolve_manifest_path(extension: str, names: list[str]) -> str | None:
    candidates = ["AndroidManifest.xml"]
    if extension == ".aab":
        candidates = ["base/manifest/AndroidManifest.xml", "AndroidManifest.xml"]

    for candidate in candidates:
        if candidate in names:
            return candidate

    return None


def _scan_external_android_tools(file_name: str, file_bytes: bytes) -> list[dict[str, str]]:
    tool_result = analyze_with_jadx(file_name=file_name, file_bytes=file_bytes)
    return _build_jadx_findings(tool_result)


def _build_jadx_findings(tool_result: AndroidExternalToolResult) -> list[dict[str, str]]:
    if not tool_result.available or not tool_result.executed:
        return []

    grouped = _group_external_tool_values(tool_result)
    findings: list[dict[str, str]] = []

    readable_source = grouped.get("readable_source", [])
    if readable_source:
        sample = ", ".join(readable_source[:MAX_EXTERNAL_TOOL_SAMPLE_VALUES])
        findings.append(
            {
                "id": "ANDROID-JADX-CODE-001",
                "title": "Heuristic: readable source identifiers recovered from APK code",
                "severity": "medium",
                "category": "code",
                "description": (
                    "Heuristic finding: JADX recovered readable source identifiers from "
                    f"{tool_result.source_files_scanned} decompiled source file(s), sample: {sample}"
                ),
                "recommendation": (
                    "Review release obfuscation settings (R8/ProGuard) and keep sensitive logic server-side where possible"
                ),
                "source": "jadx/source",
                "evidence": readable_source[:MAX_EXTERNAL_TOOL_SAMPLE_VALUES],
                "detection_method": "jadx-source-analysis",
                "source_location": _first_signal_location(tool_result, "readable_source"),
            }
        )

    hardcoded_urls = grouped.get("hardcoded_url", [])
    if hardcoded_urls:
        sample = ", ".join(hardcoded_urls[:MAX_EXTERNAL_TOOL_SAMPLE_VALUES])
        findings.append(
            {
                "id": "ANDROID-JADX-URL-001",
                "title": "Heuristic: hardcoded URLs discovered in decompiled Android code",
                "severity": "medium",
                "category": "network",
                "description": (
                    "Heuristic finding: JADX surfaced "
                    f"{len(hardcoded_urls)} hardcoded URL(s) in decompiled source, sample: {sample}"
                ),
                "recommendation": "Review embedded endpoints for insecure, staging, or non-production destinations",
                "source": "jadx/source",
                "evidence": hardcoded_urls[:MAX_EXTERNAL_TOOL_SAMPLE_VALUES],
                "detection_method": "jadx-source-analysis",
                "source_location": _first_signal_location(tool_result, "hardcoded_url"),
            }
        )

    candidate_secrets = grouped.get("candidate_secret", [])
    if candidate_secrets:
        sample = ", ".join(candidate_secrets[:MAX_EXTERNAL_TOOL_SAMPLE_VALUES])
        findings.append(
            {
                "id": "ANDROID-JADX-SECRET-001",
                "title": "Heuristic: candidate secrets found in decompiled Android code",
                "severity": "high",
                "category": "secrets",
                "description": (
                    "Heuristic finding: JADX surfaced "
                    f"{len(candidate_secrets)} candidate secret assignment(s), sample: {sample}"
                ),
                "recommendation": "Remove embedded secrets and move credentials behind server-side controls",
                "source": "jadx/source",
                "evidence": candidate_secrets[:MAX_EXTERNAL_TOOL_SAMPLE_VALUES],
                "detection_method": "jadx-source-analysis",
                "source_location": _first_signal_location(tool_result, "candidate_secret"),
            }
        )

    naming_patterns = grouped.get("naming_pattern", [])
    if naming_patterns:
        sample = ", ".join(naming_patterns[:MAX_EXTERNAL_TOOL_SAMPLE_VALUES])
        findings.append(
            {
                "id": "ANDROID-JADX-NAME-001",
                "title": "Heuristic: notable package or class names surfaced by JADX",
                "severity": "low",
                "category": "code",
                "description": (
                    "Heuristic finding: Decompiled package/class names suggest debug, internal, or sensitive code areas, "
                    f"sample: {sample}"
                ),
                "recommendation": "Review release packaging to exclude or harden debug-only and sensitive code paths",
                "source": "jadx/source",
                "evidence": naming_patterns[:MAX_EXTERNAL_TOOL_SAMPLE_VALUES],
                "detection_method": "jadx-source-analysis",
                "source_location": _first_signal_location(tool_result, "naming_pattern"),
            }
        )

    return findings


def _group_external_tool_values(tool_result: AndroidExternalToolResult) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for signal in tool_result.signals:
        values = grouped.setdefault(signal.kind, [])
        if signal.value not in values:
            values.append(signal.value)

    return grouped


def _first_signal_location(tool_result: AndroidExternalToolResult, kind: str) -> str | None:
    for signal in tool_result.signals:
        if signal.kind == kind:
            return signal.location
    return None


def _finalize_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    for finding in findings:
        finding_id = str(finding["id"])
        source = str(finding.get("source", "android-analyzer"))
        finding.setdefault("confidence_level", _infer_confidence_level(finding_id))
        finding.setdefault("evidence", _infer_evidence(finding))
        finding.setdefault("detection_method", _infer_detection_method(finding_id))
        finding.setdefault("source_location", _infer_source_location(source))
    return findings


def _infer_confidence_level(finding_id: str) -> str:
    if finding_id in {"ANDROID-METADATA-001", "ANDROID-STRINGS-000", "ANDROID-MANIFEST-002"}:
        return "informational"
    if finding_id.startswith("ANDROID-STRINGS") or finding_id.startswith("ANDROID-JADX"):
        return "heuristic"
    if finding_id in {"ANDROID-MANIFEST-BACKUP-001", "ANDROID-MANIFEST-BACKUP-002"}:
        return "heuristic"
    return "confirmed"


def _infer_detection_method(finding_id: str) -> str:
    if finding_id.startswith("ANDROID-METADATA"):
        return "archive-metadata-inspection"
    if finding_id.startswith("ANDROID-MANIFEST"):
        return "manifest-inspection"
    if finding_id.startswith("ANDROID-STRINGS"):
        return "archive-string-scan"
    if finding_id.startswith("ANDROID-JADX"):
        return "jadx-source-analysis"
    if finding_id.endswith("FORMAT-001"):
        return "extension-validation"
    if finding_id.endswith("ARCHIVE-001") or finding_id.endswith("ARCHIVE-BOMB"):
        return "zip-validation"
    return "android-static-analysis"


def _infer_source_location(source: str) -> str | None:
    return None if source.startswith("archive/") or source == "upload/extension" else source


def _infer_evidence(finding: dict[str, object]) -> list[str]:
    finding_id = str(finding["id"])
    description = str(finding.get("description", ""))

    explicit_evidence = {
        "ANDROID-MANIFEST-DBG-001": ['android:debuggable="true"'],
        "ANDROID-MANIFEST-NET-001": ['android:usesCleartextTraffic="true"'],
        "ANDROID-MANIFEST-BACKUP-001": ['android:allowBackup="true"'],
        "ANDROID-MANIFEST-BACKUP-002": [
            'android:allowBackup="true"',
            "android:fullBackupContent missing",
            "android:dataExtractionRules missing",
        ],
        "ANDROID-MANIFEST-EXP-001": ['android:exported="true"'],
        "ANDROID-MANIFEST-404": ["supported manifest path missing"],
        "ANDROID-MANIFEST-002": ["manifest decode failed"],
        "ANDROID-ARCHIVE-001": ["ZIP parsing failed"],
    }
    if finding_id in explicit_evidence:
        return explicit_evidence[finding_id]

    if finding_id == "ANDROID-METADATA-001":
        return description.split(": ", 1)[-1].split(", ")[:MAX_EXTERNAL_TOOL_SAMPLE_VALUES]

    if "sample: " in description:
        sample = description.split("sample: ", 1)[1]
        return [item.strip() for item in sample.split(", ") if item.strip()][:MAX_EXTERNAL_TOOL_SAMPLE_VALUES]

    return []
