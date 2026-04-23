from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import re
from zipfile import BadZipFile, ZipFile

from analyzers.safe_zip import ZipExtractionLimitExceeded, validate_zip_limits

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
) -> list[dict[str, str]]:
    extension = file_extension.lower()
    if extension not in {".apk", ".aab"}:
        return [
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

    try:
        with ZipFile(BytesIO(file_bytes), "r") as archive:
            if max_extracted_bytes is None:
                validate_zip_limits(archive)
            else:
                validate_zip_limits(archive, max_extracted_bytes=max_extracted_bytes)
            metadata = _extract_basic_metadata(extension=extension, archive=archive, file_bytes=file_bytes)
            findings = _build_metadata_findings(file_name=file_name, metadata=metadata)
            findings.extend(_inspect_manifest(archive=archive, metadata=metadata))
            findings.extend(_scan_archive_strings(archive=archive))
            return findings
    except ZipExtractionLimitExceeded as exc:
        return [
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
    except BadZipFile:
        return [
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


def _scan_archive_strings(archive: ZipFile) -> list[dict[str, str]]:
    urls: set[str] = set()
    secrets: set[str] = set()
    scanned_files = 0

    for entry in archive.infolist():
        if entry.is_dir() or scanned_files >= MAX_TEXT_FILES_SCANNED:
            continue

        file_name = entry.filename
        if not _looks_like_text(file_name=file_name, size=entry.file_size):
            continue

        scanned_files += 1
        try:
            content = archive.read(file_name).decode("utf-8", errors="ignore")
        except Exception:
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


def _looks_like_text(file_name: str, size: int) -> bool:
    if size <= 0 or size > MAX_TEXT_FILE_SIZE:
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
