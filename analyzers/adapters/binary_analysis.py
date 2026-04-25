from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha1
from io import BytesIO
import logging
import plistlib
import re
from typing import Protocol
from zipfile import BadZipFile, ZipFile, ZipInfo

logger = logging.getLogger(__name__)

ANDROID_NATIVE_LIBRARY_PATTERN = re.compile(r"(^|/)lib/[^/]+/[^/]+\.so$", re.IGNORECASE)
DEFAULT_MAX_ARTIFACTS = 20
DEFAULT_MAX_ARTIFACT_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class BinaryArtifact:
    platform: str
    path: str
    kind: str
    data: bytes


class BinaryAnalysisAdapter(Protocol):
    name: str

    def supports(self, artifact: BinaryArtifact) -> bool:
        ...

    def analyze(self, artifact: BinaryArtifact) -> list[dict[str, str]]:
        ...


class BinaryAnalysisError(Exception):
    """Raised when a binary adapter cannot analyze an artifact."""


class BinaryAnalysisRouter:
    def __init__(self, adapters: list[BinaryAnalysisAdapter]):
        self.adapters = adapters

    def analyze_package(
        self,
        file_name: str,
        file_bytes: bytes,
        platform: str,
        file_extension: str,
        max_artifacts: int = DEFAULT_MAX_ARTIFACTS,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> list[dict[str, str]]:
        artifacts = extract_binary_artifacts(
            file_name=file_name,
            file_bytes=file_bytes,
            platform=platform,
            file_extension=file_extension,
            max_artifacts=max_artifacts,
            max_artifact_bytes=max_artifact_bytes,
        )
        if not artifacts or not self.adapters:
            return []

        findings: list[dict[str, str]] = []
        for artifact in artifacts:
            for adapter in self.adapters:
                try:
                    if not adapter.supports(artifact):
                        continue
                    findings.extend(adapter.analyze(artifact))
                except Exception as exc:
                    logger.warning(
                        "Binary adapter %s failed for %s: %s",
                        getattr(adapter, "name", adapter.__class__.__name__),
                        artifact.path,
                        exc,
                    )
        return findings


class BinaryMetadataAdapter:
    name = "binary-metadata"

    def supports(self, artifact: BinaryArtifact) -> bool:
        return _detect_binary_format(artifact.data)["format"] != "unknown"

    def analyze(self, artifact: BinaryArtifact) -> list[dict[str, str]]:
        metadata = _detect_binary_format(artifact.data)
        if metadata["format"] == "unknown":
            return []

        details = [
            f"path={artifact.path}",
            f"kind={artifact.kind}",
            f"format={metadata['format']}",
            f"size_bytes={len(artifact.data)}",
        ]
        if metadata["bits"]:
            details.append(f"bits={metadata['bits']}")
        if metadata["architecture"]:
            details.append(f"architecture={metadata['architecture']}")
        if metadata["endianness"]:
            details.append(f"endianness={metadata['endianness']}")

        findings = [
            {
                "id": _finding_id(artifact=artifact, suffix="METADATA"),
                "title": "Binary metadata extracted",
                "severity": "low",
                "category": "binary-metadata",
                "description": "Extracted lightweight binary metadata: " + ", ".join(details),
                "recommendation": (
                    "Use a deeper binary-analysis adapter for symbol, control-flow, "
                    "and vulnerability-oriented inspection"
                ),
                "source": f"binary-metadata/{artifact.path}",
            }
        ]

        if b"http://" in artifact.data.lower():
            findings.append(
                {
                    "id": _finding_id(artifact=artifact, suffix="HTTP-STRING"),
                    "title": "Heuristic: HTTP marker found in binary",
                    "severity": "medium",
                    "category": "binary-network",
                    "description": (
                        f"Binary artifact {artifact.path} contains an HTTP marker. "
                        "This is a lightweight string heuristic, not proof of insecure transport."
                    ),
                    "recommendation": (
                        "Validate whether the binary can initiate cleartext network traffic "
                        "and prefer HTTPS-only endpoints"
                    ),
                    "source": f"binary-strings/{artifact.path}",
                }
            )

        return findings


def run_optional_binary_analysis(
    enabled: bool,
    file_name: str,
    file_bytes: bytes,
    platform: str,
    file_extension: str,
    max_artifacts: int = DEFAULT_MAX_ARTIFACTS,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    adapters: list[BinaryAnalysisAdapter] | None = None,
) -> list[dict[str, str]]:
    if not enabled:
        return []

    configured_adapters = [BinaryMetadataAdapter()] if adapters is None else adapters
    if not configured_adapters:
        logger.info("Binary analysis skipped because no binary adapters are configured")
        return []

    try:
        return BinaryAnalysisRouter(configured_adapters).analyze_package(
            file_name=file_name,
            file_bytes=file_bytes,
            platform=platform,
            file_extension=file_extension,
            max_artifacts=max_artifacts,
            max_artifact_bytes=max_artifact_bytes,
        )
    except Exception as exc:
        logger.warning("Binary analysis unavailable: %s", exc)
        return []


def extract_binary_artifacts(
    file_name: str,
    file_bytes: bytes,
    platform: str,
    file_extension: str,
    max_artifacts: int = DEFAULT_MAX_ARTIFACTS,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> list[BinaryArtifact]:
    extension = file_extension.lower()
    if platform == "android" and extension in {".apk", ".aab"}:
        return _extract_android_artifacts(file_bytes, max_artifacts, max_artifact_bytes)
    if platform == "ios" and extension == ".ipa":
        return _extract_ios_artifacts(file_bytes, max_artifacts, max_artifact_bytes)

    logger.debug("No binary artifact extractor for %s (%s)", file_name, file_extension)
    return []


def _extract_android_artifacts(
    file_bytes: bytes,
    max_artifacts: int,
    max_artifact_bytes: int,
) -> list[BinaryArtifact]:
    artifacts: list[BinaryArtifact] = []
    try:
        with ZipFile(BytesIO(file_bytes), "r") as archive:
            for entry in archive.infolist():
                if len(artifacts) >= max_artifacts:
                    break
                if entry.is_dir() or not ANDROID_NATIVE_LIBRARY_PATTERN.search(entry.filename):
                    continue
                artifact = _read_artifact(
                    archive=archive,
                    entry=entry,
                    platform="android",
                    kind="android-native-library",
                    max_artifact_bytes=max_artifact_bytes,
                )
                if artifact is not None:
                    artifacts.append(artifact)
    except BadZipFile:
        return []
    return artifacts


def _extract_ios_artifacts(
    file_bytes: bytes,
    max_artifacts: int,
    max_artifact_bytes: int,
) -> list[BinaryArtifact]:
    artifacts: list[BinaryArtifact] = []
    try:
        with ZipFile(BytesIO(file_bytes), "r") as archive:
            names = set(archive.namelist())
            main_binary_path = _find_ios_main_binary_path(archive, names)
            if main_binary_path:
                entry = archive.getinfo(main_binary_path)
                artifact = _read_artifact(
                    archive=archive,
                    entry=entry,
                    platform="ios",
                    kind="ios-app-binary",
                    max_artifact_bytes=max_artifact_bytes,
                )
                if artifact is not None:
                    artifacts.append(artifact)

            for entry in archive.infolist():
                if len(artifacts) >= max_artifacts:
                    break
                if entry.is_dir() or entry.filename == main_binary_path:
                    continue
                if not _looks_like_ios_binary_path(entry.filename):
                    continue
                artifact = _read_artifact(
                    archive=archive,
                    entry=entry,
                    platform="ios",
                    kind="ios-linked-binary",
                    max_artifact_bytes=max_artifact_bytes,
                )
                if artifact is not None:
                    artifacts.append(artifact)
    except (BadZipFile, KeyError):
        return []
    return artifacts


def _read_artifact(
    archive: ZipFile,
    entry: ZipInfo,
    platform: str,
    kind: str,
    max_artifact_bytes: int,
) -> BinaryArtifact | None:
    if entry.file_size <= 0 or entry.file_size > max_artifact_bytes:
        return None
    try:
        data = archive.read(entry.filename)
    except (KeyError, RuntimeError, BadZipFile):
        return None
    return BinaryArtifact(platform=platform, path=entry.filename, kind=kind, data=data)


def _find_ios_main_binary_path(archive: ZipFile, names: set[str]) -> str | None:
    info_plist_path = next(
        (
            name
            for name in names
            if name.startswith("Payload/") and name.endswith(".app/Info.plist")
        ),
        None,
    )
    if not info_plist_path:
        return None

    try:
        info = plistlib.loads(archive.read(info_plist_path))
    except (plistlib.InvalidFileException, ValueError, KeyError):
        return None

    executable = info.get("CFBundleExecutable") if isinstance(info, dict) else None
    if not executable:
        return None

    app_dir = info_plist_path.rsplit("/", 1)[0]
    binary_path = f"{app_dir}/{executable}"
    return binary_path if binary_path in names else None


def _looks_like_ios_binary_path(path: str) -> bool:
    lower = path.lower()
    if lower.endswith(".dylib"):
        return True

    parts = path.split("/")
    for index, part in enumerate(parts):
        if not part.endswith(".framework") or index + 1 >= len(parts):
            continue
        framework_name = part[: -len(".framework")]
        if parts[index + 1] == framework_name:
            return True
    return False


def _detect_binary_format(data: bytes) -> dict[str, str]:
    if data.startswith(b"\x7fELF"):
        return _detect_elf_metadata(data)
    if len(data) >= 4:
        return _detect_macho_metadata(data)
    return _unknown_metadata()


def _detect_elf_metadata(data: bytes) -> dict[str, str]:
    bits = {"1": "32-bit", "2": "64-bit"}.get(str(data[4]), "unknown") if len(data) > 4 else ""
    endianness = {"1": "little", "2": "big"}.get(str(data[5]), "") if len(data) > 5 else ""
    byteorder = "big" if endianness == "big" else "little"
    machine = int.from_bytes(data[18:20], byteorder=byteorder) if len(data) >= 20 else 0
    architecture = {
        0x03: "x86",
        0x28: "arm",
        0x3E: "x86_64",
        0xB7: "aarch64",
    }.get(machine, f"machine-{machine}" if machine else "")

    return {
        "format": "elf",
        "bits": bits,
        "architecture": architecture,
        "endianness": endianness,
    }


def _detect_macho_metadata(data: bytes) -> dict[str, str]:
    magic = data[:4]
    if magic == b"\xca\xfe\xba\xbe":
        return {"format": "fat-mach-o", "bits": "multi-arch", "architecture": "", "endianness": "big"}
    if magic == b"\xbe\xba\xfe\xca":
        return {"format": "fat-mach-o", "bits": "multi-arch", "architecture": "", "endianness": "little"}

    macho_magics = {
        b"\xfe\xed\xfa\xce": ("mach-o", "32-bit", "big"),
        b"\xce\xfa\xed\xfe": ("mach-o", "32-bit", "little"),
        b"\xfe\xed\xfa\xcf": ("mach-o", "64-bit", "big"),
        b"\xcf\xfa\xed\xfe": ("mach-o", "64-bit", "little"),
    }
    if magic not in macho_magics:
        return _unknown_metadata()

    binary_format, bits, endianness = macho_magics[magic]
    byteorder = "big" if endianness == "big" else "little"
    cputype = int.from_bytes(data[4:8], byteorder=byteorder, signed=True) if len(data) >= 8 else 0
    architecture = {
        7: "x86",
        12: "arm",
        16777223: "x86_64",
        16777228: "arm64",
    }.get(cputype, f"cpu-{cputype}" if cputype else "")

    return {
        "format": binary_format,
        "bits": bits,
        "architecture": architecture,
        "endianness": endianness,
    }


def _unknown_metadata() -> dict[str, str]:
    return {"format": "unknown", "bits": "", "architecture": "", "endianness": ""}


def _finding_id(artifact: BinaryArtifact, suffix: str) -> str:
    digest = sha1(f"{artifact.platform}|{artifact.path}|{suffix}".encode("utf-8")).hexdigest()[:10].upper()
    return f"BINARY-{artifact.platform.upper()}-{suffix}-{digest}"
