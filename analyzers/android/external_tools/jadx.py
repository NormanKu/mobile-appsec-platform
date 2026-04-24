from __future__ import annotations

import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory

from .models import AndroidExternalToolResult, AndroidExternalToolSignal

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|client[_-]?secret|secret|token|passwd|password)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{8,})"
)
PACKAGE_PATTERN = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)", re.MULTILINE)
CLASS_PATTERN = re.compile(r"\b(class|interface|object|enum)\s+([A-Za-z_][A-Za-z0-9_]*)")

DEFAULT_TIMEOUT_SECONDS = 45
DEFAULT_MAX_SOURCE_FILES = 200
DEFAULT_MAX_SOURCE_FILE_SIZE = 300_000
SOURCE_EXTENSIONS = {".java", ".kt"}
AUTO_GENERATED_CLASS_NAMES = {"BuildConfig", "R"}
IGNORED_URLS = {
    "http://schemas.android.com/apk/res/android",
    "https://schemas.android.com/apk/res/android",
}
SUSPICIOUS_NAME_KEYWORDS = (
    "admin",
    "debug",
    "demo",
    "internal",
    "mock",
    "sandbox",
    "secret",
    "staging",
    "test",
    "token",
)


class JadxAdapter:
    def __init__(
        self,
        jadx_path: str | None = None,
        timeout_seconds: int | None = None,
        max_source_files: int | None = None,
        max_source_file_size: int | None = None,
    ) -> None:
        self.jadx_path = jadx_path if jadx_path is not None else os.getenv("APPSEC_ANDROID_JADX_PATH")
        self.timeout_seconds = timeout_seconds or _read_int_env(
            "APPSEC_ANDROID_JADX_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
        )
        self.max_source_files = max_source_files or _read_int_env(
            "APPSEC_ANDROID_JADX_MAX_SOURCE_FILES",
            DEFAULT_MAX_SOURCE_FILES,
        )
        self.max_source_file_size = max_source_file_size or _read_int_env(
            "APPSEC_ANDROID_JADX_MAX_SOURCE_FILE_SIZE",
            DEFAULT_MAX_SOURCE_FILE_SIZE,
        )

    def analyze_apk(self, *, file_name: str, file_bytes: bytes) -> AndroidExternalToolResult:
        executable = self._resolve_executable()
        if not executable:
            logger.info("JADX enrichment skipped for %s because jadx is not installed", file_name)
            return AndroidExternalToolResult(tool_name="jadx", available=False, executed=False)

        with TemporaryDirectory(prefix="jadx-") as temp_dir:
            working_dir = Path(temp_dir)
            apk_path = working_dir / _normalize_input_name(file_name)
            output_dir = working_dir / "jadx-output"
            apk_path.write_bytes(file_bytes)

            try:
                process = self._run_jadx(
                    executable=executable,
                    input_path=apk_path,
                    output_dir=output_dir,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                logger.warning("JADX enrichment failed for %s: %s", file_name, exc)
                return AndroidExternalToolResult(
                    tool_name="jadx",
                    available=True,
                    executed=False,
                    error=str(exc),
                )

            if process.returncode != 0:
                error_message = _summarize_process_error(process)
                logger.warning("JADX returned non-zero exit code for %s: %s", file_name, error_message)
                return AndroidExternalToolResult(
                    tool_name="jadx",
                    available=True,
                    executed=False,
                    error=error_message,
                )

            signals, scanned_files = self._collect_signals(output_dir)
            return AndroidExternalToolResult(
                tool_name="jadx",
                available=True,
                executed=True,
                signals=signals,
                source_files_scanned=scanned_files,
            )

    def _resolve_executable(self) -> str | None:
        if self.jadx_path:
            configured = Path(self.jadx_path)
            if configured.is_file() and os.access(configured, os.X_OK):
                return str(configured)
            return shutil.which(self.jadx_path)

        return shutil.which("jadx")

    def _run_jadx(
        self,
        *,
        executable: str,
        input_path: Path,
        output_dir: Path,
    ) -> subprocess.CompletedProcess[str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        return subprocess.run(
            [executable, "--no-res", "-d", str(output_dir), str(input_path)],
            capture_output=True,
            check=False,
            text=True,
            timeout=self.timeout_seconds,
        )

    def _collect_signals(self, output_dir: Path) -> tuple[tuple[AndroidExternalToolSignal, ...], int]:
        collected: list[AndroidExternalToolSignal] = []
        seen: set[tuple[str, str]] = set()
        scanned_files = 0

        for source_path in self._iter_source_files(output_dir):
            if scanned_files >= self.max_source_files:
                break

            try:
                file_size = source_path.stat().st_size
            except OSError as exc:
                logger.debug("Skipping unreadable JADX output %s: %s", source_path, exc)
                continue

            if file_size <= 0 or file_size > self.max_source_file_size:
                continue

            try:
                content = source_path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.debug("Skipping unreadable JADX output %s: %s", source_path, exc)
                continue

            scanned_files += 1
            relative_path = source_path.relative_to(output_dir).as_posix()
            package_name = _extract_package_name(content)
            class_names = _extract_class_names(content)

            for identifier in _extract_readable_identifiers(package_name, class_names, source_path):
                _append_signal(
                    collected,
                    seen,
                    kind="readable_source",
                    value=identifier,
                    location=relative_path,
                )

            for url in URL_PATTERN.findall(content):
                if _is_noteworthy_url(url):
                    _append_signal(
                        collected,
                        seen,
                        kind="hardcoded_url",
                        value=url,
                        location=relative_path,
                    )

            for match in SECRET_PATTERN.finditer(content):
                indicator = f"{match.group(1)}={match.group(2)[:6]}..."
                _append_signal(
                    collected,
                    seen,
                    kind="candidate_secret",
                    value=indicator,
                    location=relative_path,
                )

            for identifier in _extract_suspicious_identifiers(package_name, class_names):
                _append_signal(
                    collected,
                    seen,
                    kind="naming_pattern",
                    value=identifier,
                    location=relative_path,
                )

        return tuple(collected), scanned_files

    def _iter_source_files(self, output_dir: Path) -> list[Path]:
        return sorted(
            path
            for path in output_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS
        )


def analyze_with_jadx(
    *,
    file_name: str,
    file_bytes: bytes,
    adapter: JadxAdapter | None = None,
) -> AndroidExternalToolResult:
    active_adapter = adapter or JadxAdapter()
    return active_adapter.analyze_apk(file_name=file_name, file_bytes=file_bytes)


def _append_signal(
    collected: list[AndroidExternalToolSignal],
    seen: set[tuple[str, str]],
    *,
    kind: str,
    value: str,
    location: str,
) -> None:
    key = (kind, value)
    if key in seen:
        return

    seen.add(key)
    collected.append(AndroidExternalToolSignal(kind=kind, value=value, location=location))


def _extract_package_name(content: str) -> str | None:
    match = PACKAGE_PATTERN.search(content)
    return match.group(1) if match else None


def _extract_class_names(content: str) -> list[str]:
    return [match.group(2) for match in CLASS_PATTERN.finditer(content)]


def _extract_readable_identifiers(
    package_name: str | None,
    class_names: list[str],
    source_path: Path,
) -> list[str]:
    readable: list[str] = []
    for class_name in class_names:
        if not _looks_meaningful_identifier(class_name):
            continue

        readable.append(f"{package_name}.{class_name}" if package_name else class_name)

    if readable:
        return readable[:3]

    fallback_name = source_path.stem
    if _looks_meaningful_identifier(fallback_name):
        return [f"{package_name}.{fallback_name}" if package_name else fallback_name]

    return []


def _extract_suspicious_identifiers(package_name: str | None, class_names: list[str]) -> list[str]:
    identifiers: list[str] = []
    if package_name and _contains_suspicious_keyword(package_name):
        identifiers.append(package_name)

    for class_name in class_names:
        if _contains_suspicious_keyword(class_name):
            identifiers.append(f"{package_name}.{class_name}" if package_name else class_name)

    return identifiers


def _contains_suspicious_keyword(value: str) -> bool:
    lowered = value.lower()
    return any(keyword in lowered for keyword in SUSPICIOUS_NAME_KEYWORDS)


def _looks_meaningful_identifier(identifier: str) -> bool:
    simple_name = identifier.rsplit(".", 1)[-1]
    if simple_name in AUTO_GENERATED_CLASS_NAMES or simple_name.startswith("R$"):
        return False

    if len(simple_name) <= 2:
        return False

    if re.fullmatch(r"[A-Za-z]\d?", simple_name):
        return False

    if re.fullmatch(r"[a-z]{1,3}", simple_name):
        return False

    return True


def _is_noteworthy_url(url: str) -> bool:
    return url.lower() not in IGNORED_URLS


def _normalize_input_name(file_name: str) -> str:
    normalized = Path(file_name).name or "sample.apk"
    return normalized if normalized.endswith(".apk") else f"{normalized}.apk"


def _read_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if not raw_value:
        return default

    try:
        parsed = int(raw_value)
    except ValueError:
        logger.warning("Ignoring invalid integer value for %s: %r", name, raw_value)
        return default

    return parsed if parsed > 0 else default


def _summarize_process_error(process: subprocess.CompletedProcess[str]) -> str:
    output = (process.stderr or process.stdout or "jadx execution failed").strip()
    compact = " ".join(output.split())
    return compact[:240]
