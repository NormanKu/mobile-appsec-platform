"""Safe ZIP extraction utilities with decompression bomb protection."""

from __future__ import annotations

from zipfile import ZipFile

DEFAULT_MAX_EXTRACTED_BYTES = 200 * 1024 * 1024  # 200 MB
DEFAULT_MAX_FILES = 5_000


class ZipExtractionLimitExceeded(Exception):
    """Raised when a ZIP archive exceeds safe extraction limits."""


def validate_zip_limits(
    archive: ZipFile,
    max_extracted_bytes: int = DEFAULT_MAX_EXTRACTED_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
) -> None:
    entries = archive.infolist()

    if len(entries) > max_files:
        raise ZipExtractionLimitExceeded(
            f"Archive contains {len(entries)} entries, exceeding limit of {max_files}"
        )

    total_uncompressed = sum(entry.file_size for entry in entries)
    if total_uncompressed > max_extracted_bytes:
        raise ZipExtractionLimitExceeded(
            f"Total uncompressed size {total_uncompressed} bytes exceeds limit of {max_extracted_bytes} bytes"
        )


def safe_read(
    archive: ZipFile,
    entry_name: str,
    max_size: int = DEFAULT_MAX_EXTRACTED_BYTES,
) -> bytes:
    info = archive.getinfo(entry_name)
    if info.file_size > max_size:
        raise ZipExtractionLimitExceeded(
            f"Entry {entry_name} ({info.file_size} bytes) exceeds single-file limit of {max_size} bytes"
        )
    return archive.read(entry_name)
