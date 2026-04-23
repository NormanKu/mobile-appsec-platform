from pathlib import Path

from fastapi import UploadFile

from app.core.config import settings
from app.errors.exceptions import UploadValidationError

SUPPORTED_EXTENSIONS = {".apk", ".aab", ".ipa"}


def validate_upload_file(file: UploadFile) -> tuple[str, str]:
    file_name = file.filename or "unknown"
    extension = Path(file_name).suffix.lower()

    if extension not in SUPPORTED_EXTENSIONS:
        raise UploadValidationError(
            code="INVALID_FILE_TYPE",
            message="Only .apk, .aab, or .ipa files are supported",
            status_code=400,
            details={"file_name": file_name, "allowed_extensions": sorted(SUPPORTED_EXTENSIONS)},
        )

    size = _get_upload_size(file)
    if size > settings.max_upload_size_bytes:
        raise UploadValidationError(
            code="FILE_TOO_LARGE",
            message=f"Upload exceeds max size of {settings.max_upload_size_bytes} bytes",
            status_code=413,
            details={"file_name": file_name, "size_bytes": size, "max_size_bytes": settings.max_upload_size_bytes},
        )

    return file_name, extension


def _get_upload_size(file: UploadFile) -> int:
    current = file.file.tell()
    file.file.seek(0, 2)
    size = file.file.tell()
    file.file.seek(current)
    return size
