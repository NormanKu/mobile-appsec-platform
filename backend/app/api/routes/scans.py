from fastapi import APIRouter, File, Request, UploadFile, status

from app.core.config import settings
from app.core.rate_limiter import limiter
from app.errors.exceptions import UploadValidationError
from app.models.error import ErrorResponse
from app.models.scan import ScanJobStatusResponse
from app.services.scan_jobs import ScanJobInput, scan_job_store
from app.services.upload_validator import validate_upload_file

router = APIRouter(tags=["analysis"])


@router.post(
    "/scans",
    response_model=ScanJobStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {"description": "Scan job accepted"},
        400: {"model": ErrorResponse, "description": "Invalid upload request"},
        413: {"model": ErrorResponse, "description": "Upload too large"},
        422: {"model": ErrorResponse, "description": "Validation error"},
    },
)
@limiter.limit(settings.rate_limit_upload)
async def start_scan(
    request: Request, file: UploadFile = File(...)
) -> ScanJobStatusResponse:
    file_name, extension = validate_upload_file(file)
    platform = "android" if extension in {".apk", ".aab"} else "ios"
    file_bytes = await file.read()

    return scan_job_store.submit(
        ScanJobInput(
            file_name=file_name,
            platform=platform,
            file_bytes=file_bytes,
            file_extension=extension,
            max_zip_extracted_bytes=settings.max_zip_extracted_bytes,
            max_zip_files=settings.max_zip_files,
            max_text_file_size=settings.max_text_file_size,
            max_text_files_scanned=settings.max_text_files_scanned,
        )
    )


@router.get(
    "/scans/{job_id}",
    response_model=ScanJobStatusResponse,
    responses={
        200: {"description": "Current scan job status"},
        404: {"model": ErrorResponse, "description": "Scan job not found"},
    },
)
async def get_scan(job_id: str) -> ScanJobStatusResponse:
    job = scan_job_store.get(job_id)
    if job is None:
        raise UploadValidationError(
            code="SCAN_JOB_NOT_FOUND",
            message="Scan job was not found",
            status_code=404,
            details={"job_id": job_id},
        )

    return job
