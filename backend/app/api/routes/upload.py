import asyncio
from functools import partial

from fastapi import APIRouter, File, Request, UploadFile

from app.core.config import settings
from app.core.rate_limiter import limiter
from app.models.error import ErrorResponse
from app.models.report import IOS_EXAMPLE_REPORT, ANDROID_EXAMPLE_REPORT, NormalizedAnalysisReport
from app.services.report_builder import build_normalized_report
from app.services.upload_validator import validate_upload_file

router = APIRouter(tags=["analysis"])


@router.post(
    "/upload",
    response_model=NormalizedAnalysisReport,
    responses={
        200: {
            "description": "Normalized static analysis report",
            "content": {
                "application/json": {
                    "examples": {
                        "android": {"summary": "Android example", "value": ANDROID_EXAMPLE_REPORT},
                        "ios": {"summary": "iOS example", "value": IOS_EXAMPLE_REPORT},
                    }
                }
            },
        },
        400: {"model": ErrorResponse, "description": "Invalid upload request or malformed archive"},
        413: {"model": ErrorResponse, "description": "Upload too large or archive exceeds safe extraction limits"},
        422: {"model": ErrorResponse, "description": "Validation error"},
    },
)
@limiter.limit(settings.rate_limit_upload)
async def upload_binary(request: Request, file: UploadFile = File(...)) -> NormalizedAnalysisReport:
    file_name, extension = validate_upload_file(file)
    platform = "android" if extension in {".apk", ".aab"} else "ios"

    file_bytes = await file.read()

    report = await asyncio.get_event_loop().run_in_executor(
        None,
        partial(
            build_normalized_report,
            file_name=file_name,
            platform=platform,
            file_bytes=file_bytes,
            file_extension=extension,
            max_zip_extracted_bytes=settings.max_zip_extracted_bytes,
            max_zip_files=settings.max_zip_files,
            max_text_file_size=settings.max_text_file_size,
            max_text_files_scanned=settings.max_text_files_scanned,
        ),
    )
    return report
