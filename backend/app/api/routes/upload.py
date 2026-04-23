import asyncio
from functools import partial

from fastapi import APIRouter, File, UploadFile

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
        400: {"model": ErrorResponse, "description": "Invalid upload request"},
        413: {"model": ErrorResponse, "description": "Upload too large"},
        422: {"model": ErrorResponse, "description": "Validation error"},
    },
)
async def upload_binary(file: UploadFile = File(...)) -> NormalizedAnalysisReport:
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
        ),
    )
    return report
