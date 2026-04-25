import asyncio
from functools import partial
import logging

from fastapi import APIRouter, File, Form, Request, UploadFile
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings
from app.models.error import ErrorResponse
from app.models.report import IOS_EXAMPLE_REPORT, ANDROID_EXAMPLE_REPORT, NormalizedAnalysisReport
from app.errors.exceptions import UploadValidationError
from app.services.report_builder import build_normalized_report
from app.services.scan_history import ScanHistoryStore
from app.services.upload_validator import validate_upload_file

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(tags=["analysis"])
logger = logging.getLogger(__name__)


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
        500: {"model": ErrorResponse, "description": "Analysis or persistence failed"},
    },
)
@limiter.limit(settings.rate_limit_upload)
async def upload_binary(
    request: Request,
    file: UploadFile = File(...),
    project_id: str | None = Form(default=None),
    project_name: str | None = Form(default=None),
    app_id: str | None = Form(default=None),
    app_name: str | None = Form(default=None),
    app_version_id: str | None = Form(default=None),
    version_name: str | None = Form(default=None),
    build_identifier: str | None = Form(default=None),
) -> NormalizedAnalysisReport:
    file_name, extension = validate_upload_file(file)
    platform = "android" if extension in {".apk", ".aab"} else "ios"

    file_bytes = await file.read()

    try:
        report = await asyncio.get_event_loop().run_in_executor(
            None,
            partial(
                build_normalized_report,
                file_name=file_name,
                platform=platform,
                file_bytes=file_bytes,
                file_extension=extension,
                max_zip_extracted_bytes=settings.max_zip_extracted_bytes,
            ),
        )
    except Exception as exc:
        logger.exception("Scan analysis failed for %s", file_name)
        failed_scan_id = None
        try:
            failed_scan = ScanHistoryStore().save_failed_scan(
                file_name=file_name,
                file_extension=extension,
                platform=platform,
                error_code="SCAN_ANALYSIS_FAILED",
                error_message=str(exc),
                project_id=project_id,
                project_name=project_name,
                app_id=app_id,
                app_name=app_name,
                app_version_id=app_version_id,
                version_name=version_name,
                build_identifier=build_identifier,
            )
            failed_scan_id = failed_scan.id
        except ValueError as context_exc:
            raise UploadValidationError(
                code="INVALID_SCAN_CONTEXT",
                message=str(context_exc),
                status_code=400,
            ) from context_exc
        except Exception:
            logger.exception("Failed to persist failed scan record for %s", file_name)

        raise UploadValidationError(
            code="SCAN_ANALYSIS_FAILED",
            message="Analysis failed before a normalized report was produced",
            status_code=500,
            details={"scan_id": failed_scan_id, "file_name": file_name},
        ) from exc

    try:
        ScanHistoryStore().save_report(
            report,
            project_id=project_id,
            project_name=project_name,
            app_id=app_id,
            app_name=app_name,
            app_version_id=app_version_id,
            version_name=version_name,
            build_identifier=build_identifier,
        )
    except ValueError as exc:
        raise UploadValidationError(
            code="INVALID_SCAN_CONTEXT",
            message=str(exc),
            status_code=400,
        ) from exc
    except Exception as exc:
        logger.exception("Failed to persist completed scan for %s", file_name)
        raise UploadValidationError(
            code="SCAN_PERSISTENCE_FAILED",
            message="Analysis completed but the scan result could not be persisted",
            status_code=500,
            details={"file_name": file_name},
        ) from exc
    return report
