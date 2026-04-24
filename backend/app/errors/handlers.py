from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.errors.exceptions import UploadValidationError


def _error_payload(code: str, message: str, details: dict | None = None) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }


async def upload_validation_exception_handler(
    _: Request, exc: UploadValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_payload(exc.code, exc.message, exc.details),
    )


async def request_validation_exception_handler(
    _: Request, exc: RequestValidationError
) -> JSONResponse:
    missing_file_error = any(
        err.get("loc") == ("body", "file") and err.get("type") == "missing"
        for err in exc.errors()
    )

    if missing_file_error:
        return JSONResponse(
            status_code=400,
            content=_error_payload(
                "MISSING_FILE",
                "No file was provided in the upload request",
                {"field": "file"},
            ),
        )

    return JSONResponse(
        status_code=422,
        content=_error_payload(
            "VALIDATION_ERROR",
            "Request validation failed",
            {"errors": exc.errors()},
        ),
    )
