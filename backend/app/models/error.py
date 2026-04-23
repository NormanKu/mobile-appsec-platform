from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    code: str = Field(..., examples=["INVALID_FILE_TYPE"])
    message: str = Field(..., examples=["Only .apk, .aab, or .ipa files are supported"])
    details: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail
